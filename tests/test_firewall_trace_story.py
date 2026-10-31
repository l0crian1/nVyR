"""Narrative control flow must remain faithful to the underlying trace evidence."""

from nvyr.helpers import firewall_trace_analysis as analysis
from nvyr.helpers.firewall_trace_output import story, chain_visits, visit_result
from tests.test_firewall_trace_analysis import capture, NATIVE
from tests.trace_examples import example_trace, report_for


def journey(*events, detail=False):
    """Use the production parser and analyzer before rendering a selected trace."""
    report = analysis.analyze(capture(*events), identifier='abc')
    return story(report['traces'][0], detail=detail)


def test_nested_chain_story_and_itinerary_preserve_calls_and_resumptions():
    """Nested returns should read in execution order rather than as isolated verdicts."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_forward rule jump ipv4_name_A comment "10|" (verdict jump ipv4_name_A)',
        'trace id abc inet nvyr_filter ipv4_name_A rule jump ipv4_name_B comment "20|" (verdict jump ipv4_name_B)',
        'trace id abc inet nvyr_filter ipv4_name_B rule return comment "30|" (verdict return)',
        'trace id abc inet nvyr_filter ipv4_name_A rule return comment "40|" (verdict return)',
        'trace id abc inet nvyr_filter ipv4_forward rule drop comment "50|" (verdict drop)',
    )

    expected = [
        'jumped to named IPv4 chain A',
        'jumped to named IPv4 chain B',
        'Rule 30 in named IPv4 chain B returned',
        'Processing resumed in named IPv4 chain A',
        'Rule 40 in named IPv4 chain A returned',
        'Processing resumed in the IPv4 forward firewall',
        'Rule 50 in IPv4 forward firewall dropped',
    ]
    body = output.split('STORY\n')[1].split('TABLES AND CHAINS VISITED')[0]
    indices = [body.index(line) for line in expected]
    assert indices == sorted(indices)
    assert 'firewall ipv4 forward filter rule 50' in output
    assert 'Expression:' not in output


def test_goto_does_not_invent_a_return_to_the_replaced_chain():
    """A return after goto resumes the jump caller, not the chain that used goto."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_forward rule jump ipv4_name_A comment "10|" (verdict jump ipv4_name_A)',
        'trace id abc inet nvyr_filter ipv4_name_A rule goto ipv4_name_B comment "20|" (verdict goto ipv4_name_B)',
        'trace id abc inet nvyr_filter ipv4_name_B rule return comment "30|" (verdict return)',
        'trace id abc inet nvyr_filter ipv4_forward rule accept comment "40|" (verdict accept)',
    )

    assert 'goto; no return to this rule' in ' '.join(output.split())
    assert 'Processing resumed in named IPv4 chain A' not in output
    assert 'Processing resumed in the IPv4 forward firewall' in output


def test_nat_story_uses_observed_endpoints_and_retains_all_evidence_in_detail():
    """The native example must include the translation, not merely an established reply."""
    report = report_for(NATIVE['dnat-address-port'])
    trace = example_trace(report, 'dnat-address-port')
    output = story(trace)
    detailed = story(trace, detail=True)

    assert 'applied destination NAT' in output
    prose = ' '.join(output.split())
    assert 'The destination changed from 203.0.113.9:8000 to 198.51.100.2:9000' in prose
    assert 'Expression:' not in output
    assert 'Native evidence' not in output
    assert detailed.startswith(output)
    assert 'Native evidence' in detailed
    assert 'Capture line ' in detailed
    for event in trace['steps']:
        assert event['raw'] in detailed


def test_nat_without_a_later_header_does_not_invent_the_translated_tuple():
    """A literal NAT target is not an observed post-translation packet header."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_nat_prerouting rule dnat ip to 10.0.0.1:8443 comment "10|web" (verdict accept)',
    )

    assert 'applied destination NAT' in output
    assert 'No packet-header changes recorded.' in output
    assert '10.0.0.1:8443' not in output


def test_reject_story_distinguishes_a_reset_from_a_silent_drop():
    """Both have a native drop verdict, but only reject requests a response."""
    rejection = journey(
        'trace id abc inet nvyr_filter ipv4_forward rule reject with tcp reset comment "10|SSH" (verdict drop)')
    drop = journey(
        'trace id abc inet nvyr_filter ipv4_forward rule drop comment "10|SSH" (verdict drop)')

    assert 'rejected with a TCP reset' in rejection
    assert 'IPv4 forward firewall dropped' in drop
    assert 'reset' not in drop
    assert 'response was delivered' not in rejection


def test_acceptance_does_not_hide_a_later_drop():
    """An accepted base-chain pass is not the end of the packet journey."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_prerouting rule accept comment "10|" (verdict accept)',
        'trace id abc inet nvyr_filter ipv4_forward rule drop comment "20|" (verdict drop)',
    )

    body = output.split('STORY\n')[1].split('TABLES AND CHAINS VISITED')[0]
    assert body.index('accepted') < body.index('dropped')
    assert 'DROP — last observed decision at firewall ipv4 forward filter rule 20' in output


def test_vrf_story_continues_after_the_preliminary_output_accept():
    """Real traffic shows the VRF pass and then the member-interface pass."""
    report = report_for(NATIVE['vrf-output'])
    output = story(example_trace(report, 'vrf-output'))

    assert 'accepted the preliminary VRF output pass' in output
    assert 'output path changed from "TRACEVRF" to "tr-out"' in output
    body = output.split('STORY\n')[1].split('TABLES AND CHAINS VISITED')[0]
    assert body.index('preliminary VRF') < body.index('Rule 10 in output firewall accepted')


def test_reused_ids_start_new_stories_without_carrying_nat_or_chain_context():
    """Repeated observation passes must not become a fictional reverse NAT operation."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_prerouting packet: ip saddr 192.0.2.1 ip daddr 203.0.113.1 ip id 1 tcp dport 80',
        'trace id abc inet nvyr_filter ipv4_nat_prerouting rule dnat ip to 10.0.0.1:8080 comment "10|" (verdict accept)',
        'trace id abc inet nvyr_filter ipv4_forward packet: ip saddr 192.0.2.1 ip daddr 10.0.0.1 ip id 1 tcp dport 8080',
        'trace id abc inet nvyr_filter ipv4_forward rule accept comment "20|" (verdict accept)',
        'trace id abc inet nvyr_filter ipv4_prerouting packet: ip saddr 192.0.2.1 ip daddr 203.0.113.1 ip id 2 tcp dport 80',
    )

    assert 'OBSERVATION PASS 2' in output
    assert 'changed from 10.0.0.1:8080 to 203.0.113.1:80' not in output
    second_pass = output.split('OBSERVATION PASS 2')[1]
    assert 'Processing resumed' not in second_pass
    assert 'after nat destination rule 10' not in second_pass


def test_quoted_log_prefix_is_not_treated_as_a_reject_or_nat_statement():
    """Words inside a prefix or description must never alter the narrated verdict."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_forward rule log prefix "reject dnat" accept comment "10|drop" (verdict accept)',
    )

    assert 'accepted' in output
    assert 'included packet logging' in output
    assert 'rejected with' not in output
    assert 'applied destination NAT' not in output


def test_conntrack_repetition_is_collapsed_but_state_changes_remain():
    """Repeated snapshots should not interrupt the narrative with identical state."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_prerouting conntrack: ct direction 0 ct state 0x8 ct id 12',
        'trace id abc inet nvyr_filter ipv4_forward conntrack: ct direction 0 ct state 0x8 ct id 12',
        'trace id abc inet nvyr_filter ipv4_forward conntrack: ct direction 1 ct state 0x2 ct id 12',
    )

    assert output.count('classified the packet as new') == 1
    assert output.count('original direction') == 1
    assert 'classified the packet as established' in output
    assert 'reply direction' in output
    assert 'ct id 12' not in output


def test_continuing_unknown_statement_remains_visible():
    """Unrecognized operations need their expression instead of disappearing from the story."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_forward rule meta mark set 42 comment "10|tag" (verdict continue)',
    )

    assert 'continued' in output
    assert 'Evaluated: meta mark set 42' in output
    assert 'No subsequent accept or drop was recorded.' in output


def test_terminal_controls_are_escaped_in_the_narrative_too():
    """Rule descriptions can be untrusted saved evidence."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_forward rule drop comment "10|\\u001b[2J" (verdict drop)',
    )

    assert '\x1b' not in output
    assert '\\x1b' in output


def test_conntrack_nat_status_match_is_not_a_nat_action():
    """A rule matching translated connections must not claim to translate them again."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_forward rule ct status { snat, dnat } accept comment "10|" (verdict accept)',
    )

    assert 'accepted' in output
    assert 'applied source NAT' not in output
    assert 'applied destination NAT' not in output


def test_journey_uses_the_approved_sections_with_flow_and_interface_summary():
    """Readable sections are part of the output contract, not just prose formatting."""
    report = report_for(NATIVE['tcp-reject'])
    output = story(example_trace(report, 'tcp-reject'))

    headings = ['STORY', 'TABLES AND CHAINS VISITED', 'RULES HIT', 'OBSERVED CHANGES', 'OUTCOME']
    positions = [output.index(heading + '\n' + '─' * 76) for heading in headings]
    assert positions == sorted(positions)
    assert 'Trace e6ff4c0e' in output
    assert 'Flow       TCP 192.0.2.2:43126 → 198.51.100.2:9000' in output
    assert 'Ingress    tr-in' in output and 'Egress     tr-out' in output
    assert 'DROP —' in output.split('\nOUTCOME\n')[1]
    assert 'handle ' not in output
    assert 'Capture line' not in output


def test_real_empty_and_nonmatching_chains_remain_in_the_itinerary():
    """Native Linux emits only caller events for both empty and nonmatching chains."""
    report = report_for(NATIVE['empty-and-unmatched'])
    trace = example_trace(report, 'empty-and-unmatched')
    visits = chain_visits(trace['steps'])
    output = story(trace)

    assert [visit['identity'][2] for visit in visits] == [
        'output', 'ipv4_name_EMPTY', 'output', 'ipv4_name_MISS', 'output']
    for index in (1, 3):
        assert visits[index]['events'] == []
        assert visits[index]['return-line']
        assert visit_result(visits[index]) == 'No rule hit recorded; returned'
    assert output.count('No rule hit recorded; returned') == 2
    assert 'not matched' not in output  # Description of the rule which was never hit.
    rules = output.split('\nRULES HIT\n')[1].split('\nOBSERVED CHANGES\n')[0]
    assert 'firewall ipv4 name EMPTY rule' not in rules
    assert 'firewall ipv4 name MISS rule' not in rules


def test_truncated_jump_keeps_target_without_claiming_return():
    """A jump is evidence of its target, not evidence that the target returned."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_forward rule jump ipv4_name_A comment "10|" (verdict jump ipv4_name_A)',
    )

    assert 'ipv4_name_A' in output.split('TABLES AND CHAINS VISITED')[1]
    assert 'Jump/goto target; no chain events recorded' in output
    assert 'No rule hit recorded; returned' not in output
    assert 'Processing resumed' not in output


def test_packet_only_chain_observation_is_not_a_rule_hit():
    """Observed chains with no recorded decision remain visible without fabricated matches."""
    output = journey(
        'trace id abc inet observations untouched packet: ip saddr 192.0.2.1 ip daddr 192.0.2.2',
    )

    assert 'inet observations' in output
    assert 'untouched' in output
    assert 'Observed; no rule hit recorded' in output
    assert 'No rule hits recorded.' in output
    assert 'No verdict was recorded.' in output


def test_table_and_family_are_part_of_the_visit_identity():
    """Identically named chains in different nftables tables/families stay distinct."""
    events = (
        'trace id abc ip filter input policy accept',
        'trace id abc inet filter input policy accept',
        'trace id abc inet other input policy drop',
    )
    trace = analysis.analyze(capture(*events), identifier='abc')['traces'][0]
    visits = chain_visits(trace['steps'])

    assert [visit['identity'] for visit in visits] == [
        ('ip', 'filter', 'input'), ('inet', 'filter', 'input'), ('inet', 'other', 'input')]


def test_observed_changes_include_ttl_ports_and_marks_with_line_references():
    """The default view exposes all changes, not only NAT addresses."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_prerouting packet: ip saddr 192.0.2.1 ip daddr 203.0.113.1 ip ttl 64 tcp dport 80 mark 0',
        'trace id abc inet nvyr_filter ipv4_forward packet: ip saddr 192.0.2.1 ip daddr 203.0.113.1 ip ttl 63 tcp dport 8080 mark 42',
    )

    changes = output.split('\nOBSERVED CHANGES\n')[1].split('\nOUTCOME\n')[0]
    assert 'TTL' in changes and 'Destination port' in changes and 'Mark' in changes
    assert changes.count('L3') == 3
    assert '64' in changes and '63' in changes
    assert '80' in changes and '8080' in changes
    assert 'TTL changed from 64 to 63 (L3)' in output


def test_late_packet_observation_does_not_erase_the_last_verdict():
    """A post-NAT header can follow the final recorded decision."""
    output = journey(
        'trace id abc inet nvyr_filter ipv4_nat_postrouting rule masquerade comment "10|" (verdict accept)',
        'trace id abc inet observers after_nat packet: ip saddr 203.0.113.1 ip daddr 192.0.2.1',
    )

    result = output.split('\nOUTCOME\n')[1]
    assert 'ACCEPT — last observed decision at nat source rule 10 (L2)' in result


def test_mss_rewrite_statement_is_reported_without_inventing_an_observed_value():
    """Expose MSS mangling from the rule, but do not put rt mtu into observed changes."""
    output = journey(
        'trace id abc inet mangle forward rule tcp option maxseg size set rt mtu (verdict continue)',
    )

    assert 'set TCP MSS: rt mtu' in output
    changes = output.split('\nOBSERVED CHANGES\n')[1].split('\nOUTCOME\n')[0]
    assert 'No packet-header changes recorded.' in changes
