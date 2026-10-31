"""Packet evidence, ordered traversal, capture boundaries and operational inspection."""

import io
import json

import pytest

from nvyr.errors import OperationalError, RouterError
from nvyr.helpers import access, firewall_trace, firewall_trace_analysis as analysis
from nvyr.helpers.firewall_trace_output import render
from nvyr.op_scripts import firewall_trace as commands
from tests.trace_examples import load_corpus


def capture(*lines, complete=True):
    """Use the capture writer's actual record format, with real base-chain metadata."""
    records = [{'event': 'capture', 'format': 1, 'chains': [
        {'family': 'inet', 'table': 'nvyr_filter', 'name': 'ipv4_prerouting', 'hook': 'prerouting'},
        {'family': 'inet', 'table': 'nvyr_filter', 'name': 'ipv4_forward', 'hook': 'forward'},
        {'family': 'inet', 'table': 'nvyr_filter', 'name': 'ipv6_input', 'hook': 'input'}]}]
    records.extend(firewall_trace.event_record(line) for line in lines)
    if complete:
        records.append({'event': 'capture-end', 'reason': 'duration', 'events': len(lines)})
    return io.StringIO(''.join(json.dumps(record) + '\n' for record in records))


def test_ipv6_headers_are_not_confused_with_inet_table_family():
    """Native numeric protocol fields and full IPv6 endpoints survive decoding."""
    line = 'trace id abc inet nvyr_filter ipv6_input packet: iif "eth1" ip6 saddr 2001:db8::1 ip6 daddr 2001:db8::2 ip6 nexthdr 6 ip6 hoplimit 63 tcp sport 50000 tcp dport 443 tcp flags == syn'
    report = analysis.analyze(capture(line), detail=True)
    packet = report['traces'][0]['first']
    assert packet['family'] == 'ipv6'
    assert packet['protocol'] == 'tcp'
    assert packet['tcp-flags'] == 'syn'
    assert packet['hop-limit'] == '63'
    assert '[2001:db8::1]:50000' in render(report)
    assert report['traces'][0]['hooks'] == ['input']


def test_nat_ports_and_address_changes_are_observations_not_rule_literals():
    """A NAT rule alone proves evaluation, while later packet headers prove rewrites."""
    lines = [
        'trace id abc inet nvyr_filter ipv4_prerouting packet: ip saddr 192.0.2.1 ip daddr 198.51.100.1 ip protocol 6 tcp sport 50000 tcp dport 443',
        'trace id abc inet nvyr_filter ipv4_nat_prerouting rule dnat ip to 10.0.0.1:8443 comment "10|web" # handle 7 (verdict accept)',
        'trace id abc inet nvyr_filter ipv4_forward packet: ip saddr 192.0.2.1 ip daddr 10.0.0.1 ip protocol 6 tcp sport 50000 tcp dport 8443',
        'trace id abc inet nvyr_filter ipv4_nat_postrouting packet: ip saddr 192.0.2.1 ip daddr 10.0.0.1 ip protocol 6 tcp sport 50000 tcp dport 9443',
    ]
    report = analysis.analyze(capture(*lines), detail=True)
    trace = report['traces'][0]
    assert trace['observations'] == 3
    assert len(trace['changes']) == 2
    assert trace['changes'][0]['fields']['destination-address'] == {'before': '198.51.100.1', 'after': '10.0.0.1'}
    assert trace['changes'][1]['fields']['destination-port']['after'] == '9443'
    assert trace['steps'][1]['handle'] == 7
    assert trace['steps'][1]['path'] == 'nat destination rule 10'
    before = analysis.analyze(capture(*lines[:2]))
    assert not before['traces'][0]['changes']
    assert 'Final verdict' not in render(report, stories=True)


def test_tuple_filters_cannot_combine_fields_from_different_observations():
    """A public address and its translated port never form an observed tuple here."""
    lines = [
        'trace id abc inet nvyr_filter ipv4_prerouting packet: ip saddr 192.0.2.1 ip daddr 198.51.100.1 tcp dport 443',
        'trace id abc inet nvyr_filter ipv4_forward packet: ip saddr 192.0.2.1 ip daddr 10.0.0.1 tcp dport 8443',
    ]
    assert not analysis.analyze(capture(*lines), filters={'destination-address': '198.51.100.1', 'destination-port': '8443'})['traces']
    assert analysis.analyze(capture(*lines), filters={'destination-address': '10.0.0.1', 'destination-port': '8443'})['traces']


def test_nested_returns_and_revisited_chains_remain_ordered():
    """A summary must not deduplicate away the return to a caller or a second hook visit."""
    lines = [
        'trace id abc inet nvyr_filter ipv4_forward rule jump ipv4_name_A comment "10|" (verdict jump ipv4_name_A)',
        'trace id abc inet nvyr_filter ipv4_name_A rule jump ipv4_name_B comment "20|" (verdict jump ipv4_name_B)',
        'trace id abc inet nvyr_filter ipv4_name_B rule return comment "30|" (verdict return)',
        'trace id abc inet nvyr_filter ipv4_name_A rule return comment "40|" (verdict return)',
        'trace id abc inet nvyr_filter ipv4_forward rule drop comment "50|" (verdict drop)',
    ]
    report = analysis.analyze(capture(*lines), identifier='abc')
    trace = report['traces'][0]
    assert [step['chain'] for step in trace['steps']] == ['ipv4_forward', 'ipv4_name_A', 'ipv4_name_B', 'ipv4_name_A', 'ipv4_forward']
    assert trace['last-verdict'] == 'drop'
    assert trace['last-location'] == 'firewall ipv4 forward filter rule 50'
    assert 'named IPv4 chain B returned' in render(report, stories=True)


def test_interleaved_packets_are_independent_and_ids_select_exactly():
    """Interleaved trace lines retain packet-local traversal and metadata."""
    lines = [
        'trace id a inet nvyr_filter ipv4_forward packet: ip saddr 192.0.2.1 ip daddr 192.0.2.2 udp sport 1 udp dport 2',
        'trace id b inet nvyr_filter ipv6_input packet: ip6 saddr ::1 ip6 daddr ::1 icmpv6 type 128 icmpv6 code 0',
        'trace id a inet nvyr_filter ipv4_forward rule accept comment "10|" (verdict accept)',
        'trace id b inet nvyr_filter ipv6_input policy drop',
    ]
    report = analysis.analyze(capture(*lines), detail=True)
    assert [trace['events'] for trace in report['traces']] == [2, 2]
    assert [trace['last-verdict'] for trace in report['traces']] == ['accept', 'drop']
    selected = analysis.analyze(capture(*lines), filters={'family': 'ipv6', 'verdict': 'drop', 'hook': 'input'})
    assert [trace['id'] for trace in selected['traces']] == ['b']
    assert analysis.analyze(capture(*lines), identifier='ff')['traces'] == []


def test_bad_incomplete_unknown_and_oversized_captures(monkeypatch):
    """Damaged JSON errors explicitly; incomplete and unknown native evidence stays visible."""
    with pytest.raises(OperationalError, match='line 1'):
        analysis.analyze(io.StringIO('{'))
    report = analysis.analyze(capture('new native format', complete=False))
    assert len(report['warnings']) == 2
    assert report['unparsed'][0]['raw'] == 'new native format'
    monkeypatch.setattr(analysis, 'MAX_EVENTS', 1)
    with pytest.raises(OperationalError, match='250,000'):
        analysis.analyze(capture('unknown one', 'unknown two'))


def test_capture_reader_refuses_links_and_nonregular_files(tmp_path, monkeypatch):
    """Reading a saved trace must not expose arbitrary files through a symlink."""
    monkeypatch.setattr(firewall_trace, 'DIRECTORY', tmp_path)
    outside = tmp_path.parent / 'private'
    outside.write_text('private')
    (tmp_path / 'capture.jsonl').symlink_to(outside)
    with pytest.raises(OperationalError):
        analysis.read(str(tmp_path / 'capture.jsonl'))
    with pytest.raises(OperationalError):
        analysis.read('/etc/passwd')


def test_native_id_reuse_is_not_a_nat_rewrite():
    """A recycled packet ID must not make the new packet appear reverse-translated."""
    lines = [
        'trace id abc inet nvyr_filter ipv4_prerouting packet: ip saddr 192.0.2.1 ip daddr 203.0.113.1 ip id 100 tcp dport 80',
        'trace id abc inet nvyr_filter ipv4_forward packet: ip saddr 192.0.2.1 ip daddr 198.51.100.1 ip id 100 tcp dport 8080',
        'trace id abc inet nvyr_filter ipv4_prerouting packet: ip saddr 192.0.2.1 ip daddr 203.0.113.1 ip id 101 tcp dport 80',
    ]
    trace = analysis.analyze(capture(*lines), detail=True)['traces'][0]
    assert trace['passes'] == 2
    assert len(trace['changes']) == 1
    assert trace['steps'][-1]['new-pass']
    assert trace['warnings']


def test_native_conntrack_decode_preserves_unknown_status_bits():
    """New native conntrack events expose useful state without losing future flags."""
    line = 'trace id abc inet nvyr_filter ipv4_forward conntrack: ct direction 1 ct state 0x2 ct status 0x10,0x20,0x40000000 ct id 42'
    report = analysis.analyze(capture(line), detail=True)
    connection = report['traces'][0]['connections'][0]
    assert connection == {'direction': 'reply', 'state': ['established'],
                          'status': ['snat', 'dnat', '0x40000000'], 'id': '42'}
    assert not report['unparsed']


def test_native_rules_explain_group_references_and_global_policy():
    """Recognized objects become CLI paths while native expressions remain intact."""
    line = 'trace id abc inet nvyr_filter ipv4_forward rule ip saddr . tcp dport @ipv4_match_group_ALLOWED tcp dport vmap @ipv4_map_SERVICE comment "10|services" # handle 8 (verdict accept)'
    record = firewall_trace.event_record(line)
    assert record['references'] == ['firewall group match-group ipv4 ALLOWED', 'firewall group map ipv4 SERVICE']
    state = firewall_trace.event_record('trace id abc inet nvyr_filter forward rule ct state vmap { 2 : accept } (verdict accept)')
    assert state['path'] == 'firewall global-options state-policy'
    described = firewall_trace.event_record('trace id abc inet nvyr_filter ipv4_input rule accept comment "10|not # handle 99" # handle 8 (verdict accept)')
    assert described['handle'] == 8


def test_terminal_controls_in_saved_native_evidence_are_escaped():
    """Detailed output must display control characters rather than execute them."""
    report = analysis.analyze(capture('unknown \x1b[2J native\ttext'), detail=True)
    output = render(report, detail=True)
    assert '\x1b' not in output
    assert '\\x1b' in output


NATIVE = load_corpus()


@pytest.mark.parametrize('scenario', sorted(NATIVE))
def test_real_kernel_trace_corpus(scenario):
    """Replay real traffic evidence on ordinary CI without requiring a privileged kernel."""
    fixture = NATIVE[scenario]
    records = [{'event': 'capture', 'format': 1, 'chains': fixture['chains']}]
    records.extend({'event': 'native', 'raw': line} for line in fixture['events'])
    records.append({'event': 'capture-end', 'reason': 'duration', 'events': len(fixture['events'])})
    report = analysis.analyze(io.StringIO(''.join(json.dumps(record) + '\n' for record in records)), detail=True)
    assert report['events'] == len(fixture['events'])
    assert sum(trace['events'] for trace in report['traces']) == report['events']
    assert not report['warnings'] and not report['unparsed']
    assert render(report, detail=True)

    if scenario in ('silent-drop', 'tcp-reject', 'ipv6-reject', 'base-policy-drop'):
        assert any(trace['last-verdict'] == 'drop' for trace in report['traces'])
    if scenario in ('dnat-address-port', 'dnat-port-only', 'snat', 'masquerade'):
        changes = [change for trace in report['traces'] for change in trace['changes']]
        field = 'source-address' if scenario in ('snat', 'masquerade') else 'destination-port'
        assert any(field in change['fields'] for change in changes)
    if scenario == 'vrf-output':
        assert any(change['fields'].get('outbound-interface') == {'before': 'TRACEVRF', 'after': 'tr-out'}
                   for trace in report['traces'] for change in trace['changes'])
    if scenario == 'notrack':
        assert any('untracked' in connection.get('state', [])
                   for trace in report['traces'] for connection in trace['connections'])
    if scenario == 'nested-return':
        assert any(sum(step.get('verdict') == 'return' for step in trace['steps']) >= 2 for trace in report['traces'])
    if scenario == 'ingress':
        assert any('ingress' in trace['hooks'] for trace in report['traces'])


def test_operational_inspection_dispatch_filters_and_raw(controller, monkeypatch, capsys):
    """The operational grammar owns filters and preserves a structured API result."""
    line = 'show firewall trace /config/traces/test.jsonl ipv6 protocol tcp id abc detail'
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    controller.execute(line)
    assert calls == [['firewall_trace.nvyr.op', 'show', line]]
    received = {}
    def read(path, **options):
        received.update(path=path, **options)
        return {'traces': [], 'warnings': [], 'unparsed': [], 'end': None}
    monkeypatch.setattr(analysis, 'read', read)
    assert json.loads(commands.show(line, raw=True))['traces'] == []
    assert received['filters'] == {'family': 'ipv6', 'protocol': 'tcp'}
    assert received['identifier'] == 'abc' and received['detail']
    commands.show(line)
    assert 'No matching packet traces.' in capsys.readouterr().out
    with pytest.raises(OperationalError, match='only one'):
        commands.show('show firewall trace /config/traces/test.jsonl ipv4 ipv6')
    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError):
            controller.execute(line)
    finally:
        access.role.reset(token)
