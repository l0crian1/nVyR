"""Named maps use one typed key model and one firewall/NAT transaction."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import RouterError
from nvyr.helpers import nftables
from nvyr.helpers.nftables_formatters import nft_map, nft_group_lookup, nft_group_fields, nft_field_type
from tests.lifecycle import firewall_context
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree


def definition():
    return {'match': {'destination-port': True, 'source-address': True, 'protocol': True}, 'result-type': 'verdict',
            'entry': {'WEB': {'source-address': '192.0.2.10', 'protocol': 'tcp',
                              'destination-port': '443', 'result': {'action': 'accept'}}}}


def rendered(tree, previous=None, recovery=False):
    schema = Schema.bundled()
    schema.validate_configuration(tree)
    effective = ReadOnlyTree(schema.defaults(tree))
    before = ReadOnlyTree(schema.defaults(previous or {}))
    context = firewall_context(effective, before, 'firewall', ('firewall',), recovery,
                            previous_effective=before, schema=schema)
    firewall.verify(effective, context)
    return firewall.generate(effective, context)


def test_cli_maps_anchor_suggest_reference_and_commit_once(controller, engine, session):
    controller.execute('set firewall group map ipv4 SERVICES match source-address protocol destination-port', session)
    controller.execute('set firewall group map ipv4 SERVICES result-type verdict', session)
    controller.execute('set firewall group map ipv4 SERVICES entry WEB source-address 192.0.2.10 protocol tcp destination-port 443 result action accept', session)
    controller.execute('set firewall ipv4 forward filter rule 10 map SERVICES', session)
    controller.execute('set nat source rule 10 outbound-interface eth0 translation address masquerade', session)

    command = 'set firewall ipv4 forward filter rule 20 map '
    assert 'SERVICES' in dict(controller.completion(command, session)['candidates'])
    assert 'SERVICES' not in dict(controller.completion(command.replace('ipv4', 'ipv6'), session)['candidates'])
    with pytest.raises(RouterError, match='referenced'):
        controller.execute('delete firewall group map ipv4 SERVICES', session)

    engine.modules['firewall'].calls.clear()
    assert engine.commit(session)['results'] == {'firewall': {'success': True}}
    assert [stage for _, stage, _ in engine.modules['firewall'].calls] == ['get_config', 'verify', 'generate', 'apply']
    assert 'nat' not in engine.schema.owners

    controller.execute('delete firewall ipv4 forward filter rule 10 map', session)
    controller.execute('delete firewall group map ipv4 SERVICES', session)
    assert 'SERVICES' not in dict(controller.completion(command, session)['candidates'])


def test_map_types_order_comments_tracking_and_no_mutation():
    mapping = definition()
    mapping['counter'] = True
    mapping['entry']['WEB']['description'] = 'Public HTTPS'
    original = deepcopy(mapping)
    text = nft_map('ipv4', 'SERVICES', ReadOnlyTree(mapping), {'last-used': True})

    assert nft_group_fields(mapping) == ['source-address', 'protocol', 'destination-port']
    assert nft_group_lookup('ipv4', mapping) == 'ip saddr . meta l4proto . th dport'
    assert 'type ipv4_addr . inet_proto . inet_service : verdict;' in text
    assert '192.0.2.10 . tcp . 443 comment "WEB|Public HTTPS" : accept' in text
    assert text.count('counter;') == text.count('last;') == 1
    assert mapping == original


@pytest.mark.parametrize('options', [{}, {'counter': True}, {'last-used': True}, {'counter': True, 'last-used': True}])
def test_map_global_tracking_does_not_become_explicit_configuration(options):
    mapping = definition()
    text = rendered({'firewall': {'group': {'map': {'ipv4': {'M': mapping}}}, 'global-options': options}})
    assert ('    counter;' in text) == ('counter' in options)
    assert ('    last;' in text) == ('last-used' in options)
    assert 'counter' not in mapping and 'last-used' not in mapping


@pytest.mark.parametrize('fields,valid', [
    (['source-address', 'destination-address', 'inbound-interface', 'outbound-interface'], True),
    (['source-address', 'destination-address', 'inbound-interface', 'outbound-interface', 'destination-port'], False),
    (['source-address', 'destination-address', 'protocol', 'source-port', 'destination-port'], True),
    (['source-address', 'destination-address', 'protocol', 'source-port', 'destination-port', 'state'], False),
])
def test_key_field_and_byte_limits(fields, valid):
    mapping = {'match': dict.fromkeys(fields, True), 'result-type': 'verdict'}
    if 'state' in mapping['match']:
        del mapping['match']['state']
        mapping['match']['connection'] = {'state': True}
    if valid:
        firewall.verify_map('ipv6', 'M', mapping, {})
    else:
        with pytest.raises(RouterError, match='maximum') as error:
            firewall.verify_map('ipv6', 'M', mapping, {})
        if len(fields) == 5:
            assert '66 bytes (maximum 64 bytes)' in str(error.value)
            assert 'Parameter sizes:' in str(error.value)
            assert 'Including 4-byte field alignment: 68 bytes' in str(error.value)


def test_key_sizes_match_nft_storage_types():
    assert nft_field_type('source-address', 'ipv4') == ('ipv4_addr', 4)
    assert nft_field_type('source-address', 'ipv6') == ('ipv6_addr', 16)
    assert nft_field_type('destination-port', 'ipv4') == ('inet_service', 2)
    assert nft_field_type('source-mac', 'ipv4') == ('ether_addr', 6)
    assert nft_field_type('inbound-interface', 'ipv6') == ('ifname', 16)


@pytest.mark.parametrize('change,message', [
    (lambda m: m.pop('match'), 'match field'),
    (lambda m: m.pop('result-type'), 'result-type'),
    (lambda m: m['entry']['WEB'].pop('protocol'), 'missing match'),
    (lambda m: m['entry']['WEB'].update({'source-port': '1234'}), 'undeclared match'),
    (lambda m: m['entry']['WEB'].update(protocol='icmp'), 'port protocol'),
    (lambda m: m['entry']['WEB'].update(result={}), 'requires exactly'),
    (lambda m: m['entry']['WEB']['result'].update(address='192.0.2.1'), 'requires exactly'),
    (lambda m: m['entry']['WEB'].update(result={'action': 'jump', 'jump-target': 'MISSING'}), 'not a named chain'),
    (lambda m: m['entry'].update({'SECOND': deepcopy(m['entry']['WEB'])}), 'duplicate or overlapping'),
])
def test_map_cross_field_validation(change, message):
    mapping = definition()
    change(mapping)
    with pytest.raises(RouterError, match=message):
        firewall.verify_map('ipv4', 'M', mapping, {})


@pytest.mark.parametrize('family,first,second', [
    ('ipv4', '192.0.2.0/24', '192.0.2.1'),
    ('ipv4', '192.0.2.1-192.0.2.10', '192.0.2.10-192.0.2.20'),
    ('ipv6', '2001:db8::/64', '2001:0db8:0:0::1'),
    ('ipv6', '2001:db8::1', '2001:0db8::1'),
])
def test_overlap_detection_normalizes_addresses_and_checks_all_components(family, first, second):
    mapping = {'match': {'source-address': True, 'protocol': True}, 'result-type': 'verdict', 'entry': {
        'A': {'source-address': first, 'protocol': 'tcp', 'result': {'action': 'accept'}},
        'B': {'source-address': second, 'protocol': 'udp', 'result': {'action': 'drop'}},
    }}
    firewall.verify_map(family, 'M', mapping, {})
    mapping['entry']['B']['protocol'] = 'tcp'
    with pytest.raises(RouterError, match='overlapping'):
        firewall.verify_map(family, 'M', mapping, {})


def test_entry_comment_limit_includes_identifier_and_utf8_description():
    mapping = definition()
    mapping['entry']['WEB']['description'] = 'é' * 63
    with pytest.raises(RouterError, match='128-byte'):
        firewall.verify_map('ipv4', 'M', mapping, {})


@pytest.mark.parametrize('extra', [
    {'protocol': ['tcp']}, {'source-address': {'192.0.2.1': {}}},
    {'action': 'accept'}, {'jump-target': 'OTHER'}, {'offload-target': 'FAST'},
])
def test_map_rules_reject_overlapping_matches_and_separate_actions(extra):
    mapping = definition()
    rule = {'map': 'M'} | extra
    with pytest.raises(RouterError, match='cannot be combined'):
        firewall.verify_rule(rule, ('firewall', 'ipv4', 'forward', 'filter', 'rule', '10'), {}, maps={'M': mapping})


def test_map_rule_type_and_family_are_verified():
    path = ('firewall', 'ipv6', 'input', 'filter', 'rule', '10')
    with pytest.raises(RouterError, match='not configured'):
        firewall.verify_rule({'map': 'M'}, path, {}, maps={})
    with pytest.raises(RouterError, match='result-type'):
        firewall.verify_rule({'map': 'M'}, path, {}, maps={'M': {'result-type': 'address'}})


def test_jump_targets_and_interface_references_use_registrar(controller, session):
    controller.execute('set firewall ipv4 name HTTPS', session)
    controller.execute('set interfaces dummy dum9', session)
    controller.execute('set firewall group map ipv4 M match inbound-interface', session)
    controller.execute('set firewall group map ipv4 M result-type verdict', session)
    controller.execute('set firewall group map ipv4 M entry A inbound-interface dum9 result action jump result jump-target HTTPS', session)
    for command in ['delete interfaces dummy dum9', 'delete firewall ipv4 name HTTPS']:
        with pytest.raises(RouterError, match='referenced'):
            controller.execute(command, session)


@pytest.mark.parametrize('kind,result', [
    ('address', {'address': '10.0.0.10'}), ('port', {'port': '8080'}),
    ('address-port', {'address': '10.0.0.10', 'port': '8080'}),
])
def test_nat_map_rendering_and_atomic_order(kind, result):
    mapping = {'match': {'inbound-interface': True, 'protocol': True, 'destination-port': True}, 'result-type': kind,
               'entry': {'WEB': {'inbound-interface': 'eth0', 'protocol': 'tcp', 'destination-port': '443', 'result': result}}}
    tree = {'firewall': {'group': {'map': {'ipv4': {'M': mapping}}}},
            'nat': {'destination': {'rule': {'10': {'map': 'M'}}}}}
    previous = deepcopy(tree)
    previous['firewall']['group']['map']['ipv4']['M']['description'] = 'Previous'
    text = rendered(tree, previous)
    assert text.index('flush chain inet nvyr_filter ipv4_nat_prerouting') < text.index('destroy map inet nvyr_filter ipv4_map_M')
    assert text.index('map ipv4_map_M {') < text.index('dnat ')
    assert 'iifname . meta l4proto . th dport map @ipv4_map_M' in text


def test_firewall_and_nat_fail_and_restore_together(controller, engine, session, monkeypatch):
    controller.execute('set firewall ipv4 input filter rule 10 action accept', session)
    controller.execute('set nat source rule 10 outbound-interface eth0 translation address masquerade', session)
    assert engine.commit(session)['results']['firewall']['success']
    before = deepcopy(engine.running)

    controller.execute('set firewall ipv4 input filter rule 10 action drop', session)
    controller.execute('set nat source rule 10 translation address 203.0.113.1', session)
    def reject(*args, **kwargs):
        raise RouterError('Kernel rejected transaction')
    monkeypatch.setattr(nftables.manager, 'apply', reject)
    result = engine.commit(session)
    assert not result['results']['firewall']['success']
    assert engine.running == before
    assert engine.view(session) != before


def test_recovery_discovers_maps_and_removes_them_before_named_chains(monkeypatch):
    monkeypatch.setattr(nftables, 'manager', SimpleNamespace(
        rule_limits=lambda: [], named_state=lambda: [], icmp_groups=lambda: [], singleton_groups=lambda: [], match_groups=lambda: [], maps=lambda: [('ipv6', 'ORPHAN')], named_chains=lambda: [('ipv6', 'TARGET')], flowtables=lambda: []))
    text = rendered({}, recovery=True)
    assert text.index('destroy map inet nvyr_filter ipv6_map_ORPHAN') < text.index('destroy chain inet nvyr_filter ipv6_name_TARGET')


def test_delete_map_uses_previous_values():
    previous = {'firewall': {'group': {'map': {'ipv4': {'OLD': definition()}}}}}
    text = rendered({}, previous)
    assert 'destroy map inet nvyr_filter ipv4_map_OLD' in text
    assert 'map ipv4_map_OLD {' not in text


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_map_and_entry_descriptions_are_separate(controller, session, family):
    controller.execute(f'set firewall group map {family} M description "Map description"', session)
    controller.execute(f'set firewall group map {family} M match protocol', session)
    controller.execute(f'set firewall group map {family} M result-type verdict', session)
    controller.execute(f'set firewall group map {family} M entry A protocol tcp description "Entry description" result action accept', session)
    text = rendered(controller.engine.view(session))
    assert 'comment "Map description";' in text
    assert 'tcp comment "A|Entry description" : accept' in text


@pytest.mark.parametrize('description', ['x' * 129, 'é' * 65, 'embedded"quote'])
def test_map_description_rejects_unrenderable_comments(description):
    tree = {'firewall': {'group': {'map': {'ipv4': {'M': {'description': description}}}}}}
    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration(tree)


def test_map_discovery_only_returns_owned_maps(monkeypatch):
    entries = [
        {'family': 'inet', 'table': 'nvyr_filter', 'name': 'ipv4_map_SERVICES'},
        {'family': 'inet', 'table': 'nvyr_filter', 'name': 'ipv6_map_SERVICES'},
        {'family': 'inet', 'table': 'other', 'name': 'ipv4_map_FOREIGN'},
        {'family': 'ip', 'table': 'nvyr_filter', 'name': 'ipv4_map_FOREIGN'},
        {'family': 'inet', 'table': 'nvyr_filter', 'name': 'unmanaged_map'},
    ]
    monkeypatch.setattr(nftables, 'cmd', lambda argv: json.dumps({
        'nftables': [{'map': entry} for entry in entries],
    }))
    assert nftables.Manager().maps() == [('ipv4', 'SERVICES'), ('ipv6', 'SERVICES')]


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('local', [[], ['counter'], ['last-used'], ['counter', 'last-used']])
@pytest.mark.parametrize('global_flags', [[], ['counter'], ['last-used'], ['counter', 'last-used']])
def test_map_tracking_flags_are_additive_without_duplicate_statements(family, local, global_flags):
    mapping = {'match': {'protocol': True}, 'result-type': 'verdict'}
    mapping.update(dict.fromkeys(local, True))
    original = deepcopy(mapping)
    text = nft_map(family, 'M', mapping, dict.fromkeys(global_flags, True))
    assert text.count('counter;') == int('counter' in local or 'counter' in global_flags)
    assert text.count('last;') == int('last-used' in local or 'last-used' in global_flags)
    assert mapping == original


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('edit', [False, True])
def test_map_match_anchor_stages_abbreviations_and_deletes_individual_fields(controller, engine, session, family, edit):
    root = f'firewall group map {family} M'
    prefix = root + ' match '
    if edit:
        controller.execute('edit ' + root + ' match', session)
        prefix = ''

    controller.execute('set ' + prefix + 'source-a destination-a proto', session)
    mapping = engine.view(session)['firewall']['group']['map'][family]['M']
    assert mapping['match'] == {
        'source-address': True, 'destination-address': True, 'protocol': True,
    }

    controller.execute('delete ' + prefix + 'destination-address', session)
    assert engine.view(session)['firewall']['group']['map'][family]['M']['match'] == {
        'source-address': True, 'protocol': True,
    }


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('mode', [{}, {'tab': True}, {'space': True}, {'explicit': True}])
def test_map_match_anchor_completion_returns_to_unused_fields(controller, session, family, mode):
    line = f'set firewall group map {family} M match source-address '
    candidates = dict(controller.completion(line, session, **mode)['candidates'])
    assert {'destination-address', 'destination-mac', 'destination-port', 'protocol'} <= candidates.keys()
    assert 'source-address' not in candidates
    if mode.get('explicit'):
        assert '<Enter>' in candidates

    partial = dict(controller.completion(line + 'des', session, **mode)['candidates'])
    if mode.get('space'):
        # Space cannot finish an ambiguous keyword; Tab/help still show choices.
        assert not partial
    else:
        assert {'destination-address', 'destination-mac', 'destination-port'} <= partial.keys()
    assert controller.completion(line + 'destination-a', session, **mode)['replacement'] == 'destination-address'


@pytest.mark.parametrize('suffix', ['unknown-field', 'destination'])
def test_invalid_or_ambiguous_map_match_does_not_stage_partial_fields(controller, engine, session, suffix):
    before = engine.view(session)
    with pytest.raises(RouterError):
        controller.execute('set firewall group map ipv4 M match source-address ' + suffix, session)
    assert engine.view(session) == before


@pytest.mark.parametrize('protocols', [[], ['tcp'], ['tcp', 'udp']])
def test_consumer_ports_can_use_map_protocols(protocols):
    mapping = {'match': {'protocol': True}, 'result-type': 'verdict', 'entry': {
        value: {'protocol': value, 'result': {'action': 'accept'}} for value in protocols}}
    rule = {'map': 'M', 'destination-port': ['443'], 'outbound-interface': ['eth0']}
    tree = {'firewall': {'group': {'map': {'ipv4': {'M': mapping}}},
                        'ipv4': {'forward': {'filter': {'rule': {'10': rule}}}}}}
    assert 'th dport { 443 } meta l4proto vmap @ipv4_map_M' in rendered(tree)

    mapping['entry']['ICMP'] = {'protocol': 'icmp', 'result': {'action': 'accept'}}
    with pytest.raises(RouterError, match='requires an explicit port protocol'):
        rendered(tree)


@pytest.mark.parametrize('direction,interface', [('source', 'outbound-interface'), ('destination', 'inbound-interface')])
def test_nat_interface_can_be_an_independent_rule_match(direction, interface):
    mapping = {'match': {'destination-address': True}, 'result-type': 'address',
               'entry': {'A': {'destination-address': '203.0.113.10', 'result': {'address': '10.0.0.10'}}}}
    tree = {'firewall': {'group': {'map': {'ipv4': {'M': mapping}}}},
            'nat': {direction: {'rule': {'10': {'map': 'M', interface: ['eth0']}}}}}
    text = rendered(tree)
    expression = 'oifname' if direction == 'source' else 'iifname'
    assert expression + ' { "eth0" }' in text
    assert 'ip daddr map @ipv4_map_M' in text

    del tree['nat'][direction]['rule']['10'][interface]
    with pytest.raises(RouterError, match='must match ' + interface):
        rendered(tree)
