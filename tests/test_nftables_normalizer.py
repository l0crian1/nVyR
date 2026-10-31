"""Operational data from real nftables 1.1.7 full and scoped listings."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from nvyr.helpers.nftables_normalizer import normalize


FIXTURES = Path(__file__).parent / 'fixtures' / 'nftables'


@pytest.fixture
def listings():
    return json.loads((FIXTURES / 'listings.json').read_text())


def table(document):
    return normalize(document)['tables']['inet']['nvyr_filter']


def rules(document, chain='ipv4_forward'):
    return {rule['number']: rule for rule in table(document)['chains'][chain]['rules'] if 'number' in rule}


def rule_document(*statements, comment='10|example'):
    return {'nftables': [{'rule': {
        'family': 'inet', 'table': 'nvyr_filter', 'chain': 'ipv4_forward',
        'handle': 42, 'comment': comment, 'expr': list(statements),
    }}]}


@pytest.mark.parametrize('definition,expected', [
    ({'rate': 10, 'per': 'second', 'burst': 20},
     {'rate': {'packets': '10/s'}, 'burst': {'packets': '20'}}),
    ({'rate': 1024, 'rate_unit': 'mbytes', 'per': 'second', 'burst': 64, 'burst_unit': 'kbytes', 'inv': True},
     {'rate': {'bytes': '1024m/s'}, 'burst': {'bytes': '64k'}, 'over': True}),
    ({'rate': 1024, 'rate_unit': 'bytes', 'per': 'minute', 'burst': 0, 'burst_unit': 'bytes'},
     {'rate': {'bytes': '1024/m'}, 'burst': {'bytes': '0'}}),
])
def test_limits_use_structured_units_in_operational_data(definition, expected):
    document = rule_document({'limit': definition})
    original = deepcopy(document)

    assert rules(document)['10']['limit'] == expected
    assert document == original


@pytest.mark.parametrize('result,value,expected', [
    ('oif', True, {'outbound-interface': ['exists']}),
    ('oif', False, {'outbound-interface': ['missing']}),
    ('oifname', 'eth0', {'outbound-interface': ['eth0']}),
    ('oifname', {'set': ['eth0', 'eth1']}, {'outbound-interface': ['eth0', 'eth1']}),
    ('type', 'local', {'route-type': ['local']}),
    ('type', {'set': ['local', 'broadcast']}, {'route-type': ['local', 'broadcast']}),
])
def test_fib_match_normalization(result, value, expected):
    document = rule_document({'match': {
        'op': '==', 'left': {'fib': {'result': result, 'flags': ['saddr', 'iif', 'mark']}}, 'right': value,
    }})
    original = deepcopy(document)
    rule = rules(document)['10']

    assert rule['fib'] == {
        'lookup': {'source-address': True, 'inbound-interface': True, 'packet-mark': True},
        'result': expected,
    }
    assert 'unsupported' not in rule
    assert document == original


@pytest.mark.parametrize('result,value,comparison', [('oif', 3, '=='), ('oif', True, '!='), ('type', 123, '==')])
def test_unknown_fib_semantics_remain_visible(result, value, comparison):
    document = rule_document({'match': {
        'op': comparison, 'left': {'fib': {'result': result, 'flags': ['saddr']}}, 'right': value,
    }})
    assert 'unsupported' in rules(document)['10']


def test_different_fib_lookups_are_not_merged():
    document = rule_document(
        {'match': {'op': '==', 'left': {'fib': {'result': 'type', 'flags': ['saddr']}}, 'right': 'local'}},
        {'match': {'op': '!=', 'left': {'fib': {'result': 'type', 'flags': ['daddr']}}, 'right': 'broadcast'}},
    )
    rule = rules(document)['10']
    assert rule['fib']['lookup'] == {'source-address': True}
    assert len(rule['unsupported']) == 1


def test_full_and_scoped_chain_use_identical_rules(listings):
    full = table(listings['ruleset'])
    scoped = table(listings['chain'])

    assert full['chains']['ipv4_forward'] == scoped['chains']['ipv4_forward']
    assert 'metadata' not in scoped
    assert scoped['sets'] == {} and scoped['maps'] == {}
    assert scoped['chains']['ipv4_forward']['rules'][7]['map'] == 'POLICY'
    assert list(scoped['chains']) == ['ipv4_forward']


def test_scoped_groups_and_inventory_only(listings):
    full = table(listings['ruleset'])
    scoped = table(listings['map'])
    assert scoped['maps'] == {'ipv4_map_POLICY': full['maps']['ipv4_map_POLICY']}
    assert scoped['chains'] == {}

    group = table(listings['set'])['sets']['ipv4_address_group_LEARNED']
    assert group['entries'][0]['key'] == ['192.0.2.1']
    assert 0 < group['entries'][0]['expires'] <= 600

    inventory = table(listings['chains'])
    assert set(inventory['chains']) == set(full['chains'])
    assert all('rules' not in chain for chain in inventory['chains'].values())


def test_normalization_does_not_modify_or_alias_input(listings):
    original = deepcopy(listings)
    result = table(listings['ruleset'])
    result['chains']['ipv4_forward']['rules'][0]['counter']['packets'] = 999
    result['sets']['ipv4_address_group_LEARNED']['flags'].append('test')

    assert listings == original
    json.dumps(normalize(listings['ruleset']))


def test_rule_fields_and_statistics(listings):
    rule = rules(listings['chain'])['10']
    assert rule['state'] == ['established', 'related']
    assert rule['connection-status'] == ['confirmed,offload', 'dnat,snat']
    assert rule['inbound-interface'] == ['eth0', 'eth1']
    assert rule['outbound-interface'] == ['eth2']
    assert rule['packet-type'] == 'host'
    assert rule['counter'] == {'packets': 0, 'bytes': 0}
    assert rule['last-used'] is None
    assert rule['action'] == 'accept'
    assert rule['number'] == '10' and rule['description'] == 'states'
    assert 'unsupported' not in rule


def test_addresses_masks_ranges_and_comparisons(listings):
    result = rules(listings['chain'])
    rule = result['20']
    assert rule['source-address'] == {'192.0.2.0/24': {}}
    assert rule['destination-address'] == {'10.0.0.0/24': {}, '203.0.113.1': {}}
    assert rule['source-mac'] == {'11:22:33:00:00:00': {'mask': 'ff:ff:ff:00:00:00'}}
    assert rule['packet-mark'] == [1, '10-20']
    assert rule['connection-mark'] == [3]
    assert rule['dscp'] == [10]
    assert rule['ttl'] == {'gt': 10, 'lt': 100}
    assert result['94']['source-address'] == {'192.0.2.0': {'mask': '255.0.255.0'}}
    assert result['95']['destination-address'] == {'2001:0:db8::': {'mask': 'ffff:0:ffff::'}}
    assert result['95']['last-used'] == 2


def test_transport_and_icmp_fields(listings):
    result = rules(listings['chain'])
    rule = result['30']
    assert rule['protocol'] == ['tcp']
    assert rule['destination-port'] == [80, 443]
    assert rule['source-port'] == [1234]
    assert rule['tcp-mss'] == [1460]
    assert rule['log'] == {'prefix': 'test'}
    assert rule['jump-target'] == 'TARGET'

    assert result['40']['protocol'] == ['icmp']
    assert result['40']['icmp-type'] == ['destination-unreachable', 'echo-request']
    assert result['40']['icmp-code'] == [0]
    assert result['50']['protocol'] == ['ipv6-icmp']
    assert result['50']['icmp-type'] == ['nd-neighbor-solicit']
    assert result['50']['ttl'] == {'eq': 255}


def test_references_and_dynamic_update_do_not_need_group_definitions(listings):
    result = rules(listings['chain'])
    assert result['60']['source-address-group'] == 'LEARNED'
    assert result['60']['destination-port-group'] == 'WEB'
    assert result['70']['match-group'] == 'PAIR'
    assert result['70']['match-group-fields'] == ['source-address', 'destination-port']
    assert result['80']['map-fields'] == ['source-address', 'destination-port']
    assert result['90']['add-to-group'] == {'source-address': 'LEARNED', 'timeout': 300}
    assert result['96']['notrack'] is True
    assert result['97']['connection-status'] == ['confirmed,helper,offload']


def test_sets_maps_and_entry_tracking(listings):
    result = table(listings['ruleset'])
    group = result['sets']['ipv4_address_group_LEARNED']
    assert group['timeout'] == 600 and group['gc-interval'] == 30
    assert group['size'] == 65535 and group['counter'] is True and group['last-used'] is True
    assert group['entries'][0]['counter'] == {'packets': 0, 'bytes': 0}
    assert group['entries'][0]['last-used'] is None
    assert result['sets']['port_group_WEB']['entries'][-1]['key'] == ['8000-8010']

    mapping = result['maps']['ipv4_map_POLICY']
    assert mapping['key-datatypes'] == ['ipv4_addr', 'inet_service']
    assert mapping['description'] == 'Policy'
    entry = mapping['entries'][0]
    assert entry['key'] == ['192.0.2.1', 443]
    assert entry['name'] == 'one' and entry['description'] == 'entry'
    assert entry['result'] == {'action': 'jump', 'jump-target': 'TARGET'}
    assert result['maps']['ipv4_map_NAT']['entries'][0]['result'] == {'address': '10.0.0.1', 'port': 8443}


def test_anonymous_dispatch_maps_keep_entry_counters(listings):
    chain = table(listings['chain'])['chains']['ipv4_forward']
    maps = [rule['verdict-map'] for rule in chain['rules'] if 'verdict-map' in rule]
    assert maps[0]['fields'] == ['state']
    assert maps[0]['entries'][0]['counter'] == {'packets': 0, 'bytes': 0}
    assert maps[0]['entries'][0]['result'] == {'action': 'drop'}
    assert maps[1]['fields'] == ['address-family']
    assert maps[1]['entries'][0]['result'] == {'action': 'jump', 'jump-target': 'TARGET'}


def test_nat_results(listings):
    result = rules(listings['ruleset'], 'ipv4_nat_prerouting')
    assert result['1']['map'] == 'NAT'
    assert result['1']['map-fields'] == ['destination-address', 'destination-port']
    assert result['2']['translation'] == {
        'address': '10.0.0.1-10.0.0.10', 'port': '1000-2000',
        'persistent': True, 'port-mapping': 'random',
    }
    assert result['3']['translation'] == {'address': 'masquerade', 'port-mapping': 'fully-random'}
    assert result['4']['action'] == 'return'
    assert result['5']['action'] == 'snat'
    assert result['6']['translation'] == {'port': 8080}


def test_inequality_is_normalized_and_unknown_statements_remain_visible():
    inequality = {'match': {'op': '!=', 'left': {'meta': {'key': 'mark'}}, 'right': 10}}
    document = rule_document(inequality, {'future-statement': {'value': 3}}, {'accept': None})
    rule = rules(document)['10']

    assert 'packet-mark' not in rule
    assert rule['not']['packet-mark'] == [10]
    assert rule['unsupported'][0]['position'] == 1
    assert rule['action'] == 'accept'
    rule['unsupported'][0]['expression']['future-statement']['value'] = 20
    assert document['nftables'][0]['rule']['expr'][1]['future-statement']['value'] == 3


def test_repeated_matches_are_not_silently_changed_from_and_to_or():
    def match(value):
        return {'match': {'op': '==', 'left': {'meta': {'key': 'mark'}}, 'right': value}}

    rule = rules(rule_document(match(1), match(2)))['10']
    assert rule['packet-mark'] == [1]
    assert rule['unsupported'][0]['expression'] == match(2)


def test_no_group_type_can_be_inferred_from_datatype_alone():
    document = {'nftables': [{'map': {
        'family': 'inet', 'table': 'nvyr_filter', 'name': 'ipv4_map_UNUSED',
        'type': ['ipv4_addr', 'ipv4_addr'], 'map': 'verdict',
        'elem': [[{'concat': ['192.0.2.1', '198.51.100.1']}, {'accept': None}]],
    }}]}
    mapping = table(document)['maps']['ipv4_map_UNUSED']
    assert mapping['entries'][0]['key'] == ['192.0.2.1', '198.51.100.1']
    assert 'match' not in mapping


def test_configured_columns_follow_renderer_order_not_input_order(listings):
    configuration = {'firewall': {'group': {'map': {'ipv4': {'POLICY': {
        'match': {'destination-port': True, 'source-address': True},
    }}}}}}
    before = deepcopy(configuration)
    result = normalize(listings['map'], configuration=configuration)
    mapping = result['tables']['inet']['nvyr_filter']['maps']['ipv4_map_POLICY']

    assert mapping['match-fields'] == ['source-address', 'destination-port']
    assert dict(zip(mapping['match-fields'], mapping['entries'][0]['key'])) == {
        'source-address': '192.0.2.1', 'destination-port': 443,
    }
    assert configuration == before

    configuration['firewall']['group']['map']['ipv4']['POLICY']['match'] = {'source-address': True}
    with pytest.raises(ValueError, match='POLICY.*datatypes'):
        normalize(listings['map'], configuration=configuration)


def test_configured_match_group_columns_and_singleton_member_names(listings):
    configuration = {'firewall': {'group': {'match-group': {'ipv4': {'PAIR': {
        'match': {'destination-port': True, 'source-address': True},
    }}}}}}
    result = normalize(listings['ruleset'], configuration=configuration)
    groups = result['tables']['inet']['nvyr_filter']['sets']
    assert groups['ipv4_match_group_PAIR']['match-fields'] == ['source-address', 'destination-port']
    assert groups['ipv4_address_group_LEARNED']['match-fields'] == ['address']
    assert groups['port_group_WEB']['match-fields'] == ['port']


@pytest.mark.parametrize(('comparison', 'interval', 'expected'), [
    ('!=', [100, 10], {'gt': 10, 'lt': 100}),
    ('==', [11, 99], {'gt': 10, 'lt': 100}),
])
def test_coalesced_ttl_comparisons(comparison, interval, expected):
    document = rule_document({'match': {
        'left': {'payload': {'protocol': 'ip', 'field': 'ttl'}},
        'op': comparison, 'right': {'range': interval},
    }})
    assert rules(document)['10']['ttl'] == expected


def test_unsupported_mask_does_not_become_an_unmasked_comparison():
    document = rule_document({'match': {
        'left': {'&': [{'payload': {'protocol': 'ip', 'field': 'ttl'}}, 15]},
        'op': '==', 'right': 10,
    }})
    rule = rules(document)['10']
    assert 'ttl' not in rule
    assert rule['unsupported'][0]['reason'] == 'Unsupported bitmask'


def test_conntrack_state_bit_test_and_unknown_status_bits():
    document = rule_document(
        {'match': {'left': {'ct': {'key': 'state'}}, 'op': 'in', 'right': 'established'}},
        {'match': {'left': {'ct': {'key': 'status'}}, 'op': '==', 'right': 0x10008}},
    )
    rule = rules(document)['10']
    assert rule['state'] == ['established']
    assert rule['connection-status'] == ['0x10000,confirmed']


def test_unknown_map_result_is_preserved():
    document = {'nftables': [{'map': {
        'family': 'inet', 'table': 'nvyr_filter', 'name': 'ipv4_map_FUTURE',
        'type': 'ipv4_addr', 'map': 'future_type', 'elem': [['192.0.2.1', 123]],
    }}]}
    entry = table(document)['maps']['ipv4_map_FUTURE']['entries'][0]
    assert entry['unsupported'] == ['192.0.2.1', 123]


def test_counter_without_statistics_is_not_reported_as_zero():
    rule = rules(rule_document({'counter': None}))['10']
    assert rule['counter'] == {}
    assert rules(rule_document({'counter': 'external'}))['10']['unsupported'][0]['expression'] == {
        'counter': 'external',
    }


def test_rule_only_scoped_input_and_comments_with_extra_separators():
    document = rule_document({'accept': None}, comment='default|a|b')
    rule = rules(document)['default']
    assert rule['description'] == 'a|b'
    assert rule['handle'] == 42
    assert list(table(document)['chains']) == ['ipv4_forward']


def test_family_namespace_order_and_missing_collection_contents(listings):
    document = deepcopy(listings['chain'])
    document['nftables'].reverse()
    expected = list(reversed(table(listings['chain'])['chains']['ipv4_forward']['rules']))
    assert table(document)['chains']['ipv4_forward']['rules'] == expected

    document = {'nftables': [
        {'table': {'family': 'ip', 'name': 'same'}},
        {'table': {'family': 'ip6', 'name': 'same'}},
        {'set': {'family': 'ip', 'table': 'same', 'name': 'empty', 'type': 'ipv4_addr', 'elem': []}},
        {'set': {'family': 'ip', 'table': 'same', 'name': 'omitted', 'type': 'ipv4_addr'}},
    ]}
    result = normalize(document)['tables']
    assert set(result) == {'ip', 'ip6'}
    assert result['ip']['same']['sets']['empty']['entries'] == []
    assert 'entries' not in result['ip']['same']['sets']['omitted']


@pytest.mark.parametrize('document', [None, {}, {'nftables': {}}, {'nftables': [None]}])
def test_malformed_listing(document):
    with pytest.raises(ValueError, match='nftables'):
        normalize(document)


def test_empty_listing_and_unknown_objects():
    assert normalize({'nftables': []}) == {'metadata': {}, 'tables': {}}
    record = {'future-object': {'name': 'new'}}
    assert normalize({'nftables': [record]})['unsupported'] == [record]
