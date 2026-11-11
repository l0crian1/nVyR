"""CGN schema, allocation, conflict detection and atomic object selection.

Packet translation belongs to the shared routed functional scenario.
"""

from copy import deepcopy

import pytest

from nvyr.config_scripts import firewall, nat
from nvyr.errors import RouterError
from nvyr.helpers import cgnat
from nvyr.op_scripts.cgnat import allocation_rows
from nvyr.op_scripts import cgnat as operations
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree
from tests.lifecycle import firewall_context


@pytest.fixture(scope='module')
def schema():
    return Schema.bundled()


@pytest.fixture
def configuration(schema):
    return schema.defaults({'nat': {'cgnat': {
        'pool': {'PUBLIC': {'public-address': ['203.0.113.10-203.0.113.11']}},
        'rule': {'10': {'source-address': ['100.64.0.1-100.64.0.3'], 'pool': 'PUBLIC',
                        'outbound-interface': ['eth2'], 'counter': {}}},
    }}})


def render(schema, configuration, previous=None):
    current = ReadOnlyTree(configuration)
    before = ReadOnlyTree(previous or {})
    context = firewall_context(current, before, 'firewall', ('firewall',), previous_effective=before, schema=schema)
    return firewall.generate(current, context)['rules']


def test_defaults_union_and_lookup(schema, configuration):
    schema.validate_configuration(configuration)
    nat.verify(configuration, None)
    rule = configuration['nat']['cgnat']['rule']['10']
    rule['source-address'] += ['100.64.0.2/31', '100.64.0.1']
    assert cgnat.count(cgnat.subscribers(configuration, rule)) == 3
    assert list(cgnat.elements(configuration, rule)) == [
        '100.64.0.1 : 203.0.113.10 . 1024-2047',
        '100.64.0.2 : 203.0.113.10 . 2048-3071',
        '100.64.0.3 : 203.0.113.10 . 3072-4095',
    ]
    row = ['10', 'default', 'PUBLIC', '100.64.0.2', '203.0.113.10', '2048-3071']
    assert allocation_rows(configuration, subscriber='100.64.0.2') == [row]
    assert allocation_rows(configuration, public='203.0.113.10', port=3071) == [row]
    assert allocation_rows(configuration, public='203.0.113.10', port=4096) == []


def test_offset_and_unused_tail(configuration):
    pool = configuration['nat']['cgnat']['pool']['PUBLIC']
    pool.update({'port-range': '2000-2999', 'block-size': '300'})
    rule = configuration['nat']['cgnat']['rule']['10']
    rule['allocation-offset'] = '2'
    nat.verify(configuration, None)
    assert cgnat.capacity(pool) == 6
    assert list(cgnat.elements(configuration, rule)) == [
        '100.64.0.1 : 203.0.113.10 . 2600-2899',
        '100.64.0.2 : 203.0.113.11 . 2000-2299',
        '100.64.0.3 : 203.0.113.11 . 2300-2599',
    ]


@pytest.mark.parametrize('change,error', [
    ({'source-address': ['0.0.0.0/0']}, 'allocation requires'),
    ({'allocation-offset': '125'}, 'allocation requires'),
    ({'pool': 'MISSING'}, 'configured pool'),
    ({'vrf': 'MISSING'}, 'not configured'),
    ({'source-port': ['80']}, 'protocol'),
])
def test_invalid_relationships(configuration, change, error):
    configuration['nat']['cgnat']['rule']['10'].update(change)
    with pytest.raises(RouterError, match=error):
        nat.verify(configuration, None)


def test_conflicts_and_identical_allocations(configuration):
    rules = configuration['nat']['cgnat']['rule']
    rules['20'] = deepcopy(rules['10'])
    rules['20']['protocol'] = ['tcp']
    nat.verify(configuration, None)
    rules['20']['source-address'] = ['100.64.1.1']
    with pytest.raises(RouterError, match='conflicts with CGN rule 10'):
        nat.verify(configuration, None)
    rules['20']['allocation-offset'] = '3'
    nat.verify(configuration, None)
    rules['20'] = {'disable': True}
    nat.verify(configuration, None)


def test_source_groups_and_vrf_boundary(configuration):
    rule = configuration['nat']['cgnat']['rule']['10']
    del rule['source-address']
    rule['source-address-group'] = 'SUBSCRIBERS'
    configuration['firewall'] = {'group': {'address-group': {'ipv4': {
        'SUBSCRIBERS': {'address': ['100.64.0.1/32']}}}}}
    nat.verify(configuration, None)
    configuration['firewall']['group']['address-group']['ipv4']['SUBSCRIBERS']['dynamic'] = {}
    with pytest.raises(RouterError, match='static address group'):
        nat.verify(configuration, None)
    del configuration['firewall']['group']['address-group']['ipv4']['SUBSCRIBERS']['dynamic']
    configuration['interfaces'] = {'ethernet': {'eth2': {'vrf': 'BLUE'}}}
    configuration['vrf'] = {'name': {'BLUE': {'table': '500'}}}
    with pytest.raises(RouterError, match='outside VRF default'):
        nat.verify(configuration, None)
    rule['vrf'] = 'BLUE'
    nat.verify(configuration, None)


def test_generation_and_incremental_pool_update(schema, configuration):
    text = render(schema, configuration)
    assert 'type ipv4_addr : interval ipv4_addr . inet_service' in text
    assert 'ct zone 0 meta l4proto { tcp, udp, icmp }' in text
    assert 'snat ip to ip saddr map @cgnat_allocation_10' in text
    assert 'jump ipv4_cgnat' in text
    assert 'meta nfproto vmap { ipv4 : jump ipv4_nat_postrouting }' in text
    before = deepcopy(configuration)
    configuration['nat']['cgnat']['pool']['PUBLIC']['port-range'] = '2048-65535'
    text = render(schema, configuration, before)
    assert 'destroy map inet nvyr_filter cgnat_allocation_10' in text
    assert '100.64.0.1 : 203.0.113.10 . 2048-3071' in text
    assert 'flush chain inet nvyr_filter ipv4_nat_postrouting' in text
    assert 'cgnat_allocation_10' not in render(schema, configuration, configuration)


def test_ordinary_nat_precedes_cgn_and_removal(schema, configuration):
    configuration['nat']['source'] = {'rule': {'5': {'outbound-interface': ['eth2'], 'exclude': True}}}
    text = render(schema, configuration)
    assert text.index('return comment "5|"') < text.index('jump ipv4_cgnat')
    remaining = deepcopy(configuration)
    del remaining['nat']['cgnat']
    text = render(schema, remaining, configuration)
    assert 'destroy map inet nvyr_filter cgnat_allocation_10' in text
    assert 'destroy chain inet nvyr_filter ipv4_cgnat' in text
    assert 'jump ipv4_cgnat' not in text
    assert 'return comment "5|"' in text


@pytest.mark.parametrize('suffix', ['protocol gre', 'source-address not 100.64.0.1',
                                   'block-size 0', 'port-range 5000-1024'])
def test_cli_rejects_invalid_values(schema, suffix):
    branch = 'pool PUBLIC' if suffix.startswith(('block-size', 'port-range')) else 'rule 10'
    with pytest.raises(RouterError):
        schema.set_paths(('nat cgnat ' + branch + ' ' + suffix).split())


def test_operational_views(configuration, monkeypatch, capsys):
    monkeypatch.setattr(operations, 'configuration', lambda: configuration)
    monkeypatch.setattr(operations.firewall, '_load_table', lambda **kwargs: {
        'chains': {'ipv4_cgnat': {'rules': [{'number': '10', 'counter': {'packets': 12, 'bytes': 768}}]}}})
    operations.pools()
    assert 'PUBLIC' in capsys.readouterr().out
    operations.rules(number='10')
    output = capsys.readouterr().out
    assert 'Installed' in output and '768' in output
    operations.allocation(subscriber='100.64.0.1')
    output = capsys.readouterr().out
    assert '1024-2047' in output and 'Configured allocations' in output
    with pytest.raises(RouterError, match='not configured'):
        operations.rules(number='99')


def test_vrf_guard_rendering_and_current_zone_ledger(configuration, tmp_path, monkeypatch):
    from nvyr.helpers.nftables_formatters import nft_cgnat_rule
    from nvyr.helpers import vrf_conntrack

    configuration['vrf'] = {'name': {'BLUE': {'table': '500'}}}
    configuration['interfaces'] = {'ethernet': {'eth2': {'vrf': 'BLUE'}, 'eth3': {}}}
    rule = configuration['nat']['cgnat']['rule']['10']
    rule['vrf'] = 'BLUE'
    monkeypatch.setattr(vrf_conntrack, 'read_ledger', lambda directory: (None, 'boot', {
        'boot': 'boot', 'zones': {'BLUE:500': 17}}))
    zones = cgnat.zone_numbers(configuration, tmp_path)
    text = nft_cgnat_rule(configuration, '10', rule, zones)
    assert 'ct zone 17' in text and 'oifname { "BLUE", "eth2" }' in text
    assert 'eth3' not in text
    monkeypatch.setattr(vrf_conntrack, 'read_ledger', lambda directory: (None, 'boot', {'boot': 'old'}))
    with pytest.raises(RouterError, match='current VRF'):
        cgnat.zone_numbers(configuration, tmp_path)


@pytest.mark.parametrize('matches,expected', [
    ({'protocol': ['tcp'], 'destination-port': ['443']}, 'th dport { 443 }'),
    ({'protocol': ['udp'], 'not': {'destination-port': ['53']}}, 'th dport != { 53 }'),
    ({'destination-address': ['198.51.100.0/24']}, 'ip daddr { 198.51.100.0/24 }'),
    ({'not': {'destination-address': ['10.0.0.0/8']}}, 'ip daddr != { 10.0.0.0/8 }'),
    ({'packet-mark': ['42']}, 'meta mark { 42 }'),
    ({'connection': {'mark': ['42']}}, 'ct mark { 42 }'),
    ({'protocol': ['icmp'], 'port-mapping': 'fully-random'}, '@cgnat_allocation_10 fully-random'),
])
def test_shared_match_formatting(schema, configuration, matches, expected):
    configuration['nat']['cgnat']['rule']['10'].update(matches)
    schema.validate_configuration(configuration)
    nat.verify(configuration, None)
    assert expected in render(schema, configuration)


def test_static_subscriber_change_rebuilds_allocation(schema, configuration):
    rule = configuration['nat']['cgnat']['rule']['10']
    del rule['source-address']
    rule['source-address-group'] = 'CLIENTS'
    configuration['firewall'] = {'group': {'address-group': {'ipv4': {
        'CLIENTS': {'address': ['100.64.0.1']}}}}}
    before = deepcopy(configuration)
    configuration['firewall']['group']['address-group']['ipv4']['CLIENTS']['address'].append('100.64.0.2')
    text = render(schema, configuration, before)
    assert 'destroy map inet nvyr_filter cgnat_allocation_10' in text
    assert '100.64.0.2 : 203.0.113.10 . 2048-3071' in text


def test_unrelated_group_does_not_rebuild_cgn(schema, configuration):
    before = deepcopy(configuration)
    configuration['firewall'] = {'group': {'address-group': {'ipv4': {
        'UNRELATED': {'address': ['192.0.2.1']}}}}}
    text = render(schema, configuration, before)
    assert 'cgnat_allocation_' not in text
    assert 'ipv4_cgnat' not in text
