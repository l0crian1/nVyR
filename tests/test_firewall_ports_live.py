"""Native port guards and lookups, isolated from all host interfaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('protocol', ['sctp', 'udplite', 'dccp'])
def test_transport_ports_in_native_packet_path(family, protocol):
    isolated(f'family = {family!r}\nprotocol = {protocol!r}\n' + '''
from smoketests.firewall_support import send_firewall_transport
from smoketests.assertions import assert_firewall_counter

run('ip', 'link', 'set', 'lo', 'up')
for feature in ('direct', 'port-group', 'map', 'match-group', 'excluded-group', 'dynamic', 'limit'):
    apply({})
    rule = {'outbound-interface': ['lo'], 'protocol': [protocol],
            'counter': {'group': 'MATCHED'}, 'action': 'drop'}
    groups = {'counter-group': {'MATCHED': {}}}
    names = {}
    definition = {'match': {'protocol': True, 'destination-port': True},
                  'entry': {'SERVICE': {'protocol': protocol, 'destination-port': '53098'}}}

    if feature == 'direct':
        rule.update({'destination-port': ['53098-53100'], 'not': {'destination-port': ['53099', '53100']}})
    elif feature == 'port-group':
        groups['port-group'] = {'SERVICE': {'port': ['53098']}}
        rule['destination-port-group'] = 'SERVICE'
    elif feature in ('map', 'match-group', 'excluded-group', 'dynamic'):
        kind = 'map' if feature == 'map' else 'match-group'
        if feature == 'dynamic':
            definition['dynamic'] = {}
            definition.pop('entry')
            rule['add-to-group'] = {'match-group': 'SERVICE'}
        else:
            del rule['protocol']
            if feature == 'excluded-group':
                rule['not'] = {kind: 'SERVICE'}
            else:
                rule[kind] = 'SERVICE'
        if feature == 'map':
            definition['result-type'] = 'verdict'
            definition['entry']['SERVICE']['result'] = {'action': 'jump', 'jump-target': 'COUNT'}
            names['COUNT'] = {'rule': {'1': {'counter': rule.pop('counter'), 'action': rule.pop('action')}}}
        groups[kind] = {family: {'SERVICE': definition}}
    else:
        rule['limit'] = {'rate': {'packets': '100/s'}, 'per': 'protocol,destination-port'}

    fallback = {'outbound-interface': ['lo'], 'protocol': [protocol], 'action': 'drop'}
    tree = {'firewall': {'group': groups, family: {
        'name': names, 'output': {'raw': {'rule': {'10': rule, '20': fallback}}}}}}
    apply(tree)
    send_firewall_transport(protocol, family=family)
    send_firewall_transport(protocol, family=family, destination_port=53099)
    expected = 2 if feature in ('dynamic', 'limit') else 1
    assert_firewall_counter('MATCHED', expected)
    if feature == 'dynamic':
        listing = run('nft', '-s', 'list', 'set', 'inet', 'nvyr_filter', family + '_match_group_SERVICE')
        assert protocol + ' . 53098' in listing, listing
        assert protocol + ' . 53099' in listing, listing
apply({})
''')
