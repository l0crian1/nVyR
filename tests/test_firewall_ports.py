"""Port-bearing transports share matching, but not NAT translation capabilities."""

from copy import deepcopy

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import RouterError
from nvyr.helpers import nftables
from nvyr.helpers.nftables_formatters import nft_group_guard
from tests.test_firewall_maps import rendered
from tests.test_nftables_normalizer import rule_document, rules


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('protocol', ['tcp', 'udp', 'sctp', 'udplite', 'dccp'])
@pytest.mark.parametrize('feature', ['direct', 'port-group', 'map', 'match-group', 'excluded-group', 'dynamic', 'limit', 'connection-limit'])
def test_port_matching_across_consumers(family, protocol, feature):
    rule = {'action': 'accept', 'protocol': [protocol]}
    groups = {}
    definition = {'match': {'protocol': True, 'destination-port': True},
                  'entry': {'SERVICE': {'protocol': protocol, 'destination-port': '53098'}}}

    if feature == 'direct':
        rule.update({'source-port': ['53097'], 'destination-port': ['53098-53100'],
                     'not': {'destination-port': ['53099', '53100']}})
    elif feature == 'port-group':
        groups['port-group'] = {'SERVICE': {'port': ['53098-53100']}}
        rule['destination-port-group'] = 'SERVICE'
    elif feature in {'map', 'match-group', 'excluded-group', 'dynamic'}:
        kind = 'map' if feature == 'map' else 'match-group'
        if feature == 'map':
            definition['result-type'] = 'verdict'
            definition['entry']['SERVICE']['result'] = {'action': 'accept'}
            del rule['action']
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
        groups[kind] = {family: {'SERVICE': definition}}
    elif feature == 'limit':
        rule['limit'] = {'rate': {'packets': '10/s'}, 'per': 'destination-port'}
    else:
        rule['connection'] = {'limit': {'over': '5', 'per': 'destination-port'}}

    tree = {'firewall': {'group': groups, family: {'forward': {'filter': {'rule': {'10': rule}}}}}}
    original = deepcopy(tree)
    text = rendered(tree)

    assert 'th dport' in text
    assert protocol in text
    assert tree == original


@pytest.mark.parametrize('protocol', ['sctp', 'udplite', 'dccp'])
def test_port_translation_remains_separate(protocol):
    """Widening match validation must not enable new NAT port translations."""
    rule = {'protocol': [protocol], 'destination-port': ['53098']}
    nftables.verify_ports(rule, ('nat', 'source', 'rule', '10'))

    with pytest.raises(RouterError, match='port protocol'):
        nftables.verify_ports(rule, ('nat', 'source', 'rule', '10'), translation=True)

    mapping = {'match': {'protocol': True, 'destination-port': True}, 'result-type': 'port',
               'entry': {'SERVICE': {'protocol': protocol, 'destination-port': '53098',
                                     'result': {'port': '53099'}}}}
    with pytest.raises(RouterError, match='port result requires protocol tcp or udp'):
        firewall.verify_map('ipv4', 'SERVICE', mapping, {})

    assert nft_group_guard('ipv4', ['destination-port'], 'port') == 'meta l4proto { tcp, udp } '


@pytest.mark.parametrize('protocol', ['icmp', 'gre', 'esp'])
@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
def test_non_port_protocols_remain_invalid(protocol, family):
    """A valid protocol name does not imply a transport-port layout."""
    with pytest.raises(RouterError, match='port protocol'):
        nftables.verify_ports(
            {'protocol': [protocol], 'destination-port': ['53']},
            ('firewall', family, 'forward', 'filter', 'rule', '10'),
        )


@pytest.mark.parametrize('protocol', ['sctp', 'udplite', 'dccp'])
def test_native_protocol_specific_port_listing(protocol):
    """Native listings may replace th dport with the selected protocol's name."""
    document = rule_document({'match': {
        'op': '==', 'left': {'payload': {'protocol': protocol, 'field': 'dport'}}, 'right': 53098,
    }}, {'accept': None})
    rule = rules(document)['10']

    assert rule['destination-port'] == [53098]
    assert rule['protocol'] == [protocol]
    assert 'unsupported' not in rule
