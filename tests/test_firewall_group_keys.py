"""Match-groups and maps reject identical complete keys, not intersecting ranges."""

from copy import deepcopy

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import ValidationError
from nvyr.helpers.nftables_formatters import NFT_KEYMAP, NFT_FAMILY_FIELDS
from nvyr.schema import Schema


VALUES = {
    'state': ('new', 'established'),
    'connection-status': ('seen-reply', 'assured'),
    'packet-type': ('host', 'multicast'),
    'inbound-interface': ('eth1', 'eth2'),
    'outbound-interface': ('eth1', 'eth2'),
    'inbound-link-group': ('10', '20'),
    'outbound-link-group': ('10', '20'),
    'vlan-id': ('10', '20'),
    'vlan-priority': ('1', '2'),
    'source-mac': ('02:00:00:00:00:01', '02:00:00:00:00:02'),
    'destination-mac': ('02:00:00:00:00:01', '02:00:00:00:00:02'),
    'packet-mark': ('1-10', '5-20'),
    'connection-mark': ('1-10', '5-20'),
    'dscp': ('1-10', '5-20'),
    'protocol': ('tcp', 'udp'),
    'tcp-flags': ('syn,not ack', 'syn,ack'),
    'icmp-type': ('echo-request', 'echo-reply'),
    'icmp-code': ('0', '1'),
    'source-port': ('100-200', '150-250'),
    'destination-port': ('100-200', '150-250'),
    'connection-direction': ('original', 'reply'),
    'connection-family': ('ipv4', 'ipv6'),
    'connection-protocol': ('tcp', 'udp'),
    'connection-zone': ('1-10', '5-20'),
    'connection-helper': ('ftp', 'tftp'),
    'connection-id': ('1-10', '5-20'),
    'connection-expiration': ('1s', '2s'),
}
FIELDS = [field for field, metadata in NFT_KEYMAP.items() if metadata.size and field != 'connection-label']


def put_field(target, field, value):
    path = NFT_KEYMAP[field].path or (field,)
    for component in path[:-1]:
        target = target.setdefault(component, {})
    target[path[-1]] = value


def values_for(field, family):
    if field.endswith('-address'):
        return ('192.0.2.0/24', '192.0.2.1') if family == 'ipv4' else ('2001:db8::/64', '2001:db8::1')
    if field.startswith('connection-') and field.endswith(('-port', '-zone')):
        return '100-200', '150-250'
    if field.endswith(('-packets', '-bytes', '-average-packet-size')):
        return '1', '2'
    return VALUES[field]


def verify(kind, family, group):
    if kind == 'map':
        firewall.verify_map(family, 'TEST', group, {})
    else:
        firewall.verify_match_group(family, 'TEST', group)


@pytest.mark.parametrize('kind', ['map', 'match-group'])
@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
@pytest.mark.parametrize('field', FIELDS)
def test_one_different_component_is_a_distinct_key(kind, family, field):
    if family == 'inet' and field in NFT_FAMILY_FIELDS:
        pytest.skip('family-specific field')

    protocol = ('icmp' if family == 'ipv4' else 'ipv6-icmp') if field.startswith('icmp-') else 'tcp'
    group = {'match': {'protocol': True}, 'entry': {
        'A': {'protocol': protocol}, 'B': {'protocol': protocol},
    }}
    put_field(group['match'], field, True)
    first, second = values_for(field, family)
    put_field(group['entry']['A'], field, first)
    put_field(group['entry']['B'], field, second)
    if kind == 'map':
        group['result-type'] = 'verdict'
        group['entry']['A']['result'] = {'action': 'accept'}
        group['entry']['B']['result'] = {'action': 'drop'}

    Schema.bundled().validate_configuration({'firewall': {'group': {kind: {family: {'TEST': group}}}}})
    verify(kind, family, group)

    # Results and entry names cannot distinguish otherwise identical lookup keys.
    put_field(group['entry']['B'], field, first)
    with pytest.raises(ValidationError, match='duplicate lookup keys'):
        verify(kind, family, group)


@pytest.mark.parametrize('kind', ['map', 'match-group'])
@pytest.mark.parametrize('family,host,anywhere', [
    ('ipv4', '10.5.5.5', '0.0.0.0/0'), ('ipv6', '2001:db8::5', '::/0'),
])
def test_crossed_source_destination_keys(kind, family, host, anywhere):
    group = {'match': {'source-address': True, 'destination-address': True}, 'entry': {
        '1': {'source-address': anywhere, 'destination-address': host},
        '2': {'source-address': host, 'destination-address': anywhere},
    }}
    if kind == 'map':
        group['result-type'] = 'verdict'
        group['entry']['1']['result'] = {'action': 'accept'}
        group['entry']['2']['result'] = {'action': 'drop'}
    verify(kind, family, group)

    group['entry']['3'] = deepcopy(group['entry']['1'])
    with pytest.raises(ValidationError, match='duplicate lookup keys'):
        verify(kind, family, group)


@pytest.mark.parametrize('result_type,first,second', [
    ('verdict', {'action': 'accept'}, {'action': 'drop'}),
    ('address', {'address': '192.0.2.1'}, {'address': '192.0.2.2'}),
    ('port', {'port': '1000'}, {'port': '2000'}),
    ('address-port', {'address': '192.0.2.1', 'port': '1000'},
                     {'address': '192.0.2.2', 'port': '2000'}),
])
def test_map_results_never_distinguish_duplicate_keys(result_type, first, second):
    key = {'source-address': '1.1.1.1', 'destination-address': '2.2.2.2', 'protocol': 'tcp'}
    group = {'match': dict.fromkeys(key, True), 'result-type': result_type,
             'entry': {'A': key | {'result': first}, 'B': key | {'result': second}}}
    with pytest.raises(ValidationError, match='duplicate lookup keys'):
        verify('map', 'ipv4', group)

    group['entry']['B']['destination-address'] = '2.2.2.3'
    verify('map', 'ipv4', group)
