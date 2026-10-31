"""Exercise native quota accounting and resets in disposable network namespaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def test_shared_quota_packets_reset_and_lifecycle():
    isolated(r'''
import socket
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.op_scripts.firewall import clear_counter, clear_quota

run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {'group': {
    'quota-group': {'UNTIL': {'bytes': '100'}, 'OVER': {'bytes': '100', 'over': True}},
    'counter-group': {'U': {}, 'O': {}},
}}}
for family in ('ipv4', 'ipv6'):
    tree['firewall'][family] = {'output': {'filter': {'rule': {
        '10': {'protocol': ['udp'], 'destination-port': ['53001'],
               'quota': {'group': 'UNTIL'}, 'counter': {'group': 'U'}, 'action': 'continue'},
        '20': {'protocol': ['udp'], 'destination-port': ['53001'],
               'quota': {'group': 'OVER'}, 'counter': {'group': 'O'}, 'action': 'continue'},
    }}}}
apply(tree)

def send(family):
    address = '127.0.0.1' if family == socket.AF_INET else '::1'
    with socket.socket(family, socket.SOCK_DGRAM) as receiver:
        receiver.bind((address, 53001))
        receiver.settimeout(2)
        with socket.socket(family, socket.SOCK_DGRAM) as sender:
            sender.sendto(b'0123456789', (address, 53001))
        assert receiver.recv(32) == b'0123456789'

def table():
    return normalize(json.loads(run('nft', '-j', 'list', 'ruleset')))['tables']['inet']['nvyr_filter']

# Both families consume the same objects: 38 + 58 bytes fit; another 38 exceeds them.
send(socket.AF_INET)
send(socket.AF_INET6)
send(socket.AF_INET)
data = table()
assert data['counters']['counter_group_U']['packets'] == 2, data
assert data['counters']['counter_group_O']['packets'] == 1, data
assert data['quotas']['quota_group_UNTIL']['remaining'] == 0
assert data['quotas']['quota_group_OVER']['exhausted'] is True

# Changing a consuming chain leaves both shared quotas and counters intact.
tree['firewall']['ipv4']['output']['filter']['rule']['10']['description'] = 'Rebuilt consumer'
text = apply(tree)
assert 'destroy quota' not in text
assert table()['quotas']['quota_group_UNTIL']['used'] == 100
assert table()['counters']['counter_group_U']['packets'] == 2

# Reset operations are scoped to one object and do not touch another quota/counter.
clear_quota('UNTIL')
clear_counter('U')
data = table()
assert data['quotas']['quota_group_UNTIL']['used'] == 0
assert data['quotas']['quota_group_OVER']['used'] == 100
assert data['counters']['counter_group_U']['packets'] == 0
assert data['counters']['counter_group_O']['packets'] == 1
send(socket.AF_INET)
assert table()['counters']['counter_group_U']['packets'] == 1
assert table()['counters']['counter_group_O']['packets'] == 2

# Reconfiguring the quota itself resets its usage and atomically rebuilds consumers.
tree['firewall']['group']['quota-group']['UNTIL']['bytes'] = '200'
text = apply(tree)
assert 'destroy quota inet nvyr_filter quota_group_UNTIL' in text
assert table()['quotas']['quota_group_UNTIL']['used'] == 0
assert table()['quotas']['quota_group_OVER']['used'] == 100

# Recovery also discovers and removes owned objects absent from the new configuration.
apply({}, recovery=True)
assert Manager().named_state() == []
''')


def test_inline_quota_units_modes_boundaries_and_scoped_json():
    isolated(r'''
from nvyr.helpers.nftables_normalizer import normalize

tree = {'firewall': {}}
for family in ('ipv4', 'ipv6'):
    rules = {}
    for number, amount in enumerate(['0', '64k', '100m', '10g', '9223372036854775807'], 1):
        rules[str(number)] = {'quota': {'bytes': amount, 'over': True}, 'action': 'continue'}
    rules['10'] = {'quota': {'bytes': '1g', 'until': True}, 'action': 'accept'}
    tree['firewall'][family] = {'output': {'raw': {'rule': rules}}}
apply(tree)

for family in ('ipv4', 'ipv6'):
    document = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'nvyr_filter', family + '_output_raw'))
    rules = normalize(document)['tables']['inet']['nvyr_filter']['chains'][family + '_output_raw']['rules']
    assert not any(rule.get('unsupported') for rule in rules), rules
    quotas = {rule['number']: rule['quota'] for rule in rules if 'quota' in rule}
    assert quotas['1']['bytes'] == 0
    assert quotas['4']['bytes'] == 10 * 1024**3
    assert quotas['5']['bytes'] == 9223372036854775807
    assert quotas['10']['mode'] == 'until'
apply({})
''')
