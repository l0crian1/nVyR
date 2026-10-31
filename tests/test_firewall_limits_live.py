"""Exercise native rate and connection state without touching host networking."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def test_all_key_fields_byte_rates_and_recovery():
    isolated(r'''
fields = ['source-address', 'destination-address', 'source-port', 'destination-port',
          'protocol', 'inbound-interface', 'outbound-interface', 'source-mac',
          'destination-mac', 'packet-mark', 'connection-mark']
tree = {'firewall': {}}
for family in ('ipv4', 'ipv6'):
    rules = {}
    for number, field in enumerate(fields, 1):
        rules[str(number)] = {'action': 'continue',
            'limit': {'per': field, 'rate': {'bytes': '1m/s'}, 'burst': {'bytes': '64k'}, 'over': True},
            'connection': {'limit': {'per': field, 'over': '5'}}}
    rules['100'] = {'action': 'continue', 'limit': {
        'per': 'source-address,destination-address,destination-port',
        'source-prefix-length': '24' if family == 'ipv4' else '64',
        'destination-prefix-length': '2', 'rate': {'packets': '10/s'}}}
    # Gigabyte input and capacity boundaries must be accepted by native nftables.
    rules['101'] = {'action': 'continue', 'limit': {
        'rate': {'bytes': '1g/s'}, 'burst': {'bytes': '3g'}}}
    rules['102'] = {'action': 'continue', 'limit': {'rate': {'bytes': '18446744073/s'}}}
    tree['firewall'][family] = {'forward': {'filter': {'rule': rules}}}
apply(tree)
assert len(Manager().rule_limits()) == 46
# Full and scoped operational listings should recognize these new expressions.
from nvyr.helpers.nftables_normalizer import normalize
for command in [('ruleset',), ('chain', 'inet', 'nvyr_filter', 'ipv4_forward')]:
    table = normalize(json.loads(run('nft', '-j', 'list', *command)))['tables']['inet']['nvyr_filter']
    for chain in table['chains'].values():
        for rule in chain.get('rules', []):
            assert 'unsupported' not in rule, rule
    rules = table['chains']['ipv4_forward']['rules']
    masked = next(rule for rule in rules if rule.get('number') == '100')
    assert masked['limit']['source-prefix-length'] == 24, masked
    assert masked['limit']['destination-prefix-length'] == 2, masked
    byte_rule = next(rule for rule in rules if rule.get('number') == '1')
    assert byte_rule['limit']['rate'] == {'bytes': '1m/s'}, byte_rule
    assert byte_rule['limit']['burst'] == {'bytes': '64k'}, byte_rule
    giga = next(rule for rule in rules if rule.get('number') == '101')
    assert giga['limit']['rate'] == {'bytes': '1024m/s'}, giga
previous = {}
apply({}, recovery=True)
assert Manager().rule_limits() == []
''')


def test_per_source_and_subnet_buckets_and_lifecycle():
    isolated(r'''
import socket
run('ip', 'link', 'set', 'lo', 'up')
options = {'per': 'source-address', 'rate': {'packets': '1/h'}, 'burst': {'packets': '2'}, 'over': True}
rule = {'action': 'drop', 'protocol': ['udp'], 'destination-port': ['53001'],
        'counter': {}, 'limit': options}
tree = {'firewall': {'ipv4': {'output': {'filter': {'rule': {'10': rule}}}}}}
apply(tree)

def send(address, count):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.bind((address, 0))
        for _ in range(count):
            try:
                sender.sendto(b'test', ('127.0.0.1', 53001))
            except PermissionError:
                # A local output DROP reports EPERM; verify the exact drop count below.
                pass

def dropped():
    data = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_output'))
    for item in data['nftables']:
        rule = item.get('rule', {})
        if rule.get('comment') == '10|':
            return next(stmt['counter']['packets'] for stmt in rule['expr'] if 'counter' in stmt)

send('127.0.0.2', 3)
send('127.0.0.3', 3)
assert dropped() == 2, dropped()

# An unrelated chain commit must preserve both buckets and their counters.
tree['firewall']['ipv4']['input'] = {'filter': {'default-action': 'accept'}}
apply(tree)
send('127.0.0.2', 1)
assert dropped() == 3, dropped()

# Rebuilding this chain changes the key and resets its private state atomically.
options['source-prefix-length'] = '24'
apply(tree)
send('127.0.0.2', 2)
send('127.0.0.3', 1)
assert dropped() == 1, dropped()
send('127.0.1.2', 2)
assert dropped() == 1, dropped()

# A rejected native transaction leaves the installed bucket untouched.
try:
    Manager().apply('flush table inet nvyr_filter\ninvalid statement\n', directory)
    raise AssertionError('Invalid transaction accepted')
except RouterError:
    pass
send('127.0.0.2', 1)
assert dropped() == 2, dropped()

# Without per, different subnets consume the same single rule-wide bucket.
del options['per']
del options['source-prefix-length']
apply(tree)
assert Manager().rule_limits() == []
send('127.0.0.2', 2)
send('127.0.1.2', 1)
assert dropped() == 1, dropped()
apply({})
assert Manager().rule_limits() == []
''')


def test_ipv6_subnets_and_destination_ports_are_independent_keys():
    isolated(r'''
import socket
run('ip', 'link', 'set', 'lo', 'up')
for address in ('2001:db8:1::2', '2001:db8:1::3', '2001:db8:2::2'):
    run('ip', '-6', 'address', 'add', address + '/128', 'dev', 'lo', 'nodad')
rule = {'action': 'continue', 'counter': {}, 'protocol': ['udp'],
    'limit': {'rate': {'packets': '1/h'}, 'burst': {'packets': '1'}, 'over': True,
              'per': 'source-address,destination-port', 'source-prefix-length': '64'}}
tree = {'firewall': {'ipv6': {'output': {'filter': {'rule': {'10': rule}}}}}}
apply(tree)

for address, port in [('2001:db8:1::2', 53001), ('2001:db8:1::3', 53001),
                      ('2001:db8:2::2', 53001), ('2001:db8:1::2', 53002)]:
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sender:
        sender.bind((address, 0))
        sender.sendto(b'ipv6', ('::1', port))

data = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv6_output'))
rule = next(item['rule'] for item in data['nftables'] if item.get('rule', {}).get('comment') == '10|')
count = next(stmt['counter']['packets'] for stmt in rule['expr'] if 'counter' in stmt)
assert count == 1, count
apply({})
''')


def test_connection_counts_reject_extra_connections_per_source():
    isolated('''
import socket
run('ip', 'link', 'set', 'lo', 'up')
rule = {
    'action': 'drop',
    'connection': {'state': ['new'], 'limit': {'per': 'source-address', 'over': '1'}},
    'protocol': ['tcp'],
    'destination-port': ['53002'],
    'counter': {},
}
tree = {'firewall': {'ipv4': {'output': {'filter': {'rule': {'10': rule}}}}}}
apply(tree)
listener = socket.socket()
listener.bind(('127.0.0.1', 53002))
listener.listen(5)
connections = []
try:
    for source, succeeds in [('127.0.0.2', True), ('127.0.0.2', False), ('127.0.0.3', True)]:
        client = socket.socket()
        connections.append(client)
        client.bind((source, 0))
        client.settimeout(0.2)
        result = client.connect_ex(('127.0.0.1', 53002))
        assert (result == 0) == succeeds, (source, result)
        if succeeds:
            accepted, _ = listener.accept()
            connections.append(accepted)
            client.sendall(b'active')
            assert accepted.recv(6) == b'active'
finally:
    for connection in connections:
        connection.close()
    listener.close()
apply({})
assert Manager().rule_limits() == []
''')
