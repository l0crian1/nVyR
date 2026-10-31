"""Exercise conntrack rules and groups in disposable network namespaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(
    os.environ.get('NVYR_NETWORK_TEST') != '1',
    reason='requires isolated privileged nftables container',
)


def test_native_connection_fields_and_typeof_groups():
    isolated('''
from nvyr.helpers.nftables_normalizer import normalize

tree = {'firewall': {'global-options': {'connection-accounting': True},
    'ipv4': {'forward': {'filter': {'rule': {}}}},
    'group': {'map': {'ipv4': {}}, 'match-group': {'ipv6': {}}}}}
fields = [
    {'direction': ['original', 'reply']}, {'family': ['ipv4']},
    {'protocol': ['tcp', 'udp']}, {'zone': ['0-2']}, {'id': ['10-20']},
    {'helper': ['ftp']}, {'label': ['0,127']}, {'label': ['0,1', '2']},
    {'not': {'label': ['1', '2']}}, {'expiration': {'gt': '1s', 'lt': '10s'}},
    {'original': {'packets': {'gt': '10'}}},
    {'reply': {'bytes': {'lt': '1g'}}},
    {'total': {'average-packet-size': {'eq': '1k'}}},
    {'original': {'source-address': ['192.0.2.0/24']}},
    {'protocol': ['tcp'], 'reply': {'destination-port': ['80', '443']}},
    {'original': {'zone': ['0']}, 'reply': {'zone': ['0']}},
]
rules = tree['firewall']['ipv4']['forward']['filter']['rule']
for number, connection in enumerate(fields, 1):
    rules[str(number)] = {'action': 'continue', 'connection': connection}

# Unqualified integer/string keys need typeof; ordinary tuple keys keep type.
for name, match, connection in [
    ('ID', {'id': True}, {'id': '42'}),
    ('HELPER', {'helper': True}, {'helper': 'ftp'}),
    ('ZONE', {'zone': True, 'mark': True}, {'zone': '0-2', 'mark': '42'}),
    ('COUNTS', {'original': {'packets': True}, 'mark': True}, {'original': {'packets': '5'}, 'mark': '42'}),
    ('AGE', {'expiration': True}, {'expiration': '10s'}),
]:
    tree['firewall']['group']['map']['ipv4'][name] = {
        'match': {'connection': match}, 'result-type': 'verdict',
        'entry': {'ONE': {'connection': connection, 'result': {'action': 'accept'}}}}
tree['firewall']['group']['match-group']['ipv6']['TUPLE'] = {
    'match': {'connection': {'protocol': True, 'original': {'destination-address': True, 'destination-port': True}}},
    'entry': {'WEB': {'connection': {'protocol': 'tcp', 'original': {
        'destination-address': '2001:db8::1', 'destination-port': '443'}}}}}
apply(tree)
document = json.loads(run('nft', '-j', 'list', 'ruleset'))
table = normalize(document, configuration=tree)['tables']['inet']['nvyr_filter']
for rule in table['chains']['ipv4_forward']['rules']:
    assert 'unsupported' not in rule, rule
assert table['maps']['ipv4_map_HELPER']['match-fields'] == ['connection-helper']
assert table['maps']['ipv4_map_ID']['entries'][0]['key'] == [42]
assert table['sets']['ipv6_match_group_TUPLE']['match-fields'] == [
    'connection-protocol', 'connection-original-destination-address', 'connection-original-destination-port']

# Replacement/recovery use the ordinary group lifecycle, including typed keys.
apply({})
apply(tree, recovery=True)
''')


def test_original_destination_survives_dnat_and_accounting_sees_packets():
    isolated('''
import socket

run('ip', 'link', 'set', 'lo', 'up')
Path('/proc/sys/net/netfilter/nf_conntrack_acct').write_text('1')
receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver.bind(('127.0.0.1', 41002))
receiver.settimeout(2)
tree = {'firewall': {'global-options': {'connection-accounting': True},
    'ipv4': {'input': {'filter': {'rule': {
        '10': {'action': 'continue', 'counter': {}, 'destination-port': ['41002'], 'protocol': ['udp'],
               'connection': {'protocol': ['udp'], 'original': {'destination-port': ['41001']}}},
        '20': {'action': 'continue', 'counter': {}, 'connection': {'direction': ['original'],
               'original': {'packets': {'gt': '0'}}}},
    }}}}}}
apply(tree)
run('nft', 'add', 'chain', 'inet', 'nvyr_filter', 'test_dnat',
    '{ type nat hook output priority dstnat; policy accept; }')
run('nft', 'add', 'rule', 'inet', 'nvyr_filter', 'test_dnat',
    'udp dport 41001 dnat ip to 127.0.0.1:41002')
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sender.sendto(b'conntrack smoke', ('127.0.0.1', 41001))
assert receiver.recv(128) == b'conntrack smoke'
listing = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_input'))
for record in listing['nftables']:
    rule = record.get('rule', {})
    if rule.get('comment') in ('10|', '20|'):
        counter = next(item['counter'] for item in rule['expr'] if 'counter' in item)
        assert counter['packets'] == 1, rule
sender.close()
receiver.close()
''')


def test_native_comparisons_program_distinct_fields():
    isolated('''
# Check the actual netlink program: nft 1.1.7's listing coalescer can incorrectly
# merge adjacent opposite comparisons on different CT keys when displaying them.
text = 'add table inet probe\\nadd chain inet probe c\\n'
text += 'add rule inet probe c ct expiration < 10s ct original bytes > 1024\\n'
result = subprocess.run(['nft', '--debug=netlink', '-f', '-'], input=text,
                        text=True, capture_output=True, check=True)
assert 'ct load expiration' in result.stdout
assert 'ct load bytes' in result.stdout
assert 'cmp lt' in result.stdout and 'cmp gt' in result.stdout
''')


def test_dynamic_connection_keys_load_through_normal_pipeline():
    isolated('''
from nvyr.helpers.nftables_formatters import NFT_KEYMAP

groups = {}
rules = {}
for number, (name, field) in enumerate(NFT_KEYMAP.items(), 1):
    if not field.path or name == 'connection-label':
        continue
    match = {}
    node = match
    for component in field.path[:-1]:
        node = node.setdefault(component, {})
    node[field.path[-1]] = True
    if name.endswith('-port'):
        match['connection']['protocol'] = True
    group_name = 'KEY' + str(number)
    groups[group_name] = {'match': match, 'dynamic': {}}
    rules[str(number)] = {'action': 'continue', 'add-to-group': {'match-group': group_name}}
tree = {'firewall': {'global-options': {'connection-accounting': True},
    'group': {'match-group': {'ipv4': groups}},
    'ipv4': {'forward': {'filter': {'rule': rules}}}}}
apply(tree)
assert len(Manager().match_groups()) == len(groups)
''')


def test_label_bits_and_alternatives_match_real_connections():
    isolated('''
from nvyr.helpers.nftables_formatters import nft_rule

run('ip', 'link', 'set', 'lo', 'up')
run('nft', 'add', 'table', 'inet', 'labels')
run('nft', 'add', 'chain', 'inet', 'labels', 'output',
    '{ type filter hook output priority filter; policy accept; }')
run('nft', 'add', 'rule', 'inet', 'labels', 'output', 'ct label set 0 | 1 | 127')
for number, values in enumerate([['0,127'], ['0,1', '2'], ['2', '3'], ['0,2']], 1):
    rule = {'connection': {'label': values}, 'counter': {}, 'action': 'continue'}
    run('nft', 'add', 'rule', 'inet', 'labels', 'output', nft_rule('ipv4', 'output', str(number), rule))
run('ping', '-c', '1', '-W', '1', '127.0.0.1')
listing = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'labels', 'output'))
counts = {}
for record in listing['nftables']:
    rule = record.get('rule', {})
    if 'comment' in rule:
        counts[rule['comment']] = next(item['counter']['packets'] for item in rule['expr'] if 'counter' in item)
assert counts['1|'] > 0 and counts['2|'] > 0, counts
assert counts['3|'] == counts['4|'] == 0, counts
''')
