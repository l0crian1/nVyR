"""Opt-in JSON normalization checks against nft in disposable namespaces."""

import os
from pathlib import Path
import subprocess
import sys

import pytest


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires root and disposable network namespaces')


def isolated(script):
    # All nft changes happen after unshare, never in the router's network namespace.
    result = subprocess.run(['unshare', '-n', sys.executable, '-c', script],
                            text=True, capture_output=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr


COMMON = '''
import json
import subprocess

from nvyr.helpers.nftables_normalizer import normalize
from nvyr.helpers.nftables_formatters import nft_rule, nft_map, nft_match_group, nft_group_update

def run(*argv):
    return subprocess.check_output(argv, text=True)

def load(batch):
    result = subprocess.run(['nft', '-f', '-'], input=batch, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr

def listing(*scope):
    document = json.loads(run('nft', '-j', 'list', *scope))
    return normalize(document)['tables']['inet']['nvyr_filter']

def no_unsupported(value):
    if isinstance(value, dict):
        assert 'unsupported' not in value, value
        for item in value.values():
            no_unsupported(item)
    elif isinstance(value, list):
        for item in value:
            no_unsupported(item)
'''


def test_live_full_and_scoped_listings():
    batch = (Path(__file__).parent / 'fixtures/nftables/listing.nft').read_text()
    isolated(COMMON + f'load({batch!r})\n' + '''
full = listing('ruleset')
chain = listing('chain', 'inet', 'nvyr_filter', 'ipv4_forward')
no_unsupported(full)
assert [rule.get('number') for rule in chain['chains']['ipv4_forward']['rules']] == [
    rule.get('number') for rule in full['chains']['ipv4_forward']['rules']]
assert chain['sets'] == {} and chain['maps'] == {}
assert chain['chains']['ipv4_forward']['rules'][7]['map'] == 'POLICY'

for kind, name in [('set', 'ipv4_address_group_LEARNED'), ('map', 'ipv4_map_POLICY')]:
    scoped = listing(kind, 'inet', 'nvyr_filter', name)
    no_unsupported(scoped)
    assert scoped[kind + 's'][name]['entries'][0]['counter']['packets'] == 0
''')


def test_live_all_keymap_fields_actions_and_map_results():
    isolated(COMMON + '''
batch = ['add table inet nvyr_filter', 'add chain inet nvyr_filter ipv4_name_TARGET']
cases = {
    'connection': {'state': ['established'], 'status': ['confirmed,offload', 'snat,dnat'], 'mark': ['9', '30-40']},
    'packet-type': 'other',
    'inbound-interface': ['eth0'],
    'outbound-interface': ['eth1'],
    'source-mac': {'00:11:22:33:44:55': {}},
    'destination-mac': {'00:11:22:33:44:66': {}},
    'packet-mark': ['5', '10-20'],
    'dscp': ['10', '20-30'],
    'ttl': {'gt': '10', 'lt': '100'},
    'protocol': ['tcp', 'udp'],
    'icmp-code': ['0', '1'],
    'source-port': ['100', '200-300'],
    'destination-port': ['443'],
    'tcp-mss': ['1400', '1450-1460'],
    'log': {},
    'counter': {},
    'last-used': True,
    'notrack': True,
}
for family in ('ipv4', 'ipv6'):
    chain = family + '_forward'
    batch.append('add chain inet nvyr_filter ' + chain)
    fields = dict(cases)
    fields['source-address'] = {'192.0.2.1' if family == 'ipv4' else '2001:db8::1': {}}
    fields['destination-address'] = {'198.51.100.0/24' if family == 'ipv4' else '2001:db8:1::/64': {}}
    fields['icmp-type'] = ['echo-request']
    for index, (field, value) in enumerate(fields.items(), 1):
        rule = {field: value, 'action': 'accept', 'description': field}
        if field in ('source-port', 'destination-port'):
            rule['protocol'] = ['tcp', 'udp']
        elif field == 'tcp-mss':
            rule['protocol'] = ['tcp']
        elif field.startswith('icmp-'):
            rule['protocol'] = ['icmp' if family == 'ipv4' else 'ipv6-icmp']
        batch.append('add rule inet nvyr_filter ' + chain + ' ' + nft_rule(family, 'forward', str(index), rule))
    for index, action in enumerate(('accept', 'drop', 'return', 'continue', 'reject'), 100):
        rule = {'action': action, 'description': action}
        batch.append('add rule inet nvyr_filter ' + chain + ' ' + nft_rule(family, 'forward', str(index), rule))

for kind, result in [('address', {'address': '10.0.0.1'}), ('port', {'port': '8080'}),
                     ('address-port', {'address': '10.0.0.1', 'port': '8080'})]:
    definition = {'match': {'protocol': True, 'destination-port': True}, 'result-type': kind,
                  'entry': {'web': {'protocol': 'tcp', 'destination-port': '443', 'result': result}}}
    batch.append('table inet nvyr_filter {\\n' + nft_map('ipv4', kind, definition) + '\\n}')

dynamic = {'match': {'source-address': True, 'protocol': True},
           'dynamic': {'timeout': '10m', 'size': '65535', 'gc-interval': '30s'}}
batch.append('table inet nvyr_filter {\\n' + nft_match_group('ipv4', 'DYNAMIC', dynamic) + '\\n}')
batch.append('add rule inet nvyr_filter ipv4_forward ' + nft_group_update('ipv4', {'match-group': 'DYNAMIC'}, {'DYNAMIC': dynamic}))
load('\\n'.join(batch))

full = listing('ruleset')
no_unsupported(full)
for family in ('ipv4', 'ipv6'):
    for rule in full['chains'][family + '_forward']['rules']:
        field = rule.get('description')
        if field == 'connection':
            assert {'state', 'connection-status', 'connection-mark'} <= rule.keys(), rule
        elif field in cases or field in ('icmp-type', 'source-address', 'destination-address'):
            assert field in rule, rule

assert full['maps']['ipv4_map_address']['entries'][0]['result'] == {'address': '10.0.0.1'}
assert full['maps']['ipv4_map_port']['entries'][0]['result'] == {'port': 8080}
assert full['chains']['ipv4_forward']['rules'][-1]['add-to-group'] == {
    'match-group': 'DYNAMIC', 'match-fields': ['source-address', 'protocol']}
''')


def test_live_flowtable_and_offload():
    isolated(COMMON + '''
run('ip', 'link', 'add', 'test0', 'type', 'veth', 'peer', 'name', 'test1')
load("""
add table inet nvyr_filter
add flowtable inet nvyr_filter flowtable_FAST { hook ingress priority 0; devices = { test0, test1 }; }
add chain inet nvyr_filter ipv4_forward
add rule inet nvyr_filter ipv4_forward meta l4proto tcp flow add @flowtable_FAST comment "10|offload"
""")
result = listing('ruleset')
no_unsupported(result)
assert set(result['flowtables']['flowtable_FAST']['interface']) == {'test0', 'test1'}
rule = result['chains']['ipv4_forward']['rules'][0]
assert rule['action'] == 'offload' and rule['offload-target'] == 'FAST'
''')


def test_live_learned_entries_and_ttl_boundaries():
    isolated(COMMON + '''
run('ip', 'link', 'set', 'lo', 'up')
load("""
add table inet nvyr_filter
add set inet nvyr_filter ipv4_address_group_LEARNED { type ipv4_addr; flags dynamic,timeout; timeout 10m; gc-interval 30s; size 100; counter; last; }
add chain inet nvyr_filter output { type filter hook output priority 0; policy accept; }
add rule inet nvyr_filter output ip saddr 127.0.0.1 update @ipv4_address_group_LEARNED { ip saddr } comment "1|learn"
add rule inet nvyr_filter output icmp type echo-request ip ttl > 10 ip ttl < 100 counter last accept comment "2|bounded TTL"
""")

for ttl in ('10', '11', '99', '100'):
    run('ping', '-4', '-c', '1', '-W', '1', '-t', ttl, '127.0.0.1')

data = listing('ruleset')
no_unsupported(data)
entry = data['sets']['ipv4_address_group_LEARNED']['entries'][0]
assert entry['key'] == ['127.0.0.1']
assert 'name' not in entry and 'description' not in entry
assert entry['counter']['packets'] == 8
assert entry['last-used'] is not None and entry['last-used'] >= 0
assert 0 < entry['expires'] <= 600

rule = data['chains']['output']['rules'][1]
assert rule['ttl'] == {'gt': 10, 'lt': 100}
assert rule['counter']['packets'] == 2
assert rule['last-used'] is not None
''')
