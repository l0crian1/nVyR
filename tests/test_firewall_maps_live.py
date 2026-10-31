"""Exercise named maps against nftables in isolated disposable namespaces."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')

COMMON = '''
import json, subprocess, tempfile
from copy import deepcopy
from pathlib import Path
from nvyr.config_scripts import firewall
from nvyr.errors import RouterError
from nvyr.helpers.nftables import Manager
from tests.lifecycle import firewall_context
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree

schema = Schema.bundled()
directory = Path(tempfile.mkdtemp())
previous = {}

def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True).stdout

def apply(tree, recovery=False):
    global previous
    schema.validate_configuration(tree)
    effective = ReadOnlyTree(schema.defaults(tree))
    before = ReadOnlyTree(schema.defaults(previous))
    context = firewall_context(effective, before, 'firewall', ('firewall',), recovery,
                            previous_effective=before)
    firewall.verify(effective, context)
    text = firewall.generate(effective, context)
    Manager().apply(text, directory)
    previous = deepcopy(tree)
    return text
'''


def isolated(script):
    assert Path('/.dockerenv').exists() and os.geteuid() == 0
    result = subprocess.run(['unshare', '-n', sys.executable, '-c', COMMON + script],
                            text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stdout + result.stderr


def test_verdict_maps_packets_global_tracking_replacement_and_recovery():
    isolated('''
run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {'global-options': {'counter': True, 'last-used': True}, 'group': {'map': {}}}}
for family, address in [('ipv4', '127.0.0.1'), ('ipv6', '::1')]:
    tree['firewall']['group']['map'][family] = {'LOCAL': {
        'match': {'destination-address': True}, 'result-type': 'verdict', 'description': 'Local policy',
        'entry': {'local': {'destination-address': address, 'description': 'Local traffic',
                            'result': {'action': 'jump', 'jump-target': 'TARGET'}}}}}
    tree['firewall'][family] = {'name': {'TARGET': {'default-action': 'drop'}},
        'output': {'filter': {'rule': {'10': {'map': 'LOCAL'}}}}}
apply(tree)
for version, address in [('-4', '127.0.0.1'), ('-6', '::1')]:
    assert subprocess.run(['ping', version, '-c', '1', '-W', '1', address], capture_output=True).returncode != 0
listing = run('nft', 'list', 'maps', 'inet')
assert 'local|Local traffic' in listing
assert 'comment \"Local policy\"' in listing
assert 'counter packets 1' in listing and 'last used' in listing, listing
assert set(Manager().maps()) == {('ipv4', 'LOCAL'), ('ipv6', 'LOCAL')}
for family in ('ipv4', 'ipv6'):
    tree['firewall'][family]['name']['TARGET']['default-action'] = 'accept'
apply(tree)
run('ping', '-4', '-c', '1', '-W', '1', '127.0.0.1')
run('ping', '-6', '-c', '1', '-W', '1', '::1')
# A cyclic jump through a map must fail atomically, preserving the live rules.
before = run('nft', '-s', 'list', 'ruleset')
bad = deepcopy(tree)
bad['firewall']['ipv4']['name']['TARGET']['rule'] = {'10': {'map': 'LOCAL'}}
try:
    apply(bad)
    raise AssertionError('Map jump cycle accepted')
except RouterError:
    pass
assert run('nft', '-s', 'list', 'ruleset') == before
# Recovery discovers orphaned maps even without an old configuration snapshot.
previous = {}
apply({}, recovery=True)
assert Manager().maps() == [] and Manager().named_chains() == []
''')


def test_map_datatypes_intervals_and_nat_result_types():
    isolated('''
fields = {
    'state': 'established', 'connection-status': 'snat,dnat', 'packet-type': 'host',
    'inbound-interface': 'eth0', 'outbound-interface': 'eth1',
    'source-mac': '00:11:22:33:44:55', 'destination-mac': '00:11:22:33:44:66',
    'source-address': '192.0.2.0/24', 'destination-address': '203.0.113.1-203.0.113.10',
    'packet-mark': '1-10', 'connection-mark': '20-30', 'dscp': '10-20', 'protocol': 'tcp',
}
maps = {}
for index, (field, value) in enumerate(fields.items()):
    matches = {field: True}
    values = {field: value}
    if field in ('state', 'connection-status', 'connection-mark'):
        key = field.removeprefix('connection-')
        matches = {'connection': {key: True}}
        values = {'connection': {key: value}}
    maps['FIELD' + str(index)] = {'match': matches, 'result-type': 'verdict',
        'entry': {'A': {**values, 'result': {'action': 'continue'}}}}
# Typed transport concatenations and every supported NAT result shape.
for kind, result in [('address', {'address': '10.0.0.10'}),
                     ('port', {'port': '8080'}),
                     ('address-port', {'address': '10.0.0.10', 'port': '8080'})]:
    maps['NAT'] = {'match': {'inbound-interface': True, 'protocol': True, 'destination-port': True},
        'result-type': kind, 'entry': {'WEB': {'inbound-interface': 'eth0',
            'protocol': 'tcp', 'destination-port': '440-450', 'result': result}}}
    tree = {'firewall': {'group': {'map': {'ipv4': maps}},
                         'global-options': {'counter': True, 'last-used': True}},
            'nat': {'destination': {'rule': {'10': {'map': 'NAT'}}}}}
    apply(tree)
    apply(tree)
    text = run('nft', '-s', 'list', 'ruleset')
    assert 'map @ipv4_map_NAT' in text
# Removing consumers and their maps together must leave no references behind.
apply({})
assert Manager().maps() == []
''')


def test_icmp_rules_maps_and_independent_matches_with_real_packets():
    isolated('''
run('ip', 'link', 'set', 'lo', 'up')
for family, version, address in [('ipv4', '-4', '127.0.0.1'), ('ipv6', '-6', '::1')]:
    def ping():
        return subprocess.run(['ping', version, '-c', '1', '-W', '1', address],
                              capture_output=True).returncode

    # Type and code match the actual echo packet, with unrelated matches retained.
    protocol = 'icmp' if family == 'ipv4' else 'ipv6-icmp'
    rule = {'action': 'drop', 'protocol': [protocol], 'icmp-type': ['echo-request'], 'icmp-code': ['0'],
            'outbound-interface': ['lo']}
    tree = {'firewall': {family: {'output': {'filter': {'rule': {'10': rule}}}}}}
    apply(tree)
    assert ping() != 0
    rule['icmp-code'] = ['1']
    apply(tree)
    assert ping() == 0

    # Native type lists and numeric code lists also load independently.
    rule.pop('icmp-code')
    rule['icmp-type'] = ['echo-request', 'echo-reply']
    apply(tree)
    assert ping() != 0
    rule.pop('icmp-type')
    rule['icmp-code'] = ['0', '255']
    apply(tree)
    assert ping() != 0

    # A map supplies protocol/type/code; the consuming rule still filters its interface.
    mapping = {'match': {'protocol': True, 'icmp-type': True, 'icmp-code': True}, 'result-type': 'verdict',
               'entry': {'ECHO': {'protocol': protocol, 'icmp-type': 'echo-request', 'icmp-code': '0',
                                  'result': {'action': 'drop'}}}}
    tree['firewall']['group'] = {'map': {family: {'M': mapping}}}
    rule.clear()
    rule.update({'map': 'M', 'outbound-interface': ['lo'], 'counter': {}})
    apply(tree)
    assert ping() != 0
    rule['outbound-interface'] = ['other0']
    apply(tree)
    assert ping() == 0

    # Every accepted symbolic type must be understood by the installed nftables.
    from nvyr.helpers.validators import ICMP_TYPES
    mapping['match'] = {'protocol': True, 'icmp-type': True}
    for type_name in ICMP_TYPES[family]:
        mapping['entry'] = {'A': {'protocol': protocol, 'icmp-type': type_name, 'result': {'action': 'continue'}}}
        apply(tree)
apply({})
''')


def test_transport_rule_matches_can_use_protocol_from_map():
    isolated('''
mapping = {'match': {'protocol': True}, 'result-type': 'verdict',
           'entry': {'TCP': {'protocol': 'tcp', 'result': {'action': 'accept'}}}}
tree = {'firewall': {'group': {'map': {'ipv4': {'M': mapping}}},
                    'ipv4': {'forward': {'filter': {'rule': {'10': {
                        'map': 'M', 'destination-port': ['443'], 'outbound-interface': ['eth0']}}}}}}}
apply(tree)
listing = run('nft', '-s', 'list', 'ruleset')
assert 'dport 443' in listing and 'vmap @ipv4_map_M' in listing
''')
