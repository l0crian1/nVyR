"""Singleton set packet matching and lifecycle on the real isolated kernel."""

import os

import pytest

from tests.test_firewall_maps_live import isolated

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def test_address_and_interface_sets_constrain_packets_with_maps_and_match_groups():
    isolated('''
import re
run('ip', 'link', 'set', 'lo', 'up')
for family, version, address, network in [('ipv4', '-4', '127.0.0.1', '127.0.0.0/8'),
                                           ('ipv6', '-6', '::1', '::/127')]:
    protocol = 'icmp' if family == 'ipv4' else 'ipv6-icmp'
    groups = {
        'interface-group': {'G': {'interface': ['lo'], 'description': 'Local interface'}},
        'address-group': {family: {'G': {'address': [network, address, address + '-' + address]}}},
        'map': {family: {'M': {'match': {'icmp-type': True, 'protocol': True}, 'result-type': 'verdict',
                              'entry': {'ECHO': {'icmp-type': 'echo-request', 'protocol': protocol,
                                                 'result': {'action': 'drop'}}}}}},
        'match-group': {family: {'G': {'match': {'source-address': True},
                                     'entry': {'LOCAL': {'source-address': address}}}}},
    }
    rule = {'outbound-interface-group': 'G', 'destination-address-group': 'G', 'map': 'M', 'match-group': 'G'}
    tree = {'firewall': {'group': groups, 'global-options': {'counter': True, 'last-used': True}, family: {'output': {'filter': {'rule': {'10': rule}}}}}}

    def ping():
        return subprocess.run(['ping', version, '-c', '1', '-W', '1', address], capture_output=True).returncode

    # Overlapping prefixes and exact addresses represent one membership union.
    apply(tree)
    tracked = ['interface_group_G', family + '_address_group_G']
    def packets(name):
        listing = run('nft', 'list', 'set', 'inet', 'nvyr_filter', name)
        return int(re.search(r'counter packets ([0-9]+)', listing).group(1))
    before_packets = {name: packets(name) for name in tracked}
    assert ping() != 0
    for name in tracked:
        listing = run('nft', 'list', 'set', 'inet', 'nvyr_filter', name)
        assert packets(name) == before_packets[name] + 1 and 'last used' in listing, listing
    assert 'flags interval' in run('nft', 'list', 'set', 'inet', 'nvyr_filter', family + '_address_group_G')
    assert 'Local interface' in run('nft', 'list', 'set', 'inet', 'nvyr_filter', 'interface_group_G')

    # Empty sets stay valid and do not match any packets.
    del groups['interface-group']['G']['interface']
    apply(tree)
    assert ping() == 0
    groups['interface-group']['G']['interface'] = ['lo']
    del groups['address-group'][family]['G']['address']
    apply(tree)
    assert ping() == 0

# Recovery removes owned sets even if the previous config was not published.
previous = {}
apply({}, recovery=True)
assert Manager().singleton_groups() == []
''')


def test_port_sets_match_udp_and_mac_sets_load_in_both_families():
    isolated('''
import socket
run('ip', 'link', 'set', 'lo', 'up')
groups = {'port-group': {'G': {'port': ['53000', '53000-53002', '53001'], 'counter': True, 'last-used': True}},
          'mac-group': {'G': {'address': ['02:00:00:00:00:01'], 'counter': True, 'last-used': True}}}
tree = {'firewall': {'group': groups}}
for family, address, af in [('ipv4', '127.0.0.1', socket.AF_INET), ('ipv6', '::1', socket.AF_INET6)]:
    tree['firewall'][family] = {'output': {'filter': {'rule': {
        '10': {'destination-port-group': 'G', 'protocol': ['udp'], 'action': 'drop'},
        '20': {'source-mac-group': 'G', 'destination-mac-group': 'G', 'action': 'accept'},
    }}}}
    apply(tree)
    receiver = socket.socket(af, socket.SOCK_DGRAM)
    sender = socket.socket(af, socket.SOCK_DGRAM)
    receiver.settimeout(0.1)
    try:
        receiver.bind((address, 53001))
        # A matching destination port is dropped immediately by the local output rule.
        try:
            sender.sendto(b'blocked', (address, 53001))
        except PermissionError:
            pass
        try:
            receiver.recvfrom(128)
            raise AssertionError('Port group did not drop the datagram')
        except TimeoutError:
            pass

        listing = run('nft', 'list', 'set', 'inet', 'nvyr_filter', 'port_group_G')
        assert 'counter packets 1' in listing and 'last used' in listing, listing

        # Updating the membership removes the match without changing the rule.
        groups['port-group']['G']['port'] = ['53000']
        apply(tree)
        sender.sendto(b'allowed', (address, 53001))
        assert receiver.recvfrom(128)[0] == b'allowed'
        groups['port-group']['G']['port'] = ['53000-53002']
    finally:
        receiver.close()
        sender.close()
apply({})
assert Manager().singleton_groups() == []
''')


def test_singleton_commit_confirm_recovery_and_atomic_failure():
    isolated('''
from nvyr.controller import Controller
from nvyr.engine import Engine
from nvyr.storage import Store
from tests.lifecycle import LifecycleStub, RecordingModule

modules = {owner: LifecycleStub() for owner in schema.owners}
modules['firewall'] = RecordingModule(firewall)
now = [100.0]
engine = Engine(schema, modules, Store(directory), clock=lambda: now[0])
session = engine.open('test', 'namespace')
controller = Controller(engine)

def execute(command):
    return controller.execute(command, session)

def members():
    return run('nft', '-s', 'list', 'set', 'inet', 'nvyr_filter', 'ipv4_address_group_G')

execute('set firewall group address-group ipv4 G address 192.0.2.1')
execute('set firewall ipv4 forward filter rule 10 source-address-group G action accept')
assert engine.commit(session)['results']['firewall']['success']
execute('delete firewall group address-group ipv4 G address 192.0.2.1')
execute('set firewall group address-group ipv4 G address 192.0.2.2')
assert engine.commit(session, minutes=1, confirmed_minutes=1)['results']['firewall']['success']
assert '192.0.2.2' in members()
now[0] = 161
engine.tick()
assert '192.0.2.1' in members() and '192.0.2.2' not in members()

# A failed replacement preserves all installed groups and consumers.
before = run('nft', '-s', 'list', 'ruleset')
execute('set firewall group address-group ipv4 G address 192.0.2.3')
execute('set firewall ipv4 name LOOP rule 1 action jump jump-target LOOP')
execute('set firewall ipv4 forward filter rule 10 action jump jump-target LOOP')
result = engine.commit(session)
assert not result['results']['firewall']['success'], result
assert run('nft', '-s', 'list', 'ruleset') == before
engine.discard(session)

engine.save(session)
run('nft', 'flush', 'ruleset')
engine = Engine(schema, modules, Store(directory), clock=lambda: now[0])
assert '192.0.2.1' in members()
session = engine.open('test', 'namespace')
controller = Controller(engine)
execute('delete firewall')
assert engine.commit(session)['results']['firewall']['success']
assert Manager().singleton_groups() == []
''')
