"""Opt-in zone dispatch tests using real nftables in disposable network namespaces."""

from tests.test_nftables_live import isolated, pytestmark


PACKET_TEST = r'''
import struct
import time
from tests.test_firewall_maps import rendered
from nvyr.helpers.nftables_normalizer import normalize

# Keep automatic IPv6 control traffic out of the exact UDP packet counters.
# Packet injection below does not need neighbor discovery, and VRF output uses
# a permanent neighbor entry before testing the member-interface pass.
run('nft', 'add', 'table', 'inet', 'zone_test_background')
run('nft', 'add', 'chain', 'inet', 'zone_test_background', 'output',
    '{ type filter hook output priority -10; policy accept; }')
run('nft', 'add', 'rule', 'inet', 'zone_test_background', 'output', 'meta l4proto != udp drop')

run('ip', 'link', 'set', 'lo', 'up')
run('ip', 'link', 'add', 'eth98', 'type', 'veth', 'peer', 'name', 'peer98')
run('ip', 'link', 'set', 'eth98', 'up')
run('ip', 'link', 'set', 'peer98', 'up')
run('ip', 'address', 'add', '192.0.2.1/24', 'dev', 'eth98')
run('ip', '-6', 'address', 'add', '2001:db8::1/64', 'dev', 'eth98', 'nodad')
run('ip', 'link', 'add', 'eth99', 'type', 'dummy')
run('ip', 'link', 'set', 'eth99', 'up')
run('ip', 'address', 'add', '198.51.100.1/24', 'dev', 'eth99')
run('ip', '-6', 'address', 'add', '2001:db8:1::1/64', 'dev', 'eth99', 'nodad')
run('sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1',
    'net.ipv4.conf.all.rp_filter=0', 'net.ipv4.conf.eth98.rp_filter=0')

config = {'firewall': {
    'zone': {'USERS': {'interface': ['eth98']}, 'WAN': {'interface': ['eth99']},
             'LOCAL': {'local-zone': True}},
    'zone-policy': {'from-zone': {
        'USERS': {'to-zone': {'LOCAL': {family + '-policy': 'IN'}, 'WAN': {family + '-policy': 'FWD'}}},
        'LOCAL': {'to-zone': {'USERS': {family + '-policy': 'OUT'}}}}},
    family: {'name': {name: {'default-action': 'drop', 'rule': {
        '10': {'protocol': ['udp'], 'destination-port': ['53098'], 'counter': {}, 'action': 'accept'}}}
        for name in ('IN', 'OUT', 'FWD')},
        'input': {'filter': {'default-action': 'drop'}},
        'output': {'filter': {'default-action': 'drop'}},
        'forward': {'filter': {'default-action': 'drop'}}}}}
manager = Manager()
manager.apply(rendered(config), directory)

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

destination_mac = bytes.fromhex(json.loads(run('ip', '-j', 'link', 'show', 'eth98'))[0]['address'].replace(':', ''))
source_mac = bytes.fromhex(json.loads(run('ip', '-j', 'link', 'show', 'peer98'))[0]['address'].replace(':', ''))

def send(destination, port=53098):
    payload = b'nvyr-zone-test'
    udp = struct.pack('!HHHH', 53097, port, 8 + len(payload), 0) + payload
    if family == 'ipv4':
        source = socket.inet_aton('192.0.2.2')
        target = socket.inet_aton(destination)
        header = struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(udp), 1, 0, 64, 17, 0, source, target)
        header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        frame = destination_mac + source_mac + b'\x08\x00' + header + udp
    else:
        source = socket.inet_pton(socket.AF_INET6, '2001:db8::2')
        target = socket.inet_pton(socket.AF_INET6, destination)
        pseudo = source + target + struct.pack('!I3xB', len(udp), 17)
        udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp)) + udp[8:]
        header = struct.pack('!IHBB16s16s', 6 << 28, len(udp), 17, 64, source, target)
        frame = destination_mac + source_mac + b'\x86\xdd' + header + udp
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sender:
        sender.bind(('peer98', 0))
        sender.send(frame)

def count(chain, number):
    for item in snapshot():
        rule = item.get('rule', {})
        if rule.get('chain') == chain and rule.get('comment', '').split('|')[0] == number:
            return next(part['counter']['packets'] for part in rule['expr'] if 'counter' in part)
    raise AssertionError((chain, number, snapshot()))

def received(chain, number, expected):
    deadline = time.monotonic() + 3
    while count(chain, number) < expected and time.monotonic() < deadline:
        time.sleep(.01)
    assert count(chain, number) == expected, snapshot()

def element_counter(hook, key):
    table = normalize({'nftables': snapshot()})['tables']['inet']['nvyr_filter']
    mapping = table['maps'][family + '_zone_' + hook]
    return next(entry['counter'] for entry in mapping['entries'] if entry['key'] == key)

local = '192.0.2.1' if family == 'ipv4' else '2001:db8::1'
remote = '198.51.100.2' if family == 'ipv4' else '2001:db8:1::2'
send(local)
received(family + '_name_IN', '10', 1)
send(remote)
received(family + '_name_FWD', '10', 1)
assert element_counter('forward', ['eth98', 'eth99'])['packets'] == 1
assert element_counter('forward', ['eth98', 'eth99'])['bytes'] > 0
assert element_counter('forward', ['eth99', 'eth98']) == {'packets': 0, 'bytes': 0}
assert element_counter('input', ['eth98'])['packets'] >= 1

# Local output is classified by the real outgoing interface.
with socket.socket(socket.AF_INET if family == 'ipv4' else socket.AF_INET6, socket.SOCK_DGRAM) as sender:
    sender.sendto(b'zone-output', ('192.0.2.2' if family == 'ipv4' else '2001:db8::2', 53098))
received(family + '_name_OUT', '10', 1)
assert element_counter('output', ['eth98'])['packets'] >= 1
assert element_counter('output', ['eth98'])['bytes'] > 0

# Ordinary hook rules override the zone policy, without editing the map.
changed = deepcopy(config)
changed['firewall'][family]['input']['filter']['rule'] = {
    '1': {'protocol': ['udp'], 'destination-port': ['53098'], 'counter': {}, 'action': 'drop'}}
mapping = run('nft', '-s', '-a', 'list', 'map', 'inet', 'nvyr_filter', family + '_zone_input')
forward_counter = element_counter('forward', ['eth98', 'eth99'])
manager.apply(rendered(changed, config), directory)
send(local)
received(family + '_input', '1', 1)
assert count(family + '_name_IN', '10') == 1
assert run('nft', '-s', '-a', 'list', 'map', 'inet', 'nvyr_filter', family + '_zone_input') == mapping
assert element_counter('forward', ['eth98', 'eth99']) == forward_counter
manager.apply(rendered(config, changed), directory)

# The same zone maps classify INPUT through a VRF member using sdifname.
run('ip', 'link', 'add', 'BLUE', 'type', 'vrf', 'table', '100')
run('ip', 'link', 'set', 'BLUE', 'up')
run('ip', 'link', 'set', 'eth98', 'master', 'BLUE')
# Enslaving resets IPv6 addresses on this kernel; restore the fixture address as netlinkd does.
run('ip', '-6', 'address', 'replace', '2001:db8::1/64', 'dev', 'eth98', 'nodad')
send(local)
received(family + '_name_IN', '10', 2)
assert run('nft', '-s', '-a', 'list', 'map', 'inet', 'nvyr_filter', family + '_zone_input') == mapping
assert element_counter('input', ['eth98'])['packets'] >= 2

# The VRF-device pass bypasses zone dispatch; the member pass enforces the policy.
def send_vrf(port=53098, *, expect_drop=False):
    with socket.socket(socket.AF_INET if family == 'ipv4' else socket.AF_INET6, socket.SOCK_DGRAM) as sender:
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'BLUE\x00')
        try:
            sender.sendto(b'zone-vrf-output', ('192.0.2.2' if family == 'ipv4' else '2001:db8::2', port))
        except PermissionError:
            # A local OUTPUT drop can be reported to sendto; counters below
            # must still prove which rule actually dropped the packet.
            if not expect_drop:
                raise

peer_address = '192.0.2.2' if family == 'ipv4' else '2001:db8::2'
peer_mac = ':'.join(f'{byte:02x}' for byte in source_mac)
run('ip', 'neighbor', 'replace', peer_address, 'lladdr', peer_mac, 'nud', 'permanent', 'dev', 'eth98')
before_default = count(family + '_output', 'default')
before_bypass = count(family + '_output', 'vrf-bypass')
send_vrf()
received(family + '_name_OUT', '10', 2)
assert count(family + '_output', 'vrf-bypass') == before_bypass + 1
assert count(family + '_output', 'default') == before_default

# A denied port still reaches the policy's drop verdict on the member pass.
before_drop = count(family + '_name_OUT', 'default')
send_vrf(port=53099, expect_drop=True)
received(family + '_name_OUT', 'default', before_drop + 1)
assert count(family + '_name_OUT', '10') == 2

# Explicit output rules must still take precedence over the generated bypass.
changed = deepcopy(config)
changed['firewall'][family]['output']['filter']['rule'] = {
    '1': {'protocol': ['udp'], 'destination-port': ['53098'], 'counter': {}, 'action': 'drop'}}
manager.apply(rendered(changed, config), directory)
send_vrf(expect_drop=True)
received(family + '_output', '1', 1)
assert count(family + '_output', 'vrf-bypass') == 0
assert count(family + '_name_OUT', '10') == 2
manager.apply(rendered(config, changed), directory)

# A member interface outside every zone must still hit the normal hook default.
changed = deepcopy(config)
changed['firewall']['zone']['USERS']['interface'] = ['peer98']
manager.apply(rendered(changed, config), directory)
before_default = count(family + '_output', 'default')
send_vrf(expect_drop=True)
received(family + '_output', 'default', before_default + 1)
assert count(family + '_name_OUT', '10') == 2
'''


def test_ipv4_zone_packet_dispatch_and_vrf_input_output():
    isolated("family = 'ipv4'\n" + PACKET_TEST)


def test_ipv6_zone_packet_dispatch_and_vrf_input_output():
    isolated("family = 'ipv6'\n" + PACKET_TEST)


def test_native_zone_comments_lifecycle_and_recovery():
    isolated('''
from tests.test_firewall_zones import configuration
from tests.test_firewall_maps import rendered
from nvyr.helpers.nftables_normalizer import normalize
from tests.lifecycle import firewall_context

config = configuration()
manager = Manager()
manager.apply(rendered(config), directory)
table = normalize({'nftables': snapshot()})['tables']['inet']['nvyr_filter']
assert not any(rule.get('unsupported') for chain in table['chains'].values() for rule in chain['rules'])
entries = table['maps']['ipv4_zone_forward']['entries']
assert any(entry['key'] == ['eth1', 'eth0'] and entry['comment'] == 'USERS to WAN' for entry in entries)
untouched = run('nft', '-a', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_output')

# A policy edit replaces its map and caller without resetting unrelated objects.
changed = deepcopy(config)
changed['firewall']['ipv4']['name']['WEB']['default-action'] = 'drop'
manager.apply(rendered(changed, config), directory)
assert run('nft', '-a', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_output') == untouched

# Membership changes release old map references in the same transaction.
changed['firewall']['zone']['USERS']['interface'].remove('eth2')
manager.apply(rendered(changed, config), directory)
assert 'eth2' not in run('nft', 'list', 'map', 'inet', 'nvyr_filter', 'ipv4_zone_forward')

# Restart with no previous snapshot must discover every fixed generated map.
schema = Schema.bundled()
effective = ReadOnlyTree(schema.defaults(changed))
context = firewall_context(effective, ReadOnlyTree({}), 'firewall', ('firewall',), True,
                           previous_effective=ReadOnlyTree({}))
from nvyr.helpers import nftables
nftables.manager = manager
manager.apply(firewall.generate(effective, context), directory)

# Removing zones restores the original hook configuration and removes all maps.
empty = deepcopy(changed)
del empty['firewall']['zone']
del empty['firewall']['zone-policy']
manager.apply(rendered(empty, changed), directory)
assert '_zone_' not in run('nft', 'list', 'ruleset')
assert '192.0.2.10' in run('nft', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_forward')
''')


def test_zone_engine_check_failed_commit_confirm_and_restart():
    isolated('''
from nvyr.controller import Controller
from nvyr.engine import Engine
from nvyr.helpers import nftables
from nvyr.storage import Store
from tests.lifecycle import LifecycleStub

nftables.manager = Manager()
schema = Schema.bundled()
modules = {name: LifecycleStub() for name in schema.owners}
modules['firewall'] = firewall
store = Store(directory / 'engine')
engine = Engine(schema, modules, store)
controller = Controller(engine)
session = engine.open('root', 'zone-test')

def command(text):
    return controller.execute(text, session)

command('set firewall zone USERS interface eth98')
command('set firewall zone WAN interface eth99')
command('set firewall zone LOCAL local-zone')
assert engine.commit(session)['results']['firewall']['success']
original = run('nft', '-s', 'list', 'ruleset')

# Check and rejected validation must not touch any installed object.
command('set firewall zone USERS intra-zone default-action drop')
assert engine.check(session)['results']['firewall']['success']
assert run('nft', '-s', 'list', 'ruleset') == original
command('set firewall zone WAN interface eth98')
result = engine.commit(session)
assert not result['results']['firewall']['success'], result
assert run('nft', '-s', 'list', 'ruleset') == original
engine.discard(session)

# Commit-confirm restores the original zone verdicts and generated dispatch.
command('set firewall zone USERS intra-zone default-action drop')
assert engine.commit(session, minutes=1, confirmed_minutes=1)['results']['firewall']['success']
assert 'USERS to USERS" : drop' in run('nft', 'list', 'map', 'inet', 'nvyr_filter', 'ipv4_zone_forward')
engine.clock = lambda: engine.pending['deadline'] + 1
engine.tick()
assert engine.pending is None
assert 'USERS to USERS" : accept' in run('nft', 'list', 'map', 'inet', 'nvyr_filter', 'ipv4_zone_forward')

# Recovery reconstructs all generated objects after loss of the native table.
run('nft', 'delete', 'table', 'inet', 'nvyr_filter')
restarted = Engine(schema, modules, store)
assert restarted.running == engine.running
assert 'eth98' in run('nft', 'list', 'map', 'inet', 'nvyr_filter', 'ipv6_zone_input')
''')
