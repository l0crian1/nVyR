"""Native setters and packet effects in disposable network namespaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def test_native_setters_every_supported_hook_and_family():
    isolated(r'''
from nvyr.helpers.nftables_normalizer import normalize

tree = {'firewall': {}}
for family in ('ipv4', 'ipv6', 'inet'):
    branches = tree['firewall'][family] = {}
    for hook, stage in [('input', 'filter'), ('forward', 'filter'), ('output', 'filter'),
                        ('output', 'raw'), ('prerouting', 'raw')]:
        options = {'packet-mark': '0xffffffff', 'tcp-mss': '1360'}
        if stage == 'filter':
            options['connection-mark'] = '0x20'
        if hook in {'forward', 'output'}:
            options['tcp-mss'] = 'clamp-to-pmtu'
        if family != 'inet':
            options.update(dscp='af41', ttl='63')
        branches.setdefault(hook, {})[stage] = {'rule': {'10': {
            'protocol': ['tcp'], 'tcp-flags': ['syn'], 'modify': options, 'action': 'continue',
        }}}
apply(tree)
document = json.loads(run('nft', '-j', 'list', 'ruleset'))
table = normalize(document)['tables']['inet']['nvyr_filter']
modified = []
for chain in table['chains'].values():
    for rule in chain.get('rules', []):
        assert 'unsupported' not in rule, rule
        if 'modify' in rule:
            modified.append(rule)
assert len(modified) == 15, modified
assert sum(rule['modify'].get('tcp-mss') == 'clamp-to-pmtu' for rule in modified) == 9, modified

previous_tree = deepcopy(tree)
tree['firewall']['ipv4']['output']['filter']['rule']['10']['modify']['ttl'] = '62'
apply(tree)
apply(previous_tree)
apply({})
''')


def test_udp_packet_headers_marks_and_ecn_ipv4():
    isolated(r'''
import socket
import struct

run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {'ipv4': {'output': {'filter': {'rule': {
    '10': {'protocol': ['udp'], 'destination-port': ['5300'], 'modify': {
        'packet-mark': '32', 'connection-mark': '64', 'dscp': 'ef', 'ttl': '42',
    }, 'action': 'continue'},
    '20': {'protocol': ['udp'], 'destination-port': ['5300'], 'packet-mark': ['32'],
           'connection': {'mark': ['64']}, 'counter': {}, 'action': 'accept'},
}, 'default-action': 'drop'}}}}}
apply(tree)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
    receiver.bind(('127.0.0.1', 5300))
    receiver.settimeout(2)
    receiver.setsockopt(socket.IPPROTO_IP, socket.IP_RECVTOS, 1)
    receiver.setsockopt(socket.IPPROTO_IP, 12, 1)  # Linux IP_RECVTTL, not exposed by every Python build.
    sender.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, 3)
    sender.sendto(b'modified', ('127.0.0.1', 5300))
    payload, ancillary, flags, address = receiver.recvmsg(128, 128)
    assert payload == b'modified'
    metadata = {kind: data for level, kind, data in ancillary if level == socket.IPPROTO_IP}
    assert metadata[socket.IP_TOS][0] == 187, metadata  # EF with the original ECN bits.
    assert struct.unpack('i', metadata[socket.IP_TTL])[0] == 42, metadata
listing = run('nft', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_output')
assert 'counter packets 1' in listing, listing
assert 'mark=64' in run('conntrack', '-L', '-f', 'ipv4', '-p', 'udp', '--dport', '5300')
''')


def test_udp_packet_headers_marks_and_ecn_ipv6():
    isolated(r'''
import socket
import struct

run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {'ipv6': {'output': {'filter': {'rule': {
    '10': {'protocol': ['udp'], 'destination-port': ['5300'], 'modify': {
        'packet-mark': '32', 'connection-mark': '64', 'dscp': 'ef', 'ttl': '42',
    }, 'action': 'continue'},
    '20': {'protocol': ['udp'], 'destination-port': ['5300'], 'packet-mark': ['32'],
           'connection': {'mark': ['64']}, 'counter': {}, 'action': 'accept'},
}, 'default-action': 'drop'}}}}}
apply(tree)
with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sender:
    receiver.bind(('::1', 5300))
    receiver.settimeout(2)
    receiver.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVTCLASS, 1)
    receiver.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_RECVHOPLIMIT, 1)
    sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_TCLASS, 3)
    sender.sendto(b'modified', ('::1', 5300))
    payload, ancillary, flags, address = receiver.recvmsg(128, 128)
    assert payload == b'modified'
    metadata = {kind: struct.unpack('i', data)[0] for level, kind, data in ancillary if level == socket.IPPROTO_IPV6}
    assert metadata[socket.IPV6_TCLASS] == 187, metadata
    assert metadata[socket.IPV6_HOPLIMIT] == 42, metadata
listing = run('nft', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv6_output')
assert 'counter packets 1' in listing, listing
assert 'mark=64' in run('conntrack', '-L', '-f', 'ipv6', '-p', 'udp', '--dport', '5300')
''')


def test_tcp_mss_fixed_and_route_clamp_preserve_smaller_advertisements():
    isolated(r'''
import socket

run('ip', 'link', 'set', 'lo', 'up')
run('ip', 'link', 'set', 'lo', 'mtu', '1500')
for family, address, native in [(socket.AF_INET, '127.0.0.1', 'ipv4'), (socket.AF_INET6, '::1', 'ipv6')]:
    for value, ceiling in [('1200', 1200), ('clamp-to-pmtu', 1460 if native == 'ipv4' else 1440)]:
        tree = {'firewall': {native: {'output': {'filter': {'rule': {'10': {
            'protocol': ['tcp'], 'tcp-flags': ['syn'],
            'modify': {'tcp-mss': value}, 'action': 'continue',
        }}}}}}}
        apply(tree)
        for advertised in (1000, 1400):
            with socket.socket(family, socket.SOCK_STREAM) as server, socket.socket(family, socket.SOCK_STREAM) as client:
                server.bind((address, 0))
                server.listen(1)
                client.settimeout(2)
                client.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, advertised)
                client.connect(server.getsockname())
                accepted, peer = server.accept()
                with accepted:
                    client.sendall(b'MSS and checksum test')
                    assert accepted.recv(128) == b'MSS and checksum test'
                    mss = accepted.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
                    assert 0 < mss <= min(advertised, ceiling), (value, advertised, mss)
''')


FORWARDED_PACKETS = r'''
import socket
import struct

run('ip', 'link', 'add', 'left', 'type', 'veth', 'peer', 'name', 'sender')
run('ip', 'link', 'add', 'right', 'type', 'veth', 'peer', 'name', 'receiver')
for interface in ('left', 'sender', 'right', 'receiver'):
    run('ip', 'link', 'set', interface, 'up')
run('ip', 'link', 'set', 'right', 'mtu', '1280')
version = 4 if family == 'ipv4' else 6
source = '192.0.2.2' if version == 4 else '2001:db8:1::2'
target = '198.51.100.2' if version == 4 else '2001:db8:2::2'
left = '192.0.2.1/24' if version == 4 else '2001:db8:1::1/64'
right = '198.51.100.1/24' if version == 4 else '2001:db8:2::1/64'
run('ip', 'address', 'add', left, 'dev', 'left', *([] if version == 4 else ['nodad']))
run('ip', 'address', 'add', right, 'dev', 'right', *([] if version == 4 else ['nodad']))
run('sysctl', '-qw', 'net.ipv4.ip_forward=1' if version == 4 else 'net.ipv6.conf.all.forwarding=1')
# AF_PACKET sees the frame first; stop its capture peer reentering the router stack.
run('nft', 'add', 'table', 'inet', 'capture_guard')
run('nft', 'add', 'chain', 'inet', 'capture_guard', 'receive',
    '{ type filter hook prerouting priority -310; policy accept; }')
run('nft', 'add', 'rule', 'inet', 'capture_guard', 'receive', 'iifname "receiver" drop')
links = {item['ifname']: item['address'] for item in json.loads(run('ip', '-j', 'link'))}
run('ip', 'neigh', 'replace', target, 'lladdr', links['receiver'], 'nud', 'permanent', 'dev', 'right')

def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

af = socket.AF_INET if version == 4 else socket.AF_INET6
saddr = socket.inet_pton(af, source)
daddr = socket.inet_pton(af, target)
ethertype = 0x0800 if version == 4 else 0x86dd
ethernet = bytes.fromhex(links['left'].replace(':', '') + links['sender'].replace(':', '')) + struct.pack('!H', ethertype)

def pseudo(length):
    if version == 4:
        return saddr + daddr + struct.pack('!BBH', 0, 6, length)
    return saddr + daddr + struct.pack('!I3xB', length, 6)

def matched_packets():
    listing = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'nvyr_filter', family + '_forward'))
    rule = next(item['rule'] for item in listing['nftables'] if item.get('rule', {}).get('comment') == '20|')
    return next(statement['counter']['packets'] for statement in rule['expr'] if 'counter' in statement)

with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ethertype)) as capture, socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sender:
    capture.bind(('receiver', 0))
    capture.settimeout(3)
    sender.bind(('sender', 0))
    for index, (setting, advertised, flags) in enumerate([
        ('1100', 1460, 2), ('clamp-to-pmtu', 1460, 2),
        ('clamp-to-pmtu', 900, 2), ('1100', None, 2),
    ]):
        tree = {'firewall': {family: {
            'prerouting': {'raw': {'rule': {'10': {
                'protocol': ['tcp'], 'destination-port': ['5300'], 'tcp-flags': ['syn'],
                'modify': {'packet-mark': '3', 'ttl': '61', 'tcp-mss': '1400'}, 'action': 'continue',
            }}}},
            'forward': {'filter': {'default-action': 'drop', 'rule': {
                '10': {'protocol': ['tcp'], 'destination-port': ['5300'], 'tcp-flags': ['syn'],
                       'packet-mark': ['3'], 'ttl': {'eq': '60'}, 'modify': {
                           'packet-mark': '4', 'connection-mark': '5', 'dscp': 'ef', 'ttl': '42', 'tcp-mss': setting,
                       }, 'action': 'continue'},
                '20': {'packet-mark': ['4'], 'connection': {'mark': ['5']}, 'counter': {}, 'action': 'accept'},
            }}},
        }}}
        apply(tree)
        before = matched_packets()
        options = b'' if advertised is None else struct.pack('!BBH', 2, 4, advertised)
        tcp = struct.pack('!HHIIBBHHH', 20000 + index, 5300, 1, 0, (5 + len(options)//4) << 4, flags, 8192, 0, 0) + options
        tcp = tcp[:16] + struct.pack('!H', checksum(pseudo(len(tcp)) + tcp)) + tcp[18:]
        if version == 4:
            header = struct.pack('!BBHHHBBH4s4s', 0x45, 3, 20+len(tcp), index, 0, 64, 6, 0, saddr, daddr)
            header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
        else:
            header = struct.pack('!IHBB16s16s', (6 << 28) | (3 << 20), len(tcp), 6, 64, saddr, daddr)
        sender.send(ethernet + header + tcp)
        while True:
            try:
                packet = capture.recv(2048)[14:]
            except TimeoutError:
                raise AssertionError((index, run('nft', 'list', 'ruleset'))) from None
            if version == 4 and packet[12:20] == saddr + daddr:
                break
            if version == 6 and packet[8:40] == saddr + daddr:
                break
        if version == 4:
            assert packet[1] == 187 and packet[8] == 42, packet.hex()
            assert checksum(packet[:20]) == 0, packet.hex()
            received_tcp = packet[20:]
        else:
            assert (int.from_bytes(packet[:4], 'big') >> 20) & 255 == 187, packet.hex()
            assert packet[7] == 42, packet.hex()
            received_tcp = packet[40:]
        assert checksum(pseudo(len(received_tcp)) + received_tcp) == 0, received_tcp.hex()
        if advertised is None:
            assert received_tcp[12] >> 4 == 5, received_tcp.hex()
        else:
            expected = min(advertised, 1400, 1100 if setting == '1100' else (1240 if version == 4 else 1220))
            assert int.from_bytes(received_tcp[22:24], 'big') == expected, (expected, received_tcp.hex())
        assert matched_packets() == before + 1, (index, before, matched_packets(), run('nft', 'list', 'ruleset'))
'''


def test_forwarded_packet_modifications_ipv4():
    isolated("family = 'ipv4'\n" + FORWARDED_PACKETS)


def test_forwarded_packet_modifications_ipv6():
    isolated("family = 'ipv6'\n" + FORWARDED_PACKETS)
