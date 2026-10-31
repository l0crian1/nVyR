"""Opt-in VRF ingress and link-group packet tests in an isolated network namespace."""

from tests.test_nftables_live import isolated, pytestmark


PACKET_TEST = '''
from tests.test_firewall_maps import rendered
from nvyr.helpers.nftables_normalizer import normalize
import struct, time

run('ip', 'link', 'add', 'BLUE', 'type', 'vrf', 'table', '100')
run('ip', 'link', 'set', 'BLUE', 'up', 'group', '22')
run('ip', 'link', 'add', 'eth98', 'type', 'veth', 'peer', 'name', 'peer98')
run('ip', 'link', 'set', 'eth98', 'master', 'BLUE')
run('ip', 'link', 'set', 'eth98', 'up', 'group', '11')
run('ip', 'link', 'set', 'peer98', 'up')
run('ip', 'address', 'add', '192.0.2.1/24', 'dev', 'eth98')
run('ip', '-6', 'address', 'add', '2001:db8::1/64', 'dev', 'eth98', 'nodad')

config = {'vrf': {'name': {'BLUE': {'table': '100'}}},
          'interfaces': {'ethernet': {'eth98': {'vrf': 'BLUE', 'link-group': '11'}}},
          'firewall': {'group': {'interface-group': {'MEMBERS': {'vrf': True, 'interface': ['eth98']}}},
          family: {'input': {'filter': {'rule': {
              '10': {'inbound-interface': ['eth98'], 'protocol': ['udp'], 'counter': {}, 'action': 'continue'},
              '20': {'inbound-interface-group': 'MEMBERS', 'protocol': ['udp'], 'counter': {}, 'action': 'continue'},
              '30': {'inbound-link-group': ['22'], 'protocol': ['udp'], 'counter': {}, 'action': 'continue'},
              '40': {'inbound-link-group': ['11'], 'protocol': ['udp'], 'counter': {}, 'action': 'continue'},
              '50': {'not': {'inbound-interface': ['eth98']}, 'protocol': ['udp'], 'counter': {}, 'action': 'continue'},
          }}}, 'prerouting': {'raw': {'rule': {
              '10': {'inbound-interface': ['eth98'], 'inbound-link-group': ['11'], 'protocol': ['udp'], 'counter': {}, 'action': 'continue'},
          }}}}}}
Manager().apply(rendered(config), directory)

# Inject a real ingress UDP frame, bypassing same-namespace local routing shortcuts.
def checksum(data):
    if len(data) % 2:
        data += b'\\x00'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

destination_mac = bytes.fromhex(json.loads(run('ip', '-j', 'link', 'show', 'eth98'))[0]['address'].replace(':', ''))
source_mac = bytes.fromhex(json.loads(run('ip', '-j', 'link', 'show', 'peer98'))[0]['address'].replace(':', ''))
payload = b'nvyr-vrf-test'
udp = struct.pack('!HHHH', 53097, 53098, 8 + len(payload), 0) + payload
if family == 'ipv4':
    source = socket.inet_aton('192.0.2.2')
    destination = socket.inet_aton('192.0.2.1')
    header = struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(udp), 1, 0, 64, 17, 0, source, destination)
    header = header[:10] + struct.pack('!H', checksum(header)) + header[12:]
    frame = destination_mac + source_mac + b'\\x08\\x00' + header + udp
else:
    source = socket.inet_pton(socket.AF_INET6, '2001:db8::2')
    destination = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
    pseudo = source + destination + struct.pack('!I3xB', len(udp), 17)
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp)) + udp[8:]
    header = struct.pack('!IHBB16s16s', 6 << 28, len(udp), 17, 64, source, destination)
    frame = destination_mac + source_mac + b'\\x86\\xdd' + header + udp
with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sender:
    sender.bind(('peer98', 0))
    sender.send(frame)

def counts(chain):
    result = {}
    for item in snapshot():
        rule = item.get('rule', {})
        if rule.get('chain') == chain:
            result[rule['comment'].split('|')[0]] = next(
                expression['counter']['packets'] for expression in rule['expr'] if 'counter' in expression)
    return result

deadline = time.monotonic() + 3
while counts(family + '_input')['10'] == 0 and time.monotonic() < deadline:
    time.sleep(.02)
assert counts(family + '_input')['10'] == 1, snapshot()
assert counts(family + '_input')['20'] == 1
assert counts(family + '_input')['30'] == 1  # INPUT sees the VRF master's group.
assert counts(family + '_input')['40'] == 0
assert counts(family + '_input')['50'] == 0
assert counts(family + '_prerouting')['10'] >= 1
normalized = normalize({'nftables': snapshot()})
assert 'sdifname' not in json.dumps(normalized)  # Presented as inbound-interface.
'''


def test_ipv4_real_vrf_slave_matching_and_link_group_hook_semantics():
    isolated("family = 'ipv4'\n" + PACKET_TEST)


def test_ipv6_real_vrf_slave_matching_and_link_group_hook_semantics():
    isolated("family = 'ipv6'\n" + PACKET_TEST)


def test_native_link_group_maps_sets_and_per_key_limits():
    isolated('''
config = {'group': {
    'map': {'ipv4': {'LINKS': {'match': {'inbound-link-group': True, 'outbound-link-group': True},
        'result-type': 'verdict', 'entry': {'one': {'inbound-link-group': '11', 'outbound-link-group': '22',
        'result': {'action': 'continue'}}}}}},
    'match-group': {'ipv6': {'LINKS': {'match': {'inbound-link-group': True},
        'entry': {'one': {'inbound-link-group': '11'}}}}}},
    'ipv4': {'forward': {'filter': {'rule': {'10': {'map': 'LINKS'},
        '20': {'action': 'accept', 'limit': {'rate': {'packets': '10/s'}, 'per': 'inbound-link-group,outbound-link-group'}}}}}},
    'ipv6': {'input': {'filter': {'rule': {'10': {'action': 'accept', 'match-group': 'LINKS'}}}}}}
apply(config)
text = run('nft', 'list', 'ruleset')
assert 'iifgroup . oifgroup vmap @ipv4_map_LINKS' in text, text
assert 'iifgroup @ipv6_match_group_LINKS' in text
assert 'iifgroup . oifgroup limit rate' in text, text
''')
