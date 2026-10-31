"""Native packet tests for identical flag semantics and one-time side effects."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_rules_sets_maps_all_flag_values_and_packet_lengths(family):
    isolated(f"family = {family!r}\n" + '''
import socket
import struct
from nvyr.helpers.nftables_normalizer import normalize
from tests.test_tcp_flags import group_definition

run('ip', 'link', 'set', 'lo', 'up')
address = '127.0.0.1' if family == 'ipv4' else '::1'
af = socket.AF_INET if family == 'ipv4' else socket.AF_INET6
base_length = 40 if family == 'ipv4' else 60
rule = {'protocol': ['tcp'], 'tcp-flags': ['syn,not ack,not rst', 'rst'],
        'counter': {}, 'last-used': True, 'action': 'continue'}
tree = {'firewall': {
    'group': {
        'map': {family: {'M': group_definition('map')}},
        'match-group': {family: {'S': group_definition('match-group')}},
    },
    family: {'output': {'filter': {'default-action': 'drop', 'rule': {
        '10': rule,
        '20': {'match-group': 'S', 'counter': {}, 'action': 'continue'},
        '30': {'map': 'M'},
        '40': {'packet-length': [str(base_length), '80-100'],
               'not': {'packet-length': ['90']}, 'counter': {}, 'action': 'continue'},
    }}}},
}}
apply(tree)

def listing():
    document = json.loads(run('nft', '-j', 'list', 'ruleset'))
    return normalize(document, configuration=tree)['tables']['inet']['nvyr_filter']

def count(table, number):
    return next(rule['counter']['packets'] for rule in table['chains'][family + '_output']['rules']
                if rule.get('number') == number)

def send(flags, payload=0, port=8080):
    packet = struct.pack('!HHIIBBHHH', 12345, port, 1, 0, 80, flags, 1024, 0, 0) + bytes(payload)
    with socket.socket(af, socket.SOCK_RAW, socket.IPPROTO_TCP) as sender:
        if family == 'ipv6':
            sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_CHECKSUM, 16)
        try:
            sender.sendto(packet, (address, 0))
        except PermissionError:
            pass  # The final output rule deliberately drops the test packets.

expected_total = 0
for flags in range(256):
    # SYN without ACK/RST, or any RST. Unmentioned bits must not matter.
    expected = bool(flags & 4) or (bool(flags & 2) and not flags & 16)
    before = listing()
    send(flags)
    after = listing()
    assert count(after, '10') - count(before, '10') == int(expected), flags
    assert count(after, '20') - count(before, '20') == int(expected), flags
    assert count(after, '40') - count(before, '40') == 1
    expected_total += int(expected)

    # Expanded map keys count the same packet only once and display one row per entry.
    mapping = after['maps'][family + '_map_M']
    assert all('unsupported' not in entry for entry in mapping['entries']), mapping
    assert len(mapping['entries']) == 2, mapping
    assert sum(entry['counter']['packets'] for entry in mapping['entries']) == expected_total

table = listing()
group = table['sets'][family + '_match_group_S']
assert len(group['entries']) == 2
assert sum(entry['counter']['packets'] for entry in group['entries']) == expected_total
assert all(entry['last-used'] is not None for entry in group['entries'])
assert all('unsupported' not in entry for entry in table['chains'][family + '_output']['rules']), table

# Other concatenated fields remain part of the lookup after expanding flags.
before = listing()
send(2, port=9999)
after = listing()
assert count(after, '10') == count(before, '10') + 1
assert count(after, '20') == count(before, '20')

# Packet length measures the IP header plus transport/payload, with exclusions.
for length in (79, 80, 90, 100, 101):
    before = listing()
    send(0, payload=length - base_length)
    after = listing()
    assert count(after, '40') - count(before, '40') == int(length in (80, 100)), length

# Overlapping rule alternatives still evaluate counters and verdicts once.
rule['tcp-flags'] = ['syn', 'rst']
apply(tree)
before = listing()
send(6)
after = listing()
assert count(after, '10') - count(before, '10') == 1

# A no-op preserves the objects, while removing one alternative changes matching.
apply(tree)
assert count(listing(), '10') == count(after, '10')
rule['tcp-flags'].remove('syn')
apply(tree)
before = listing()
send(2)
assert count(listing(), '10') == count(before, '10')
send(4)
assert count(listing(), '10') == count(before, '10') + 1
''')


def test_dynamic_group_learns_complete_flag_values():
    isolated('''
import socket
import struct
from nvyr.helpers.nftables_normalizer import normalize

run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {
    'group': {'match-group': {'ipv4': {'LEARNED': {
        'match': {'protocol': True, 'tcp-flags': True},
        'dynamic': {'size': '256', 'timeout': '10m'},
    }}}},
    'ipv4': {'output': {'filter': {'default-action': 'drop', 'rule': {
        '10': {'add-to-group': {'match-group': 'LEARNED'}, 'action': 'continue'},
        '20': {'match-group': 'LEARNED', 'counter': {}, 'action': 'continue'},
    }}}},
}}
apply(tree)

# Different flag bytes must become distinct learned keys, even without entries.
for flags in (2, 18, 4):
    packet = struct.pack('!HHIIBBHHH', 12345, 8080, 1, 0, 80, flags, 1024, 0, 0)
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as sender:
        try:
            sender.sendto(packet, ('127.0.0.1', 0))
        except PermissionError:
            pass  # Drop the test packets before delivery to the local TCP stack.

document = json.loads(run('nft', '-j', 'list', 'ruleset'))
table = normalize(document, configuration=tree)['tables']['inet']['nvyr_filter']
entries = table['sets']['ipv4_match_group_LEARNED']['entries']
assert len(entries) == 3, entries
assert all('unsupported' not in entry for entry in entries), entries
rule = next(rule for rule in table['chains']['ipv4_output']['rules'] if rule.get('number') == '20')
assert rule['counter']['packets'] == 3, rule
''')
