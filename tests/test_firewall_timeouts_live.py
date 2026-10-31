"""Native timeout assignment and object replacement in disposable network namespaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def test_timeout_objects_all_families_lifecycle_and_normalization():
    """TCP/UDP policies, inet selection and recovery use real nftables transactions."""
    isolated(r'''
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.helpers.nftables_timeouts import native_names

tree = {'firewall': {'group': {'timeout-group': {}}}}
for family in ('ipv4', 'ipv6', 'inet'):
    tree['firewall']['group']['timeout-group'][family] = {
        'UDP': {'protocol': 'udp', 'timeout': {'unreplied': '10s', 'replied': '30s'}},
        'TCP': {'protocol': 'tcp', 'timeout': {'established': '1d'}},
    }
    tree['firewall'][family] = {'output': {'filter': {'rule': {
        '10': {'protocol': ['udp'], 'connection': {'timeout-group': 'UDP'}, 'action': 'continue'},
        '20': {'protocol': ['tcp'], 'connection': {'timeout-group': 'TCP'}, 'action': 'continue'},
    }}}}
apply(tree)
owned = [name for kind, name in Manager().named_state() if kind == 'ct timeout']
assert len(owned) == 8, owned

table = normalize(json.loads(run('nft', '-j', 'list', 'ruleset')))['tables']['inet']['nvyr_filter']
assert len(table['ct timeouts']) == 8, table
for chain in table['chains'].values():
    for rule in chain.get('rules', []):
        assert 'unsupported' not in rule, rule

tree['firewall']['group']['timeout-group']['inet']['UDP']['timeout']['replied'] = '40s'
text = apply(tree)
assert 'destroy ct timeout inet nvyr_filter inet_timeout_group_UDP_ip6' in text, text
record = json.loads(run('nft', '-j', 'list', 'table', 'inet', 'nvyr_filter'))
assert next(item['ct timeout'] for item in record['nftables'] if item.get('ct timeout', {}).get('name') == 'inet_timeout_group_UDP_ip')['policy']['replied'] == 40, record

# Recovery discovers policies even if the previous effective configuration is lost.
previous = {}
apply({}, recovery=True)
assert not [name for kind, name in Manager().named_state() if kind == 'ct timeout']
''')


def test_inet_udp_packet_timeouts_ipv4_and_ipv6():
    """A single inet rule assigns both UDP states for both IP families."""
    isolated(r'''
import socket
import time

run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {'group': {'timeout-group': {'inet': {'DNS': {
    'protocol': 'udp', 'timeout': {'unreplied': '10s', 'replied': '30s'},
}}}}, 'inet': {'output': {'filter': {'rule': {'10': {
    'protocol': ['udp'], 'destination-port': ['5300'], 'action': 'accept',
    'connection': {'timeout-group': 'DNS'},
}}}}}}}
apply(tree)

for family, native, address in [(socket.AF_INET, 'ipv4', '127.0.0.1'), (socket.AF_INET6, 'ipv6', '::1')]:
    with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
        receiver.bind((address, 5300))
        receiver.settimeout(2)
        sender.settimeout(2)
        sender.sendto(b'first', (address, 5300))
        data, peer = receiver.recvfrom(128)
        listing = run('conntrack', '-L', '-f', native, '-p', 'udp', '--dport', '5300')
        assert '[UNREPLIED]' in listing, listing
        assert 8 <= int(listing.split()[2]) <= 10, listing

        receiver.sendto(data, peer)
        sender.recvfrom(128)
        # UDP stream timeout applies after its native reply/stream qualification.
        time.sleep(3)
        sender.sendto(b'second', (address, 5300))
        data, peer = receiver.recvfrom(128)
        receiver.sendto(data, peer)
        sender.recvfrom(128)
        listing = run('conntrack', '-L', '-f', native, '-p', 'udp', '--dport', '5300')
        assert 28 <= int(listing.split()[2]) <= 30, listing
''')


def test_tcp_policy_is_retained_after_established_fast_accept():
    """Only the opening packet needs assignment, ahead of later state-policy accepts."""
    isolated(r'''
import socket

run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {
    'global-options': {'state-policy': {'established': {'action': 'accept'}}},
    'group': {'timeout-group': {'inet': {'APP': {
        'protocol': 'tcp', 'timeout': {'established': '90s'},
    }}}},
    'inet': {'output': {'filter': {'rule': {'10': {
        'protocol': ['tcp'], 'destination-port': ['5301'], 'action': 'accept',
        'connection': {'timeout-group': 'APP'},
    }}}}},
}}
apply(tree)
for family, native, address in [(socket.AF_INET, 'ipv4', '127.0.0.1'), (socket.AF_INET6, 'ipv6', '::1')]:
    with socket.socket(family, socket.SOCK_STREAM) as listener, socket.socket(family, socket.SOCK_STREAM) as sender:
        listener.bind((address, 5301))
        listener.listen(1)
        sender.connect((address, 5301))
        receiver, _ = listener.accept()
        with receiver:
            sender.sendall(b'test')
            assert receiver.recv(4) == b'test'
            receiver.sendall(b'test')
            assert sender.recv(4) == b'test'
            listing = run('conntrack', '-L', '-f', native, '-p', 'tcp', '--dport', '5301')
            assert 'ESTABLISHED' in listing, listing
            assert 88 <= int(listing.split()[2]) <= 90, listing

            # Replacing the native object detaches its policy from existing flows.
            tree['firewall']['group']['timeout-group']['inet']['APP']['timeout']['established'] = '120s'
            apply(tree)
            sender.sendall(b'next')
            assert receiver.recv(4) == b'next'
            receiver.sendall(b'next')
            assert sender.recv(4) == b'next'
            listing = run('conntrack', '-L', '-f', native, '-p', 'tcp', '--dport', '5301')
            default = int(run('sysctl', '-n', 'net.netfilter.nf_conntrack_tcp_timeout_established'))
            assert default - 2 <= int(listing.split()[2]) <= default, listing

            # Restore the initial policy before exercising the other address family.
            tree['firewall']['group']['timeout-group']['inet']['APP']['timeout']['established'] = '90s'
            apply(tree)
''')
