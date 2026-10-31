"""Packet-level ICMP group checks in disposable network namespaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def test_type_code_ranges_negation_tracking_and_recovery():
    """Use raw loopback packets to distinguish paired ICMP codes from cross products.

    Rule and element counters verify matching independently of textual output.
    Reconfiguration also checks negation, type-only sets and recovery cleanup.
    """
    isolated('''
import socket
import struct
from nvyr.helpers.nftables_normalizer import normalize

run('ip', 'link', 'set', 'lo', 'up')
for family, af, protocol_number, type_number, address in [
    ('ipv4', socket.AF_INET, socket.IPPROTO_ICMP, 3, '127.0.0.1'),
    ('ipv6', socket.AF_INET6, socket.IPPROTO_ICMPV6, 1, '::1'),
]:
    protocol = 'icmp' if family == 'ipv4' else 'ipv6-icmp'
    definition = {'match': 'type-code', 'type': {
        'destination-unreachable': {'code': ['0-2']}, 'time-exceeded': {'code': ['1']}}}
    rule = {'icmp-group': 'G', 'protocol': [protocol], 'action': 'drop', 'counter': {}}
    tree = {'firewall': {'global-options': {'counter': True, 'last-used': True},
        'group': {'icmp-group': {family: {'G': definition}}},
        family: {'output': {'filter': {'rule': {'10': rule}}}}}}
    apply(tree)

    def packets():
        listing = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'nvyr_filter', family + '_output'))
        for item in listing['nftables']:
            native_rule = item.get('rule', {})
            if native_rule.get('comment') == '10|':
                return next(statement['counter']['packets'] for statement in native_rule['expr'] if 'counter' in statement)
        raise AssertionError('Missing test rule')

    def send(code, packet_type=type_number):
        message = struct.pack('!BBHI', packet_type, code, 0, 0) + bytes(32)
        if family == 'ipv4':
            checksum = sum(struct.unpack('!20H', message))
            checksum = (checksum & 65535) + (checksum >> 16)
            checksum = (checksum & 65535) + (checksum >> 16)
            message = message[:2] + struct.pack('!H', (~checksum) & 65535) + message[4:]
        with socket.socket(af, socket.SOCK_RAW, protocol_number) as sender:
            try:
                sender.sendto(message, (address, 0))
            except PermissionError:
                pass  # The output drop is the behavior under test.

    # Every value inside the interval matches, and the adjacent value does not.
    for code in (0, 1, 2, 3):
        before = packets()
        send(code)
        assert packets() - before == (1 if code <= 2 else 0), (family, code)

    # Codes stay paired with their own type rather than forming a cross product.
    time_exceeded = 11 if family == 'ipv4' else 3
    before = packets()
    send(0, time_exceeded)
    assert packets() == before
    send(1, time_exceeded)
    assert packets() == before + 1

    document = json.loads(run('nft', '-j', 'list', 'ruleset'))
    table = normalize(document, configuration=tree)['tables']['inet']['nvyr_filter']
    group = table['sets'][family + '_icmp_group_G']
    assert group['match-fields'] == ['icmp-type', 'icmp-code'], group
    assert group['counter'] and group['last-used'], group
    assert all('unsupported' not in entry for entry in group['entries']), group
    assert sorted(entry['counter']['packets'] for entry in group['entries']) == [1, 3], group
    assert all('unsupported' not in entry for entry in table['chains'][family + '_output']['rules']), table

    # A no-op commit preserves the installed objects and their statistics.
    before = packets()
    apply(tree)
    assert packets() == before

    # Separate codes create separate elements, leaving intervening codes unmatched.
    definition['type']['destination-unreachable']['code'] = ['0', '3']
    apply(tree)
    for code in (0, 1, 2, 3):
        before = packets()
        send(code)
        assert packets() - before == (1 if code in (0, 3) else 0), (family, code)

    # Deleting one alternative leaves the other installed and independently counted.
    definition['type']['destination-unreachable']['code'].remove('0')
    apply(tree)
    for code in (0, 3):
        before = packets()
        send(code)
        assert packets() - before == (1 if code == 3 else 0), (family, code)

    definition['type']['destination-unreachable']['code'] = ['0-2']
    apply(tree)

    # Negative membership reverses the pair test while retaining the protocol guard.
    rule['not'] = {'icmp-group': rule.pop('icmp-group')}
    apply(tree)
    for code in (0, 1, 2, 3):
        before = packets()
        send(code)
        assert packets() - before == (0 if code <= 2 else 1), (family, code)

    # A type-only replacement changes the set datatype and rebuilds its consumer.
    definition['match'] = 'type'
    for options in definition['type'].values():
        options.clear()
    rule['icmp-group'] = rule.pop('not')['icmp-group']
    apply(tree)
    before = packets()
    send(3)
    assert packets() == before + 1

    # Unpublished owned objects are discovered and removed during recovery.
    previous = {}
    apply({}, recovery=True)
    assert Manager().icmp_groups() == []
''')
