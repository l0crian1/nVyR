"""Learn real packet keys and observe timeout refresh in disposable namespaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def test_packet_learning_refresh_expiry_and_tracking():
    isolated(r'''
import time
run('ip', 'link', 'set', 'lo', 'up')
for family, version, address in [('ipv4', '-4', '127.0.0.1'), ('ipv6', '-6', '::1')]:
    groups = {'address-group': {family: {'G': {'dynamic': {'timeout': '2s', 'gc-interval': '1s'}}}}}
    rule = {'action': 'accept', 'add-to-group': {'source-address': 'G'}}
    tree = {'firewall': {'group': groups, 'global-options': {'counter': True, 'last-used': True},
                        family: {'output': {'filter': {'rule': {'10': rule}}}}}}
    apply(tree)

    def ping():
        run('ping', version, '-c', '1', '-W', '1', address)

    def listing():
        return run('nft', 'list', 'set', 'inet', 'nvyr_filter', family + '_address_group_G')

    # Both request and reply refresh the same exact source-address element.
    ping()
    first = listing()
    assert address in first and 'counter packets 2' in first and 'last used' in first, first
    time.sleep(1.2)
    ping()
    time.sleep(1.2)
    current = listing()
    assert address in current and 'counter packets 4' in current, current

    # It expires after the final refresh, without any configuration commit.
    deadline = time.monotonic() + 4
    while 'elements =' in listing() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert 'elements =' not in listing(), listing()

    # The rule can override the default lifetime without changing the set default.
    rule['add-to-group']['timeout'] = '1s'
    groups['address-group'][family]['G']['dynamic']['timeout'] = '1h'
    apply(tree)
    ping()
    assert address in listing()
    deadline = time.monotonic() + 3
    while 'elements =' in listing() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert 'elements =' not in listing(), listing()
apply({})
''')


def test_concatenated_updates_capacity_and_atomic_failure():
    isolated(r'''
import socket
run('ip', 'link', 'set', 'lo', 'up')
for family, af, address in [('ipv4', socket.AF_INET, '127.0.0.1'), ('ipv6', socket.AF_INET6, '::1')]:
    definition = {'dynamic': {'size': '1'}, 'counter': True, 'last-used': True,
                  'match': {'source-address': True, 'protocol': True, 'destination-port': True}}
    rule = {'action': 'continue', 'add-to-group': {'match-group': 'G'}}
    tree = {'firewall': {'group': {'match-group': {family: {'G': definition}}},
                        family: {'output': {'filter': {'rule': {'10': rule}}}}}}
    apply(tree)
    sender = socket.socket(af, socket.SOCK_DGRAM)
    try:
        sender.sendto(b'first', (address, 53001))
        sender.sendto(b'refresh', (address, 53001))
        sender.sendto(b'full', (address, 53002))
    finally:
        sender.close()
    listing = run('nft', 'list', 'set', 'inet', 'nvyr_filter', family + '_match_group_G')
    assert '53001' in listing and '53002' not in listing, listing
    assert 'counter packets 2' in listing and 'last used' in listing, listing

    # A rejected transaction must preserve learned entries as well as rules.
    before = run('nft', '-s', 'list', 'ruleset')
    try:
        Manager().apply('flush table inet nvyr_filter\ninvalid statement\n', directory)
        raise AssertionError('Invalid transaction succeeded')
    except RouterError:
        pass
    assert run('nft', '-s', 'list', 'ruleset') == before

    # Unchanged groups preserve learned members; changing their definition rebuilds them.
    apply(tree)
    assert '53001' in run('nft', 'list', 'set', 'inet', 'nvyr_filter', family + '_match_group_G')
    definition['description'] = 'Rebuild this group'
    apply(tree)
    assert 'elements =' not in run('nft', 'list', 'set', 'inet', 'nvyr_filter', family + '_match_group_G')
previous = {}
apply({}, recovery=True)
assert Manager().match_groups() == []
''')


def test_native_duration_limits_and_preconfigured_members():
    isolated(r'''
definition = {'dynamic': {'timeout': '18446744073s', 'gc-interval': '4294967s'},
              'address': ['192.0.2.1']}
tree = {'firewall': {'group': {'address-group': {'ipv4': {'G': definition}}}}}
apply(tree)
listing = run('nft', 'list', 'set', 'inet', 'nvyr_filter', 'ipv4_address_group_G')
assert '213503d23h34m33s' in listing and '49d17h2m47s' in listing, listing
assert '192.0.2.1' in listing, listing
apply({})
''')


def test_every_declared_dynamic_key_loads_on_the_kernel():
    isolated(r'''
from nvyr.helpers.nftables_formatters import NFT_KEYMAP
for family in ('ipv4', 'ipv6'):
    groups = {}
    rules = {}
    for field, metadata in NFT_KEYMAP.items():
        if not metadata.dynamic:
            continue
        fields = {}
        node = fields
        path = metadata.path or (field,)
        for component in path[:-1]:
            node = node.setdefault(component, {})
        node[path[-1]] = True

        rule = {'action': 'continue', 'add-to-group': {'match-group': field}}
        if field in {'icmp-type', 'icmp-code', 'tcp-flags', 'source-port', 'destination-port'}:
            fields['protocol'] = True
        if metadata.path and field.endswith('-port'):
            fields['connection']['protocol'] = True
        groups[field] = {'dynamic': {}, 'match': fields}
        rules[str(len(rules) + 1)] = rule
    tree = {'firewall': {'global-options': {'connection-accounting': True},
                        'group': {'match-group': {family: groups}},
                        family: {'output': {'filter': {'rule': rules}}}}}
    apply(tree)
    assert len(Manager().match_groups()) == len(groups)
apply({})
''')


def test_protocol_guards_learn_tcp_udp_and_icmp_without_rule_protocols():
    isolated(r'''
import socket
run('ip', 'link', 'set', 'lo', 'up')
for family, af, address, version in [('ipv4', socket.AF_INET, '127.0.0.1', '-4'),
                                     ('ipv6', socket.AF_INET6, '::1', '-6')]:
    groups = {
        'PORTS': {'dynamic': {}, 'match': {'source-address': True, 'destination-address': True,
                                          'protocol': True, 'destination-port': True}},
        'ICMP': {'dynamic': {}, 'match': {'protocol': True, 'icmp-type': True, 'icmp-code': True}},
    }
    rules = {
        '10': {'action': 'continue', 'add-to-group': {'match-group': 'PORTS'}},
        '20': {'action': 'continue', 'add-to-group': {'match-group': 'ICMP'}},
    }
    tree = {'firewall': {'group': {'match-group': {family: groups}},
                         family: {'input': {'filter': {'rule': rules}}}}}
    apply(tree)

    # Both transport protocols are learned; the generated guard excludes ICMP.
    with socket.socket(af, socket.SOCK_DGRAM) as receiver, socket.socket(af, socket.SOCK_DGRAM) as sender:
        receiver.bind((address, 53001))
        receiver.settimeout(2)
        sender.sendto(b'udp', (address, 53001))
        assert receiver.recv(16) == b'udp'
    with socket.socket(af, socket.SOCK_STREAM) as listener, socket.socket(af, socket.SOCK_STREAM) as sender:
        listener.bind((address, 53003))
        listener.listen(1)
        sender.settimeout(2)
        sender.connect((address, 53003))
        connection, _ = listener.accept()
        connection.close()
    run('ping', version, '-c', '1', '-W', '1', address)

    ports = run('nft', 'list', 'set', 'inet', 'nvyr_filter', family + '_match_group_PORTS')
    assert '. udp . 53001' in ports and '. tcp . 53003' in ports, ports
    assert 'icmp' not in ports, ports
    icmp = run('nft', 'list', 'set', 'inet', 'nvyr_filter', family + '_match_group_ICMP')
    assert 'echo-request' in icmp and 'echo-reply' in icmp, icmp
apply({})
''')
