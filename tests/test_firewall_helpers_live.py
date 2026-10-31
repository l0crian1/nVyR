"""Real helper object maps and packet assignment in disposable network namespaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def test_helper_objects_replacement_recovery_and_display():
    """All objects load; removal releases references and operational output stays complete."""
    isolated(r'''
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.op_scripts import firewall as display

tree = {'firewall': {'global-options': {'connection-tracking': {'helper': {
    'ftp': True, 'tftp': True, 'sip': True,
}}}, 'ipv4': {'name': {'UNCHANGED': {'default-action': 'drop'}}}}}
apply(tree)
document = json.loads(run('nft', '-j', 'list', 'ruleset'))
table = normalize(document)['tables']['inet']['nvyr_filter']
assert len(table['ct helpers']) == 4, table
assert 'unsupported' not in table['maps']['conntrack_helpers'], table['maps']
assert len(table['maps']['conntrack_helpers']['entries']) == 4, table['maps']
for hook in ('input', 'forward', 'output'):
    rule = next(rule for rule in table['chains'][hook]['rules'] if rule.get('number') == 'global-helpers')
    assert 'unsupported' not in rule, rule
    assert rule['helper-map'] == 'conntrack_helpers', rule
    assert display._action(rule) == 'assign helpers'
old_handle = table['chains']['ipv4_name_UNCHANGED']['handle']

del tree['firewall']['global-options']['connection-tracking']['helper']['sip']
apply(tree)
table = normalize(json.loads(run('nft', '-j', 'list', 'ruleset')))['tables']['inet']['nvyr_filter']
assert len(table['ct helpers']) == 2, table
assert table['chains']['ipv4_name_UNCHANGED']['handle'] == old_handle

previous = {}
apply({}, recovery=True)
listing = run('nft', 'list', 'ruleset')
assert 'conntrack_helper' not in listing, listing
''')


PACKETS = r"""
import socket, sys
from nvyr.helpers import conntrack as tracking

run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {'global-options': {'connection-tracking': {'helper': {
    'ftp': True, 'tftp': True, 'sip': True,
}}}}}
apply(tree)
# Isolate the hook under test so another assignment point cannot conceal a failure.
for other in ('input', 'forward', 'output'):
    if other != hook:
        run('nft', 'flush', 'chain', 'inet', 'nvyr_filter', other)

children = []
def peer(name, local, remote):
    process = subprocess.Popen(['unshare', '-n', sys.executable, '-u', '-c',
                                'import time; print("ready", flush=True); time.sleep(40)'],
                               stdout=subprocess.PIPE, text=True)
    children.append(process)
    # Wait for namespace creation instead of assuming a fixed startup delay.
    assert process.stdout.readline().strip() == 'ready'
    run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', name + 'p')
    run('ip', 'link', 'set', name + 'p', 'netns', str(process.pid))
    run('ip', 'addr', 'add', local + prefix, 'dev', name, *(['nodad'] if family == 'ipv6' else []))
    run('ip', 'link', 'set', name, 'up')
    command = ['nsenter', '-t', str(process.pid), '-n']
    run(*command, 'ip', 'link', 'set', 'lo', 'up')
    run(*command, 'ip', 'addr', 'add', remote + prefix, 'dev', name + 'p', *(['nodad'] if family == 'ipv6' else []))
    run(*command, 'ip', 'link', 'set', name + 'p', 'up')
    return command

version = '-6' if family == 'ipv6' else '-4'
prefix = '/64' if family == 'ipv6' else '/24'
local, client_ip, gateway, server_ip = (('2001:db8:1::1', '2001:db8:1::2', '2001:db8:2::1', '2001:db8:2::2')
    if family == 'ipv6' else ('192.0.2.1', '192.0.2.2', '198.51.100.1', '198.51.100.2'))
try:
    client = peer('client', local, client_ip)
    if hook == 'forward':
        server = peer('server', gateway, server_ip)
        run(*client, 'ip', version, 'route', 'add', 'default', 'via', local)
        run(*server, 'ip', version, 'route', 'add', 'default', 'via', gateway)
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
        Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')
        destination, sender = server_ip, client
    elif hook == 'input':
        server, destination, sender = [], local, client
    else:
        server, destination, sender = client, client_ip, []

    # A native post-assignment counter proves hits and misses continue through the hook.
    run('nft', 'add', 'rule', 'inet', 'nvyr_filter', hook, 'counter', 'comment', '"after-helper"')
    for protocol, port, helper in [('tcp', 21, 'ftp'), ('udp', 69, 'tftp'),
                                   ('tcp', 5060, 'sip'), ('udp', 5060, 'sip'), ('udp', 5300, None)]:
        listener_code = '''import socket, sys
sock = socket.socket(socket.AF_INET6 if sys.argv[1] == 'ipv6' else socket.AF_INET,
                     socket.SOCK_STREAM if sys.argv[2] == 'tcp' else socket.SOCK_DGRAM)
sock.bind((sys.argv[3], int(sys.argv[4])))
if sys.argv[2] == 'tcp': sock.listen()
print('ready', flush=True)
if sys.argv[2] == 'tcp':
    connection, _ = sock.accept()
    connection.recv(20)
else: sock.recvfrom(20)
'''
        listener = subprocess.Popen([*server, sys.executable, '-u', '-c', listener_code,
                                     family, protocol, destination, str(port)], stdout=subprocess.PIPE, text=True)
        children.append(listener)
        assert listener.stdout.readline().strip() == 'ready'
        send_code = '''import socket, sys
sock = socket.socket(socket.AF_INET6 if sys.argv[1] == 'ipv6' else socket.AF_INET,
                     socket.SOCK_STREAM if sys.argv[2] == 'tcp' else socket.SOCK_DGRAM)
sock.settimeout(3)
sock.connect((sys.argv[3], int(sys.argv[4])))
sock.send(b'hello')
'''
        run(*sender, sys.executable, '-c', send_code, family, protocol, destination, str(port))
        assert listener.wait(timeout=5) == 0
        listing = run('conntrack', '-L', '-f', family, '-p', protocol, '--dport', str(port))
        assert (f'helper={helper}' in listing) if helper else ('helper=' not in listing), listing
        records = [record for record in tracking.read(family=family, protocol=protocol)
                   if record['original'].get('destination-port') == port]
        assert records and all(record.get('helper') == helper for record in records), records

    listing = run('nft', 'list', 'chain', 'inet', 'nvyr_filter', hook)
    assert 'counter packets 0 bytes 0 comment "after-helper"' not in listing, listing
finally:
    for process in reversed(children):
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
"""


def test_input_helper_assignment_ipv4():
    """IPv4 local services receive the configured helper at INPUT."""
    isolated("family, hook = 'ipv4', 'input'\n" + PACKETS)


def test_input_helper_assignment_ipv6():
    """IPv6 local services receive the same helpers through the shared map."""
    isolated("family, hook = 'ipv6', 'input'\n" + PACKETS)


def test_output_helper_assignment_ipv4():
    """Locally originated IPv4 service connections receive helpers at OUTPUT."""
    isolated("family, hook = 'ipv4', 'output'\n" + PACKETS)


def test_output_helper_assignment_ipv6():
    """Locally originated IPv6 service connections receive helpers at OUTPUT."""
    isolated("family, hook = 'ipv6', 'output'\n" + PACKETS)


def test_forward_helper_assignment_ipv4():
    """Routed IPv4 service connections receive helpers before family dispatch."""
    isolated("family, hook = 'ipv4', 'forward'\n" + PACKETS)


def test_forward_helper_assignment_ipv6():
    """Routed IPv6 service connections receive helpers before family dispatch."""
    isolated("family, hook = 'ipv6', 'forward'\n" + PACKETS)


def test_tftp_related_connection_through_source_nat():
    """A translated control request creates an expectation for the server's data port."""
    isolated(r'''
import sys

children = []
def endpoint(name, router_address, peer_address):
    process = subprocess.Popen(['unshare', '-n', sys.executable, '-u', '-c',
        'import time; print("ready", flush=True); time.sleep(30)'], stdout=subprocess.PIPE, text=True)
    children.append(process)
    assert process.stdout.readline().strip() == 'ready'
    run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', name + 'p')
    run('ip', 'link', 'set', name + 'p', 'netns', str(process.pid))
    run('ip', 'addr', 'add', router_address + '/24', 'dev', name)
    run('ip', 'link', 'set', name, 'up')
    command = ['nsenter', '-t', str(process.pid), '-n']
    run(*command, 'ip', 'addr', 'add', peer_address + '/24', 'dev', name + 'p')
    run(*command, 'ip', 'link', 'set', name + 'p', 'up')
    run(*command, 'ip', 'route', 'add', 'default', 'via', router_address)
    return command

try:
    client = endpoint('client', '192.0.2.1', '192.0.2.2')
    server = endpoint('server', '198.51.100.1', '198.51.100.2')
    Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    tree = {'firewall': {
        'global-options': {'connection-tracking': {'helper': {'tftp': True}},
                           'state-policy': {'related': {'action': 'accept'}, 'established': {'action': 'accept'}}},
        'ipv4': {'forward': {'filter': {'default-action': 'drop', 'rule': {
            '10': {'inbound-interface': ['client'], 'protocol': ['udp'],
                   'destination-port': ['69'], 'action': 'accept'},
        }}}},
    }, 'nat': {'source': {'rule': {'10': {'outbound-interface': ['server'],
                                         'translation': {'address': 'masquerade'}}}}}}
    apply(tree)
    # Package softdeps load this with nf_conntrack_tftp; source-only tests load it explicitly.
    run('modprobe', 'nf_nat_tftp')
    server_code = '\n'.join([
        'import socket',
        'listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)',
        'listener.bind(("198.51.100.2", 69))',
        'print("ready", flush=True)',
        'request, address = listener.recvfrom(512)',
        'assert address[0] == "198.51.100.1", address',
        'data = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)',
        'data.bind(("198.51.100.2", 40000))',
        'data.sendto(b"payload", address)',
    ])
    listener = subprocess.Popen([*server, sys.executable, '-u', '-c', server_code],
                                stdout=subprocess.PIPE, text=True)
    children.append(listener)
    assert listener.stdout.readline().strip() == 'ready'
    client_code = '\n'.join([
        'import socket',
        'client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)',
        'client.settimeout(3)',
        'client.sendto(b"\\x00\\x01test\\x00octet\\x00", ("198.51.100.2", 69))',
        'payload, address = client.recvfrom(512)',
        'assert payload == b"payload" and address == ("198.51.100.2", 40000), (payload, address)',
    ])
    run(*client, sys.executable, '-c', client_code)
    assert listener.wait(timeout=5) == 0
    listing = run('conntrack', '-L', '-p', 'udp')
    assert 'helper=tftp' in listing and 'sport=40000' in listing, listing
finally:
    for process in reversed(children):
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
''')


def test_helper_assignment_does_not_accept_dropped_traffic():
    """A helper-map hit must still reach the following user drop rule."""
    isolated(r'''
import socket

run('ip', 'link', 'set', 'lo', 'up')
apply({'firewall': {
    'global-options': {'connection-tracking': {'helper': {'tftp': True}}},
    'inet': {'output': {'filter': {'rule': {'10': {
        'protocol': ['udp'], 'destination-port': ['69'], 'action': 'drop', 'counter': {},
    }}}}},
}})
listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
listener.bind(('127.0.0.1', 69))
listener.settimeout(0.2)
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sender.sendto(b'blocked', ('127.0.0.1', 69))
except PermissionError:
    # OUTPUT drops can report EPERM directly to the sending application.
    pass
try:
    listener.recvfrom(100)
    raise AssertionError('Helper assignment bypassed drop')
except TimeoutError:
    pass
listing = run('nft', 'list', 'chain', 'inet', 'nvyr_filter', 'output')
assert 'counter packets 1 bytes' in listing, listing
''')
