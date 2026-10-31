"""Check reject responses on the kernel in isolated network namespaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def test_every_response_hook_default_and_state_policy_loads():
    isolated('''
from nvyr.helpers.nftables_normalizer import normalize
from tests.test_firewall_reject import RESPONSES

tree = {'firewall': {'global-options': {
    'reject-response': 'admin-prohibited',
    'state-policy': {'invalid': {'action': 'reject'}, 'established': {'action': 'accept'}},
}}}
for family, responses in RESPONSES.items():
    rules = {str(index): {'action': 'reject', 'reject-response': response}
             for index, response in enumerate(responses, 1)}
    rules['100'] = {'action': 'reject', 'reject-response': 'tcp-reset', 'protocol': ['tcp']}
    chain = {'rule': rules, 'default-action': 'reject'}
    tree['firewall'][family] = {
        'input': {'filter': deepcopy(chain)},
        'forward': {'filter': deepcopy(chain)},
        'output': {'filter': deepcopy(chain), 'raw': deepcopy(chain)},
        'prerouting': {'raw': deepcopy(chain)},
        'name': {'INNER': deepcopy(chain), 'OUTER': {
            'rule': {'10': {'action': 'jump', 'jump-target': 'INNER'}}}},
    }
    tree['firewall'][family]['forward']['filter']['rule']['1'] = {'action': 'jump', 'jump-target': 'OUTER'}
apply(tree)

document = json.loads(run('nft', '-j', 'list', 'ruleset'))
table = normalize(document)['tables']['inet']['nvyr_filter']
for chain in table['chains'].values():
    for rule in chain.get('rules', []):
        assert 'unsupported' not in rule, rule
assert any(rule.get('number') == 'invalid' and rule.get('action') == 'reject'
           for rule in table['chains']['input']['rules'])

# Mixed verdict-map and ordinary state policies remain visible in operational output.
from contextlib import redirect_stdout
from io import StringIO
from nvyr.op_scripts.firewall import _show_chain
output = StringIO()
with redirect_stdout(output):
    _show_chain('State policy (input)', table['chains']['input'], None, False, False)
assert 'invalid' in output.getvalue() and 'reject' in output.getvalue()
assert 'established' in output.getvalue() and 'accept' in output.getvalue()

# A global change must update inherited rejects without changing explicit choices.
tree['firewall']['global-options']['reject-response'] = 'no-route'
apply(tree)
listing = run('nft', 'list', 'chain', 'inet', 'nvyr_filter', 'input')
assert 'reject with icmpx no-route' in listing, listing
apply(tree, recovery=True)
apply({})
assert 'reject' not in run('nft', 'list', 'table', 'inet', 'nvyr_filter')
''')


def test_packets_receive_global_override_default_and_tcp_responses():
    isolated('''
import errno
import socket

run('ip', 'link', 'set', 'lo', 'up')
for family, af, address in [('ipv4', socket.AF_INET, '127.0.0.1'),
                            ('ipv6', socket.AF_INET6, '::1')]:
    rule = {'action': 'reject', 'protocol': ['udp'], 'destination-port': ['53021']}
    chain = {'rule': {'10': rule}}
    tree = {'firewall': {'global-options': {'reject-response': 'admin-prohibited'},
                         family: {'input': {'filter': chain}}}}
    apply(tree)

    def udp_response():
        protocol = socket.IPPROTO_ICMP if af == socket.AF_INET else socket.IPPROTO_ICMPV6
        with socket.socket(af, socket.SOCK_RAW, protocol) as capture:
            capture.settimeout(1)
            with socket.socket(af, socket.SOCK_DGRAM) as sender:
                sender.sendto(b'reject test', (address, 53021))
            packet = capture.recv(4096)
            offset = (packet[0] & 15) * 4 if af == socket.AF_INET else 0
            return tuple(packet[offset:offset + 2])

    # Inspect the actual ICMP type/code instead of platform-specific socket errors.
    prohibited = (3, 13) if family == 'ipv4' else (1, 1)
    unreachable = (3, 3) if family == 'ipv4' else (1, 4)
    assert udp_response() == prohibited
    rule['reject-response'] = 'port-unreachable'
    apply(tree)
    assert udp_response() == unreachable

    # Default-action rejects also inherit the global response.
    rule.clear()
    rule.update({'action': 'jump', 'jump-target': 'REJECT',
                 'protocol': ['udp'], 'destination-port': ['53021']})
    tree['firewall'][family]['name'] = {'REJECT': {'default-action': 'reject'}}
    apply(tree)
    assert udp_response() == prohibited

    # A TCP listener would accept this connection unless the reset rule intercepted it.
    with socket.socket(af, socket.SOCK_STREAM) as listener:
        listener.bind((address, 0))
        listener.listen(1)
        chain.clear()
        chain['rule'] = {'20': {'action': 'reject', 'reject-response': 'tcp-reset',
                               'protocol': ['tcp'], 'destination-port': [str(listener.getsockname()[1])]}}
        apply(tree)
        with socket.socket(af, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            assert client.connect_ex(listener.getsockname()) == errno.ECONNREFUSED
    apply({})
''')


def test_rejecting_state_policy_sends_global_response():
    isolated('''
import socket

run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {'ipv4': {'input': {'filter': {}}},
    'global-options': {'state-policy': {'established': {'action': 'accept'}}}}}
apply(tree)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
    server.bind(('127.0.0.1', 0))
    server.settimeout(1)
    client.settimeout(1)
    client.connect(server.getsockname())

    # Exchange traffic in both directions so the next packet is established.
    client.send(b'query')
    message, peer = server.recvfrom(64)
    server.sendto(b'reply', peer)
    assert client.recv(64) == b'reply'

    tree['firewall']['global-options'] = {'reject-response': 'admin-prohibited',
        'state-policy': {'established': {'action': 'reject'}}}
    apply(tree)
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as capture:
        capture.settimeout(1)
        client.send(b'rejected')
        packet = capture.recv(4096)
        offset = (packet[0] & 15) * 4
        assert tuple(packet[offset:offset + 2]) == (3, 13)

    document = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'nvyr_filter', 'input'))
    from nvyr.helpers.nftables_normalizer import normalize
    rules = normalize(document)['tables']['inet']['nvyr_filter']['chains']['input']['rules']
    rejected = next(rule for rule in rules if rule.get('number') == 'established')
    assert rejected['counter']['packets'] == 1
''')
