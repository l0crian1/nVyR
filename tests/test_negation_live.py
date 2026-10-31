"""Opt-in checks against real nftables in isolated container network namespaces."""

import os

import pytest

from tests.test_nftables_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                               reason='requires isolated privileged nftables container')


def test_negated_fields_load_and_normalize_in_both_families():
    isolated('''
from nvyr.helpers.nftables_normalizer import normalize

for family in ('ipv4', 'ipv6'):
    address = '192.0.2.1' if family == 'ipv4' else '2001:db8::1'
    mask = '255.255.0.255' if family == 'ipv4' else 'ffff:ffff:ffff::ffff'
    protocol = 'icmp' if family == 'ipv4' else 'ipv6-icmp'
    exclusions = [
        {'connection': {'state': ['new', 'related']}},
        {'connection': {'status': ['confirmed,snat,dnat', 'assured']}},
        {'packet-type': 'host'},
        {'inbound-interface': ['lo', 'dum0']},
        {'outbound-interface': ['lo', 'dum1']},
        {'source-address': {address: {}}},
        {'destination-address': {address: {'mask': mask}}},
        {'source-mac': {'02:11:22:33:44:55': {}}},
        {'destination-mac': {'02:11:22:33:44:55': {'mask': 'ff:ff:00:ff:00:ff'}}},
        {'packet-mark': ['1', '8-16']},
        {'connection': {'mark': ['1', '2']}},
        {'dscp': ['10', '30']},
        {'protocol': ['tcp', 'udp']},
        {'source-port': ['80', '443']},
        {'destination-port': ['8000-9000']},
        {'tcp-mss': ['1200', '1460']},
        {'icmp-type': ['echo-request'], 'icmp-code': ['0']},
    ]
    rules = {}
    for number, excluded in enumerate(exclusions, 1):
        rule = {'action': 'continue', 'not': excluded}
        if 'connection' in excluded:
            rule = {'action': 'continue', 'connection': {'not': excluded['connection']}}
        if any(field in excluded for field in ('source-port', 'destination-port', 'tcp-mss')):
            rule['protocol'] = ['tcp']
        if 'icmp-type' in excluded:
            rule['protocol'] = [protocol]
        rules[str(number)] = rule
    rules['100'] = {'action': 'continue', 'ttl': {'not': {'eq': '64'}}}
    rules['101'] = {'action': 'continue', 'fib': {
        'lookup': {'source-address': True},
        'result': {'not': {'outbound-interface': ['lo', 'dum0']}}}}
    rules['102'] = {'action': 'continue', 'fib': {
        'lookup': {'destination-address': True},
        'result': {'not': {'route-type': ['local', 'broadcast']}}}}

    apply({family: {'forward': {'filter': {'rule': rules}}}})
    normalized = normalize({'nftables': snapshot()})
    chain = normalized['tables']['inet']['nvyr_filter']['chains'][family + '_forward']
    installed = {rule['number']: rule for rule in chain['rules']}
    for number, expected in rules.items():
        actual = installed[number]
        assert 'unsupported' not in actual, actual
        if 'not' in expected:
            assert set(actual['not']) == set(expected['not']), actual
        elif 'connection' in expected:
            names = {'state': 'state', 'status': 'connection-status', 'mark': 'connection-mark'}
            assert set(actual['not']) == {names[key] for key in expected['connection']['not']}, actual
        elif 'ttl' in expected:
            assert actual['ttl']['not']['eq'] == 64, actual
        else:
            assert actual['fib']['lookup'] == expected['fib']['lookup'], actual
            for field, values in expected['fib']['result']['not'].items():
                assert set(actual['fib']['result']['not'][field]) == set(values), actual
''')


def test_mixed_address_and_port_exclusions_match_packets_and_single_deletion():
    isolated('''
from nvyr.helpers.nftables_normalizer import normalize

run('ip', 'link', 'set', 'lo', 'up')
rule = {
    'action': 'continue', 'protocol': ['udp'], 'counter': {},
    'source-address': {'127.0.0.0/8': {}}, 'destination-port': ['40000-40002'],
    'not': {'source-address': {'127.0.0.2': {}, '127.0.0.3': {}},
            'destination-port': ['40001', '40002']},
}
config = {'ipv4': {'output': {'filter': {'rule': {'10': rule}}}}}
apply(config)

def send(source, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(('127.0.0.1', port))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind((source, 0))
            client.sendto(b'negation-test', ('127.0.0.1', port))
        assert server.recv(100) == b'negation-test'

def packets():
    normalized = normalize({'nftables': snapshot()})
    chain = normalized['tables']['inet']['nvyr_filter']['chains']['ipv4_output']
    return next(rule['counter']['packets'] for rule in chain['rules'] if rule['number'] == '10')

# Both the positive set and every exclusion must be satisfied.
for source in ('127.0.0.1', '127.0.0.2', '127.0.0.3'):
    for port in (40000, 40001, 40002):
        send(source, port)
assert packets() == 1, packets()

# Removing one excluded port rebuilds the chain while retaining the other exclusions.
rule['not']['destination-port'].remove('40001')
apply(config)
for source in ('127.0.0.1', '127.0.0.2', '127.0.0.3'):
    for port in (40000, 40001, 40002):
        send(source, port)
assert packets() == 2, packets()
''')


def test_negated_group_references_use_exact_tuple_membership():
    isolated('''
from nvyr.helpers.nftables_normalizer import normalize

run('ip', 'link', 'set', 'lo', 'up')
groups = {'match-group': {'ipv4': {'EXCLUDED': {
    'match': {'source-address': True, 'destination-port': True, 'protocol': True},
    'counter': True, 'last-used': True,
    'entry': {'one': {'source-address': '127.0.0.2', 'destination-port': '40000', 'protocol': 'udp'}},
}}}}
rule = {'action': 'continue', 'protocol': ['udp'], 'counter': {},
        'not': {'match-group': 'EXCLUDED'}}
apply({'group': groups, 'ipv4': {'output': {'filter': {'rule': {'10': rule}}}}})

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
    server.bind(('127.0.0.1', 40000))
    for source in ('127.0.0.1', '127.0.0.2', '127.0.0.3'):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.bind((source, 0))
            client.sendto(b'group-test', ('127.0.0.1', 40000))
        assert server.recv(100) == b'group-test'

normalized = normalize({'nftables': snapshot()})
chain = normalized['tables']['inet']['nvyr_filter']['chains']['ipv4_output']
actual = next(rule for rule in chain['rules'] if rule['number'] == '10')
assert actual['counter']['packets'] == 2, actual
assert actual['not']['match-group'] == 'EXCLUDED', actual
assert 'unsupported' not in actual, actual
''')
