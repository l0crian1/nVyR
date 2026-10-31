"""Verify shared runtime state with real packets in a disposable namespace."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


@pytest.mark.parametrize('per', [None, 'source-address'])
def test_shared_allowance_and_counter_survive_consumer_rebuilds(per):
    isolated(f'per = {per!r}\n' + r'''
import socket
from tests.test_firewall_named_state import configuration
from nvyr.helpers.nftables_normalizer import normalize

run('ip', 'link', 'set', 'lo', 'up')
tree = configuration(per)
rules = tree['firewall']['ipv4']['output']['filter']['rule']
# Different ports select separate rules sharing one allowance and counter.
for number, port in [('10', '53001'), ('20', '53002')]:
    rules[number].update({'protocol': ['udp'], 'destination-port': [port], 'action': 'drop'})
apply(tree)

def send(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        try:
            sender.sendto(b'test', ('127.0.0.1', port))
        except PermissionError:
            # DROP on local output reports EPERM; the named counter proves it matched.
            pass

def table():
    data = json.loads(run('nft', '-j', 'list', 'ruleset'))
    return normalize(data, configuration=tree)['tables']['inet']['nvyr_filter']

def counted():
    return table()['counters']['counter_group_TOTAL']['packets']

send(53001)
send(53002)
assert counted() == 0
send(53001)
send(53002)
assert counted() == 2

# Rebuilding a consumer must not refill the shared bucket or reset the total.
rules['10']['description'] = 'Consumer changed'
apply(tree)
send(53002)
assert counted() == 3

# Every supported listing, including scoped rules, must recognize references.
installed = table()
for rule in installed['chains']['ipv4_output']['rules']:
    assert 'unsupported' not in rule, rule
shared = next(rule for rule in installed['chains']['ipv4_output']['rules'] if rule.get('number') == '10')
assert shared['counter']['group'] == 'TOTAL'
assert shared['limit']['group'] == 'SHARED'
scoped = normalize(json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_output')))
assert 'unsupported' not in scoped

# A failed transaction must leave both packet state and the last good rules intact.
try:
    Manager().apply('add rule inet nvyr_filter ipv4_output invalid_expression', directory)
except RouterError:
    pass
else:
    raise AssertionError('Invalid nftables input unexpectedly succeeded')
send(53001)
assert counted() == 4

# A group type change releases consumers before replacing the named object.
options = tree['firewall']['group']['limit-group']['ipv4']['SHARED']
if per:
    options.pop('per')
else:
    options['per'] = 'source-address'
apply(tree)
send(53001)
assert counted() == 4

# Recovery also discovers objects absent from both supplied config snapshots.
previous = {}
apply({}, recovery=True)
assert Manager().named_state() == []
''')


def test_all_log_options_ipv6_named_limit_and_nat_counter():
    isolated(r'''
from nvyr.helpers.nftables_normalizer import normalize
tree = {'firewall': {
    'group': {'counter-group': {'TOTAL': {}}, 'limit-group': {'ipv6': {
        'BYTE': {'rate': {'bytes': '1g/s'}, 'burst': {'bytes': '64k'}, 'description': 'Bytes'},
        'KEY': {'rate': {'packets': '10/s'}, 'per': 'source-address,destination-port',
                'source-prefix-length': '64', 'description': 'Subnets'},
    }}},
    'ipv6': {'forward': {'filter': {'rule': {
        '10': {'action': 'continue', 'limit': {'group': 'BYTE'}, 'counter': {'group': 'TOTAL'}},
        '20': {'action': 'continue', 'limit': {'group': 'KEY'}},
    }}}},
}, 'nat': {'source': {'rule': {'10': {
    'exclude': True, 'outbound-interface': ['lo'], 'counter': {'group': 'TOTAL'},
    'log': {'level': 'notice', 'flags': 'ether'},
}}}}}
rules = tree['firewall']['ipv6']['forward']['filter']['rule']
flags = ['tcp-sequence', 'tcp-options', 'ip-options', 'skuid', 'ether', 'all',
         'tcp-sequence,tcp-options,ip-options,skuid,ether']
levels = ['emerg', 'alert', 'crit', 'err', 'warn', 'notice', 'info', 'debug']
for number, level in enumerate(levels, 100):
    rules[str(number)] = {'action': 'continue', 'log': {'level': level, 'flags': flags[number % len(flags)]}}
apply(tree)
table = normalize(json.loads(run('nft', '-j', 'list', 'ruleset')), configuration=tree)['tables']['inet']['nvyr_filter']
for chain in table['chains'].values():
    for rule in chain.get('rules', []):
        assert 'unsupported' not in rule, rule
assert table['limits']['ipv6_limit_group_BYTE']['rate'] == {'bytes': '1024m/s'}
assert table['sets']['ipv6_limit_group_KEY']['match-fields'] == ['source-address', 'destination-port']
apply({}, recovery=True)
''')
