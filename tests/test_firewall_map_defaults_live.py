"""Exercise default map results and their tracking in isolated network namespaces."""

from tests.test_firewall_maps_live import isolated, pytestmark


def verdict_default(family):
    """An exact key wins; a default decides misses until it is removed."""
    isolated(f'family = {family!r}\n' + '''
from smoketests.firewall_support import send_firewall_udp
from nvyr.helpers.nftables_normalizer import normalize
run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {
    'global-options': {'counter': True, 'last-used': True},
    'group': {'map': {family: {'SERVICES': {
        'match': {'protocol': True, 'destination-port': True}, 'result-type': 'verdict',
        'entry': {'OTHER': {'protocol': 'udp', 'destination-port': '53099', 'result': {'action': 'drop'}}},
        'default-result': {'action': 'accept'},
    }}}},
    family: {'input': {'filter': {'rule': {'10': {'map': 'SERVICES'}}, 'default-action': 'drop'}}},
}}
apply(tree)
assert send_firewall_udp(2, family=family) == 2
mapping = tree['firewall']['group']['map'][family]['SERVICES']
table = normalize(json.loads(run('nft', '-j', 'list', 'ruleset')), configuration=tree)['tables']['inet']['nvyr_filter']
entries = table['maps'][family + '_map_SERVICES']['entries']
default = next(entry for entry in entries if entry.get('default'))
assert default['counter']['packets'] == 2, default
assert default['last-used'] is not None, default
assert next(entry for entry in entries if entry.get('name') == 'OTHER')['counter']['packets'] == 0
# A matching key overrides the fallback, regardless of the catch-all's position.
mapping['entry']['OTHER']['destination-port'] = '53098'
apply(tree)
assert send_firewall_udp(1, family=family) == 0
mapping['entry']['OTHER']['destination-port'] = '53099'
mapping['default-result']['action'] = 'drop'
apply(tree)
assert send_firewall_udp(1, family=family) == 0
# Removing the default restores ordinary lookup-miss fall-through.
del mapping['default-result']
tree['firewall'][family]['input']['filter']['default-action'] = 'accept'
apply(tree)
assert send_firewall_udp(1, family=family) == 1
''')


def test_ipv4_concatenated_default_and_tracking():
    """IPv4 misses use the catch-all and keep separate element statistics."""
    verdict_default('ipv4')


def test_ipv6_concatenated_default_and_tracking():
    """IPv6 has the same lookup, replacement and removal behavior."""
    verdict_default('ipv6')


def test_inet_default_jump_replacement_and_cycle_rollback():
    """Default-only maps traverse nested policies and obey atomic replacement."""
    isolated('''
from smoketests.firewall_support import send_firewall_udp
run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {
    'group': {'map': {'inet': {'SERVICES': {
        'match': {'protocol': True}, 'result-type': 'verdict',
        'default-result': {'action': 'jump', 'jump-target': 'OUTER'},
    }}}},
    'inet': {
        'name': {'OUTER': {'rule': {'10': {'action': 'jump', 'jump-target': 'INNER'}}},
                 'INNER': {'default-action': 'accept'}},
        'input': {'filter': {'rule': {'10': {'map': 'SERVICES'}}}},
    },
}}
apply(tree)
assert send_firewall_udp(1, family='ipv4') == 1
assert send_firewall_udp(1, family='ipv6') == 1
before = run('nft', '-s', 'list', 'ruleset')
bad = deepcopy(tree)
bad['firewall']['inet']['name']['INNER']['rule'] = {'10': {'map': 'SERVICES'}}
try:
    apply(bad)
    raise AssertionError('Recursive default jump accepted')
except RouterError:
    pass
assert run('nft', '-s', 'list', 'ruleset') == before

tree['firewall']['inet']['name']['INNER']['default-action'] = 'drop'
apply(tree)
assert send_firewall_udp(1, family='ipv4') == 0
assert send_firewall_udp(1, family='ipv6') == 0
previous = {}
apply({}, recovery=True)
assert Manager().maps() == [] and Manager().named_chains() == []
''')


def test_interval_default_and_tcp_flag_normalization():
    """Range lookups and expanded TCP keys both retain a whole-key fallback."""
    isolated('''
from smoketests.firewall_support import send_firewall_udp
from nvyr.helpers.nftables_normalizer import normalize
run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {
    'group': {'map': {'ipv4': {'SOURCES': {
        'match': {'source-address': True}, 'result-type': 'verdict',
        'entry': {'LOCAL': {'source-address': '127.0.0.0/30', 'result': {'action': 'accept'}}},
        'default-result': {'action': 'drop'},
    }}, 'inet': {'FLAGS': {
        'match': {'protocol': True, 'tcp-flags': True}, 'result-type': 'verdict',
        'entry': {'SYN': {'protocol': 'tcp', 'tcp-flags': 'syn,not ack', 'result': {'action': 'accept'}}},
        'default-result': {'action': 'drop'},
    }}}},
    'ipv4': {'input': {'filter': {'rule': {'10': {'map': 'SOURCES'}}}}},
}}
apply(tree)
assert send_firewall_udp(1, source='127.0.0.2') == 1
assert send_firewall_udp(1, source='127.0.0.5') == 0
table = normalize(json.loads(run('nft', '-j', 'list', 'ruleset')), configuration=tree)['tables']['inet']['nvyr_filter']
entries = table['maps']['inet_map_FLAGS']['entries']
assert any(entry.get('default') for entry in entries), entries
assert not any(entry.get('unsupported') for entry in entries), entries
''')


def test_default_continue_and_return():
    """Continue evaluates the next named-chain rule; return resumes its caller."""
    isolated('''
from smoketests.firewall_support import send_firewall_udp
run('ip', 'link', 'set', 'lo', 'up')
tree = {'firewall': {
    'group': {'map': {'inet': {'SERVICES': {
        'match': {'protocol': True}, 'result-type': 'verdict',
        'default-result': {'action': 'continue'},
    }}}},
    'inet': {
        'name': {'POLICY': {'rule': {'10': {'map': 'SERVICES'}, '20': {'action': 'drop'}}}},
        'input': {'filter': {'rule': {
            '10': {'action': 'jump', 'jump-target': 'POLICY'}, '20': {'action': 'accept'},
        }}},
    },
}}
apply(tree)
assert send_firewall_udp(1) == 0
tree['firewall']['group']['map']['inet']['SERVICES']['default-result']['action'] = 'return'
apply(tree)
assert send_firewall_udp(1) == 1
''')


def nat_default(direction, kind):
    """Observe translated packets crossing a veth link into an isolated endpoint."""
    isolated(f'direction = {direction!r}; kind = {kind!r}\n' + '''
import os, socket, time
child = subprocess.Popen(['unshare', '-n', 'sleep', '60'])
endpoint = None
try:
    deadline = time.monotonic() + 3
    while os.readlink('/proc/' + str(child.pid) + '/ns/net') == os.readlink('/proc/self/ns/net'):
        assert time.monotonic() < deadline
        time.sleep(0.01)
    run('ip', 'link', 'set', 'lo', 'up')
    run('ip', 'link', 'add', 'inside0', 'type', 'veth', 'peer', 'name', 'peer0')
    run('ip', 'link', 'set', 'peer0', 'netns', str(child.pid))
    run('ip', 'link', 'set', 'inside0', 'up')
    run('ip', 'address', 'add', '198.18.0.1/24', 'dev', 'inside0')
    run('ip', 'address', 'add', '10.0.0.10/32', 'dev', 'lo')
    prefix = ['nsenter', '-t', str(child.pid), '-n', 'ip']
    run(*prefix, 'link', 'set', 'lo', 'up')
    run(*prefix, 'link', 'set', 'peer0', 'up')
    run(*prefix, 'address', 'add', '198.18.0.2/24', 'dev', 'peer0')
    with open('/proc/self/ns/net', 'rb') as original, open('/proc/' + str(child.pid) + '/ns/net', 'rb') as target:
        try:
            os.setns(target.fileno(), 0)
            endpoint = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            endpoint.bind(('198.18.0.2', 53098))
            endpoint.settimeout(2)
        finally:
            os.setns(original.fileno(), 0)
    result = {}
    if 'address' in kind:
        result['address'] = '10.0.0.10' if direction == 'destination' else '198.18.0.9'
    if 'port' in kind:
        result['port'] = '8443'
    interface = 'inbound-interface' if direction == 'destination' else 'outbound-interface'
    apply({'firewall': {'group': {'map': {'ipv4': {'TRANSLATE': {
        'match': {'protocol': True}, 'result-type': kind, 'default-result': result,
    }}}}}, 'nat': {direction: {'rule': {'10': {'map': 'TRANSLATE', interface: ['inside0']}}}}})
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as local:
        local.settimeout(2)
        if direction == 'destination':
            address = result.get('address', '198.18.0.1')
            port = int(result.get('port', '53098'))
            local.bind((address, port))
            endpoint.sendto(b'catch-all DNAT', ('198.18.0.1', 53098))
            assert local.recvfrom(128)[0] == b'catch-all DNAT'
        else:
            local.bind(('198.18.0.1', 53097))
            local.sendto(b'catch-all SNAT', endpoint.getsockname())
            payload, peer = endpoint.recvfrom(128)
            assert payload == b'catch-all SNAT'
            assert peer == (result.get('address', '198.18.0.1'), int(result.get('port', '53097'))), peer
finally:
    if endpoint is not None:
        endpoint.close()
    child.terminate()
    child.wait()
''')


def test_dnat_default_address():
    """DNAT can obtain an address from the catch-all."""
    nat_default('destination', 'address')


def test_dnat_default_port():
    """DNAT can obtain a port while retaining the original address."""
    nat_default('destination', 'port')


def test_dnat_default_address_port():
    """DNAT uses both components of the fallback result."""
    nat_default('destination', 'address-port')


def test_snat_default_address():
    """SNAT can select its source address from the default result."""
    nat_default('source', 'address')


def test_snat_default_port():
    """SNAT can select only a fallback source port."""
    nat_default('source', 'port')


def test_snat_default_address_port():
    """SNAT applies both parts of a fallback translation."""
    nat_default('source', 'address-port')
