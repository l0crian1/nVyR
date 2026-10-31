"""Native prefix sets and zone dispatch, including interfaces created after load."""

import os

import pytest

from tests.test_nftables_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def test_native_rule_group_negation_and_tracking():
    isolated('''
run('ip', 'link', 'set', 'lo', 'up')
config = {'group': {'interface-group': {
    'LOCAL': {'interface': ['l*', 'lo'], 'counter': True, 'last-used': True},
    'OTHER': {'interface': ['wg*']},
}}}
for family in ('ipv4', 'ipv6'):
    config[family] = {'output': {'filter': {'rule': {
        '10': {'action': 'continue', 'outbound-interface': ['l*', 'lo'], 'counter': {}},
        '20': {'action': 'continue', 'not': {'outbound-interface': ['wg*']}, 'counter': {}},
        '30': {'action': 'continue', 'outbound-interface-group': 'LOCAL', 'counter': {}},
        '40': {'action': 'continue', 'not': {'outbound-interface-group': 'OTHER'}, 'counter': {}},
    }}}}
apply(config)
run('ping', '-4', '-c', '1', '-W', '1', '127.0.0.1')
run('ping', '-6', '-c', '1', '-W', '1', '::1')
from nvyr.helpers.nftables_normalizer import normalize
table = normalize({'nftables': snapshot()})['tables']['inet']['nvyr_filter']
for family in ('ipv4', 'ipv6'):
    rules = table['chains'][family + '_output']['rules']
    for rule in rules:
        if rule['number'] in ('10', '20', '30', '40'):
            assert rule['counter']['packets'] > 0, rule
            assert 'unsupported' not in rule, rule
native = run('nft', 'list', 'set', 'inet', 'nvyr_filter', 'interface_group_LOCAL')
assert '"l*"' in native and 'packets 0' not in native, native
assert 'last used never' not in native, native
''')


def test_native_zone_prefixes_forward_late_created_interfaces():
    isolated('''
config = {'zone': {
    'VPN': {'interface': ['wg*', 'wg0'], 'default-action': 'accept'},
    'WAN': {'interface': ['eth*'], 'default-action': 'accept'},
    'LOCAL': {'local-zone': True, 'default-action': 'accept'},
}, 'ipv4': {'forward': {'filter': {'default-action': 'drop'}}},
   'ipv6': {'forward': {'filter': {'default-action': 'drop'}}}}
apply(config)
original = {item['map']['name']: item['map']['handle'] for item in snapshot() if 'map' in item}

# Install the zone maps before either member exists; no subsequent apply is made.
run('ip', 'netns', 'add', 'wild-left')
try:
    run('ip', 'netns', 'add', 'wild-right')
    try:
        # Addresses are exclusive to these namespaces; avoid waiting for link-local DAD.
        run('sysctl', '-w', 'net.ipv6.conf.default.accept_dad=0')
        for namespace, device, number in [('wild-left', 'wg0', 1), ('wild-right', 'eth0', 2)]:
            run('ip', 'netns', 'exec', namespace, 'sysctl', '-w', 'net.ipv6.conf.default.accept_dad=0')
            run('ip', 'link', 'add', device, 'type', 'veth', 'peer', 'name', 'peer')
            run('ip', 'link', 'set', 'peer', 'netns', namespace)
            run('ip', 'address', 'add', f'192.0.{number}.1/24', 'dev', device)
            run('ip', '-6', 'address', 'add', f'2001:db8:{number}::1/64', 'dev', device, 'nodad')
            run('ip', 'link', 'set', device, 'up')
            run('ip', '-n', namespace, 'address', 'add', f'192.0.{number}.2/24', 'dev', 'peer')
            run('ip', '-n', namespace, '-6', 'address', 'add', f'2001:db8:{number}::2/64', 'dev', 'peer', 'nodad')
            run('ip', '-n', namespace, 'link', 'set', 'peer', 'up')
            run('ip', '-n', namespace, 'route', 'add', 'default', 'via', f'192.0.{number}.1')
            run('ip', '-n', namespace, '-6', 'route', 'add', 'default', 'via', f'2001:db8:{number}::1')
        run('sysctl', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
        run('ip', 'netns', 'exec', 'wild-left', 'ping', '-4', '-c', '1', '-W', '2', '192.0.2.2')
        run('ip', 'netns', 'exec', 'wild-left', 'ping', '-6', '-c', '1', '-W', '2', '2001:db8:2::2')

        for item in snapshot():
            mapping = item.get('map', {})
            if mapping.get('name', '').endswith('_zone_forward'):
                assert mapping['handle'] == original[mapping['name']]
                entry = next(key['elem'] for key, verdict in mapping['elem']
                             if key['elem']['comment'] == 'VPN to WAN')
                assert entry['val'] == {'concat': ['wg*', 'eth*']}, entry
                assert entry['counter']['packets'] > 0, entry
    finally:
        run('ip', 'netns', 'delete', 'wild-right')
finally:
    run('ip', 'netns', 'delete', 'wild-left')
''')
