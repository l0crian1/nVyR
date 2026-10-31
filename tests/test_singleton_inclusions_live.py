"""Expanded singleton sets against nftables in disposable network namespaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


@pytest.mark.parametrize('family,address,version', [('ipv4', '127.0.0.1', '-4'), ('ipv6', '::1', '-6')])
def test_included_members_match_packets_and_child_edits_rebuild_consumers(family, address, version):
    isolated(f'''
run('ip', 'link', 'set', 'lo', 'up')
family, address, version = {family!r}, {address!r}, {version!r}
groups = {{
    'address-group': {{family: {{
        'CHILD': {{'address': [address]}},
        'MIDDLE': {{'include-group': ['CHILD']}},
        'PARENT': {{'include-group': ['CHILD', 'MIDDLE'], 'counter': True}},
    }}}},
    'interface-group': {{'CHILD': {{'interface': ['lo']}}, 'PARENT': {{'include-group': ['CHILD']}}}},
    'mac-group': {{'CHILD': {{'address': ['02:00:00:00:00:01']}}, 'PARENT': {{'include-group': ['CHILD']}}}},
    'port-group': {{'CHILD': {{'port': ['80-90']}}, 'PARENT': {{'include-group': ['CHILD'], 'port': ['85-100']}}}},
}}
tree = {{'firewall': {{'group': groups, family: {{
    'name': {{'INNER': {{'rule': {{'10': {{'destination-address-group': 'PARENT', 'action': 'drop'}}}}}},
             'OUTER': {{'rule': {{'10': {{'action': 'jump', 'jump-target': 'INNER'}}}}}}}},
    'output': {{'filter': {{'rule': {{'10': {{'outbound-interface-group': 'PARENT', 'action': 'jump', 'jump-target': 'OUTER'}}}}}}}},
}}}}}}
apply(tree)

# Real packets traverse the parent set and both named-chain jumps.
assert subprocess.run(['ping', version, '-c', '1', '-W', '1', address], capture_output=True).returncode != 0
listing = run('nft', 'list', 'set', 'inet', 'nvyr_filter', family + '_address_group_PARENT')
assert 'counter packets 1' in listing, listing
assert '80-100' in run('nft', 'list', 'set', 'inet', 'nvyr_filter', 'port_group_PARENT')
assert '02:00:00:00:00:01' in run('nft', 'list', 'set', 'inet', 'nvyr_filter', 'mac_group_PARENT')

# A child-only edit removes inherited membership without editing a rule.
del groups['address-group'][family]['CHILD']['address']
text = apply(tree)
assert 'destroy chain inet nvyr_filter ' + family + '_name_OUTER' in text
assert 'destroy set inet nvyr_filter port_group_PARENT' not in text
run('ping', version, '-c', '1', '-W', '1', address)

# Recovery uses the same expansion, and removing all configuration cleans it up.
apply(tree, recovery=True)
run('ping', version, '-c', '1', '-W', '1', address)
apply({{}})
assert Manager().singleton_groups() == []
''')
