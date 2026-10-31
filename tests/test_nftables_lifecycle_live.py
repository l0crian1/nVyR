"""Observe complete-chain replacement and preserved runtime state on the kernel."""

import os

import pytest

from tests.test_firewall_maps_live import isolated

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


@pytest.mark.parametrize('through_map', [False, True])
def test_nested_jumps_atomic_replacement_and_unchanged_state(through_map):
    isolated('through_map = ' + repr(through_map) + r'''
run('ip', 'link', 'set', 'lo', 'up')
chains = {
    'BOTTOM': {'rule': {'10': {'source-address-group': 'A', 'action': 'accept', 'counter': {}}}},
    'MIDDLE': {'rule': {'10': {'action': 'jump', 'jump-target': 'BOTTOM', 'counter': {}}}},
    'TOP': {'rule': {'10': {'action': 'jump', 'jump-target': 'MIDDLE', 'counter': {}}}},
}
groups = {'address-group': {'ipv4': {
    'A': {'address': ['127.0.0.1'], 'counter': True},
    'SEEN': {'dynamic': {}, 'counter': True, 'last-used': True},
    'UNUSED': {'address': ['192.0.2.1']},
}}}
if through_map:
    groups['map'] = {'ipv4': {'VERDICTS': {
        'match': {'destination-address': True}, 'result-type': 'verdict', 'counter': True,
        'entry': {'LOCAL': {'destination-address': '127.0.0.1', 'result': {'action': 'jump', 'jump-target': 'BOTTOM'}}}}}}
    chains['MIDDLE']['rule']['10'] = {'map': 'VERDICTS', 'counter': {}}
tree = {'firewall': {'group': groups, 'ipv4': {
    'name': chains,
    'output': {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'TOP', 'counter': {}}}}},
    'input': {'filter': {'rule': {'10': {'action': 'accept', 'counter': {}, 'add-to-group': {'source-address': 'SEEN'}}}}},
}}}

def chain(name):
    return run('nft', '-a', 'list', 'chain', 'inet', 'nvyr_filter', name)

def seen():
    return run('nft', 'list', 'set', 'inet', 'nvyr_filter', 'ipv4_address_group_SEEN')

apply(tree)
run('ping', '-4', '-c', '1', '-W', '1', '127.0.0.1')
old_input = chain('ipv4_input')
old_top = chain('ipv4_name_TOP')
assert 'counter packets 2' in old_input and 'counter packets 2' in old_top
assert '127.0.0.1' in seen() and 'counter packets 2' in seen()

# Updating an unused set must not reset any chain or the learned set.
groups['address-group']['ipv4']['UNUSED']['description'] = 'Unrelated change'
apply(tree)
assert chain('ipv4_input') == old_input
assert chain('ipv4_name_TOP') == old_top
assert '127.0.0.1' in seen() and 'counter packets 2' in seen()

# Changing the referenced set replaces every transitive consumer as a whole.
groups['address-group']['ipv4']['A']['description'] = 'Changed provider'
text = apply(tree)
for name in ('BOTTOM', 'MIDDLE', 'TOP'):
    assert 'counter packets 0' in chain('ipv4_name_' + name)
    assert 'destroy chain inet nvyr_filter ipv4_name_' + name in text
assert 'destroy chain inet nvyr_filter ipv4_output' in text
assert chain('ipv4_input') == old_input
assert '127.0.0.1' in seen()
if through_map:
    assert 'destroy map inet nvyr_filter ipv4_map_VERDICTS' in text
run('ping', '-4', '-c', '1', '-W', '1', '127.0.0.1')

# A direct or verdict-map-assisted jump cycle is rejected without publishing
# any of the destruction, new chains, or counter resets from that transaction.
before = {name: chain('ipv4_name_' + name) for name in chains}
bad = deepcopy(tree)
bad['firewall']['ipv4']['name']['BOTTOM']['rule']['10'] = {'action': 'jump', 'jump-target': 'TOP'}
try:
    apply(bad)
    raise AssertionError('Nested jump cycle accepted')
except RouterError:
    pass
assert {name: chain('ipv4_name_' + name) for name in chains} == before
assert '127.0.0.1' in seen()

# Removing all consumers and their providers succeeds in the same transaction.
apply({})
assert not Manager().named_chains() and not Manager().maps() and not Manager().singleton_groups()
''')


def test_group_change_rebuilds_nat_consumer_but_unrelated_nat_commit_preserves_set():
    isolated(r'''
run('ip', 'link', 'set', 'lo', 'up')
groups = {'address-group': {'ipv4': {'A': {'address': ['127.0.0.1'], 'counter': True}}}}
tree = {'firewall': {'group': groups}, 'nat': {'source': {'rule': {'10': {
    'outbound-interface': ['lo'], 'source-address-group': 'A', 'translation': {'address': 'masquerade'}}}}}}
apply(tree)
old_set = run('nft', '-a', 'list', 'set', 'inet', 'nvyr_filter', 'ipv4_address_group_A')
tree['nat']['source']['rule']['10']['description'] = 'Only NAT changed'
text = apply(tree)
assert 'destroy chain inet nvyr_filter ipv4_nat_postrouting' in text
assert 'destroy set' not in text
assert run('nft', '-a', 'list', 'set', 'inet', 'nvyr_filter', 'ipv4_address_group_A') == old_set

groups['address-group']['ipv4']['A']['address'].append('192.0.2.1')
text = apply(tree)
assert 'destroy chain inet nvyr_filter ipv4_nat_postrouting' in text and 'destroy set' in text
assert '192.0.2.1' in run('nft', 'list', 'set', 'inet', 'nvyr_filter', 'ipv4_address_group_A')
apply({})
''')
