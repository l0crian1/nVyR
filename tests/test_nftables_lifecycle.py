"""Whole-object replacement and transitive schema-declared dependencies."""

from copy import deepcopy

import pytest

from tests.test_firewall_maps import rendered


def nested_tree(family='ipv4'):
    return {'firewall': {'group': {'address-group': {family: {'A': {'address': ['192.0.2.1'] if family == 'ipv4' else ['2001:db8::1']}}}},
        family: {'name': {
            'BOTTOM': {'rule': {'10': {'source-address-group': 'A', 'action': 'accept'}}},
            'MIDDLE': {'rule': {'10': {'action': 'jump', 'jump-target': 'BOTTOM'}}},
            'TOP': {'rule': {'10': {'action': 'jump', 'jump-target': 'MIDDLE'}}},
            'UNRELATED': {'rule': {'10': {'action': 'drop', 'counter': {}}}},
        }, 'forward': {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'TOP'}}}},
        'input': {'filter': {'default-action': 'accept'}}}}}


def destroyed(text, kind='chain'):
    prefix = f'destroy {kind} inet nvyr_filter '
    return {line[len(prefix):] for line in text.splitlines() if line.startswith(prefix)}


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('negative', [False, True])
def test_changed_set_rebuilds_every_nested_jump_consumer(family, negative):
    before = nested_tree(family)
    if negative:
        rule = before['firewall'][family]['name']['BOTTOM']['rule']['10']
        rule['not'] = {'source-address-group': rule.pop('source-address-group')}

    after = deepcopy(before)
    after['firewall']['group']['address-group'][family]['A']['description'] = 'Changed set'
    text = rendered(after, before)
    assert destroyed(text) == {family + '_name_' + name for name in ('BOTTOM', 'MIDDLE', 'TOP')} | {family + '_forward', 'forward'}
    assert destroyed(text, 'set') == {family + '_address_group_A'}
    assert family + '_name_UNRELATED' not in text
    assert family + '_input' not in text
    assert text.index('flush chain') < text.index('destroy set') < text.index('destroy chain')


def test_chain_changes_do_not_rebuild_its_unchanged_dependencies():
    before = nested_tree()
    after = deepcopy(before)
    after['firewall']['ipv4']['name']['MIDDLE']['rule']['20'] = {'action': 'drop'}
    text = rendered(after, before)
    assert destroyed(text) == {'ipv4_name_MIDDLE', 'ipv4_name_TOP', 'ipv4_forward', 'forward'}
    assert not destroyed(text, 'set')
    assert 'chain ipv4_name_BOTTOM {' not in text


def test_verdict_map_jumps_propagate_through_nested_chains():
    before = nested_tree()
    before['firewall']['group']['map'] = {'ipv4': {'VERDICTS': {
        'match': {'destination-address': True}, 'result-type': 'verdict',
        'entry': {'A': {'destination-address': '203.0.113.1', 'result': {'action': 'jump', 'jump-target': 'MIDDLE'}}}}}}
    before['firewall']['ipv4']['name']['TOP']['rule']['10'] = {'map': 'VERDICTS'}
    after = deepcopy(before)
    after['firewall']['ipv4']['name']['BOTTOM']['default-action'] = 'drop'
    text = rendered(after, before)
    assert destroyed(text, 'map') == {'ipv4_map_VERDICTS'}
    assert destroyed(text) == {'ipv4_name_BOTTOM', 'ipv4_name_MIDDLE', 'ipv4_name_TOP', 'ipv4_forward', 'forward'}
    assert text.index('destroy map') < text.index('destroy chain')
    assert text.index('add chain inet nvyr_filter ipv4_name_MIDDLE', text.index('destroy chain')) < text.index('map ipv4_map_VERDICTS {')


def test_shared_group_changes_rebuild_firewall_and_nat_consumers():
    before = nested_tree()
    before['nat'] = {'source': {'rule': {'10': {'source-address-group': 'A', 'outbound-interface': ['eth0'], 'translation': {'address': 'masquerade'}}}}}
    after = deepcopy(before)
    after['firewall']['group']['address-group']['ipv4']['A']['address'].append('192.0.2.2')
    assert {'ipv4_nat_postrouting', 'nat_postrouting'} <= destroyed(rendered(after, before))

    after = deepcopy(before)
    after['nat']['source']['rule']['10']['description'] = 'Changed NAT'
    text = rendered(after, before)
    assert destroyed(text) == {'ipv4_nat_postrouting', 'nat_postrouting'}
    assert not destroyed(text, 'set')


def test_global_defaults_only_invalidate_affected_objects():
    before = nested_tree()
    after = deepcopy(before)
    after['firewall']['global-options'] = {'counter': True}
    text = rendered(after, before)
    assert 'ipv4_name_UNRELATED' not in destroyed(text)  # Already tracks every numbered rule.
    assert 'ipv4_name_BOTTOM' in destroyed(text)
    assert 'ipv4_input' not in destroyed(text)  # No numbered rules.
    assert destroyed(text, 'set') == {'ipv4_address_group_A'}


def test_no_change_and_removal_of_last_consumer():
    before = nested_tree()
    assert not destroyed(rendered(deepcopy(before), before))
    after = deepcopy(before)
    after['firewall']['ipv4']['name']['BOTTOM']['rule']['10'] = {'action': 'accept'}
    del after['firewall']['group']['address-group']['ipv4']['A']
    text = rendered(after, before)
    assert destroyed(text, 'set') == {'ipv4_address_group_A'}
    assert 'set ipv4_address_group_A {' not in text
    assert 'ipv4_name_TOP' in destroyed(text)


def test_family_and_group_type_identities_do_not_collide():
    before = nested_tree()
    before['firewall']['group']['map'] = {'ipv6': {'A': {'match': {'source-address': True}, 'result-type': 'verdict'}}}
    before['firewall']['ipv6'] = {'output': {'filter': {'rule': {'10': {'map': 'A'}}}}}
    after = deepcopy(before)
    after['firewall']['group']['map']['ipv6']['A']['description'] = 'Changed map'
    text = rendered(after, before)
    assert destroyed(text) == {'ipv6_output', 'output'}
    assert destroyed(text, 'map') == {'ipv6_map_A'}
    assert not destroyed(text, 'set')


def test_flowtable_change_rebuilds_only_its_consumers(monkeypatch):
    from nvyr.helpers import interfaces
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    before = nested_tree()
    before['firewall']['flowtable'] = {'FAST': {'interface': ['dum0']}, 'OTHER': {'interface': ['dum2']}}
    before['firewall']['ipv4']['forward']['filter']['rule']['20'] = {'action': 'offload', 'offload-target': 'FAST'}
    after = deepcopy(before)
    after['firewall']['flowtable']['FAST']['interface'] = ['dum1']
    text = rendered(after, before)
    assert destroyed(text, 'flowtable') == {'flowtable_FAST'}
    assert destroyed(text) == {'ipv4_forward', 'forward'}
    assert 'flowtable_OTHER' not in text


def test_state_policy_changes_only_rebuild_filter_entrypoints():
    before = nested_tree()
    after = deepcopy(before)
    after['firewall']['global-options'] = {'state-policy': {'established': {'action': 'accept'}}}
    text = rendered(after, before)
    assert destroyed(text) == {'input', 'forward'}
    assert not destroyed(text, 'set')


def test_unchanged_dictionary_order_does_not_reset_counters():
    before = nested_tree()
    before['firewall']['ipv4']['name']['BOTTOM']['rule']['20'] = {'action': 'drop'}
    after = deepcopy(before)
    rules = after['firewall']['ipv4']['name']['BOTTOM']['rule']
    after['firewall']['ipv4']['name']['BOTTOM']['rule'] = dict(reversed(list(rules.items())))
    assert not destroyed(rendered(after, before))
