"""VRF input matching, Linux link-group keys and whole-chain reapplication."""

from copy import deepcopy

import pytest

from nvyr.errors import ValidationError
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


def tree(family='ipv4'):
    return {'interfaces': {'dummy': {'dum0': {'vrf': 'BLUE'}, 'dum1': {}}},
            'vrf': {'name': {'BLUE': {'table': '100'}}},
            'firewall': {family: {'input': {'filter': {'rule': {
                '10': {'action': 'accept', 'inbound-interface': ['dum0']},
                '20': {'action': 'accept', 'inbound-interface': ['dum1']},
                '30': {'action': 'accept', 'inbound-interface': ['BLUE']},
                '40': {'action': 'accept', 'not': {'inbound-interface': ['dum0']}},
            }}}}}}


def test_ipv4_input_uses_slave_names_only_for_member_matches():
    text = rendered(tree())
    assert 'meta sdifname { "dum0" } accept' in text
    assert 'meta sdifname != { "dum0" } accept' in text
    assert 'iifname { "dum1" } accept' in text
    assert 'iifname { "BLUE" } accept' in text


def test_ipv6_input_uses_slave_names_only_for_member_matches():
    text = rendered(tree('ipv6'))
    assert 'meta sdifname { "dum0" } accept' in text
    assert 'meta sdifname != { "dum0" } accept' in text
    assert 'iifname { "BLUE" } accept' in text


def test_interface_group_vrf_is_a_declaration_not_a_membership_check():
    config = tree()
    config['firewall']['group'] = {'interface-group': {'MEMBERS': {'vrf': True, 'interface': ['dum0', 'dum1', 'absent']}}}
    rules = config['firewall']['ipv4']['input']['filter']['rule']
    rules['50'] = {'action': 'accept', 'inbound-interface-group': 'MEMBERS'}
    rules['60'] = {'action': 'accept', 'not': {'inbound-interface-group': 'MEMBERS'}}
    text = rendered(config)
    assert 'meta sdifname @interface_group_MEMBERS accept' in text
    assert 'meta sdifname != @interface_group_MEMBERS accept' in text


def test_nested_named_chain_and_verdict_map_inherit_input_context():
    config = tree()
    family = config['firewall']['ipv4']
    family['name'] = {'BOTTOM': family.pop('input')['filter'],
                      'TOP': {'rule': {'10': {'action': 'jump', 'jump-target': 'BOTTOM'}}}}
    config['firewall']['group'] = {'map': {'ipv4': {'JUMP': {'match': {'source-address': True}, 'result-type': 'verdict',
        'entry': {'one': {'source-address': '192.0.2.1', 'result': {'action': 'jump', 'jump-target': 'TOP'}}}}}}}
    family['input'] = {'filter': {'rule': {'10': {'map': 'JUMP'}}}}
    assert 'meta sdifname { "dum0" } accept' in rendered(config)

    family['forward'] = {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'TOP'}}}}
    with pytest.raises(ValidationError, match='VRF-aware inbound matches cannot be shared'):
        rendered(config)


def test_moving_named_caller_rebuilds_unchanged_target_for_new_expression():
    before = tree()
    family = before['firewall']['ipv4']
    family['name'] = {'CHECK': family.pop('input')['filter']}
    family['forward'] = {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'CHECK'}}}}
    assert 'sdifname' not in rendered(before)
    after = deepcopy(before)
    after['firewall']['ipv4']['input'] = after['firewall']['ipv4'].pop('forward')
    text = rendered(after, before)
    assert 'ipv4_name_CHECK' in destroyed(text)
    assert 'meta sdifname { "dum0" } accept' in text


def test_membership_rebuilds_affected_chain_but_preserves_unrelated_chains():
    before = tree()
    before['firewall']['ipv4']['output'] = {'filter': {'rule': {'10': {'action': 'accept', 'outbound-interface': ['dum0']}}}}
    after = deepcopy(before)
    del after['interfaces']['dummy']['dum0']['vrf']
    text = rendered(after, before)
    assert destroyed(text) == {'ipv4_input', 'input'}
    assert 'sdifname' not in text


def test_link_groups_multi_negation_and_group_key_types(controller, session, engine):
    controller.execute('set firewall ipv4 forward filter rule 10 inbound-link-group 0 inbound-link-group 4294967295 outbound-link-group not 42 action accept', session)
    controller.execute('set firewall group match-group ipv4 LINKS match inbound-link-group outbound-link-group', session)
    controller.execute('set firewall group match-group ipv4 LINKS entry one inbound-link-group 1 outbound-link-group 2', session)
    controller.execute('set firewall ipv4 forward filter rule 20 match-group LINKS action accept', session)
    text = rendered(engine.view(session))
    assert 'meta iifgroup { 0, 4294967295 }' in text
    assert 'meta oifgroup != { 42 }' in text
    assert 'type devgroup . devgroup' in text
    assert 'meta iifgroup . meta oifgroup == @ipv4_match_group_LINKS' in text
    with pytest.raises(ValidationError):
        controller.execute('set firewall ipv4 forward filter rule 10 inbound-link-group 4294967296', session)


def test_link_group_hook_restrictions_follow_named_chains_and_limits():
    config = {'firewall': {'ipv4': {'input': {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'CHECK'}}}},
        'name': {'CHECK': {'rule': {'10': {'outbound-link-group': ['1'], 'action': 'accept'}}}}}}}
    with pytest.raises(ValidationError, match='outbound-link-group is unavailable in input'):
        rendered(config)
    config['firewall']['ipv4']['name']['CHECK']['rule']['10'] = {
        'limit': {'rate': {'packets': '10/s'}, 'per': 'outbound-link-group'}, 'action': 'accept'}
    with pytest.raises(ValidationError, match='outbound-link-group in input'):
        rendered(config)
