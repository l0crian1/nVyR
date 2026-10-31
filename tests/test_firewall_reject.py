"""Reject responses retain protocol safety, inheritance and whole-chain lifecycle."""

from copy import deepcopy

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import RouterError
from nvyr.helpers.nftables_formatters import nft_reject, nft_state_policy
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


RESPONSES = {
    'ipv4': ['port-unreachable', 'admin-prohibited', 'no-route', 'host-unreachable',
             'net-unreachable', 'prot-unreachable', 'frag-needed', 'net-prohibited', 'host-prohibited'],
    'ipv6': ['port-unreachable', 'admin-prohibited', 'no-route', 'host-unreachable',
             'addr-unreachable', 'policy-fail', 'reject-route'],
}


def configuration(rule, family='ipv4'):
    return {'firewall': {family: {'input': {'filter': {'rule': {'10': rule}}}}}}


@pytest.mark.parametrize('family,response', [(family, response) for family, responses in RESPONSES.items() for response in responses])
def test_response_choices_render(family, response):
    tree = configuration({'action': 'reject', 'reject-response': response}, family)
    assert nft_reject(family, response) + ' comment "10|"' in rendered(tree)


def test_cli_completion_family_validation_and_tcp_reset(controller, session, engine):
    controller.execute('set firewall global-options reject-response admin-prohibited', session)
    controller.execute('set firewall ipv4 input filter rule 10 protocol tcp action reject reject-response tcp-reset', session)
    assert 'reject with tcp reset' in rendered(engine.view(session))

    prefix = 'set firewall ipv6 input filter rule 10 reject-response '
    options = dict(controller.completion(prefix, session, explicit=True)['candidates'])
    assert 'policy-fail' in options and 'tcp-reset' in options
    assert 'net-prohibited' not in options

    for line in [prefix + 'net-prohibited',
                 'set firewall ipv4 input filter rule 20 reject-response policy-fail',
                 'set firewall global-options reject-response tcp-reset',
                 'set firewall global-options reject-response nonsense']:
        with pytest.raises(RouterError):
            controller.execute(line, session)


@pytest.mark.parametrize('rule,message', [
    ({'reject-response': 'admin-prohibited'}, 'requires action reject'),
    ({'action': 'accept', 'reject-response': 'admin-prohibited'}, 'requires action reject'),
    ({'action': 'reject', 'reject-response': 'tcp-reset'}, 'requires protocol tcp only'),
    ({'action': 'reject', 'reject-response': 'tcp-reset', 'protocol': ['udp']}, 'requires protocol tcp only'),
    ({'action': 'reject', 'reject-response': 'tcp-reset', 'protocol': ['tcp', 'udp']}, 'requires protocol tcp only'),
    ({'action': 'reject', 'reject-response': 'tcp-reset', 'not': {'protocol': ['udp']}}, 'requires protocol tcp only'),
])
def test_invalid_response_context(rule, message):
    with pytest.raises(RouterError, match=message):
        rendered(configuration(rule))


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_tcp_reset_accepts_positive_group_protocol(family):
    tree = configuration({'action': 'reject', 'reject-response': 'tcp-reset', 'match-group': 'TCP'}, family)
    group = {'match': {'protocol': True}, 'entry': {'one': {'protocol': 'tcp'}}}
    tree['firewall']['group'] = {'match-group': {family: {'TCP': group}}}
    assert 'reject with tcp reset' in rendered(tree)

    group['entry']['two'] = {'protocol': 'udp'}
    with pytest.raises(RouterError, match='requires protocol tcp only'):
        rendered(tree)


def test_map_cannot_supply_action_for_response():
    tree = configuration({'map': 'M', 'reject-response': 'admin-prohibited'})
    tree['firewall']['group'] = {'map': {'ipv4': {'M': {
        'match': {'source-address': True}, 'result-type': 'verdict',
    }}}}
    with pytest.raises(RouterError, match='requires action reject'):
        rendered(tree)


def test_global_inheritance_default_actions_and_state_policy():
    tree = configuration({'action': 'reject'})
    tree['firewall']['global-options'] = {'reject-response': 'admin-prohibited',
        'state-policy': {'invalid': {'action': 'reject'}, 'established': {'action': 'accept'}}}
    tree['firewall']['ipv4']['input']['filter']['default-action'] = 'reject'
    original = deepcopy(tree)

    text = rendered(tree)
    assert 'reject with icmpx type admin-prohibited comment "10|"' in text
    assert 'counter reject with icmpx type admin-prohibited comment "default|default-action reject"' in text
    assert 'ct state invalid counter reject with icmpx type admin-prohibited comment "invalid|"' in text
    assert 'ct state vmap { established counter : accept }' in text
    assert tree == original

    tree['firewall']['ipv4']['input']['filter']['rule']['10']['reject-response'] = 'host-unreachable'
    assert 'reject with icmpx type host-unreachable comment "10|"' in rendered(tree)
    assert 'reject comment "10|"' in rendered(configuration({'action': 'reject'}))
    assert nft_state_policy({}) == ''


def test_global_change_rebuilds_only_inheriting_chains_and_callers():
    tree = {'firewall': {'global-options': {'reject-response': 'admin-prohibited'}, 'ipv4': {
        'name': {
            'INNER': {'rule': {'10': {'action': 'reject'}}},
            'OUTER': {'rule': {'10': {'action': 'jump', 'jump-target': 'INNER'}}},
        },
        'forward': {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'OUTER'}}}},
        'input': {'filter': {'rule': {'10': {'action': 'reject', 'reject-response': 'port-unreachable'}}}},
        'output': {'filter': {'default-action': 'reject'}},
    }}}
    updated = deepcopy(tree)
    updated['firewall']['global-options']['reject-response'] = 'no-route'

    assert destroyed(rendered(updated, tree)) == {
        'ipv4_name_INNER', 'ipv4_name_OUTER', 'ipv4_forward', 'forward', 'ipv4_output', 'output',
    }
    assert destroyed(rendered(tree, tree)) == set()


def test_global_change_rebuilds_rejecting_state_policy_without_family_chains():
    tree = configuration({'action': 'accept'})
    tree['firewall']['global-options'] = {'state-policy': {'invalid': {'action': 'reject'}}}
    updated = deepcopy(tree)
    updated['firewall']['global-options']['reject-response'] = 'admin-prohibited'
    assert destroyed(rendered(updated, tree)) == {'input'}


def test_hook_restrictions_follow_nested_and_map_jumps(monkeypatch):
    # Model a future unsupported hook so indirect rejection cannot bypass verification.
    monkeypatch.setitem(firewall.NFT_FILTER_HOOKS, 'postrouting', ('postrouting', 'filter'))
    tree = {'firewall': {'ipv4': {
        'postrouting': {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'OUTER'}}}},
        'name': {
            'OUTER': {'rule': {'10': {'map': 'M'}}},
            'INNER': {'rule': {'10': {'action': 'reject'}}},
        },
    }, 'group': {'map': {'ipv4': {'M': {
        'match': {'protocol': True}, 'result-type': 'verdict',
        'entry': {'one': {'protocol': 'tcp', 'result': {'action': 'jump', 'jump-target': 'INNER'}}},
    }}}}}}

    with pytest.raises(RouterError, match='INNER rule 10: reject is not supported in the postrouting hook'):
        firewall.verify(tree, None)
