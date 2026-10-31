"""Typed inclusions, bounded graphs, completion and transitive replacement."""

from copy import deepcopy
import re

import pytest

from nvyr.errors import RouterError
from nvyr.helpers.nftables_singletons import verify_group_inclusions
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed, nested_tree


CASES = [
    ('address-group', 'ipv4', 'address', '192.0.2.1', '198.51.100.1'),
    ('address-group', 'ipv6', 'address', '2001:db8::1', '2001:db8::2'),
    ('interface-group', None, 'interface', 'eth0', 'eth1'),
    ('mac-group', None, 'address', '02:00:00:00:00:01', '02:00:00:00:00:02'),
    ('port-group', None, 'port', '443', '8000-8080'),
]


def group_tree(kind, family, definitions):
    groups = {kind: {family: definitions} if family else definitions}
    return {'firewall': {'group': groups}}


@pytest.mark.parametrize('kind,family,member,first,second', CASES)
def test_nested_members_are_unioned_without_inheriting_settings(kind, family, member, first, second):
    definitions = {
        'CHILD': {member: [first], 'description': 'Child only', 'counter': True, 'last-used': True},
        'MIDDLE': {'include-group': ['CHILD']},
        'PARENT': {'include-group': ['CHILD', 'MIDDLE'], member: [first, second]},
    }
    tree = group_tree(kind, family, definitions)
    original = deepcopy(tree)
    text = rendered(tree)
    parent = re.search(r'set \w+_PARENT \{(.*?)\n    \}', text, re.S)[1]

    assert parent.count(first) == 1
    assert second in parent
    assert 'Child only' not in parent
    assert 'counter;' not in parent and 'last;' not in parent
    assert tree == original


@pytest.mark.parametrize('kind,family,member,first,second', CASES)
def test_cli_inclusion_completion_removal_and_dependency_protection(controller, engine, session, kind, family, member, first, second):
    selector = kind + (' ' + family if family else '')
    base = 'firewall group ' + selector
    controller.execute(f'set {base} CHILD {member} {first}', session)
    controller.execute(f'set {base} OTHER {member} {second}', session)
    controller.execute(f'set {base} PARENT include-group CHILD include-group OTHER', session)

    choices = dict(controller.completion(f'set {base} NEW include-group ', session)['candidates'])
    assert {'CHILD', 'OTHER', 'PARENT'} <= choices.keys()
    with pytest.raises(RouterError, match='referenced'):
        controller.execute(f'delete {base} CHILD', session)
    with pytest.raises(RouterError, match='referenced'):
        controller.execute(f'rename {base} CHILD to {base} RENAMED', session)
    assert engine.commit(session)['results']['firewall']['success']

    controller.execute(f'delete {base} PARENT include-group CHILD', session)
    controller.execute(f'delete {base} CHILD', session)
    assert engine.commit(session)['results']['firewall']['success']
    with pytest.raises(RouterError, match='referenced'):
        controller.execute(f'delete {base} OTHER', session)


@pytest.mark.parametrize('definitions,message', [
    ({'A': {'include-group': ['A']}}, 'A -> A'),
    ({'A': {'include-group': ['B']}, 'B': {'include-group': ['C']}, 'C': {'include-group': ['A']}}, 'A -> B -> C -> A'),
    ({'A': {'include-group': ['MISSING']}}, 'not configured'),
    ({'A': {'include-group': ['B']}, 'B': {'dynamic': {}}}, 'cannot include dynamic or geoip'),
    ({'A': {'include-group': ['B']}, 'B': {'geoip': {'country': ['US']}}}, 'cannot include dynamic or geoip'),
    ({'A': {'dynamic': {}, 'include-group': ['B']}, 'B': {}}, 'cannot be combined'),
    ({'A': {'geoip': {'country': ['US']}, 'include-group': ['B']}, 'B': {}}, 'cannot be combined'),
])
def test_invalid_inclusions_fail_even_without_rules(definitions, message):
    with pytest.raises(RouterError, match=message):
        rendered(group_tree('address-group', 'ipv4', definitions))


@pytest.mark.parametrize('reverse', [False, True])
def test_eight_links_allowed_ninth_rejected_regardless_of_cache_order(reverse):
    definitions = {f'G{index}': {'include-group': [f'G{index + 1}']} for index in range(8)}
    definitions['G8'] = {'port': ['443']}
    if reverse:
        definitions = dict(reversed(list(definitions.items())))
    groups = {'port-group': definitions}
    verify_group_inclusions(groups)

    definitions['TOO_DEEP'] = {'include-group': ['G0']}
    with pytest.raises(RouterError, match='exceeds 8 levels: TOO_DEEP -> G0 -> G1.*G8'):
        verify_group_inclusions(groups)


def test_cycle_walk_is_bounded_before_python_recursion_limit():
    definitions = {f'G{index}': {'include-group': [f'G{index + 1}']} for index in range(2000)}
    definitions['G2000'] = {'include-group': ['G0']}
    with pytest.raises(RouterError, match='exceeds 8 levels'):
        verify_group_inclusions({'port-group': definitions})


def test_same_name_in_another_type_or_family_cannot_satisfy_inclusion():
    groups = {
        'address-group': {'ipv4': {'PARENT': {'include-group': ['CHILD']}}, 'ipv6': {'CHILD': {}}},
        'port-group': {'CHILD': {}},
    }
    with pytest.raises(RouterError, match="'CHILD' is not configured in firewall group address-group ipv4"):
        verify_group_inclusions(groups)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_child_change_rebuilds_parent_sets_nested_chains_and_nat(family):
    before = nested_tree(family)
    definitions = before['firewall']['group']['address-group'][family]
    definitions['MIDDLE'] = {'include-group': ['A']}
    definitions['PARENT'] = {'include-group': ['MIDDLE']}
    before['firewall'][family]['name']['BOTTOM']['rule']['10']['source-address-group'] = 'PARENT'
    if family == 'ipv4':
        nat_rule = {
            'source-address-group': 'PARENT',
            'outbound-interface': ['eth0'],
            'translation': {'address': 'masquerade'},
        }
        before['nat'] = {'source': {'rule': {'10': nat_rule}}}

    after = deepcopy(before)
    after['firewall']['group']['address-group'][family]['A']['address'] = [
        '198.51.100.1' if family == 'ipv4' else '2001:db8:1::1']
    text = rendered(after, before)

    assert destroyed(text, 'set') == {family + '_address_group_' + name for name in ('A', 'MIDDLE', 'PARENT')}
    assert {family + '_name_' + name for name in ('BOTTOM', 'MIDDLE', 'TOP')} <= destroyed(text)
    assert family + '_name_UNRELATED' not in destroyed(text)
    if family == 'ipv4':
        assert {'ipv4_nat_postrouting', 'nat_postrouting'} <= destroyed(text)


def test_removed_inclusion_rebuilds_parent_but_preserves_other_child():
    before = group_tree('port-group', None, {
        'A': {'port': ['80']}, 'B': {'port': ['443']}, 'PARENT': {'include-group': ['A', 'B']},
    })
    after = deepcopy(before)
    after['firewall']['group']['port-group']['PARENT']['include-group'] = ['B']
    del after['firewall']['group']['port-group']['A']
    text = rendered(after, before)
    assert destroyed(text, 'set') == {'port_group_A', 'port_group_PARENT'}
    assert 'elements = { 443 };' in text
    assert 'elements = { 80' not in text


def test_fail_safe_inclusions_use_local_suggestions_and_verification(controller, engine, session):
    controller.execute('set firewall group port-group MAIN port 443', session)
    controller.execute('set firewall fail-safe group port-group CHILD port 22', session)
    controller.execute('set firewall fail-safe group port-group PARENT include-group CHILD', session)
    choices = dict(controller.completion('set firewall fail-safe group port-group NEW include-group ', session)['candidates'])
    assert 'CHILD' in choices and 'MAIN' not in choices
    assert engine.commit(session)['results']['firewall_failsafe']['success']

    controller.execute('delete firewall fail-safe group port-group CHILD', session)
    result = engine.commit(session)['results']['firewall_failsafe']
    assert not result['success']
    assert 'firewall fail-safe group port-group' in result['error']
    assert 'not configured' in result['error']
