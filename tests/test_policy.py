"""Routing policy schema, validation, native rendering, and ownership boundaries."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import policy
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import frr_policy, frr_reload, validators
from nvyr.helpers.template import render


def test_filters_and_route_maps_share_one_owner(controller, engine, session, monkeypatch):
    applied = []
    monkeypatch.setattr(frr_reload, 'manager', SimpleNamespace(apply=lambda *args, **kwargs: applied.append(args)))
    controller.execute('set policy access-list ipv4 ACL rule 10 action permit address 10.0.20.0 wildcard-mask 0.0.255.0', session)
    controller.execute('set policy prefix-list ipv4 PL rule 10 action permit prefix 10.0.0.0/8 ge 16 le 24', session)
    controller.execute('set policy route-map IMPORT rule 10 action permit match ipv4 access-list ACL', session)
    controller.execute('set policy route-map IMPORT rule 10 set local-preference 200', session)

    result = engine.commit(session)

    assert result['results'] == {'policy': {'success': True}}
    assert len(applied) == 1
    assert applied[0][0] == 'policy'
    native = applied[0][1]
    assert native['access-list ACL'] == ['access-list ACL seq 10 permit 10.0.0.0 0.0.255.0']
    assert native['route-map IMPORT'] == [
        'route-map IMPORT permit 10\n match ip address ACL\n set local-preference 200',
    ]


def test_ipv6_filters_exactness_and_numeric_rule_order(controller, engine, session):
    controller.execute('set policy access-list ipv6 ACL rule 20 action deny any', session)
    controller.execute('set policy access-list ipv6 ACL rule 2 action permit prefix 2001:db8::/32 exact-match', session)
    controller.execute('set policy prefix-list ipv6 PL rule 10 action permit prefix 2001:db8::/32 ge 48 le 64', session)
    result = engine.commit(session)
    assert result['results']['policy']['success']

    commands = render('frr/policy.conf.j2', {'configuration': engine.running['policy']}).splitlines()
    assert commands == [
        'ipv6 access-list ACL seq 2 permit 2001:db8::/32 exact-match',
        'ipv6 access-list ACL seq 20 deny any',
        'ipv6 prefix-list PL seq 10 permit 2001:db8::/32 ge 48 le 64',
    ]


def test_reference_deletion_and_missing_provider(controller, engine, session):
    controller.execute('set policy prefix-list ipv4 PL rule 10 action permit prefix 10.0.0.0/8', session)
    controller.execute('set policy route-map IMPORT rule 10 action permit match ipv4 prefix-list PL', session)

    with pytest.raises(RouterError, match='referenc'):
        controller.execute('delete policy prefix-list ipv4 PL', session)

    controller.execute('set policy route-map IMPORT rule 10 match ipv6 prefix-list MISSING', session)
    result = engine.commit(session)
    assert 'MISSING' in result['results']['policy']['error']
    assert engine.running == {}


@pytest.mark.parametrize('command', [
    'set policy prefix-list ipv4 BAD rule 01 action permit',
    'set policy prefix-list ipv4 BAD rule 0 action permit',
    'set policy prefix-list ipv4 BAD rule 4294967296 action permit',
    'set policy route-map BAD rule 65536 action permit',
    'set policy access-list ipv6 BAD rule 10 wildcard-mask 0.0.0.0',
    'set policy access-list ipv4 BAD rule 10 address 300.0.0.0',
    'set policy prefix-list ipv4 BAD rule 10 prefix 10.1.2.3/24',
    'set policy prefix-list ipv6 BAD rule 10 le 129',
    'set policy route-map BAD rule 10 set community 65536:1',
    'set policy route-map BAD rule 10 set large-community 1:2:4294967296',
    'set policy route-map BAD rule 10 set as-path prepend "65000 nope"',
    'set policy route-map BAD rule 10 set as-path prepend "0"',
])
def test_invalid_schema_values(controller, session, command):
    with pytest.raises(RouterError):
        controller.execute(command, session)
    assert not session.mutations


@pytest.mark.parametrize('kind, rule, error', [
    ('access-list', {'prefix': '10.0.0.0/8'}, 'action'),
    ('access-list', {'action': 'permit'}, 'choose'),
    ('access-list', {'action': 'permit', 'any': {}, 'prefix': '10.0.0.0/8'}, 'choose'),
    ('access-list', {'action': 'permit', 'address': '10.0.0.0'}, 'together'),
    ('access-list', {'action': 'permit', 'any': {}, 'wildcard-mask': '0.0.0.0'}, 'together'),
    ('access-list', {'action': 'permit', 'any': {}, 'exact-match': {}}, 'exact-match requires'),
    ('prefix-list', {'action': 'permit'}, 'prefix is required'),
    ('prefix-list', {'action': 'permit', 'prefix': '10.0.0.0/8', 'ge': '7'}, 'ge cannot'),
    ('prefix-list', {'action': 'permit', 'prefix': '10.0.0.0/8', 'le': '7'}, 'le cannot'),
    ('prefix-list', {'action': 'permit', 'prefix': '10.0.0.0/8', 'ge': '24', 'le': '16'}, 'ge cannot exceed'),
])
def test_filter_verification(kind, rule, error):
    with pytest.raises(ValidationError, match=error):
        policy.verify({kind: {'ipv4': {'TEST': {'rule': {'10': rule}}}}}, None)


def test_length_bounds_can_equal_the_prefix():
    policy.verify({'prefix-list': {'ipv4': {'TEST': {'rule': {
        '10': {'action': 'permit', 'prefix': '10.0.0.0/8', 'ge': '8', 'le': '8'},
    }}}}}, None)


@pytest.mark.parametrize('rule,error', [
    ({'set': {'metric': '1'}}, 'action'),
    ({'action': 'permit', 'set': {'community': ['additive']}}, 'at least one community'),
    ({'action': 'permit', 'set': {'large-community': ['additive']}}, 'at least one community'),
    ({'action': 'permit', 'match': {}}, 'at least one setting'),
    ({'action': 'permit', 'match': {'ipv4': {'next-hop': {}}}}, 'at least one setting'),
    ({'action': 'permit', 'set': {'as-path': {}}}, 'at least one setting'),
])
def test_route_map_verification(rule, error):
    with pytest.raises(ValidationError, match=error):
        policy.verify({'route-map': {'TEST': {'rule': {'10': rule}}}}, None)


def test_all_route_map_actions_and_matches_render():
    rule = {'action': 'permit', 'description': 'Policy rule', 'match': {
        'interface': 'eth1', 'metric': '100', 'tag': '200',
        'ipv4': {'prefix-list': 'PL4', 'next-hop': {'access-list': 'ACL4'}},
        'ipv6': {'access-list': 'ACL6', 'next-hop': {'prefix-list': 'PL6'}},
    }, 'set': {
        'metric': '50', 'local-preference': '200', 'weight': '100', 'origin': 'igp',
        'ipv4': {'next-hop': {'address': '192.0.2.1'}}, 'ipv6': {'next-hop': {'global': '2001:db8::1'}},
        'as-path': {'prepend': '65001 65001'},
        'community': ['65001:100', '65001:200', 'additive'],
        'large-community': ['65001:100:200', 'additive'],
    }}
    original = deepcopy(rule)
    result = policy.generate({'route-map': {'IMPORT': {'rule': {'10': rule}}}}, None)
    commands = result['route-map IMPORT'][0].splitlines()
    assert sum(line.startswith(' match ') for line in commands) == 7
    assert sum(line.startswith(' set ') for line in commands) == 9
    assert ' set as-path prepend 65001 65001' in commands
    assert ' set community 65001:100 65001:200 additive' in commands
    assert ' set metric 50' in commands
    assert rule == original


def test_community_and_as_path_validators():
    assert validators.bgp_community('65535:65535')
    assert validators.bgp_community('4294967295:0:4294967295', large=True)
    assert validators.as_path_sequence('1 4294967295 1')
    assert not validators.bgp_community('1:2:3')
    assert not validators.as_path_sequence('65001\n65002')


def test_check_does_not_generate_or_apply(controller, engine, session, monkeypatch):
    controller.execute('set policy prefix-list ipv4 PL rule 10 action permit prefix 10.0.0.0/8', session)
    monkeypatch.setattr(policy, 'generate', lambda *args: pytest.fail('commit check generated configuration'))
    assert engine.check(session)['results']['policy']['success']


@pytest.mark.parametrize('configuration', [
    {'access-list': {'ipv4': {'EMPTY': {}}}},
    {'access-list': {'ipv6': {'EMPTY': {'description': 'No rules'}}}},
    {'prefix-list': {'ipv4': {'EMPTY': {}}}},
    {'prefix-list': {'ipv6': {'EMPTY': {}}}},
    {'route-map': {'EMPTY': {}}},
])
def test_empty_policies_are_rejected(configuration):
    with pytest.raises(ValidationError, match='at least one rule is required'):
        policy.verify(configuration, None)


def test_adapter_preserves_sequences_and_unowned_configuration():
    current = '''frr defaults traditional
ip route 192.0.2.0/24 blackhole
access-list FOREIGN seq 10 deny any
ip prefix-list MANAGED seq 10 permit 10.0.0.0/8
route-map MANAGED permit 10
 set metric 10
 match interface eth0
exit
route-map MANAGED deny 20
exit
route-map FOREIGN permit 10
 match ip address FOREIGN
exit
router bgp 65000
 address-family ipv4 unicast
  neighbor 192.0.2.1 route-map MANAGED in
 exit-address-family
exit
end
'''
    scopes = ['ip prefix-list MANAGED', 'route-map MANAGED']
    selected = frr_policy.adapter.select(current, scopes)
    assert selected['route-map MANAGED'] == [
        'route-map MANAGED deny 20',
        'route-map MANAGED permit 10\n match interface eth0\n set metric 10',
    ]

    replaced = frr_policy.adapter.replace(current, {scope: [] for scope in scopes})
    assert 'ip route 192.0.2.0/24 blackhole' in replaced
    assert 'access-list FOREIGN seq 10 deny any' in replaced
    assert 'route-map FOREIGN permit 10\n match ip address FOREIGN\nexit' in replaced
    assert '  neighbor 192.0.2.1 route-map MANAGED in' in replaced
    assert frr_policy.adapter.select(replaced, scopes) == {scope: [] for scope in scopes}

    restored = frr_policy.adapter.replace(replaced, selected)
    assert frr_policy.adapter.select(restored, scopes) == selected


def test_native_description_and_community_formatting():
    configuration = {
        'prefix-list': {'ipv4': {'PL': {'description': 'A policy; not a command', 'rule': {
            '10': {'action': 'permit', 'prefix': '10.0.0.0/8'},
        }}}},
        'route-map': {'RM': {'rule': {'10': {
            'action': 'permit', 'set': {'community': ['100:1', '2:2', '2:1', 'additive']},
        }}}},
    }
    commands = render('frr/policy.conf.j2', {'configuration': configuration}).splitlines()
    assert 'ip prefix-list PL description A policy; not a command' in commands
    assert ' set community 2:1 2:2 100:1 additive' in commands
