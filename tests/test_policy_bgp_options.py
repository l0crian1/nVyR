"""BGP policy boundaries, shared names, dependency guards, and native reconciliation."""

import pytest

from nvyr.config_scripts import policy
from nvyr.errors import ValidationError
from nvyr.helpers.frr_policy import adapter
from nvyr.helpers.template import render
from nvyr.helpers.validators import bgp_community, bgp_policy_adjustment, frr_policy_regex
from nvyr.schema import Schema


def test_standard_and_expanded_completion(controller, session):
    controller.execute('set policy community-list standard STANDARD rule 10 action permit community no-export', session)
    controller.execute('set policy community-list expanded EXPANDED rule 10 action permit regex "65000:"', session)
    choices = dict(controller.completion('set policy route-map IMPORT rule 10 match community-list ', session)['candidates'])
    assert 'STANDARD' in choices
    assert 'EXPANDED' in choices


def test_referenced_as_path_deletion_is_blocked(controller, session):
    controller.execute('set policy as-path-list TRANSIT rule 10 action permit regex "_65000_"', session)
    controller.execute('set policy route-map IMPORT rule 10 action permit match as-path-list TRANSIT', session)
    with pytest.raises(ValidationError, match='referenc'):
        controller.execute('delete policy as-path-list TRANSIT', session)


def test_referenced_community_deletion_is_blocked(controller, session):
    controller.execute('set policy community-list expanded CUSTOMER rule 10 action permit regex "65000:"', session)
    controller.execute('set policy route-map IMPORT rule 10 action permit match community-list CUSTOMER', session)
    with pytest.raises(ValidationError, match='referenc'):
        controller.execute('delete policy community-list expanded CUSTOMER', session)


def test_referenced_call_deletion_is_blocked(controller, session):
    controller.execute('set policy route-map COMMON rule 10 action permit', session)
    controller.execute('set policy route-map IMPORT rule 10 action permit call COMMON', session)
    with pytest.raises(ValidationError, match='referenc'):
        controller.execute('delete policy route-map COMMON', session)


def test_as_path_count_native_bound(controller, session):
    controller.execute('set policy route-map IMPORT rule 10 match as-path-count 1028', session)
    with pytest.raises(ValidationError):
        controller.execute('set policy route-map IMPORT rule 10 match as-path-count 1029', session)


def test_community_modifiers_only_apply_to_setters():
    assert bgp_community('no-export', modifiers=False)
    assert not bgp_community('no-export', large=True, modifiers=False)
    assert not bgp_community('none', modifiers=False)
    assert not bgp_community('additive', modifiers=False)
    assert bgp_community('none')
    assert not bgp_community('65536:1')
    assert not bgp_community('1:2:4294967296', large=True)


def test_adjustment_boundaries_and_sign_preservation():
    assert bgp_policy_adjustment('+4294967295')
    assert bgp_policy_adjustment('-4294967295')
    assert not bgp_policy_adjustment('+4294967296')
    assert not bgp_policy_adjustment('++50')
    assert bgp_policy_adjustment('+0')
    assert not bgp_policy_adjustment('-0', allow_zero_adjustment=False)
    lines = render('frr/policy.conf.j2', {'configuration': {'route-map': {'P': {'rule': {'10': {
        'action': 'permit', 'set': {'local-preference': '+050', 'metric': '-020'}}}}}}}).splitlines()
    assert ' set local-preference +50' in lines
    assert ' set metric -20' in lines


def test_missing_list_operand_rejected():
    configuration = {'as-path-list': {'P': {'rule': {'10': {'action': 'permit'}}}}}
    with pytest.raises(ValidationError, match='regex is required'):
        policy.verify(configuration, None)


def test_posix_expression_is_not_validated_as_python():
    assert frr_policy_regex('^[[:digit:]]+_')


@pytest.mark.parametrize('command', [
    'set policy as-path-list BAD rule 10 regex "["',
    'set policy community-list expanded BAD rule 10 regex "("',
    'set policy large-community-list expanded BAD rule 10 regex "["',
    'set policy route-map BAD rule 10 set ipv6 next-hop local 2001:db8::1',
    'set policy route-map BAD rule 10 set ipv6 next-hop local fe80::1%eth0',
    'set policy route-map BAD rule 10 set ipv6 next-hop local 192.0.2.1',
    'set policy route-map BAD rule 10 set ipv6 next-hop global fe80::1',
    'set policy route-map BAD rule 10 set ipv6 next-hop global ff02::1',
    'set policy route-map BAD rule 10 set ipv6 next-hop global ::',
    'set policy route-map BAD rule 10 set ipv6 next-hop global 2001:db8::1%eth0',
])
def test_standalone_policy_values_rejected_at_entry(controller, session, command):
    with pytest.raises(ValidationError):
        controller.execute(command, session)

    assert not session.mutations


@pytest.mark.parametrize('kind, value', [('local', '2001:db8::1'), ('global', 'fe80::1')])
def test_loaded_policy_next_hops_use_schema_validation(kind, value):
    configuration = {'policy': {'route-map': {'P': {'rule': {'10': {
        'action': 'permit', 'set': {'ipv6': {'next-hop': {kind: value}}}}}}}}}

    with pytest.raises(ValidationError):
        Schema.bundled().validate_configuration(configuration)


def test_loaded_policy_regex_uses_schema_validation():
    configuration = {'policy': {'as-path-list': {'P': {'rule': {'10': {
        'action': 'permit', 'regex': '['}}}}}}

    with pytest.raises(ValidationError, match='FRR regular expression'):
        Schema.bundled().validate_configuration(configuration)


def test_valid_posix_expression_and_next_hops_at_entry(controller, session):
    controller.execute('set policy as-path-list P rule 10 action permit regex "^[[:digit:]]+_"', session)
    controller.execute('set policy route-map P rule 10 action permit set ipv6 next-hop global fd00::1 local fe80::1', session)


def test_repeated_regex_validation_compiles_once(monkeypatch):
    from nvyr.helpers import validators

    run = validators.subprocess.run
    calls = []

    def recorded(*args, **kwargs):
        calls.append(args[0])
        return run(*args, **kwargs)

    frr_policy_regex.cache_clear()
    monkeypatch.setattr(validators.subprocess, 'run', recorded)
    try:
        assert frr_policy_regex('_65000_')
        assert frr_policy_regex('_65000_')
        assert len(calls) == 1
    finally:
        frr_policy_regex.cache_clear()


def test_empty_setter_and_optional_list_flags():
    configuration = {'community-list': {'standard': {'C': {'rule': {'10': {
        'action': 'permit', 'community': ['65000:1']}}}}},
        'route-map': {'P': {'rule': {'10': {'action': 'permit', 'match': {'community-list': {'C': {}}}}}}}}
    policy.verify(configuration, None)
    configuration['route-map']['P']['rule']['10']['set'] = {}
    with pytest.raises(ValidationError, match='at least one setting'):
        policy.verify(configuration, None)


def test_community_match_modes_conflict():
    configuration = {'community-list': {'standard': {'C': {'rule': {'10': {
        'action': 'permit', 'community': ['65000:1']}}}}},
        'route-map': {'P': {'rule': {'10': {'action': 'permit', 'match': {
            'community-list': {'C': {'any': {}, 'exact-match': {}}}}}}}}}
    with pytest.raises(ValidationError, match='mutually exclusive'):
        policy.verify(configuration, None)


def test_next_hop_global_and_local_can_coexist():
    configuration = {'route-map': {'P': {'rule': {'10': {'action': 'permit', 'set': {
        'ipv6': {'next-hop': {'global': '2001:db8::1', 'local': 'fe80::1'}}}}}}}}
    policy.verify(configuration, None)
    configuration['route-map']['P']['rule']['10']['set']['ipv6']['next-hop']['peer-address'] = {}
    with pytest.raises(ValidationError, match='mutually exclusive'):
        policy.verify(configuration, None)


def test_native_list_scope_survives_type_change_and_preserves_foreign_objects():
    before = ('bgp community-list standard OWN seq 10 permit 65000:1\n'
              'bgp community-list standard FOREIGN seq 10 permit 65000:2\n'
              'router bgp 65000\n bgp router-id 192.0.2.1\nexit\n')
    desired = adapter.desired('bgp community-list expanded OWN seq 10 permit ^65000:\n')
    result = adapter.replace(before, desired)
    assert 'standard OWN' not in result
    assert 'standard FOREIGN seq 10 permit 65000:2' in result
    assert 'router bgp 65000' in result
    assert adapter.select(result, desired) == desired
    removed = adapter.replace(result, {scope: [] for scope in desired})
    assert 'expanded OWN' not in removed


def test_same_route_map_lists_keep_both_match_and_delete_references(controller, session):
    controller.execute('set policy large-community-list standard C rule 10 action permit community 65000:1:1', session)
    controller.execute('set policy route-map P rule 10 action permit set large-community-delete C', session)
    with pytest.raises(ValidationError, match='referenc'):
        controller.execute('delete policy large-community-list standard C', session)
