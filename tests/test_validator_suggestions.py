"""Failure suggestions preserve validation and canonical candidate spelling."""

import pytest

from nvyr.errors import ValidationError
from nvyr.helpers import timezones, validators
from nvyr.schema import Schema


def test_mangles_only_transform_input():
    choices = ['alpha-beta.gamma', 'alpha_beta,gamma']
    assert validators.suggest_values(
        'alpha-beta.gamma', choices, mangles=[['-', '_'], ['.', ',']], limit=3, cutoff=1,
    ) == ['alpha_beta,gamma']
    assert choices == ['alpha-beta.gamma', 'alpha_beta,gamma']


def test_mangles_are_optional_and_applied_in_order():
    assert validators.suggest_values('a-b', ['a_b'], cutoff=1) == []
    assert validators.suggest_values('a-b', ['a.b'], mangles=[['-', '_'], ['_', '.']], cutoff=1) == ['a.b']


def test_case_folding_preserves_canonical_values_and_collisions():
    choices = ['UTC', 'Utc', 'UTC']
    assert validators.suggest_values('utc', choices, cutoff=1) == []
    assert validators.suggest_values('utc', choices, ignore_case=True, limit=3, cutoff=1) == ['UTC', 'Utc']


def test_typo_ranking_limit_and_unrelated_input():
    choices = ['America/New_York', 'America/Nuuk', 'Europe/London']
    assert validators.suggest_values('America/New_Yrok', choices) == ['America/New_York']
    assert validators.suggest_values('asdfghjkl', choices) == []
    assert validators.suggest_values('Europe/Londn', []) == []


@pytest.mark.parametrize('value,expected', [
    ('america/new-york', 'America/New_York'),
    ('AMERICA/NEW_YORK', 'America/New_York'),
    ('America/New_Yrok', 'America/New_York'),
    ('Europe/Londn', 'Europe/London'),
    ('utc', 'UTC'),
])
def test_timezone_failure_suggests_installed_canonical_name(value, expected):
    node = {'kind': 'leaf_node', 'validators': {'checks': {'time-zone': {'name': 'time-zone'}}}}
    schema = Schema(node)
    with pytest.raises(ValidationError) as error:
        schema.validate(node, value)
    assert f"Did you mean '{expected}'?" in str(error.value)
    assert error.value.token == value
    assert timezones.valid_name(expected)


def test_timezone_unrelated_input_has_no_suggestion():
    result = validators.time_zone('Europe/NotAPlace')
    assert not result
    assert not result.suggestions
    message = validators.failure_message('Europe/NotAPlace', ['time-zone'], 'AND', result.suggestions)
    assert 'Expected an installed IANA time zone' in message
    assert 'Did you mean' not in message


def test_valid_values_never_discover_suggestions(monkeypatch):
    def unexpected():
        pytest.fail('Valid values must not discover suggestions')

    monkeypatch.setattr(timezones, 'available', unexpected)
    node = {'kind': 'leaf_node', 'validators': {'checks': {'time-zone': {'name': 'time-zone'}}}}
    Schema(node).validate(node, 'UTC')

    monkeypatch.setattr(validators, 'suggest_values', unexpected)
    assert validators.prepare_list('active-active active-passive')('active-active') is True
    assert validators.prepare_list('accept drop', separator=',')('accept,drop') is True


def test_secret_failure_never_exposes_value_or_suggestions():
    node = {'kind': 'leaf_node', 'secret': True,
            'validators': {'checks': {'text': {'name': 'text'}}}}
    schema = Schema(node, validators={
        'text': lambda value: validators.ValidationFailure(suggestions=['private-correction']),
    })
    with pytest.raises(ValidationError) as error:
        schema.validate(node, 'private-input')
    assert str(error.value) == 'Invalid credential value; check the expected format'
    assert error.value.token is None


def test_failure_results_preserve_and_or_semantics():
    node = {'kind': 'leaf_node', 'validators': {'checks': {
        'text': {'name': 'text'}, 'time-zone': {'name': 'time-zone'},
    }}}
    with pytest.raises(ValidationError, match="Did you mean 'UTC'"):
        Schema(node).validate(node, 'utc')

    node['validators']['mode'] = 'OR'
    Schema(node).validate(node, 'utc')
    with pytest.raises(ValidationError, match="Did you mean 'UTC'"):
        Schema(node, validators={'text': lambda value: False}).validate(node, 'utc')


def test_timezone_suggestions_follow_installed_candidates(monkeypatch):
    monkeypatch.setattr(timezones, 'available', lambda: ['Europe/London'])
    result = validators.time_zone('america/new-york')
    assert not result
    assert not result.suggestions


def test_list_validator_owns_its_parameterized_suggestions():
    result = validators.listed('active-pasive', values='active-active active-passive')
    assert isinstance(result, validators.ValidationFailure)
    assert not result
    assert result.suggestions == ('active-passive',)

    result = validators.listed('active-pasive', values='dev-admin sys-admin net-admin read-only')
    assert not result
    assert not result.suggestions


def test_prepared_list_failure_reaches_schema_error():
    node = {'kind': 'leaf_node', 'validators': {'checks': {
        'list': {'name': 'list', 'args': {'values': 'active-active active-passive'}},
    }}}
    with pytest.raises(ValidationError, match="Did you mean 'active-passive'"):
        Schema(node).validate(node, 'active-pasive')


def test_joined_lists_suggest_complete_valid_values():
    check = validators.prepare_list('accept reject drop', separator=',')
    result = check('accept,rejct,drop')
    assert not result
    assert result.suggestions == ('accept,reject,drop',)
    assert check(result.suggestions[0]) is True

    result = check('accept,rejct,asdfghjkl')
    assert not result
    assert not result.suggestions


def test_other_validator_messages_stay_unchanged():
    assert validators.failure_message('invalid', ['text'], 'AND') == (
        "Invalid value 'invalid'. Expected nonempty single-line text without control characters."
    )


@pytest.mark.parametrize('name,value,expected,args', [
    ('container-capability', 'net_admn', 'net-admin', {}),
    ('container-capability', 'NONE', 'none', {}),
    ('ip-protocol', 'ipv6_icpm', 'ipv6-icmp', {}),
    ('icmp-type', 'destination-unreachble', 'destination-unreachable', {}),
    ('icmpv6-type', 'nd-neighbor-solicitaton', 'nd-neighbor-solicit', {}),
    ('bgp-community', 'no_advertize', 'no-advertise', {'modifiers': False}),
    ('bgp-community', 'local-as', 'local-AS', {}),
    ('bgp-community', 'additve', 'additive', {'large': True}),
    ('bgp-remote-as', 'externl', 'external', {}),
    ('geoip-country', 'us', 'US', {}),
    ('log-flags', 'ether,tcp_optons', 'ether,tcp-options', {}),
    ('tcp-flags', 'syn,not ACK', 'syn,not ack', {}),
])
def test_named_validator_suggestions_reach_schema_and_are_valid(name, value, expected, args):
    node = {'kind': 'leaf_node', 'validators': {'checks': {
        name: {'name': name, 'args': args},
    }}}
    schema = Schema(node)
    with pytest.raises(ValidationError, match=f"Did you mean '{expected}'"):
        schema.validate(node, value)

    schema.validate(node, expected)


@pytest.mark.parametrize('name,value,args', [
    ('bgp-community', 'no_advertize', {'large': True}),
    ('bgp-community', 'additve', {'modifiers': False}),
    ('bgp-community', 'additive', {'modifiers': False}),
    ('bgp-community', '65536:1', {}),
    ('bgp-community', '1:2', {'large': True}),
    ('bgp-community', '1:2:4294967296', {'large': True}),
    ('bgp-remote-as', '0', {}),
    ('bgp-remote-as', '4294967296', {}),
    ('geoip-country', 'USA', {}),
    ('geoip-country', 'xx', {}),
    ('ip-protocol', '6', {}),
    ('icmp-type', 'echo-reply,echo-request', {}),
    ('log-flags', 'ether,ether', {}),
    ('log-flags', 'ether,ETHER', {}),
    ('log-flags', 'ether,unknown', {}),
    ('tcp-flags', 'syn,not syn', {}),
    ('tcp-flags', 'syn,SYN', {}),
    ('tcp-flags', 'syn,not SYN', {}),
    ('tcp-flags', 'syn,unknown', {}),
])
def test_invalid_values_do_not_get_misleading_suggestions(name, value, args):
    result = validators.REGISTRY[name](value, **args)
    assert not result
    assert not getattr(result, 'suggestions', ())


def test_cpu_suggestions_use_current_setting_capabilities(monkeypatch):
    from nvyr.helpers import cpu_settings

    calls = []

    def available(setting):
        calls.append(setting)
        return {'governor': ['performance'],
                'energy-performance': ['balance-performance']}[setting]

    monkeypatch.setattr(cpu_settings, 'available', available)
    result = validators.cpu_policy('balance_performnce', 'energy-performance')
    assert not result
    assert result.suggestions == ('balance-performance',)
    assert calls == ['energy-performance']
    assert not validators.cpu_policy('balance_performnce', 'governor').suggestions
    assert not validators.cpu_policy('powersav', 'governor').suggestions

    monkeypatch.setattr(cpu_settings, 'available', lambda setting: [])
    assert not validators.cpu_policy('performanc', 'governor').suggestions


@pytest.mark.parametrize('name,value,args', [
    ('container-capability', 'net-admin', {}),
    ('ip-protocol', 'tcp', {}),
    ('icmp-type', 'echo-request', {}),
    ('icmpv6-type', 'echo-request', {}),
    ('bgp-community', '65535:65535', {}),
    ('bgp-community', '1:2:4294967295', {'large': True}),
    ('bgp-community', 'no-advertise', {'modifiers': False}),
    ('bgp-remote-as', '4294967295', {}),
    ('geoip-country', 'US', {}),
    ('log-flags', 'ether,tcp-options', {}),
    ('tcp-flags', 'syn,not ack', {}),
])
def test_named_valid_values_skip_suggestion_work(monkeypatch, name, value, args):
    def unexpected(*args, **kwargs):
        pytest.fail('Valid values must not discover suggestions')

    monkeypatch.setattr(validators, 'suggest_values', unexpected)
    assert validators.REGISTRY[name](value, **args) is True
