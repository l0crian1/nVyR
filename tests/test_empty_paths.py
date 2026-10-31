import pytest

from nvyr.engine import Engine
from nvyr.errors import ValidationError
from nvyr.lexer import lex
from tests.lifecycle import recorded_registry
from nvyr.render import diff_commands, set_commands
from nvyr.tree import Mutation, lookup, overlay, projected_value


@pytest.mark.parametrize('suffix,delete', [
    ('address 1.1.1.1/32', 'address 1.1.1.1/32'),
    ('description test', 'description'), ('disable', 'disable'),
])
@pytest.mark.parametrize('commit_first', [False, True])
def test_delete_last_child_preserves_interface_through_commit_save_and_restart(
        controller, engine, session, suffix, delete, monkeypatch, commit_first):
    from nvyr.helpers import interfaces

    plans = []
    monkeypatch.setattr(interfaces.manager, 'replace', lambda owner, plan, **kw: plans.append((owner, plan)))
    controller.execute('set interfaces dummy dum0 ' + suffix, session)

    if commit_first:
        assert engine.commit(session)['results']['dummy']['success']

    controller.execute('delete interfaces dummy dum0 ' + delete, session)
    expected = {'interfaces': {'dummy': {'dum0': {}}}}

    assert engine.view(session) == expected
    assert projected_value(engine.running, session.mutations, ('interfaces', 'dummy', 'dum0')) == {}
    assert 'dum0' in dict(controller.completion('set interfaces dummy ', session)['candidates'])
    assert engine.commit(session)['results']['dummy']['success']
    assert engine.running == expected

    owner, plan = plans[-1]

    assert owner == 'dummy' and 'dum0' in plan
    assert plan['dum0']['attributes']['mtu'] == 1500

    engine.save(session)

    assert engine.store.read('boot.json') == expected

    restarted = Engine(engine.schema, recorded_registry(engine.schema), engine.store)

    assert restarted.running == expected
    assert list(set_commands(engine.schema, restarted.running)) == ['set interfaces dummy dum0']

    loaded = engine.open('load', '/dev/pts/2')
    engine.stage_configuration(loaded, expected, replace=True)

    assert engine.view(loaded) == expected


@pytest.mark.parametrize('configuration', [
    {'interfaces': {}}, {'interfaces': {'dummy': {}}},
    {'interfaces': {'dummy': {'dum0': {}}}}, {'firewall': {}},
    {'firewall': {'ipv4': {'forward': {'filter': {'rule': {}}}}}},
    {'protocols': {'static': {'route': {}}}},
])
def test_empty_containers_roundtrip_and_can_be_explicitly_deleted(engine, session, configuration):
    engine.schema.validate_configuration(configuration)

    for line in set_commands(engine.schema, configuration):
        tokens = lex(line)
        engine.mutate(session, 'set', tokens[1:])

    assert engine.view(session) == configuration
    assert engine.commit(session)['changed']

    engine.stage_configuration(session, {}, replace=True)

    assert engine.view(session) == {}

    engine.commit(session)

    assert engine.running == {}

    engine.stage_configuration(session, configuration, replace=True)

    assert engine.view(session) == configuration


def test_deleting_object_keeps_parent_until_parent_is_explicitly_deleted(controller, engine, session):
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('delete interfaces dummy dum0', session)

    assert engine.view(session) == {'interfaces': {'dummy': {}}}

    controller.execute('delete interfaces dummy', session)

    assert engine.view(session) == {'interfaces': {}}

    engine.commit(session)
    controller.execute('delete interfaces', session)

    assert engine.view(session) == {}
    assert engine.commit(session)['changed'] and engine.running == {}


def test_explicit_ancestor_delete_keeps_failed_owner_and_can_be_retried(controller, engine, session, monkeypatch):
    from nvyr.helpers import interfaces

    monkeypatch.setattr(interfaces, 'exists', lambda name: name == 'eth0')
    monkeypatch.setattr(interfaces.manager, 'replace', lambda *a, **kw: None)
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('set interfaces ethernet eth0', session)
    engine.commit(session)
    controller.execute('delete interfaces', session)
    original = engine.modules['ethernet'].verify

    def fail(configuration, context):
        raise ValidationError('Ethernet cannot be removed yet')

    monkeypatch.setattr(engine.modules['ethernet'], 'verify', fail)
    result = engine.commit(session)

    assert result['results']['dummy']['success']
    assert not result['results']['ethernet']['success']
    assert engine.running == {'interfaces': {'ethernet': {'eth0': {}}}}

    monkeypatch.setattr(engine.modules['ethernet'], 'verify', original)

    assert engine.view(session) == {}

    engine.commit(session)

    assert engine.running == {} and not session.mutations


def test_projected_empty_and_missing_containers_match_overlay():
    for tree in ({}, {'a': {}}, {'a': {'b': ['last']}}):
        for mutation in (Mutation('delete', ('a', 'b')),
                         Mutation('subtract', ('a', 'b'), 'last'),
                         Mutation('delete', ('a',))):
            intended = overlay(tree, [mutation])

            for path in ((), ('a',), ('a', 'b'), ('missing',)):
                assert projected_value(tree, [mutation], path) == lookup(intended, path)


def test_diff_to_empty_instance_only_deletes_the_child(engine):
    before = {'interfaces': {'dummy': {'dum0': {'address': ['1.1.1.1/32']}}}}
    after = {'interfaces': {'dummy': {'dum0': {}}}}

    assert list(diff_commands(engine.schema, before, after)) == ['delete interfaces dummy dum0 address']


def test_completions_show_generated_defaults_and_allow_empty_containers(controller, session):
    candidates = dict(controller.completion('set firewall ipv4 forward filter ', session, explicit=True)['candidates'])

    assert candidates['default-action'] == 'Default verdict (default: accept)'
    assert '<Enter>' in candidates

    candidates = dict(controller.completion('set interfaces dummy dum0 ', session, explicit=True)['candidates'])

    assert candidates['mtu'] == 'Maximum transmission unit in bytes (default: 1500)'
