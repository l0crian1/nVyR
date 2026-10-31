"""Committed retention policy preserves running, saved and recovery state."""

import pytest

from nvyr.engine import Engine
from nvyr.errors import PersistenceError, RouterError
from nvyr.helpers import access
from nvyr.storage import Store
from nvyr.tree import lookup
from tests.lifecycle import recorded_registry


PATH = ('system', 'configuration', 'commit-revisions')


def configure(controller, engine, session, value):
    controller.execute(f'set system configuration commit-revisions {value}', session)
    return engine.commit(session)


def commits(controller, engine, session, count):
    for _ in range(count):
        controller.execute(f'set system host-name router{engine.commit_id + 1}', session)
        engine.commit(session)


def restart(engine, **kwargs):
    return Engine(engine.schema, recorded_registry(engine.schema),
                  Store(engine.store.directory), **kwargs)


def test_always_default_description_and_explicit_configuration(controller, engine, session):
    node = engine.schema.resolve(PATH).node
    assert node['default'] == {'mode': 'always', 'value': '20'}
    assert node['description'].endswith('(default: 20)')
    assert lookup(engine.schema.defaults({'system': {}}), PATH) == '20'
    assert engine.running == {}

    # Retention also applies before the system branch has ever been configured.
    for number in range(22):
        controller.execute(f'set interfaces dummy dum{number}', session)
        engine.commit(session)

    assert engine.store.history_ids() == list(range(3, 23))
    assert 'system' not in engine.running
    engine.save(session)
    assert 'system' not in engine.store.read('boot.json')


@pytest.mark.parametrize('value', ['0', '-1', '1.5', 'abc'])
def test_invalid_limits_rejected_before_staging(controller, engine, session, value):
    with pytest.raises(RouterError):
        controller.execute(f'set system configuration commit-revisions {value}', session)

    assert not session.mutations and engine.store.history_ids() == [0]


def test_smaller_and_larger_limits_apply_after_commit(controller, engine, session):
    commits(controller, engine, session, 6)
    controller.execute('set system configuration commit-revisions 3', session)
    engine.check(session)
    assert engine.store.history_ids() == list(range(7))

    result = engine.commit(session)
    assert result['results'] == {'configuration': {'success': True}}
    assert engine.store.history_ids() == [5, 6, 7]
    assert lookup(engine.running, PATH) == '3'

    configure(controller, engine, session, 6)
    commits(controller, engine, session, 2)
    assert engine.store.history_ids() == [5, 6, 7, 8, 9, 10]
    assert engine.commit_id == 10
    with pytest.raises(PersistenceError, match='not retained'):
        engine.store.historical(engine.commit_id, 6)


@pytest.mark.parametrize('path', ['system configuration commit-revisions', 'system configuration'])
def test_removal_restores_twenty_without_explicit_default(controller, engine, session, path):
    configure(controller, engine, session, 1)
    controller.execute(f'delete {path}', session)
    engine.commit(session)
    commits(controller, engine, session, 22)

    assert len(engine.store.history_ids()) == 20
    assert lookup(engine.running, PATH, None) is None
    assert lookup(engine.schema.defaults(engine.running), PATH) == '20'


def test_partial_commit_uses_successfully_published_policy(controller, engine, session, monkeypatch):
    commits(controller, engine, session, 5)
    controller.execute('set system configuration commit-revisions 1', session)
    controller.execute('set system host-name successful', session)

    def fail(*args):
        raise RouterError('Configuration management verify failed')

    with monkeypatch.context() as patch:
        patch.setattr(engine.modules['configuration'], 'verify', fail)
        result = engine.commit(session)

    assert not result['results']['configuration']['success']
    assert result['results']['system']['success']
    assert engine.store.history_ids() == list(range(7))

    controller.execute('set firewall ipv4 input filter rule 10 description unfinished', session)
    result = engine.commit(session)
    assert result['results']['configuration']['success']
    assert not result['results']['firewall']['success']
    assert engine.store.history_ids() == [7]


def test_failed_publication_does_not_prune(controller, engine, session, monkeypatch):
    commits(controller, engine, session, 5)
    before = engine.store.history_ids()
    controller.execute('set system configuration commit-revisions 1', session)
    write = engine.store.write

    def fail(name, value, **kwargs):
        if name == 'state.json':
            raise OSError('disk full')

        write(name, value, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(engine.store, 'write', fail)
        with pytest.raises(OSError, match='disk full'):
            engine.commit(session)

    assert set(before) <= set(engine.store.history_ids())
    assert engine.store.read('transaction.json')
    recovered = restart(engine)
    assert lookup(recovered.running, PATH, None) is None
    assert recovered.running['system']['host-name'] == 'router5'
    assert set(before) <= set(recovered.store.history_ids())


@pytest.mark.parametrize('recovery', ['timer', 'restart'])
def test_one_revision_preserves_saved_and_commit_confirm_recovery(controller, engine, session, recovery):
    engine.clock = lambda: 100
    commits(controller, engine, session, 4)
    before = engine.running
    engine.save(session)
    controller.execute('set system configuration commit-revisions 1', session)
    engine.commit(session, minutes=1, confirmed_minutes=1)

    assert engine.store.history_ids() == [5]
    assert engine.store.read('boot.json') == before
    assert engine.store.read('confirmed.json')['before'] == before

    if recovery == 'timer':
        engine.clock = lambda: 161
        engine.tick()
        recovered = engine
    else:
        recovered = restart(engine)

    assert recovered.running == before and recovered.pending is None
    assert recovered.commit_id == 6
    assert recovered.store.history_ids() == [5, 6]
    assert recovered.store.read('boot.json') == before
    assert recovered.store.read('confirmed.json') is None


def test_restart_and_boot_use_respective_configuration_limits(controller, engine, session):
    configure(controller, engine, session, 5)
    engine.save(session)
    configure(controller, engine, session, 1)

    recovered = restart(engine)
    assert lookup(recovered.running, PATH) == '1'
    assert recovered.store.history_ids() == [2]

    booted = restart(recovered, boot_id='new-boot')
    assert lookup(booted.running, PATH) == '5'
    assert booted.store.history_ids() == [2, 3]


def test_startup_prunes_to_policy_and_preserves_non_history_records(engine):
    for number in range(30):
        engine.store.record(number, {}, reason='test', user='root')

    engine.store.write('state.json', {'id': 29, 'configuration': {}})
    engine.store.write('boot.json', {})
    engine.store.write('unrelated.json', {'value': 'keep'})
    recovered = restart(engine)

    assert recovered.store.history_ids() == list(range(10, 30))
    assert recovered.store.read('unrelated.json') == {'value': 'keep'}
    assert recovered.store.read('boot.json') == {}


def test_roles_and_history_suggestions(controller, engine, session):
    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError, match='Permission denied'):
            controller.execute('set system configuration commit-revisions 1', session)
    finally:
        access.role.reset(token)

    token = access.role.set('net-admin')
    try:
        configure(controller, engine, session, 1)
    finally:
        access.role.reset(token)

    choices = dict(controller.completion('compare ', session, explicit=True)['candidates'])
    assert '0' in choices and '1' not in choices
    assert engine.store.historical(engine.commit_id, 0) == engine.running
