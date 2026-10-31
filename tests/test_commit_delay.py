"""Scheduled snapshots, lock reservation, authorization and rollback deadlines."""

import threading
import time

import pytest

from nvyr.engine import Engine
from nvyr.errors import BusyError, LockError, RouterError, ValidationError
from nvyr.helpers import access
from nvyr.protocol import Client
from tests.test_engine import set_
from tests.test_integration import daemon


def schedule(engine, session, *, minutes=None):
    set_(engine, session, 'system host-name scheduled')
    return engine.schedule_commit(session, 0.5, minutes=minutes, confirmed_minutes=minutes)


def test_decimal_delay_freezes_candidate_and_preserves_later_edits(engine, session):
    now = [100.0]
    engine.clock = lambda: now[0]
    result = schedule(engine, session)
    assert result['when'] == 130
    assert engine.running == {}
    set_(engine, session, 'system host-name later')

    now[0] = 129.9
    engine.tick()
    assert engine.running == {}
    now[0] = 130
    engine.tick()

    assert engine.running['system']['host-name'] == 'scheduled'
    assert engine.view(session)['system']['host-name'] == 'later'
    assert session.commit_id == engine.commit_id == 1
    assert engine.scheduled is None
    assert engine.store.read('scheduled.json') is None
    assert engine.status(session)['events'][-1]['type'] == 'scheduled-commit'
    engine.commit(session)
    assert engine.running['system']['host-name'] == 'later'


def test_success_removes_applied_intents_and_keeps_live_lock(engine, session):
    engine.clock = lambda: 100
    schedule(engine, session)
    engine.clock = lambda: 130
    engine.tick()
    assert not session.mutations
    assert engine.lock_owner == session.id
    engine.save(session)
    assert engine.store.read('boot.json')['system']['host-name'] == 'scheduled'


def test_disconnect_preserves_schedule_and_new_session_can_confirm(engine, session):
    now = [100.0]
    engine.clock = lambda: now[0]
    schedule(engine, session, minutes=0.25)
    engine.close(session)
    other = engine.open('bob', 'pts/2')
    with pytest.raises(LockError, match='scheduled'):
        engine.request_lock(other)

    now[0] = 130
    engine.tick()
    assert engine.pending['deadline'] == 145
    assert engine.running['system']['host-name'] == 'scheduled'
    engine.confirm(other)
    assert engine.lock_owner is None
    now[0] = 150
    engine.tick()
    assert engine.running['system']['host-name'] == 'scheduled'


def test_confirmation_timeout_starts_after_application(engine, session, monkeypatch):
    now = [100.0]
    engine.clock = lambda: now[0]
    original = engine._lifecycle

    def slow_apply(*args, **kwargs):
        result = original(*args, **kwargs)
        if not kwargs.get('check_only'):
            now[0] += 20
        return result

    monkeypatch.setattr(engine, '_lifecycle', slow_apply)
    schedule(engine, session, minutes=0.5)
    now[0] = 130
    engine.tick()
    assert engine.pending['deadline'] == now[0] + 30
    now[0] = engine.pending['deadline']
    engine.tick()
    assert engine.running == {}
    assert engine.pending is None


def test_expired_originating_session_does_not_cancel_schedule(engine, session):
    engine.clock = lambda: 100
    schedule(engine, session)
    engine.close(session, expired=True)
    assert engine.lock_owner == session.id
    engine.clock = lambda: 130
    engine.tick()
    assert engine.running['system']['host-name'] == 'scheduled'
    assert engine.lock_owner is None


def test_cancellation_after_reconnect_leaves_candidates_alone(engine, session):
    schedule(engine, session)
    engine.close(session)
    other = engine.open('bob', 'pts/2')
    set_(engine, other, 'system host-name other')
    engine.cancel_commit(other)
    assert engine.scheduled is None
    assert engine.store.read('scheduled.json') is None
    assert engine.lock_owner is None
    assert engine.running == {}
    assert engine.view(other)['system']['host-name'] == 'other'
    engine.request_lock(other)


def test_schedule_reserves_commit_save_and_lock_but_allows_candidates(engine, session):
    schedule(engine, session)
    other = engine.open('bob', 'pts/2')
    set_(engine, other, 'system host-name other')
    for action in (engine.commit, engine.save, engine.release_lock, engine.check):
        with pytest.raises(LockError, match='scheduled'):
            action(session)
    with pytest.raises(LockError, match='scheduled'):
        engine.request_lock(other, session.id)
    with pytest.raises(LockError):
        engine.schedule_commit(session, 1)


@pytest.mark.parametrize('delay', [0, -1, float('nan'), float('inf'), 1441, True, '1'])
def test_invalid_delay_does_not_reserve_lock(engine, session, delay):
    set_(engine, session, 'system host-name scheduled')
    with pytest.raises(ValidationError, match='delay'):
        engine.schedule_commit(session, delay)
    assert engine.scheduled is None


def test_failed_initial_verification_does_not_schedule(engine, session):
    set_(engine, session, 'firewall ipv4 input filter rule 10 description incomplete')
    with pytest.raises(ValidationError, match='verification failed'):
        engine.schedule_commit(session, 1)
    assert engine.scheduled is None
    assert engine.store.read('scheduled.json') is None
    assert session.mutations


def test_failed_execution_verification_applies_nothing(engine, session, monkeypatch):
    engine.clock = lambda: 100
    schedule(engine, session)

    def failed(*args, **kwargs):
        raise ValidationError('runtime prerequisite disappeared')

    monkeypatch.setattr(engine, '_lifecycle', failed)
    engine.clock = lambda: 130
    engine.tick()
    assert engine.running == {}
    assert engine.scheduled is None
    assert not engine.unhealthy
    assert 'runtime prerequisite disappeared' in engine.events[-1]['message']


def test_partial_failure_retains_unapplied_candidate_and_commit_history(engine, session, monkeypatch):
    engine.clock = lambda: 100
    set_(engine, session, 'system host-name scheduled')
    set_(engine, session, 'interfaces dummy dum0')
    engine.schedule_commit(session, 0.5, comment='scheduled revision')
    lifecycle = engine._lifecycle

    def failed_dummy(owner, *args, **kwargs):
        if owner == 'dummy' and not kwargs.get('check_only'):
            raise ValidationError('dummy apply failed')
        return lifecycle(owner, *args, **kwargs)

    monkeypatch.setattr(engine, '_lifecycle', failed_dummy)
    engine.clock = lambda: 130
    engine.tick()
    assert engine.running['system']['host-name'] == 'scheduled'
    assert 'interfaces' not in engine.running
    assert 'dum0' in engine.view(session)['interfaces']['dummy']
    assert engine.configuration_status(session)['changed'] == ['dummy']
    assert 'partially completed' in engine.events[-1]['message']
    assert 'dummy apply failed' in engine.events[-1]['message']
    record = next(engine.store.history_metadata(engine.commit_id))
    assert record['comment'] == 'scheduled revision'
    assert record['user'] == 'alice'


def test_due_schedule_waits_for_active_runtime_work(engine, session):
    engine.clock = lambda: 100
    schedule(engine, session)
    engine._start_activity('runtime-update')
    engine.clock = lambda: 130
    engine.tick()
    assert not engine.scheduled['executing']
    assert engine.running == {}
    engine._finish_activity()
    engine.tick()
    assert engine.running['system']['host-name'] == 'scheduled'


def test_restart_cancels_unexecuted_schedule(engine, session, caplog):
    schedule(engine, session)
    restarted = Engine(engine.schema, engine.modules, engine.store)
    assert restarted.running == {}
    assert restarted.scheduled is None
    assert engine.store.read('scheduled.json') is None
    assert 'cancelled because configd restarted' in caplog.text


def test_execution_rechecks_original_callers_authorization(engine, session, monkeypatch):
    roles = ['net-admin']
    monkeypatch.setattr(access, 'peer_role', lambda *args: roles[0])
    token = access.principal.set((engine, 'alice'))
    engine.clock = lambda: 100
    try:
        schedule(engine, session)
    finally:
        access.principal.reset(token)

    roles[0] = 'read-only'
    engine.clock = lambda: 130
    engine.tick()
    assert engine.running == {}
    assert engine.scheduled is None
    assert 'Permission denied' in engine.events[-1]['message']
    assert access.principal.get() is None


def test_execution_claim_prevents_cancellation_or_duplicate_execution(engine, session, monkeypatch):
    engine.clock = lambda: 100
    schedule(engine, session)
    started, release = threading.Event(), threading.Event()
    check = engine.check

    def blocked_check(*args, **kwargs):
        started.set()
        assert release.wait(5)
        return check(*args, **kwargs)

    monkeypatch.setattr(engine, 'check', blocked_check)
    engine.clock = lambda: 130
    worker = threading.Thread(target=engine.tick)
    worker.start()
    try:
        assert started.wait(5)
        assert engine.busy
        with pytest.raises(BusyError):
            engine.cancel_commit(session)
        engine.tick()
        assert engine.commit_id == 0
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert engine.commit_id == 1


def test_control_syntax_decimal_timers_comment_status_and_cancel(controller, engine, session):
    engine.clock = lambda: 100
    set_(engine, session, 'system host-name scheduled')
    output = controller.execute('commit-confirm 2.5 delay 0.25 comment "coordinated change"', session,
                                confirmation={'confirm_minutes': 2.5})
    assert '00:01:55 UTC' in output['text']
    assert '2.5 minutes after' in output['text']
    assert engine.scheduled['comment'] == 'coordinated change'
    assert 'Scheduled commit' in controller.execute('show config-status', session)['text']
    controller.execute('cancel', session)
    assert engine.scheduled is None
    output = controller.execute('commit delay 0.5', session)
    assert '00:02:10 UTC' in output['text']
    assert engine.pending is None


def test_control_invalid_delay_and_no_changes(controller, engine, session):
    for line in ('commit delay nope', 'commit-confirm 1 delay nope', 'commit delay nan'):
        with pytest.raises(RouterError):
            controller.execute(line, session)
    assert 'No configuration changes to schedule' in controller.execute('commit delay 0.5', session)['text']


def test_draft_and_read_only_cannot_schedule_or_cancel(engine, session):
    draft = engine.open('alice', 'pts/2', draft=True)
    with pytest.raises(LockError):
        engine.schedule_commit(draft, 1)
    schedule(engine, session)
    with pytest.raises(LockError):
        engine.cancel_commit(draft)
    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError, match='Permission denied'):
            engine.cancel_commit(session)
    finally:
        access.role.reset(token)
    assert engine.scheduled is not None


def test_cleanup_failure_does_not_execute_job_twice(engine, session, monkeypatch):
    engine.clock = lambda: 100
    schedule(engine, session)
    delete = engine.store.delete

    def failed_delete(name):
        if name == 'scheduled.json':
            raise OSError('read-only storage')
        delete(name)

    monkeypatch.setattr(engine.store, 'delete', failed_delete)
    engine.clock = lambda: 130
    with pytest.raises(OSError, match='read-only storage'):
        engine.tick()
    assert engine.scheduled is None
    assert engine.unhealthy
    assert engine.commit_id == 1
    engine.tick()
    assert engine.commit_id == 1


def test_socket_delayed_confirm_survives_disconnect(daemon):
    client = Client(daemon)
    try:
        client.request('open')
        client.request('execute', text='set interfaces dummy dum0 description scheduled')
        result = client.request('execute', text='commit-confirm 0.5 delay 0.02',
                                confirmation={'confirm_minutes': 0.5})
        assert 'Commit scheduled for' in result['text']
    finally:
        client.close()

    reconnected = Client(daemon)
    try:
        reconnected.request('open')
        deadline = time.monotonic() + 10
        while reconnected.request('status')['commit_id'] == 0:
            assert time.monotonic() < deadline, 'Scheduled commit did not execute'
            time.sleep(0.05)
        assert reconnected.request('get_config', source='running')['configuration']['interfaces']['dummy']['dum0']['description'] == 'scheduled'
        assert 'Commit confirmed.' in reconnected.request('execute', text='confirm')['text']
    finally:
        reconnected.close()


def test_socket_cancel_from_new_connection(daemon):
    client = Client(daemon)
    try:
        client.request('open')
        client.request('execute', text='set interfaces dummy dum0')
        client.request('execute', text='commit delay 1')
    finally:
        client.close()

    reconnected = Client(daemon)
    try:
        reconnected.request('open')
        assert 'Scheduled commit cancelled.' in reconnected.request('execute', text='cancel')['text']
        reconnected.request('execute', text='request-session-lock')
        assert reconnected.request('get_config', source='running')['configuration'] == {}
    finally:
        reconnected.close()
