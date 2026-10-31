"""Live commit feedback and on-demand status preserve engine semantics."""

import asyncio
import threading

import pytest

from nvyr.daemon import Server
from nvyr.errors import BusyError, LockError, RecoveryError, RouterError, SessionExpiredError
from nvyr.helpers import access
from nvyr.helpers.config_feedback import configuration_status
from nvyr.protocol import Client
from tests.test_integration import daemon


def test_status_presto_pending_saved_and_nested_context(controller, engine, session, monkeypatch):
    from nvyr.helpers import config_feedback

    original_tabulate = config_feedback.tabulate
    formats = []

    def render(*args, **kwargs):
        formats.append(kwargs['tablefmt'])
        return original_tabulate(*args, **kwargs)

    monkeypatch.setattr(config_feedback, 'tabulate', render)
    engine.session_clock = lambda: 100
    session.expires_at = 400
    original = engine.configuration_status(session)
    assert not original['changed'] and not original['unsaved']
    assert original['remaining'] == 300 and original['activity'] is None

    controller.execute('set interfaces dummy dum0', session)
    controller.execute('edit interfaces dummy dum0', session)
    status = engine.configuration_status(session)
    assert status['changed'] == ['dummy']
    text = controller.execute('show config-status', session)['text']
    assert text == configuration_status(engine.schema, status)
    assert 'dummy' in text and '00:05:00' in text and '(this session)' in text
    assert formats == ['presto', 'presto']
    assert text.splitlines()[0].strip().startswith('Session ')
    assert ' | ' in text.splitlines()[0]
    assert 'Status' not in text and 'Value' not in text and '-+-' not in text

    engine.commit(session)
    status = engine.configuration_status(session)
    assert not status['changed'] and status['unsaved']
    engine.save(session)
    assert not engine.configuration_status(session)['unsaved']


def test_status_ignores_net_zero_mutations_and_defaults(controller, engine, session):
    controller.execute('set system host-name first', session)
    engine.commit(session)
    engine.save(session)
    controller.execute('set system host-name second', session)
    controller.execute('set system host-name first', session)

    assert session.mutations
    assert engine.configuration_status(session)['changed'] == []
    assert not engine.configuration_status(session)['unsaved']


def test_status_deadline_and_disconnected_lock(controller, engine, session):
    engine.clock = lambda: 100
    controller.execute('set system host-name router', session)
    result = controller.execute('commit-confirm 1', session, confirmation={'confirm_minutes': 1})
    assert '1970-01-01 00:02:40 UTC' in result['text']
    assert 'automatic rollback' in result['text']

    other = engine.open('bob', '/dev/pts/2 from 192.0.2.1')
    assert engine.configuration_status(other)['lock'] == session.identity()
    text = controller.execute('show config-status', other)['text']
    assert '00:01:00 remaining' in text and 'alice on /dev/pts/1' in text
    engine.close(session)
    assert engine.configuration_status(other)['lock'] == {'session': session.id}


def test_release_preserves_candidate_edit_and_allows_another_owner(controller, engine, session):
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('edit interfaces dummy dum0', session)
    before = engine.view(session)
    other = engine.open('bob', '/dev/pts/2')

    assert 'released' in controller.execute('release-session-lock', session)['text']
    assert engine.lock_owner is None and session.alive
    assert engine.view(session) == before and session.edit == ('interfaces', 'dummy', 'dum0')
    engine.request_lock(other)
    with pytest.raises(LockError):
        engine.commit(session)
    with pytest.raises(LockError):
        engine.release_lock(session)

    engine.release_lock(other)
    engine.request_lock(session)
    assert engine.commit(session)['results']['dummy']['success']


def test_release_rejects_draft_pending_busy_and_expired(engine, session, controller):
    draft = engine.open('bob', 'draft', draft=True)
    with pytest.raises(LockError, match='Draft'):
        engine.release_lock(draft)

    engine.busy = True
    with pytest.raises(BusyError):
        engine.release_lock(session)
    engine.busy = False
    controller.execute('set system host-name router', session)
    engine.commit(session, minutes=1, confirmed_minutes=1)
    with pytest.raises(LockError, match='Confirm'):
        engine.release_lock(session)

    engine.confirm(session)
    engine.close(session, expired=True)
    with pytest.raises(SessionExpiredError):
        engine.release_lock(session)


@pytest.mark.parametrize('role', ['sys-admin', 'net-admin', 'read-only'])
def test_status_and_release_enforce_roles(controller, engine, session, role):
    token = access.role.set(role)
    try:
        if role == 'read-only':
            for action in (lambda: engine.configuration_status(session), lambda: engine.release_lock(session),
                           lambda: controller.execute('show config-status', session),
                           lambda: controller.execute('release-session-lock', session)):
                with pytest.raises(RouterError, match='Permission denied'):
                    action()
        else:
            assert 'Session' in controller.execute('show config-status', session)['text']
            assert 'released' in controller.execute('release-session-lock', session)['text']
    finally:
        access.role.reset(token)


def test_status_completion_and_scope(controller, session):
    assert 'config-status' in dict(controller.completion('show ', session, explicit=True)['candidates'])
    assert controller.completion('show config-st', session)['replacement'] == 'config-status'
    assert '<Enter>' in dict(controller.completion('show config-status ', session, explicit=True)['candidates'])
    assert 'release-session-lock' in dict(controller.completion('', session, explicit=True)['candidates'])
    for text, caller in [('show config-status', None), ('release-session-lock', None),
                         ('show config-status interfaces', session),
                         ('show config-status | strip-private', session),
                         ('show config-status | commands', session)]:
        with pytest.raises(RouterError):
            controller.execute(text, caller)


def test_commit_feedback_partial_failure_and_noop(controller, engine, session, monkeypatch):
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('set firewall ipv4 input filter rule 10 description unfinished', session)
    monkeypatch.setattr(engine.modules['dummy'], 'apply', lambda generated, context: context.report('A report without newline'))
    chunks = []
    result = controller.execute('commit', session, on_text=chunks.append)

    assert 'Applying dummy...\n' in chunks
    assert 'A report without newline\n' in chunks
    assert 'dummy: done\n\n' in chunks
    assert chunks.index('Applying dummy...\n') < chunks.index('A report without newline\n') < chunks.index('dummy: done\n\n')
    assert any('firewall: failed' in chunk and 'action is required' in chunk for chunk in chunks)
    assert all(chunk.endswith('\n\n') for chunk in chunks if 'firewall: failed' in chunk)
    assert 'partially completed' in result['text'] and '1 applied, 1 failed' in result['text']
    assert 'Changes remain pending: firewall.' in result['text']
    assert engine.configuration_status(session)['changed'] == ['firewall']
    assert not engine.busy and engine.activity is None

    failed = controller.execute('commit', session)['text']
    assert 'Commit failed' in failed and '0 applied, 1 failed' in failed
    engine.discard(session)
    assert controller.execute('commit', session)['text'] == 'No configuration changes to commit.\n'


@pytest.mark.parametrize('stream', [False, True])
def test_script_runs_and_commit_summary_have_blank_line_separators(controller, engine, session, stream):
    engine.session_clock = lambda: 100
    controller.execute('set firewall ipv4 forward filter rule 10 action accept', session)
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('set system host-name router', session)
    chunks = []

    result = controller.execute('commit', session, on_text=chunks.append if stream else None)
    text = ''.join(chunks) + result['text']

    assert text == (
        'Applying dummy...\n'
        'dummy: done\n\n'
        'Applying firewall...\n'
        'firewall: done\n\n'
        'Applying system...\n'
        'system: done\n\n'
        'Commit 1 completed in 0.00s.\n'
        'Running configuration has changed. Use save to persist it across reboots.\n'
    )


def test_static_feedback_is_independent_of_default_or_named_vrf(controller, session):
    controller.execute('set protocols static route 192.0.2.0/24 blackhole', session)
    controller.execute('set vrf name BLUE table 100', session)
    controller.execute('set vrf name BLUE protocols static route 198.51.100.0/24 blackhole', session)

    text = controller.execute('commit', session)['text']

    assert text.count('Applying static...\n') == 1
    assert 'static: done\n\n' in text
    assert '<instance>' not in text and 'protocols static' not in text


@pytest.mark.parametrize('operation', ['commit', 'check', 'rollback'])
def test_activity_visible_during_lifecycle(controller, engine, session, monkeypatch, operation):
    controller.execute('set system host-name router', session)
    seen = []

    def verify(configuration, context):
        status = engine.configuration_status(session)
        seen.append(status['activity'])
        assert engine.busy
        with pytest.raises(BusyError):
            engine.release_lock(session)

    if operation == 'rollback':
        engine.clock = lambda: 100
        engine.commit(session, minutes=1, confirmed_minutes=1)
        engine.clock = lambda: 161

    monkeypatch.setattr(engine.modules['system'], 'verify', verify)
    if operation == 'rollback':
        engine.tick()
    else:
        getattr(engine, operation)(session)

    assert seen[0]['operation'] == operation and seen[0]['owner'] == 'system'
    assert seen[0]['elapsed'] >= 0
    assert engine.activity is None and not engine.busy


def test_fatal_recovery_clears_activity_but_keeps_failure_visible(controller, engine, session, monkeypatch):
    controller.execute('set system host-name router', session)

    def fail(*args):
        raise RecoveryError('backend recovery failed')

    monkeypatch.setattr(engine.modules['system'], 'apply', fail)
    with pytest.raises(RecoveryError):
        controller.execute('commit', session)

    status = engine.configuration_status(session)
    assert status['unhealthy'] and status['activity'] is None
    assert engine.store.read('transaction.json')


def test_polling_does_not_compute_full_status(engine, session, monkeypatch):
    monkeypatch.setattr(engine, 'view', lambda *args: pytest.fail('polling materialized candidate'))
    monkeypatch.setattr(engine.store, 'read', lambda *args: pytest.fail('polling read saved configuration'))
    assert engine.status(session)['session'] == session.id


def test_elapsed_includes_transaction_preparation(controller, engine, session, monkeypatch):
    now = [100]
    engine.session_clock = lambda: now[0]
    session.expires_at = 400
    controller.execute('set system host-name router', session)
    write = engine.store.write

    def slow_write(name, value, **kwargs):
        if name == 'transaction.json':
            now[0] += 2

        write(name, value, **kwargs)

    def apply(value, context):
        now[0] += 3

    monkeypatch.setattr(engine.store, 'write', slow_write)
    monkeypatch.setattr(engine.modules['system'], 'apply', apply)
    assert engine.commit(session)['elapsed'] == 5


def test_api_commit_stays_structured_and_quiet(daemon):
    client = Client(daemon)
    try:
        client.request('open')
        client.request('execute', text='set system host-name router')
        chunks = []
        result = client.request('commit', on_text=chunks.append)
        assert result['changed'] and result['results']['system']['success']
        assert result['elapsed'] >= 0 and not chunks and 'text' not in result
    finally:
        client.close()


def test_reports_reach_client_before_apply_finishes(engine, tmp_path, monkeypatch):
    release, received = threading.Event(), threading.Event()
    chunks = []

    def apply(generated, context):
        context.report('Waiting in apply')
        assert release.wait(5)

    monkeypatch.setattr(engine.modules['system'], 'apply', apply)

    async def scenario():
        path = tmp_path / 'live.sock'
        server = Server(engine, identity=lambda writer: ('root', 'test terminal'))
        listener = await asyncio.start_unix_server(server.handle, path=str(path))
        client = Client(path)
        observer = Client(path)
        try:
            await asyncio.to_thread(client.request, 'open')
            await asyncio.to_thread(observer.request, 'open')
            await asyncio.to_thread(client.request, 'execute', text='set system host-name router')

            def output(chunk):
                chunks.append(chunk)
                if chunk == 'Waiting in apply\n':
                    received.set()

            task = asyncio.create_task(asyncio.to_thread(client.request, 'execute', text='commit', on_text=output))
            try:
                assert await asyncio.to_thread(received.wait, 3)
                assert not task.done() and engine.busy and engine.running == {}
                status = await asyncio.to_thread(observer.request, 'execute', text='show config-status')
                assert 'Commit: system' in status['text']
                assert 'root on test terminal' in status['text']
            finally:
                release.set()

            result = await asyncio.wait_for(task, 5)
            assert result['commit_id'] == 1
            assert chunks.index('Waiting in apply\n') < chunks.index('system: done\n\n')
            assert 'completed' in chunks[-1]
        finally:
            release.set()
            client.close()
            observer.close()
            listener.close()
            await listener.wait_closed()
            await asyncio.sleep(0)

    asyncio.run(scenario())


@pytest.mark.parametrize('failure', [BrokenPipeError, TimeoutError])
def test_feedback_disconnect_does_not_fail_commit(controller, engine, session, monkeypatch, failure):
    class Writer:
        closed = False

        def write(self, value):
            pass

        async def drain(self):
            raise failure()

        def close(self):
            self.closed = True

    controller.execute('set system host-name router', session)
    monkeypatch.setattr(engine.modules['system'], 'apply', lambda value, context: context.report('applied'))
    writer = Writer()
    result = asyncio.run(Server(engine).execute(writer, 1, 'commit', session, None))

    assert writer.closed and 'completed' in result['text']
    assert engine.running['system']['host-name'] == 'router'
    assert not engine.unhealthy and not engine.busy and engine.activity is None
    assert engine.store.read('transaction.json') is None
