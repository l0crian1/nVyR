"""Automation uses real configd sessions, permissions and commit semantics."""

import asyncio
import json
import threading
import time
from types import SimpleNamespace

import pytest
from prompt_toolkit.document import Document
from prompt_toolkit.keys import Keys

from nvyr.cli import CLI, error_text
from nvyr.config_session import ConfigurationSession, CommitError
from nvyr.daemon import Server
from nvyr.errors import RouterError, SessionExpiredError, ValidationError
from nvyr.helpers.passwords import hash_password
from nvyr.protocol import Client
from tests.test_integration import daemon


def test_library_defaults_and_cleanup(monkeypatch):
    calls = []

    class FakeClient:
        def __init__(self, path):
            calls.append(path)

        def request(self, operation, **arguments):
            calls.append((operation, arguments))
            return {}

        def close(self):
            calls.append('disconnected')

    monkeypatch.setattr('nvyr.config_session.Client', FakeClient)

    with pytest.raises(RuntimeError):
        with ConfigurationSession():
            raise RuntimeError('script failed')

    assert calls == ['/run/nvyr/configd.sock', ('open', {'timeout': 300}), ('close', {}), 'disconnected']


def test_library_set_delete_discard_commit_save_confirm_and_cleanup(daemon):
    with ConfigurationSession(socket_path=daemon) as config:
        result = config.set('set interfaces dummy dum0 description "WAN | interface" disable')

        assert 'commit_id' in result
        assert 'Configuration already exists:' in config.set('set interfaces dummy dum0 disable')['text']

        config.discard()

        assert not config.commit()['changed']

        config.set('set interfaces dummy dum0 description "WAN | interface" disable')

        assert config.commit()['results']['dummy']['success']

        config.save()
        config.delete('delete interfaces dummy dum0 disable')
        assert config.delete('delete interfaces dummy dum0 disable')['text'] == (
            'Nothing to delete: interfaces dummy dum0 disable is not configured.\n')

        assert config.commit(n=30)['changed']

        config.confirm()
        config.save()
        config.set('set interfaces dummy dum1')  # Context cleanup discards this.

    config.exit()  # Idempotent.

    with pytest.raises(RouterError, match='closed'):
        config.save()

    with ConfigurationSession(socket_path=daemon) as next_session:
        next_session.delete('delete interfaces dummy dum0')

        assert next_session.commit()['results']['dummy']['success']


def test_library_reconnect_can_confirm_without_requesting_lock(daemon):
    with ConfigurationSession(socket_path=daemon) as original:
        original.set('set interfaces dummy dum0 description confirmed')
        original.commit(n=60)

    with ConfigurationSession(socket_path=daemon) as reconnected:
        reconnected.set('set interfaces dummy dum0 description candidate')
        with pytest.raises(RouterError, match='commit-confirm'):
            reconnected.request_lock()

        result = reconnected.confirm()
        assert 'Commit confirmed.' in result['text']
        assert reconnected.get_config()['interfaces']['dummy']['dum0']['description'] == 'confirmed'
        reconnected.request_lock()
        assert reconnected.commit()['changed']
        assert reconnected.get_config()['interfaces']['dummy']['dum0']['description'] == 'candidate'


def test_failed_commit_exposes_partial_result_and_leaves_candidate(daemon):
    with ConfigurationSession(socket_path=daemon) as config:
        config.set('set interfaces dummy dum0')
        config.set('set firewall ipv4 input filter rule 10 description "No action"')

        with pytest.raises(CommitError) as error:
            config.commit()

        assert error.value.result['results']['dummy']['success']
        assert not error.value.result['results']['firewall']['success']

        config.set('set firewall ipv4 input filter rule 10 action accept')

        assert config.commit()['results']['firewall']['success']


def test_configuration_snapshots_and_replace_restore_only_changed_owners(daemon):
    with ConfigurationSession(socket_path=daemon) as config:
        assert config.get_config() == {}

        config.set('set system host-name original')
        config.set('set interfaces dummy dum0')
        config.commit()
        original = config.get_config()

        assert original == {'system': {'host-name': 'original'}, 'interfaces': {'dummy': {'dum0': {}}}}

        config.set('set interfaces dummy dum0 description changed')
        config.set('set interfaces dummy dum1')
        candidate = config.get_config(source='candidate')

        assert config.get_config() == original
        assert candidate['interfaces']['dummy'] == {'dum0': {'description': 'changed'}, 'dum1': {}}

        candidate['interfaces']['dummy'].clear()

        assert config.get_config('candidate')['interfaces']['dummy']
        assert set(config.commit()['results']) == {'dummy'}
        assert original['interfaces']['dummy'] == {'dum0': {}}

        config.set('set system host-name pending')
        assert config.load(original) == {'errors': []}
        assert config.get_config('candidate') == original
        assert config.get_config() != original  # Load only stages changes.
        assert set(config.commit()['results']) == {'dummy'}
        assert config.get_config() == original

        config.load(original)
        assert not config.commit()['changed']

        config.load({})
        assert config.get_config('candidate') == {}
        config.commit()
        assert config.get_config() == {}


def test_large_snapshot_and_replace_restore_above_old_frame_limit(daemon):
    # Real RPC and schema validation; the daemon fixture mocks host operations.
    original = {'interfaces': {'dummy': {
        f'dum{number}': {'description': 'snapshot "quoted" \\ value ' * 9}
        for number in range(18000)}}}
    assert len(json.dumps(original).encode('utf-8')) > 4 * 1024 * 1024

    with ConfigurationSession(socket_path=daemon) as config:
        assert config.load(original) == {'errors': []}
        assert config.get_config('candidate') == original
        assert config.get_config() == {}
        config.commit()
        snapshot = config.get_config()
        assert snapshot == original

        config.load({'interfaces': {'dummy': {'dum20000': {}}}})
        config.commit()
        assert config.get_config() != snapshot

        assert config.load(snapshot) == {'errors': []}
        assert config.get_config('candidate') == snapshot
        config.commit()
        assert config.get_config() == original


def test_load_merge_validation_and_closed_session(daemon):
    with ConfigurationSession(socket_path=daemon) as config:
        config.set('set system host-name pending')
        addition = {'interfaces': {'dummy': {'dum0': {}}}}
        config.load(addition, replace=False)

        expected = {'system': {'host-name': 'pending'}, **addition}
        assert config.get_config('candidate') == expected
        assert addition == {'interfaces': {'dummy': {'dum0': {}}}}

        for invalid in [[], 'set system host-name invalid', {'bad-node': {}},
                        {'interfaces': {'dummy': {'dum0': {'mtu': 'bad'}}}}, {'value': object()}]:
            with pytest.raises(RouterError):
                config.load(invalid)

            assert config.get_config('candidate') == expected

        with pytest.raises(RouterError, match='source'):
            config.get_config('saved')

    for operation in [config.get_config, lambda: config.load({})]:
        with pytest.raises(RouterError, match='closed'):
            operation()


def test_configuration_retrieval_requires_session_and_ignores_edit_scope(daemon):
    with ConfigurationSession(socket_path=daemon) as config:
        config.set('set interfaces dummy dum0')
        config._client.request('execute', text='edit interfaces dummy dum0')

        assert config.get_config('candidate') == {'interfaces': {'dummy': {'dum0': {}}}}

    client = Client(daemon)
    try:
        with pytest.raises(RouterError, match='Open a configuration session'):
            client.request('get_config')
    finally:
        client.close()


def test_library_does_not_take_locks_or_accept_stale_candidates_silently(daemon):
    with ConfigurationSession(socket_path=daemon) as first, ConfigurationSession(socket_path=daemon) as second:
        first.set('set system host-name first')
        second.set('set system host-name second')

        with pytest.raises(RouterError) as error:
            second.commit()

        assert error.value.code == 'lock'

        first.commit()
        first.exit()

        # Lock acquisition remains explicit; committing never steals it.
        second.request_lock()

        with pytest.raises(RouterError) as error:
            second.commit()

        assert error.value.code == 'confirmation_required'


def test_library_explicit_lock_takeover_preserves_other_candidate(daemon):
    with ConfigurationSession(socket_path=daemon) as first, ConfigurationSession(socket_path=daemon) as second:
        first.set('set interfaces dummy dum0')
        second.set('set interfaces dummy dum1')

        with pytest.raises(RouterError) as error:
            second.request_lock()

        assert error.value.code == 'confirmation_required'
        assert error.value.details['session'] == first.identity['session']

        second.request_lock(force=True)
        second.request_lock()  # Already held by this session.

        assert first.get_config('candidate') == {'interfaces': {'dummy': {'dum0': {}}}}
        with pytest.raises(RouterError) as error:
            first.commit()

        assert error.value.code == 'lock'
        assert second.commit()['results']['dummy']['success']

    with pytest.raises(RouterError, match='closed'):
        second.request_lock(force=True)


def test_library_force_lock_cannot_interrupt_commit_confirm(daemon):
    with ConfigurationSession(socket_path=daemon) as first, ConfigurationSession(socket_path=daemon) as second:
        first.set('set interfaces dummy dum0')
        first.commit(n=30)

        with pytest.raises(RouterError, match='commit-confirm'):
            second.request_lock(force=True)

        first.confirm()
        second.request_lock(force=True)


def test_smoketests_take_lock_and_restore_without_discarding_other_candidate(daemon, tmp_path):
    from smoketests.support import SmokeSession, preserved_configuration

    with ConfigurationSession(socket_path=daemon) as holder, SmokeSession(socket_path=daemon) as smoke:
        holder.set('set interfaces dummy dum0')
        original = holder.get_config()

        with preserved_configuration(smoke, directory=tmp_path):
            smoke.set('set interfaces dummy dum1')
            assert smoke.commit()['results']['dummy']['success']

            with pytest.raises(RouterError) as error:
                holder.commit()

            assert error.value.code == 'lock'

        assert smoke.get_config() == original
        assert holder.get_config('candidate') == {'interfaces': {'dummy': {'dum0': {}}}}
        assert not list(tmp_path.glob('nvyr-smoketest-*.json'))


@pytest.mark.parametrize('code', ['confirmation_required', 'busy', 'lock', 'session_expired', 'configuration'])
def test_library_force_lock_confirms_once_and_does_not_retry_other_errors(monkeypatch, code):
    calls = []
    failure = RouterError('Lock request failed', details={'session': 'first-owner'})
    failure.code = code
    changed = RouterError('Lock owner changed', details={'session': 'new-owner'})
    changed.code = 'confirmation_required'

    class FakeClient:
        def __init__(self, path):
            pass

        def request(self, operation, **arguments):
            if operation != 'execute':
                return {}

            calls.append(arguments)
            raise failure if len(calls) == 1 else changed

        def close(self):
            pass

    monkeypatch.setattr('nvyr.config_session.Client', FakeClient)
    with ConfigurationSession() as config:
        with pytest.raises(RouterError) as error:
            config.request_lock(force=True)

    expected = [{'text': 'request-session-lock'}]
    if code == 'confirmation_required':
        expected.append({'text': 'request-session-lock', 'confirmation': {'session': 'first-owner'}})
        assert error.value is changed
    else:
        assert error.value is failure

    assert calls == expected


@pytest.mark.parametrize('n', [True, 0, -1, 86401, 10**400, '30', float('inf'), float('nan')])
def test_library_commit_timeout_validation(daemon, n):
    with ConfigurationSession(socket_path=daemon) as config:
        with pytest.raises(RouterError, match='seconds'):
            config.commit(n=n)


@pytest.mark.parametrize('command', ['', 'commit', 'shellcmd id', 'delete system host-name', 'set system host-name router | count'])
def test_set_only_accepts_a_full_set_command(daemon, command):
    with ConfigurationSession(socket_path=daemon) as config:
        with pytest.raises(RouterError):
            config.set(command)


def test_session_lifetime_is_total_and_cleanup_releases_state(engine):
    now = [100.0]
    engine.session_clock = lambda: now[0]

    assert engine.session_timeout == 8 * 3600

    session = engine.open('alice', 'test', timeout=300)

    for when in [110, 200, 399]:
        now[0] = when
        engine.mutate(session, 'set', ['system', 'host-name', f'router{when}'])
        engine.status(session)

        assert session.expires_at == 400

    now[0] = 400
    engine.tick()

    assert session.expired and not session.alive
    assert not session.mutations and not engine.sessions and engine.lock_owner is None
    assert engine.running == {}

    for operation in [lambda: engine.mutate(session, 'set', ['system', 'host-name', 'bad']),
                      lambda: engine.commit(session), lambda: engine.confirm(session),
                      lambda: engine.save(session), lambda: engine.discard(session),
                      lambda: engine.view(session), lambda: engine.request_lock(session)]:
        with pytest.raises(SessionExpiredError):
            operation()

    fresh = engine.open('alice', 'new', timeout=10)

    assert engine.lock_owner == fresh.id


@pytest.mark.parametrize('timeout', [True, 0, -1, 10**400, '300', float('inf'), float('nan')])
def test_invalid_session_lifetimes_fail_before_open(engine, timeout):
    with pytest.raises(ValidationError, match='timeout'):
        engine.open('alice', 'test', timeout=timeout)

    assert not engine.sessions


def test_lazy_expiry_and_monotonic_clock(engine, controller):
    now = [0.0]
    engine.session_clock = lambda: now[0]
    session = engine.open('alice', 'test', timeout=1)
    engine.clock = lambda: 1e12  # Wall time is independent of the session deadline.
    engine.tick()

    assert session.alive

    now[0] = 1.0

    with pytest.raises(SessionExpiredError):
        controller.execute('show', session)

    with pytest.raises(SessionExpiredError):
        controller.completion('set ', session)

    with pytest.raises(SessionExpiredError):
        controller.load(session, '{}')

    assert not engine.sessions
    assert controller.execute('exit', session)['event'] == 'leave'


def test_expiry_preserves_commit_confirm_rollback(engine):
    now = [0.0]
    engine.clock = engine.session_clock = lambda: now[0]
    session = engine.open('alice', 'test', timeout=5)
    engine.mutate(session, 'set', ['system', 'host-name', 'temporary'])
    engine.commit(session, minutes=1, confirmed_minutes=1)
    now[0] = 5
    engine.tick()

    assert session.expired and engine.lock_owner is None
    assert engine.pending['deadline'] == 60 and engine.store.read('confirmed.json')

    fresh = engine.open('bob', 'test')

    with pytest.raises(RouterError):
        engine.request_lock(fresh)

    now[0] = 60
    engine.tick()

    assert engine.running == {} and engine.pending is None

    engine.request_lock(fresh)


def test_inflight_commit_finishes_without_restoring_expired_candidate(engine):
    now = [0.0]
    engine.session_clock = lambda: now[0]
    session = engine.open('alice', 'test', timeout=5)
    engine.mutate(session, 'set', ['system', 'host-name', 'applied'])
    entered, release = threading.Event(), threading.Event()
    results = []

    def slow_apply(*args):
        entered.set()

        assert release.wait(5)

    engine.modules['system'].apply = slow_apply
    worker = threading.Thread(target=lambda: results.append(engine.commit(session)))
    worker.start()

    try:
        assert entered.wait(5)

        now[0] = 5
        engine.tick()

        assert engine.busy and session.expired and not session.mutations
    finally:
        release.set()
        worker.join(5)

    assert results[0]['results']['system']['success']
    assert engine.running == {'system': {'host-name': 'applied'}}
    assert not session.mutations and not engine.sessions and not engine.busy


def test_rpc_expiry_does_not_leave_cli_configuration_mode(daemon, monkeypatch):
    client = Client(daemon)
    output = []
    cli = CLI(client, emit=output.append)

    try:
        opened = client.request('open', timeout=.1)
        cli.mode, cli.session_id = 'normal', opened['session']
        deadline = time.monotonic() + 5

        while True:
            status = client.request('status')
            if status['session_expired']:
                break

            assert time.monotonic() < deadline

            time.sleep(.025)

        cli.receive_status(status)
        cli.receive_status(status)

        assert len(output) == 1 and 'expired' in output[0]
        assert cli.mode == 'normal' and not cli.done

        for operation, arguments in [('execute', {'text': 'set system host-name bad'}),
                                     ('execute', {'text': 'set system login user admin authentication plaintext-password secret'}),
                                     ('commit', {}), ('load', {'content': '{}'}),
                                     ('get_config', {'source': 'running'}),
                                     ('get_config', {'source': 'candidate'}),
                                     ('complete', {'text': 'set '})]:
            with pytest.raises(SessionExpiredError) as error:
                client.request(operation, **arguments)

            assert 'expired' in error_text(error.value, arguments.get('text', ''))
            assert 'secret' not in error_text(error.value, arguments.get('text', ''))

        monkeypatch.setattr('nvyr.cli.run_in_terminal', lambda callback: callback())
        buffer = SimpleNamespace(document=Document('set system '))

        for key in ('?', Keys.ControlI):
            handler = cli.bindings().get_bindings_for_keys((key,))[0].handler
            handler(SimpleNamespace(current_buffer=buffer))

            assert output[-1] == 'Configuration session expired. Exit configuration mode and open a new session.'
            assert cli.mode == 'normal' and not cli.done
            assert buffer.document.text == 'set system '

        cli.execute_line('exit')

        assert cli.mode is None

        cli.execute_line('configure')

        assert cli.mode == 'normal' and not cli.session_expired
    finally:
        client.close()


@pytest.mark.parametrize('role', ['sys-admin', 'net-admin', 'read-only'])
def test_library_permissions_come_from_authenticated_peer(engine, tmp_path, role):
    authentication = {'encrypted-password': hash_password('test-password')}
    engine.running = {'system': {'login': {'user': {'automation': {
        'role': role, 'authentication': authentication}}}}}

    async def scenario():
        server = Server(engine, identity=lambda writer: ('automation', 'local-script'))
        path = tmp_path / 'configd.sock'
        listener = await asyncio.start_unix_server(server.handle, path=str(path))

        def script():
            if role == 'read-only':
                with pytest.raises(RouterError, match='Permission denied'):
                    ConfigurationSession(socket_path=path)

                return

            with ConfigurationSession(socket_path=path) as config:
                for source in ('running', 'candidate'):
                    snapshot = config.get_config(source)
                    user = snapshot['system']['login']['user']['automation']
                    if role == 'sys-admin':
                        assert user['authentication'] == authentication
                        config.load(snapshot)
                        assert not config.commit()['changed']
                    else:
                        assert 'authentication' not in user
                        with pytest.raises(RouterError, match='Permission denied'):
                            config.load(snapshot)

                config.set('set interfaces dummy dum0')

                assert config.commit()['results']['dummy']['success']

                if role == 'net-admin':
                    with pytest.raises(RouterError, match='Permission denied'):
                        config.set('set system login user blocked role sys-admin')

                    with pytest.raises(RouterError, match='Permission denied'):
                        config.load({'system': {'login': {'user': {'blocked': {'role': 'sys-admin'}}}}},
                                    replace=False)

                    assert 'blocked' not in config.get_config('candidate')['system']['login']['user']

        try:
            await asyncio.to_thread(script)

            assert not engine.sessions
        finally:
            listener.close()
            await listener.wait_closed()

    asyncio.run(scenario())


def test_library_timeout_override_and_commit_confirm_use_seconds(engine, tmp_path):
    now = [100.0]
    engine.session_clock = engine.clock = lambda: now[0]

    async def scenario():
        server = Server(engine, identity=lambda writer: ('root', 'local-script'))
        path = tmp_path / 'configd.sock'
        listener = await asyncio.start_unix_server(server.handle, path=str(path))

        def script():
            with ConfigurationSession(socket_path=path, timeout=20) as config:
                assert engine.sessions[config.identity['session']].expires_at == 120

                config.set('set system host-name temporary')
                config.commit(n=7)

                assert engine.pending['deadline'] == 107

            assert not engine.sessions
            assert engine.pending['deadline'] == 107

        try:
            await asyncio.to_thread(script)
            now[0] = 107
            engine.tick()

            assert engine.running == {} and engine.pending is None
        finally:
            listener.close()
            await listener.wait_closed()

    asyncio.run(scenario())
