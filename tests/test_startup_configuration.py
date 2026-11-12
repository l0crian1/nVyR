"""Startup failures must leave independent configuration and the repair CLI usable.

These tests exercise configd's publication and correction boundary; lifecycle
stubs represent section failures without changing the test machine's network.
"""

from copy import deepcopy
import threading

import pytest

from nvyr.controller import Controller
from nvyr.engine import Engine
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import access
from nvyr.schema import Schema
from nvyr.storage import Store
from tests.lifecycle import LifecycleStub


@pytest.fixture
def startup(tmp_path):
    schema = Schema.bundled()
    modules = {owner: LifecycleStub() for owner in schema.owners}
    store = Store(tmp_path)
    return schema, modules, store


def boot(startup, configuration, **kwargs):
    schema, modules, store = startup
    store.write('boot.json', configuration)
    return Engine(schema, modules, store, boot_id='test-boot', **kwargs)


def test_unsupported_firewall_setting_preserved_and_corrected(startup):
    saved = {'firewall': {'fail-safe': {}, 'ipv4': {'input': {'filter': {'default-action': 'drop'}}}},
             'system': {'host-name': 'reachable'}, 'interfaces': {'dummy': {'dum9': {}}},
             'service': {'ssh': {}}}
    engine = boot(startup, saved)
    controller = Controller(engine)
    session = engine.open('root', 'console')

    # Exclude the entire invalid firewall policy, but attempt interfaces and SSH.
    assert 'firewall' not in engine.running
    assert engine.running['interfaces'] == saved['interfaces']
    assert engine.startup_results['ssh'] == 'Applied'
    assert engine.startup_results['firewall'] == 'Not applied'
    assert engine.store.read('boot.json') == saved
    assert engine.view(session) == saved
    assert not engine.unhealthy
    assert 'fail-safe' in controller.execute('show', session)['text']
    assert 'Unknown configuration key firewall fail-safe' in controller.execute('show config-status', session)['text']

    with pytest.raises(ValidationError, match='startup failures'):
        engine.discard(session)
        engine.save(session)

    engine.close(session)
    session = engine.open('root', 'console')
    controller.execute('delete firewall fail-safe', session)
    result = engine.commit(session)
    assert all(row['success'] for row in result['results'].values())
    assert engine.running['firewall'] == {'ipv4': saved['firewall']['ipv4']}
    assert engine.startup_errors == {}
    engine.save(session)
    assert 'fail-safe' not in engine.store.read('boot.json')['firewall']


def test_failed_apply_is_pending_across_restart_and_can_be_retried(startup):
    schema, modules, store = startup
    original = modules['firewall'].apply
    def fail(generated, context):
        raise RuntimeError('nft rejected the generated policy')
    modules['firewall'].apply = fail
    desired = {'firewall': {'ipv4': {'input': {'filter': {'default-action': 'drop'}}}},
               'system': {'host-name': 'still-up'}, 'service': {'ssh': {}}}
    engine = boot(startup, desired)
    assert engine.startup_results['firewall'] == 'Failed'
    assert engine.startup_results['ssh'] == 'Applied'
    assert engine.running['system']['host-name'] == 'still-up'

    restarted = Engine(schema, modules, store, boot_id='test-boot')
    session = restarted.open('root', 'console')
    assert restarted.view(session) == desired
    assert restarted.startup_errors['firewall'] == 'nft rejected the generated policy'
    modules['firewall'].apply = original
    result = restarted.commit(session)
    assert result['results']['firewall']['success']
    assert restarted.running == desired
    assert restarted.startup_errors == {}
    assert 'startup_target' not in store.read('state.json')


def test_failed_empty_section_is_retried_even_without_tree_difference(startup):
    schema, modules, store = startup
    original = modules['container'].apply
    def fail(generated, context):
        raise RuntimeError('container inventory unavailable')
    modules['container'].apply = fail
    engine = boot(startup, {})
    assert engine.running == {}
    modules['container'].apply = original
    result = engine.commit(engine.open('root', 'console'))
    assert result['results']['container']['success']
    assert engine.startup_errors == {}
    assert not Engine(schema, modules, store, boot_id='test-boot').startup_errors


def test_load_replace_can_repair_unsupported_top_level_configuration(startup):
    engine = boot(startup, {'obsolete': {'setting': 'keep until corrected'}, 'system': {'host-name': 'router'}})
    session = engine.open('root', 'console')
    engine.stage_configuration(session, {'system': {'host-name': 'fixed'}}, replace=True)
    engine.commit(session)
    assert not engine.startup_errors
    assert engine.running == {'system': {'host-name': 'fixed'}}


def test_schema_collects_multiple_errors_without_mutating_source(startup):
    schema, _, _ = startup
    raw = {'firewall': {'obsolete': {}, 'ipv4': {'input': {'filter': {'default-action': 'bad'}}}},
           'system': {'host-name': 'valid'}}
    original = deepcopy(raw)
    errors = []
    projection = schema.validate_configuration(raw, errors=errors)
    assert len(errors) == 2
    assert errors[0][0] == ('firewall', 'obsolete')
    assert raw == original
    schema.validate_configuration(projection)
    with pytest.raises(ValidationError):
        schema.validate_configuration(raw)


def test_management_can_read_status_during_slow_startup(startup):
    _, modules, _ = startup
    entered, finish = threading.Event(), threading.Event()
    def wait(generated, context):
        entered.set()
        assert finish.wait(5)
    modules['firewall'].apply = wait
    engine = boot(startup, {'system': {'host-name': 'router'}}, defer_startup=True)
    thread = threading.Thread(target=engine.startup)
    thread.start()
    try:
        assert entered.wait(5)
        assert engine.status()['startup_pending']
        session = engine.open('root', 'console')
        assert engine.configuration_status(session)['activity']['operation'] == 'startup'
    finally:
        finish.set()
        thread.join(5)
    assert not thread.is_alive()
    assert not engine.status()['startup_pending']
    assert engine.view(session) == engine.running


def test_role_authorization_remains_available_when_login_apply_fails(startup):
    _, modules, store = startup
    login = {'user': {'admin': {'role': 'sys-admin'}}}
    store.write('state.json', {'id': 1, 'configuration': {'system': {'login': login}}})
    def fail(generated, context):
        raise RuntimeError('account apply failed')
    modules['login'].apply = fail
    engine = boot(startup, {'system': {'login': login}})
    assert 'login' in engine.startup_errors
    assert access.peer_role(engine, 'admin') == 'sys-admin'


def test_command_rendering_reports_unsupported_path_without_losing_candidate(startup):
    raw = {'firewall': {'fail-safe': {}}}
    engine = boot(startup, raw)
    session = engine.open('root', 'console')
    controller = Controller(engine)
    with pytest.raises(ValidationError, match='Unsupported configuration path: firewall fail-safe'):
        controller.execute('show | commands', session)
    with pytest.raises(ValidationError, match='Unknown configuration key'):
        controller.execute('commit', session)
    assert engine.view(session) == raw
    assert engine.store.read('boot.json') == raw


def test_repaired_owner_failure_does_not_lose_other_pending_configuration(startup):
    _, modules, store = startup
    def fail(generated, context):
        raise RuntimeError('native firewall failure')
    modules['firewall'].apply = fail
    engine = boot(startup, {'firewall': {'fail-safe': {}}, 'system': {'host-name': 'old'}})
    session = engine.open('root', 'console')
    controller = Controller(engine)
    controller.execute('delete firewall fail-safe', session)
    controller.execute('set system host-name updated', session)
    result = engine.commit(session)
    assert not result['results']['firewall']['success']
    assert engine.running['system']['host-name'] == 'updated'
    assert 'fail-safe' not in store.read('state.json')['startup_target']['firewall']
    assert engine.startup_errors['firewall'] == 'Unable to apply this configuration. Its changes remain pending; check the system logs for details.'


def test_confirmation_expiry_retains_original_failed_intent(startup):
    engine = boot(startup, {'firewall': {'fail-safe': {}}, 'system': {'host-name': 'old'}})
    now = [1000]
    engine.clock = lambda: now[0]
    session = engine.open('root', 'console')
    Controller(engine).execute('delete firewall fail-safe', session)
    engine.commit(session, minutes=1, confirmed_minutes=1)
    assert not engine.startup_errors
    now[0] += 61
    engine.tick()
    assert 'firewall' in engine.startup_errors
    assert engine.startup_results['firewall'] == 'Not applied'
    assert engine.view(session)['firewall'] == {'fail-safe': {}}
    reopened = engine.open('root', 'console', draft=True)
    assert engine.view(reopened)['firewall'] == {'fail-safe': {}}
    assert engine.store.read('state.json')['startup_target']['firewall'] == {'fail-safe': {}}


def test_failed_publication_restart_does_not_reuse_conflicting_history(startup):
    schema, modules, store = startup
    store.write('state.json', {'id': 0, 'configuration': {}, 'boot_id': 'test-boot'})
    store.record(1, {'system': {'host-name': 'interrupted'}}, reason='commit', user='root')
    store.write('transaction.json', {'before': {}, 'id': 0, 'owners': ['system']})
    engine = Engine(schema, modules, store, boot_id='test-boot')
    assert not engine.startup_errors
    assert engine.commit_id > 1
    assert store.read('history/00000000000000000001.json')['configuration']['system']['host-name'] == 'interrupted'


def test_socket_serves_status_while_startup_is_applying(startup, tmp_path):
    import asyncio
    from nvyr.daemon import serve
    from nvyr.protocol import Client

    _, modules, _ = startup
    entered, finish = threading.Event(), threading.Event()
    def wait(generated, context):
        entered.set()
        assert finish.wait(5)
    modules['firewall'].apply = wait
    engine = boot(startup, {}, defer_startup=True)
    path = tmp_path / 'configd.sock'

    async def scenario():
        task = asyncio.create_task(serve(engine, path))
        client = None
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            client = Client(path)
            status = await asyncio.to_thread(client.request, 'status')
            assert status['startup_pending']
            assert not task.done()
        finally:
            finish.set()
            if client:
                client.close()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
    asyncio.run(scenario())


def test_saved_roles_are_not_granted_until_login_apply_succeeds(startup):
    _, modules, _ = startup
    entered, finish = threading.Event(), threading.Event()
    def wait(generated, context):
        entered.set()
        assert finish.wait(5)
    modules['login'].apply = wait
    engine = boot(startup, {'system': {'login': {'user': {'admin': {'role': 'sys-admin'}}}}},
                  defer_startup=True)
    thread = threading.Thread(target=engine.startup)
    thread.start()
    try:
        assert entered.wait(5)
        with pytest.raises(RouterError, match='not authorized'):
            access.peer_role(engine, 'admin')
    finally:
        finish.set()
        thread.join(5)
    assert not thread.is_alive()
    assert access.peer_role(engine, 'admin') == 'sys-admin'
