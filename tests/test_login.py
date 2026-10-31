"""Credential ingress, authoritative role checks and account lifecycle recovery."""

import asyncio
from contextlib import contextmanager
import ctypes
import ctypes.util
import json
from pathlib import Path

import pytest

from nvyr.cli import CLI
from nvyr.config_scripts import system_login
from nvyr.controller import Controller
from nvyr.daemon import Server
from nvyr.engine import Engine
from nvyr.errors import RouterError, RecoveryError
from nvyr.helpers import access, accounts, developer_access, passwords
from nvyr.lexer import lex
from tests.lifecycle import recorded_registry
from nvyr.protocol import Client
from nvyr.schema import Schema
from nvyr.storage import Store


@pytest.mark.parametrize('enabled,pending', [(True, False), (True, True), (False, True)])
def test_account_targets_use_gathered_developer_policy(tmp_path, monkeypatch, enabled, pending):
    from copy import deepcopy
    from types import SimpleNamespace
    from nvyr.tree import ReadOnlyTree

    users = {
        'admin': {'role': 'sys-admin', 'authentication': {'encrypted-password': 'hash'}},
        'developer': {'role': 'dev-admin', 'authentication': {'encrypted-password': 'hash'}},
    }
    tree = ReadOnlyTree({'system': {'login': {'user': users}}})
    monkeypatch.setattr(developer_access, 'enabled', lambda: enabled)
    monkeypatch.setattr(developer_access, 'disable_pending', lambda: pending)
    configuration = system_login.get_config(SimpleNamespace(effective=tree, previous=tree))
    before = deepcopy(configuration)

    monkeypatch.setattr(developer_access, 'enabled', lambda: pytest.fail('repeated developer policy read'))
    monkeypatch.setattr(developer_access, 'disable_pending', lambda: pytest.fail('repeated disable read'))
    later = SimpleNamespace(startup=True, state_directory=tmp_path, recovery=False)
    applied = []
    monkeypatch.setattr(accounts.manager, 'apply', lambda *args, **kwargs: applied.append((args, kwargs)))

    system_login.verify(configuration, later)
    plan = system_login.generate(configuration, later)
    system_login.apply(plan, later)

    assert ('developer' in plan['current']) == enabled
    assert ('developer' in plan['previous']) == enabled
    assert 'admin' in plan['current'] and 'admin' in plan['previous']
    assert applied == [((plan['current'], plan['previous'], tmp_path), {'recovery': False})]
    assert configuration == before


@contextmanager
def as_role(role):
    token = access.role.set(role)

    try:
        yield
    finally:
        access.role.reset(token)


def add_user(controller, session, name='admin', role='sys-admin', password='a secret with spaces'):
    controller.execute(f'set system login user {name} authentication plaintext-password "{password}"', session)
    controller.execute(f'set system login user {name} role {role}', session)


def crypt_check(password, encrypted):
    library = ctypes.CDLL(ctypes.util.find_library('crypt'))
    library.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    library.crypt.restype = ctypes.c_char_p

    return library.crypt(password.encode(), encrypted.encode()).decode() == encrypted


def test_password_hashes_before_candidate_history_or_disk(engine, session, controller):
    secret = 'a secret with spaces'
    add_user(controller, session, password=secret)
    candidate = engine.view(session)
    auth = candidate['system']['login']['user']['admin']['authentication']

    assert set(auth) == {'encrypted-password'}
    assert crypt_check(secret, auth['encrypted-password'])
    assert not crypt_check('wrong', auth['encrypted-password'])
    assert passwords.hash_password(secret) != auth['encrypted-password']
    assert secret not in repr(session.mutations)

    engine.commit(session)
    engine.save(session)

    for path in engine.store.directory.rglob('*.json'):
        assert secret not in path.read_text() and 'plaintext-password' not in path.read_text()
        assert path.stat().st_mode & 0o077 == 0

    loaded = Engine(engine.schema, engine.modules, engine.store)

    assert loaded.running == candidate


def test_json_load_and_shorthand_and_failed_input_do_not_disclose(engine, session, controller):
    secret = 'never write this password'
    configuration = {'system': {'login': {'user': {'admin': {
        'role': 'sys-admin', 'authentication': {'plaintext-password': secret}}}}}}
    controller.load(session, json.dumps(configuration))

    assert secret not in repr(engine.view(session))

    controller.execute('edit system login user admin authentication', session)
    controller.execute('set p new-password', session)

    assert 'new-password' not in repr(engine.view(session))

    with pytest.raises(RouterError) as error:
        controller.execute('set p leaked-password extra', session)

    assert 'leaked-password' not in json.dumps(error.value.as_dict())

    errors = controller.load(session, 'set system login user admin authentication p exposed-password extra', set_format=True)

    assert errors and 'exposed-password' not in json.dumps(errors)
    assert not controller.completion('delete encrypted-password ', session, explicit=True)['candidates'][0][0].startswith('$y$')

    with pytest.raises(RouterError, match='hashed'):
        engine.schema.validate_configuration(configuration)


def test_credentials_never_enter_navigation_history(tmp_path):
    from nvyr.history import navigation_histories

    class FakeClient:
        def request(self, *args, **kwargs):
            raise RouterError('invalid credential')

    outputs = []
    cli = CLI(FakeClient(), emit=outputs.append)
    cli.histories = navigation_histories(tmp_path, persistent=True)
    cli.submit('set system login user admin authentication plaintext-password hidden-secret')
    cli.submit('set p hidden-relative-secret extra')

    assert not any('hidden-' in path.read_text() for path in tmp_path.iterdir())
    assert not any('hidden-' in line for line in outputs)


@pytest.mark.parametrize('role', ['read-only', 'net-admin'])
def test_roles_enforced_beyond_completion(engine, session, controller, role):
    add_user(controller, session)
    engine.commit(session)

    with as_role(role):
        with pytest.raises(RouterError, match='Permission denied'):
            controller.execute('shell')

        with pytest.raises(RouterError):
            controller.execute('shell', session)

        with pytest.raises(RouterError):
            add_user(controller, session, 'elevate')

        for text in ('delete system login', 'delete system', 'rename system login user admin to stolen'):
            with pytest.raises(RouterError):
                controller.execute(text, session)

        with pytest.raises(RouterError):
            engine.stage_configuration(session, {}, replace=True)

        output = controller.execute('show running-configuration | commands')['text']

        assert 'encrypted-password' not in output and '$y$' not in output

        if role == 'read-only':
            for operation in (lambda: engine.open('someone', 'fake'), lambda: engine.commit(session),
                              lambda: engine.mutate(session, 'set', lex('system host-name attack')),
                              lambda: controller.load(session, '{}')):
                with pytest.raises(RouterError, match='Permission denied'):
                    operation()
        else:
            controller.execute('set system host-name router', session)

            assert engine.commit(session)['results']['system']['success']

        names = dict(controller.completion('', explicit=True)['candidates'])

        assert 'shell' not in names
        assert ('configure' in names) == (role == 'net-admin')


def test_demotion_rechecks_existing_candidate_at_commit(engine, session, controller):
    add_user(controller, session)
    engine.commit(session)
    add_user(controller, session, 'elevate')

    with as_role('net-admin'), pytest.raises(RouterError):
        engine.commit(session)

    assert 'elevate' not in engine.running['system']['login']['user']


def test_last_admin_password_and_missing_fields(engine, session, controller):
    add_user(controller, session)

    assert engine.commit(session)['results']['login']['success']

    for command in ('delete system login', 'set system login user admin role read-only',
                    'delete system login user admin authentication'):
        controller.execute(command, session)
        result = engine.commit(session)['results']['login']

        assert not result['success']

        engine.discard(session)

    add_user(controller, session, 'replacement')
    controller.execute('delete system login user admin', session)

    assert engine.commit(session)['results']['login']['success']
    assert set(engine.running['system']['login']['user']) == {'replacement'}


def test_account_changes_persist_without_save_and_default_is_never_reseeded(tmp_path):
    store = Store(tmp_path)
    accounts.initialize(store)
    schema = Schema.bundled()
    engine = Engine(schema, recorded_registry(schema), store, boot_id='first')
    session, controller = engine.open('root', 'console'), Controller(engine)

    assert crypt_check('nvyr', engine.running['system']['login']['user']['nvyr']['authentication']['encrypted-password'])

    add_user(controller, session, 'replacement')
    controller.execute('delete system login user nvyr', session)
    controller.execute('set system host-name unsaved', session)
    engine.commit(session)
    accounts.initialize(store)
    reboot = Engine(schema, recorded_registry(schema), store, boot_id='second')

    assert set(reboot.running['system']['login']['user']) == {'replacement'}
    assert 'host-name' not in reboot.running['system']
    assert 'nvyr' not in reboot.running['system']['login']['user']


def test_confirmed_account_change_rolls_back(engine, session, controller):
    add_user(controller, session)
    engine.commit(session)
    before = engine.running
    add_user(controller, session, password='replacement password')
    engine.commit(session, minutes=1, confirmed_minutes=1)
    engine.clock = lambda: engine.pending['deadline'] + 1
    engine.tick()

    assert engine.running == before


def test_account_apply_compensation_and_failed_recovery(tmp_path, monkeypatch):
    manager = accounts.Manager()
    calls = []

    def install(users, directory):
        calls.append(users)

        if users == {'bad': {}}:
            raise OSError('account write failed')

    monkeypatch.setattr(manager, '_install', install)

    with pytest.raises(RouterError, match='previous accounts restored'):
        manager.apply({'bad': {}}, {'before': {}}, tmp_path)

    assert calls == [{'bad': {}}, {'before': {}}]

    with pytest.raises(RecoveryError):
        manager.apply({'bad': {}}, {}, tmp_path, recovery=True)


def test_peer_authorization_revokes_live_socket_and_ignores_claimed_role(engine, session, controller, tmp_path):
    add_user(controller, session, 'admin')
    add_user(controller, session, 'reader', 'read-only')
    engine.commit(session)

    async def scenario():
        server = Server(engine, identity=lambda writer: ('reader', 'test-tty'))
        path = tmp_path / 'rpc.sock'
        listener = await asyncio.start_unix_server(server.handle, path=str(path))

        def client_work():
            client = Client(path)

            try:
                assert 'Version    |' in client.request('execute', text='show version', role='sys-admin')['text']

                with pytest.raises(RouterError):
                    client.request('open', user='root', role='sys-admin')

                with pytest.raises(RouterError):
                    client.request('execute', text='shell')

                # Simulate a published role change while the socket remains open.
                engine.running['system']['login']['user'].pop('reader')

                with pytest.raises(RouterError, match='not authorized'):
                    client.request('status')
            finally:
                client.close()

        try:
            await asyncio.to_thread(client_work)
        finally:
            listener.close()
            await listener.wait_closed()

    asyncio.run(scenario())


def test_boot_policy_and_base_packages():
    root = Path(__file__).resolve().parents[1]

    assert 'traceroute' in (root/'images/router.list.chroot').read_text().splitlines()

    build = (root/'images/assemble.sh').read_text()

    assert build.count('noautologin nocomponents=user-setup,sudo') == 2
    assert '9999-nvyr-admin' not in build
    assert 'LIVE_CONFIG_NOAUTOLOGIN="true"' in (root/'packaging/nvyr-live.conf').read_text()

    sudoers = (root/'packaging/nvyr-sudoers').read_text()

    assert '%nvyr-dev-admin ALL=(ALL:ALL) ALL' in sudoers
    for role in ('sys-admin', 'net-admin', 'read-only'):
        assert f'%nvyr-{role} ALL=(root) NOPASSWD: /usr/bin/nvyr-session launch' in sudoers
