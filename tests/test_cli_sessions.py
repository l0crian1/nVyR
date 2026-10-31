"""Role boundaries, session isolation and initial-install-only developer policy.

No real account, Podman or networking mutations. Native SSH/session lifecycle
coverage lives in the opt-in login functional suite.
"""

from tests.container_harness import ContainerHarness

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nvyr import login
from nvyr.errors import RouterError
from nvyr.helpers import access, accounts, developer_access, session_runtime
from tests.container_rendering import container_unit
from nvyr.storage import atomic_json
from tests.test_login import add_user, as_role


@pytest.fixture
def developer_policy(tmp_path, monkeypatch):
    monkeypatch.setattr(developer_access, 'POLICY', tmp_path / 'developer.json')
    monkeypatch.setattr(developer_access, 'RUNTIME', tmp_path / 'runtime')
    monkeypatch.setattr(developer_access, 'RECOVERY_OWNER', tmp_path / 'recovery-owner.json')
    atomic_json(developer_access.RUNTIME / 'boot.json', {'enabled': True})


def test_sys_admin_cannot_manage_developer_through_mutations_or_load(engine, session, controller, developer_policy):
    add_user(controller, session, 'developer', 'dev-admin')
    add_user(controller, session, 'ordinary', 'sys-admin')
    engine.commit(session)

    with as_role('sys-admin'):
        for command in ('set system login user promote role dev-admin',
                        'set system login user developer authentication plaintext-password stolen',
                        'delete system login user developer',
                        'set system login user developer role read-only'):
            with pytest.raises(RouterError):
                controller.execute(command, session)
        with pytest.raises(RouterError, match='developer accounts'):
            engine.stage_configuration(session, {}, replace=True)
        add_user(controller, session, 'newreader', 'read-only')
        assert engine.commit(session)['results']['login']['success']


def test_developer_disable_is_deferred_and_preserves_last_sys_admin(engine, session, controller, developer_policy):
    add_user(controller, session, 'developer', 'dev-admin')
    engine.commit(session)
    with pytest.raises(RouterError, match='usable sys-admin'):
        developer_access.schedule_disable(engine)

    add_user(controller, session, 'ordinary', 'sys-admin')
    engine.commit(session)
    with as_role('sys-admin'), pytest.raises(RouterError, match='dev-admin'):
        developer_access.schedule_disable(engine)
    developer_access.schedule_disable(engine)

    assert developer_access.enabled()
    assert developer_access.disable_pending()
    controller.execute('delete system login user ordinary', session)
    assert not engine.commit(session)['results']['login']['success']


def test_recovery_identity_needs_matching_runtime_uid(developer_policy, monkeypatch):
    monkeypatch.setattr(developer_access.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=1234))
    assert not developer_access.recovery_active()
    atomic_json(developer_access.RUNTIME / 'recovery.json', {'uid': 1235})
    assert not developer_access.recovery_active()
    atomic_json(developer_access.RUNTIME / 'recovery.json', {'uid': 1234})
    assert developer_access.recovery_active()


def test_factory_role_is_explicit():
    ordinary = accounts.factory_configuration(encrypted='hash')
    developer = accounts.factory_configuration(encrypted='hash', developer=True)
    assert ordinary['system']['login']['user']['nvyr']['role'] == 'sys-admin'
    assert developer['system']['login']['user']['nvyr']['role'] == 'dev-admin'


def test_disabled_developer_records_restore_without_blocking_boot(developer_policy, monkeypatch, tmp_path):
    from nvyr.config_scripts import system_login

    atomic_json(developer_access.RUNTIME / 'boot.json', {'enabled': False})
    atomic_json(developer_access.POLICY, {'enabled': False})
    users = {
        'developer': {'role': 'dev-admin', 'authentication': {'encrypted-password': 'hash'}},
        'admin': {'role': 'sys-admin', 'authentication': {'encrypted-password': 'hash'}},
    }
    context = SimpleNamespace(effective={'system': {'login': {'user': users}}}, previous={},
                              startup=True, state_directory=tmp_path)
    monkeypatch.setattr(accounts.manager, 'verify', Mock())

    system_login.verify(system_login.get_config(context), context)

    context.startup = False
    with pytest.raises(RouterError, match='enabled during installation'):
        system_login.verify(system_login.get_config(context), context)


def test_group_only_override_uses_image_user_and_other_cases_need_no_inspect():
    manager = ContainerHarness()
    manager.execute = Mock(return_value='[{"Config": {"User": "app:original"}}]')

    output = manager.render_container('app', {'gid': '1002'}, 'image-id')
    assert 'User="app"' in output and 'Group=1002' in output
    manager.execute.assert_called_once_with(['podman', 'image', 'inspect', 'image-id'])

    manager.execute.reset_mock()
    manager.render_container('app', {'uid': '1001', 'gid': '1002'}, 'image-id')
    manager.render_container('app', {}, 'image-id')
    manager.execute.assert_not_called()


def test_boot_removes_only_the_recorded_recovery_identity(developer_policy, monkeypatch):
    original = Path.read_text
    monkeypatch.setattr(Path, 'read_text', lambda path, *a, **kw:
                        'boot=nvyr' if str(path) == '/proc/cmdline' else original(path, *a, **kw))
    monkeypatch.setattr(developer_access.pwd, 'getpwnam', lambda name: SimpleNamespace(pw_uid=1234))
    execute = Mock()
    monkeypatch.setattr(developer_access.subprocess, 'run', execute)
    atomic_json(developer_access.POLICY, {'enabled': False})
    atomic_json(developer_access.RECOVERY_OWNER, {'uid': 1234})
    atomic_json(developer_access.RUNTIME / 'recovery.json', {'uid': 1234})
    developer_access.boot()
    execute.assert_called_once_with(['userdel', 'nvyr-dev'], check=True)
    assert not developer_access.RECOVERY_OWNER.exists()
    assert not developer_access.recovery_active()
    assert not developer_access.enabled()


def test_live_boot_enables_developer_without_persisting_policy(developer_policy, monkeypatch):
    original = Path.read_text
    monkeypatch.setattr(Path, 'read_text', lambda path, *a, **kw:
                        'boot=live' if str(path) == '/proc/cmdline' else original(path, *a, **kw))
    developer_access.boot()
    assert developer_access.enabled()
    assert not developer_access.POLICY.exists()
    with pytest.raises(RouterError, match='Live media always enables'):
        developer_access.schedule_disable(None)


def test_recovery_password_goes_only_to_local_consoles(developer_policy, monkeypatch, tmp_path, capsys):
    from nvyr.helpers import passwords

    original = Path.read_text
    def read(path, *args, **kwargs):
        if str(path) == '/proc/cmdline':
            return 'boot=nvyr nvyr.developer-recovery=1'
        if str(path) == '/sys/class/tty/console/active':
            return 'tty0 ttyS0'
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', read)
    monkeypatch.setattr(developer_access.pwd, 'getpwnam', Mock(side_effect=[KeyError(), SimpleNamespace(pw_uid=1234)]))
    monkeypatch.setattr(developer_access.secrets, 'token_urlsafe', lambda size: 'one-boot-secret')
    monkeypatch.setattr(passwords, 'hash_password', lambda password: 'encrypted-only')
    calls = Mock()
    monkeypatch.setattr(developer_access.subprocess, 'run', calls)
    monkeypatch.setattr(developer_access, 'open', lambda path, mode: (tmp_path / Path(path).name).open(mode), raising=False)
    developer_access.boot()
    creation = next(call.args[0] for call in calls.call_args_list if call.args[0][0] == 'useradd')
    assert creation[creation.index('--shell') + 1] == '/bin/bash'
    assert 'one-boot-secret' in (tmp_path / 'tty0').read_text()
    assert 'one-boot-secret' in (tmp_path / 'ttyS0').read_text()
    assert 'one-boot-secret' not in repr(calls.call_args_list)
    assert 'one-boot-secret' not in developer_access.RECOVERY_OWNER.read_text()
    assert capsys.readouterr().out == ''


@pytest.mark.parametrize('role', ['sys-admin', 'net-admin', 'read-only'])
def test_restricted_login_executes_only_fixed_launcher(monkeypatch, role):
    monkeypatch.setattr(login, 'local_role', lambda: role)
    monkeypatch.setattr('sys.argv', ['nvyr-login'])
    execute = Mock()
    monkeypatch.setattr(login.os, 'execv', execute)
    login.main()
    execute.assert_called_once_with('/usr/bin/sudo', ['sudo', '-n', '/usr/bin/nvyr-session', 'launch'])

    execute.reset_mock()
    monkeypatch.setattr('sys.argv', ['nvyr-login', '-c', 'id'])
    with pytest.raises(SystemExit, match='interactive'):
        login.main()
    execute.assert_not_called()


def test_developer_enters_host_cli_directly(monkeypatch):
    monkeypatch.setattr(login, 'local_role', lambda: 'dev-admin')
    monkeypatch.setattr('sys.argv', ['nvyr-login'])
    execute = Mock(side_effect=SystemExit)
    monkeypatch.setattr(login.os, 'execv', execute)
    with pytest.raises(SystemExit):
        login.main()
    execute.assert_called_once_with('/usr/bin/nvyr', ['nvyr'])


def test_developer_ssh_command_uses_host_shell(monkeypatch):
    monkeypatch.setattr(login, 'local_role', lambda: 'dev-admin')
    monkeypatch.setattr('sys.argv', ['nvyr-login', '-c', 'id -un'])
    execute = Mock(side_effect=SystemExit)
    monkeypatch.setattr(login.os, 'execv', execute)

    with pytest.raises(SystemExit):
        login.main()

    execute.assert_called_once_with('/bin/bash', ['bash', '-c', 'id -un'])


def test_session_storage_and_environment_are_separate(monkeypatch):
    monkeypatch.setenv('CONTAINER_HOST', 'unix:///malicious')
    monkeypatch.setenv('PYTHONPATH', '/malicious')
    assert '/var/lib/nvyr-sessions/storage' in session_runtime.podman('ps')
    assert '/config/podman/storage' not in session_runtime.podman('ps')
    assert 'CONTAINER_HOST' not in session_runtime.environment()
    assert 'PYTHONPATH' not in session_runtime.environment()


def test_reaper_handles_lost_launcher_and_reboot_records(tmp_path, monkeypatch):
    monkeypatch.setattr(session_runtime, 'RUNTIME', tmp_path)
    identifier = 'a' * 32
    orphan = 'b' * 32
    atomic_json(tmp_path / 'sessions' / (identifier + '.json'), {'launcher': 123, 'start': '42'})
    monkeypatch.setattr(session_runtime, 'start_time', lambda pid: '43')  # Reused PID is not its owner.
    calls = []

    def execute(*arguments, **kwargs):
        calls.append(arguments)
        return SimpleNamespace(stdout=json.dumps([{'Names': ['nvyr-session-' + orphan]}]))

    monkeypatch.setattr(session_runtime, 'execute', execute)
    session_runtime.reap()
    assert ('rm', '--force', '--time=0', '--ignore', 'nvyr-session-' + identifier) in calls
    assert ('rm', '--force', '--time=0', '--ignore', 'nvyr-session-' + orphan) in calls


def test_workload_identity_defaults_and_overrides(controller, session):
    controller.execute('set container name app image alpine uid 1001 gid 1002', session)
    config = controller.engine.view(session)['container']['name']['app']
    output = container_unit('app', config, 'alpine')
    assert '\nUser=1001\n' in output and '\nGroup=1002\n' in output
    output = container_unit('app', {'image': 'alpine', 'uid': 'auto', 'gid': 'auto'}, 'alpine')
    assert '\nUser=' not in output and '\nGroup=' not in output
    output = container_unit('app', {'gid': '1002'}, 'alpine', image_user='app:app')
    assert '\nUser="app"\n' in output and '\nGroup=1002\n' in output
    for value in ('-1', '4294967295', 'root', '1:2'):
        with pytest.raises(RouterError):
            controller.execute('set container name app uid ' + value, session)


def test_shell_and_disable_commands_are_developer_only(controller):
    for role in ('sys-admin', 'net-admin', 'read-only'):
        with as_role(role):
            for command in ('shell', 'shellcmd id', 'disable system developer-access'):
                with pytest.raises(RouterError, match='Permission denied'):
                    controller.execute(command)


def test_isolated_prompt_uses_host_status_instead_of_namespace_hostname(engine, monkeypatch):
    from nvyr.cli import CLI

    monkeypatch.setattr('nvyr.cli.socket.gethostname', lambda: 'old-container-name')
    cli = CLI(Mock())
    assert '@old-container-name' in cli.prompt()

    cli.receive_status(dict(engine.status(), hostname='new-router-name'))
    assert '@new-router-name' in cli.prompt()


def test_image_builder_preserves_loader_targets_on_usr_merged_hosts(tmp_path):
    from build_tools.session_images import copy_path

    host = tmp_path / 'host'
    (host / 'usr/lib').mkdir(parents=True)
    (host / 'usr/lib/loader').write_bytes(b'loader')
    (host / 'lib').symlink_to('usr/lib')
    (host / 'lib64').mkdir()
    (host / 'lib64/loader').symlink_to('../lib/loader')
    root = tmp_path / 'image'
    copy_path(host / 'lib64/loader', root)
    assert (root / (host / 'lib64/loader').relative_to('/')).read_bytes() == b'loader'
