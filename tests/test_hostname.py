"""Hostname application, compensation, boot replay and prompt refresh."""

from email.parser import Parser
from pathlib import Path
from types import SimpleNamespace

import pytest

from nvyr.cli import CLI
from nvyr.engine import Engine
from nvyr.errors import RecoveryError, RouterError
from nvyr.helpers import system
from nvyr.helpers.system import apply_hostname
from tests.lifecycle import recorded_registry


@pytest.fixture
def host(tmp_path, monkeypatch):
    path = tmp_path / 'hostname'
    path.write_text('nvyr\n')
    hosts_path = tmp_path / 'hosts'
    hosts_path.write_text('127.0.0.1 localhost\n127.0.1.1\tnvyr\n::1 localhost ip6-localhost\n')
    current = ['nvyr']
    monkeypatch.setattr(system.socket, 'gethostname', lambda: current[0])
    monkeypatch.setattr(system.socket, 'sethostname', lambda value: current.__setitem__(0, value.decode()))
    monkeypatch.setattr(system, 'apply_hostname', lambda value: apply_hostname(value, path=path, hosts_path=hosts_path))

    return current, path


def test_commit_applies_hostname_and_prompt_and_delete_restores_default(host, controller, engine, session, monkeypatch):
    current, path = host
    monkeypatch.setattr('nvyr.cli.getpass.getuser', lambda: 'admin')
    cli = CLI(SimpleNamespace(), emit=lambda _: None)
    cli.mode = 'configuration'
    controller.execute('set system host-name test123', session)

    assert current[0] == 'nvyr'  # Staging is not application.

    result = engine.commit(session)

    assert result['results']['system']['success']
    assert current[0] == 'test123' and path.read_text() == 'test123\n'
    assert path.stat().st_mode & 0o777 == 0o644
    assert cli.prompt() == 'admin@test123# '
    assert '127.0.1.1\ttest123\n' in (path.parent / 'hosts').read_text()

    controller.execute('delete system host-name', session)

    assert engine.commit(session)['results']['system']['success']
    assert current[0] == 'nvyr' and path.read_text() == 'nvyr\n'
    assert cli.prompt() == 'admin@nvyr# '
    assert '127.0.1.1\tnvyr\n' in (path.parent / 'hosts').read_text()


def test_restart_reconciles_running_and_reboot_restores_saved(host, controller, engine, session):
    current, path = host
    controller.execute('set system host-name saved', session)
    engine.commit(session)
    engine.save(session)
    controller.execute('set system host-name unsaved', session)
    engine.commit(session)
    current[0] = 'external-change'
    path.write_text('external-change\n')
    Engine(engine.schema, recorded_registry(engine.schema), engine.store)

    assert current[0] == 'unsaved' and path.read_text() == 'unsaved\n'

    reboot = Engine(engine.schema, recorded_registry(engine.schema), engine.store, boot_id='new-boot')

    assert reboot.running['system']['host-name'] == 'saved'
    assert current[0] == 'saved' and path.read_text() == 'saved\n'
    assert '127.0.1.1\tsaved\n' in (path.parent / 'hosts').read_text()


def test_confirmed_commit_rollback_restores_host(host, controller, engine, session):
    current, path = host
    now = [0]
    engine.clock = lambda: now[0]
    controller.execute('set system host-name temporary', session)
    engine.commit(session, minutes=1, confirmed_minutes=1)

    assert current[0] == 'temporary'

    now[0] = 61
    engine.tick()

    assert current[0] == 'nvyr' and path.read_text() == 'nvyr\n'
    assert '127.0.1.1\tnvyr\n' in (path.parent / 'hosts').read_text()


def test_kernel_failure_keeps_previous_configuration(host, controller, engine, session, monkeypatch):
    current, path = host

    def fail(value):
        raise PermissionError('sethostname denied')

    monkeypatch.setattr(system.socket, 'sethostname', fail)
    controller.execute('set system host-name denied', session)
    result = engine.commit(session)

    assert not result['results']['system']['success']
    assert 'Cannot apply hostname' in result['results']['system']['error']
    assert 'sethostname denied' in result['results']['system']['error']
    assert current[0] == 'nvyr' and path.read_text() == 'nvyr\n'
    assert 'system' not in engine.running
    assert session.mutations


@pytest.mark.parametrize('after_rename', [False, True])
@pytest.mark.parametrize('existing', [False, True])
def test_file_failure_restores_kernel_and_file(host, monkeypatch, after_rename, existing):
    current, path = host

    if not existing:
        path.unlink()

    real_write = system.write

    def fail(target, text, **kwargs):
        if text == 'changed\n':
            if after_rename:
                real_write(target, text, **kwargs)

            raise RouterError('disk write failed')

        return real_write(target, text, **kwargs)

    monkeypatch.setattr(system, 'write', fail)

    with pytest.raises(RouterError, match='Cannot apply hostname'):
        system.apply_hostname('changed')

    assert current[0] == 'nvyr'
    assert path.read_text() == 'nvyr\n' if existing else not path.exists()


def test_failed_compensation_requires_recovery(host, monkeypatch):
    current, path = host

    def set_hostname(value):
        if value == b'nvyr':
            raise PermissionError('cannot restore kernel hostname')

        current[0] = value.decode()

    monkeypatch.setattr(system.socket, 'sethostname', set_hostname)
    monkeypatch.setattr(system, 'write', lambda *a, **kw: (_ for _ in ()).throw(RouterError('disk failure')))

    with pytest.raises(RecoveryError, match='Cannot restore hostname'):
        system.apply_hostname('changed')


def test_repeated_application_does_not_rewrite(host, monkeypatch):
    monkeypatch.setattr(system.socket, 'sethostname', lambda *a: pytest.fail('unnecessary syscall'))
    monkeypatch.setattr(system, 'write', lambda *a, **kw: pytest.fail('unnecessary write'))
    system.apply_hostname('nvyr')


def test_missing_local_mapping_is_repaired_without_hostname_change(host):
    current, path = host
    hosts_path = path.parent / 'hosts'
    existing = '# Static hosts\n127.0.0.1 localhost\n::1 localhost ip6-localhost\n192.0.2.1 peer'
    hosts_path.write_text(existing)

    system.apply_hostname('nvyr')

    assert current[0] == 'nvyr'
    assert hosts_path.read_text() == existing + '\n127.0.1.1\tnvyr\n'


def test_hostname_mapping_replaces_stale_entries_and_resolves_short_name(host):
    _, path = host
    hosts_path = path.parent / 'hosts'
    hosts_path.write_text('127.0.0.1 localhost\n127.0.1.1 old\n127.0.1.1 older\n::1 localhost\n')

    system.apply_hostname('edge.example.net')

    assert hosts_path.read_text() == (
        '127.0.0.1 localhost\n127.0.1.1\tedge.example.net edge\n::1 localhost\n'
    )


@pytest.mark.parametrize('after_rename', [False, True])
@pytest.mark.parametrize('existing', [False, True])
def test_hosts_failure_restores_both_files_and_kernel(host, monkeypatch, after_rename, existing):
    current, path = host
    hosts_path = path.parent / 'hosts'
    original_hosts = hosts_path.read_text()
    hosts_path.chmod(0o640)
    if not existing:
        hosts_path.unlink()

    real_write = system.write

    def fail(target, text, **kwargs):
        if target == hosts_path and 'changed' in text:
            if after_rename:
                real_write(target, text, **kwargs)
            raise RouterError('hosts publication failed')

        return real_write(target, text, **kwargs)

    monkeypatch.setattr(system, 'write', fail)

    with pytest.raises(RouterError, match='hosts publication failed'):
        system.apply_hostname('changed')

    assert current[0] == 'nvyr'
    assert path.read_text() == 'nvyr\n'
    if existing:
        assert hosts_path.read_text() == original_hosts
        assert hosts_path.stat().st_mode & 0o777 == 0o640
    else:
        assert not hosts_path.exists()


def test_image_dependencies_and_startup_order():
    root = Path(__file__).resolve().parents[1]
    packages = (root / 'images/router.list.chroot').read_text().splitlines()
    control = (root / 'packaging/debian/control').read_text()
    dependencies = [item.strip() for item in Parser().parsestr(control)['Depends'].split(',')]

    assert {'pciutils', 'ca-certificates'} <= set(packages) & set(dependencies)

    service = (root / 'packaging/nvyr-configd.service').read_text()

    assert 'live-config.service' in next(line for line in service.splitlines() if line.startswith('After='))
