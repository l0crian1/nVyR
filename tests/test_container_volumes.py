"""Bind sources, image account resolution and explicit persistent volume metadata."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import container
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import containers, filesystem, validators
from tests.container_harness import verify_container
from tests.test_containers import FakeRuntime, configuration


def test_volume_cli_accepts_host_files_and_anchored_owner(controller, engine, session):
    controller.execute('set container name APP image alpine', session)
    controller.execute('set container name APP volume HOSTS source /etc/hosts', session)
    controller.execute('set container name APP volume HOSTS destination /etc/hosts', session)
    controller.execute('set container name APP volume HOSTS read-only', session)
    controller.execute('set container name APP volume DATA source APP/data', session)
    controller.execute('set container name APP volume DATA destination /data', session)
    controller.execute('set container name APP volume DATA owner user redis group redis recursive', session)
    controller.execute('set container name APP volume DATA mode 0750', session)

    section = engine.view(session)['container']
    verify_container(section)
    assert section['name']['APP']['volume']['DATA']['owner'] == {
        'user': 'redis', 'group': 'redis', 'recursive': True}


@pytest.mark.parametrize('value', ['/etc/hosts', '/srv/data', '/config/containers/app/data', 'app/data'])
def test_volume_sources(value):
    assert validators.container_volume_source(value)


@pytest.mark.parametrize('value', ['/etc/../passwd', '//etc/hosts', '/', '../data', 'data\n', ''])
def test_invalid_volume_sources(value):
    assert not validators.container_volume_source(value)


@pytest.mark.parametrize('value', ['0', '4294967294', 'redis', '_service', 'app-user'])
def test_owner_values(value):
    assert validators.container_volume_owner(value)


@pytest.mark.parametrize('value', ['4294967295', '9' * 5000, '-1', 'a:b', 'a/b', '123x', 'redis\n'])
def test_invalid_owner_values(value):
    assert not validators.container_volume_owner(value)


def test_recursive_requires_an_owner():
    desired = configuration()
    desired['name']['APP']['volume'] = {'DATA': {
        'source': 'app', 'destination': '/data', 'owner': {'recursive': True}}}
    with pytest.raises(ValidationError, match='specify user or group'):
        verify_container(desired)


def test_generation_resolves_names_once_against_pinned_image(monkeypatch):
    calls = []

    def accounts(argv):
        calls.append(argv)
        return json.dumps({'user': {'redis': 101}, 'group': {'redis': 102}})

    monkeypatch.setattr(container, 'cmd', accounts)
    section = {'volume': {
        'DATA': {'source': 'app/data', 'destination': '/data',
                 'owner': {'user': 'redis', 'group': 'redis', 'recursive': True}, 'mode': '0750'},
        'HOSTS': {'source': '/etc/hosts', 'destination': '/etc/hosts', 'read-only': True},
        'OTHER': {'source': '/config/containers/app/other', 'destination': '/other',
                  'owner': {'user': '1000'}},
    }}
    mounts = container.volume_mounts('APP', section, 'sha256:123')

    assert len(calls) == 1
    assert calls[0][-2:] == ['accounts', 'sha256:123']
    assert mounts[0]['uid'] == 101 and mounts[0]['gid'] == 102
    assert mounts[0]['mode'] == 0o750 and mounts[0]['recursive']
    assert mounts[0]['source'] == '/config/containers/app/data' and mounts[0]['create']
    assert mounts[1]['source'] == '/etc/hosts' and not mounts[1]['create']
    assert mounts[2]['uid'] == 1000 and 'gid' not in mounts[2] and mounts[2]['create']
    section['volume']['DATA']['owner']['user'] = 'missing'
    with pytest.raises(RouterError, match="user 'missing' does not exist"):
        container.volume_mounts('APP', section, 'sha256:123')


def test_image_accounts_reads_files_and_releases_mount_on_error(tmp_path, monkeypatch):
    (tmp_path / 'etc').mkdir()
    (tmp_path / 'etc/passwd').write_text('redis:x:101:102::/:/bin/false\n')
    (tmp_path / 'etc/group').write_text('redis:x:102:\n')
    calls = []

    def command(argv):
        calls.append(argv)
        return str(tmp_path) if argv[2] == 'mount' else ''

    monkeypatch.setattr(containers, 'cmd', command)
    assert containers.image_accounts('IMAGE') == {'user': {'redis': 101}, 'group': {'redis': 102}}
    assert calls[-1] == ['podman', 'image', 'unmount', 'IMAGE']

    (tmp_path / 'etc/passwd').unlink()
    (tmp_path / 'etc/passwd').symlink_to('/etc/passwd')
    with pytest.raises(OSError):
        containers.image_accounts('IMAGE')
    assert calls[-1] == ['podman', 'image', 'unmount', 'IMAGE']


def test_missing_external_source_fails_before_stopping_containers(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    desired['name']['APP']['volume'] = {'DATA': {'source': str(tmp_path / 'absent'), 'destination': '/data'}}
    generated = runtime.generate(desired)
    with pytest.raises(RouterError, match='bind source does not exist'):
        runtime.apply(generated)
    assert not runtime.pending.exists()
    assert not any(event[:2] == ('systemctl', 'stop') for event in runtime.events)
    assert not (tmp_path / 'absent').exists()


def test_named_owner_failure_does_not_block_boot_recovery(tmp_path, monkeypatch):
    runtime = FakeRuntime(tmp_path)
    messages = []
    runtime.report = messages.append
    desired = configuration()

    def missing(*args):
        raise RouterError('Image account unavailable')

    monkeypatch.setattr(container, 'volume_mounts', missing)
    with pytest.raises(RouterError, match='Image account unavailable'):
        runtime.generate(desired)
    generated = runtime.generate(desired, recovery=True)
    assert generated['forward']['containers'] == {}
    assert 'Container unavailable: APP: Image account unavailable' in messages


def test_unmount_removes_file_and_directory_staging_targets(tmp_path, monkeypatch):
    monkeypatch.setattr(container.config, 'MOUNT_ROOT', str(tmp_path))
    root = tmp_path / 'APP'.encode().hex()
    root.mkdir()
    (root / 'file').touch()
    (root / 'directory').mkdir()
    container.unmount('APP')
    assert not root.exists()


def test_file_mount_preserves_contents_and_sets_only_requested_metadata(tmp_path, monkeypatch):
    source = tmp_path / 'hosts'
    source.write_text('127.0.0.1 example\n')
    target = tmp_path / 'mount/hosts'
    calls = []

    def mount(argv, **options):
        fd = options['pass_fds'][0]
        assert os.fstat(fd).st_ino == source.stat().st_ino
        calls.append(argv)
        return SimpleNamespace(returncode=0, stderr='')

    monkeypatch.setattr(filesystem.subprocess, 'run', mount)
    monkeypatch.setattr(filesystem, 'cmd', lambda argv: calls.append(argv))
    filesystem.bind_path(tmp_path, 'hosts', target, mode=0o640)

    assert target.is_file()
    assert source.read_text() == '127.0.0.1 example\n'
    assert source.stat().st_mode & 0o777 == 0o640
    assert calls[-1] == ['mount', '--make-private', str(target)]


def test_recursive_owner_does_not_follow_symlinks_or_chmod_children(tmp_path, monkeypatch):
    root = tmp_path / 'data'
    root.mkdir()
    child = root / 'file'
    child.write_text('data')
    child.chmod(0o600)
    outside = tmp_path / 'outside'
    outside.mkdir()
    (outside / 'untouched').write_text('outside')
    (root / 'link').symlink_to(outside, target_is_directory=True)
    visits = []
    monkeypatch.setattr(os, 'fchown', lambda fd, uid, gid: visits.append(os.fstat(fd).st_ino))

    def chown(name, uid, gid, *, dir_fd, follow_symlinks):
        assert follow_symlinks is False
        visits.append(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_ino)

    monkeypatch.setattr(os, 'chown', chown)
    descriptor = filesystem.open_source(tmp_path, 'data')
    try:
        filesystem.source_permissions(descriptor, uid=101, gid=102, recursive=True, mode=0o750)
    finally:
        os.close(descriptor)
    assert child.stat().st_ino in visits
    assert outside.stat().st_ino not in visits
    assert (outside / 'untouched').stat().st_ino not in visits
    assert child.stat().st_mode & 0o777 == 0o600
    assert root.stat().st_mode & 0o777 == 0o750


def test_recursive_owner_reports_unreadable_subtree(tmp_path, monkeypatch):
    def inaccessible(path, *, dir_fd, follow_symlinks, onerror):
        onerror(PermissionError('Cannot traverse child'))

    monkeypatch.setattr(os, 'fwalk', inaccessible)
    monkeypatch.setattr(os, 'fchown', lambda *args: None)
    descriptor = filesystem.open_directory(tmp_path)
    try:
        with pytest.raises(PermissionError, match='Cannot traverse child'):
            filesystem.source_permissions(descriptor, uid=101, recursive=True)
    finally:
        os.close(descriptor)
