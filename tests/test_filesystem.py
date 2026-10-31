"""Shared path confinement and descriptor lifetime, independent of containers."""

import os
from types import SimpleNamespace

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import filesystem


def test_directory_creation_and_descriptor_survive_source_replacement(tmp_path):
    root = tmp_path / 'root'
    descriptor = filesystem.open_directory(root, 'service/data', create=True)
    try:
        original = os.fstat(descriptor).st_ino
        (root / 'service/data').rename(root / 'service/saved')
        (root / 'service/data').symlink_to(tmp_path, target_is_directory=True)
        assert os.fstat(descriptor).st_ino == original
        assert original == (root / 'service/saved').stat().st_ino
    finally:
        os.close(descriptor)


def test_parent_traversal_and_absolute_relative_paths_rejected(tmp_path):
    with pytest.raises(ValueError, match='relative'):
        filesystem.open_directory(tmp_path, '../outside', create=True)
    with pytest.raises(ValueError, match='relative'):
        filesystem.open_directory(tmp_path, '/outside', create=True)
    with pytest.raises(ValueError, match='relative'):
        filesystem.read_text(tmp_path, 'child/../file')
    assert not list(tmp_path.iterdir())


def test_symlink_in_trusted_root_is_not_followed(tmp_path):
    destination = tmp_path / 'destination'
    destination.mkdir()
    (tmp_path / 'root').symlink_to(destination, target_is_directory=True)
    with pytest.raises(OSError):
        filesystem.open_directory(tmp_path / 'root', 'child', create=True)
    assert not list(destination.iterdir())


def test_text_file_uses_utf8_and_rejects_fifo_without_blocking(tmp_path):
    (tmp_path / 'text').write_text('NAME=réseau\n', encoding='utf-8')
    assert filesystem.read_text(tmp_path, 'text') == 'NAME=réseau\n'
    os.mkfifo(tmp_path / 'fifo')
    with pytest.raises(RouterError, match='regular file'):
        filesystem.read_text(tmp_path, 'fifo')


def test_bind_uses_pinned_descriptor_and_private_propagation(tmp_path, monkeypatch):
    calls = []
    descriptors = []

    def mount(argv, **options):
        descriptor = options['pass_fds'][0]
        descriptors.append(descriptor)
        assert argv[2] == f'/proc/self/fd/{descriptor}'
        assert os.fstat(descriptor).st_ino == (tmp_path / 'root/data').stat().st_ino
        calls.append(argv)
        return SimpleNamespace(returncode=0, stderr='')

    monkeypatch.setattr(filesystem.subprocess, 'run', mount)
    monkeypatch.setattr(filesystem, 'cmd', lambda argv: calls.append(argv))
    target = tmp_path / 'mount'
    filesystem.bind_path(tmp_path / 'root', 'data', target, create=True)

    assert calls[-1] == ['mount', '--make-private', str(target)]
    with pytest.raises(OSError):
        os.fstat(descriptors[0])


def test_failed_bind_closes_source_descriptor(tmp_path, monkeypatch):
    descriptors = []

    def mount(argv, **options):
        descriptors.extend(options['pass_fds'])
        return SimpleNamespace(returncode=1, stderr='mount denied')

    monkeypatch.setattr(filesystem.subprocess, 'run', mount)
    with pytest.raises(RouterError, match='mount denied'):
        filesystem.bind_path(tmp_path / 'root', 'data', tmp_path / 'mount', create=True)
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
