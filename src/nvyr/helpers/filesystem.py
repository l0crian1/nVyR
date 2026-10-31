"""Descriptor-based filesystem access beneath caller-selected trusted roots."""

import os
from pathlib import Path
import stat
import subprocess

from nvyr.errors import RouterError
from nvyr.helpers.process import cmd


def protected_directory(path, *, create=True):
    """Require a root-owned, non-symlink directory without group or world write."""
    path = Path(path)
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        if not create:
            return
        raise
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise RouterError(f'Reserved directory is not protected: {path}')


def open_directory(root, relative='', *, create=False):
    """Return an owned descriptor; never follow symlinks, including within root."""
    root = Path(root)
    parts = relative.split('/') if relative else []
    if not root.is_absolute() or '..' in root.parts:
        raise ValueError('Root must be an absolute path without parent traversal')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('Path must be relative without empty or parent components')

    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in (*root.parts[1:], *parts):
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def open_source(root, relative, *, create=False):
    """Open a regular file or directory without following symlinks or FIFOs."""
    parts = relative.split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('Source must be relative without empty or parent components')
    parent = open_directory(root, '/'.join(parts[:-1]), create=create)
    try:
        if create:
            try:
                os.mkdir(parts[-1], mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        metadata = os.fstat(descriptor)
        if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            os.close(descriptor)
            raise RouterError('Bind source must be a regular file or directory')
        return descriptor
    finally:
        os.close(parent)


def source_permissions(descriptor, *, uid=-1, gid=-1, mode=None, recursive=False):
    """Prepare persistent metadata; recursion never follows symbolic links."""
    def traversal_error(error):
        raise error

    if uid != -1 or gid != -1:
        os.fchown(descriptor, uid, gid)
        if recursive and stat.S_ISDIR(os.fstat(descriptor).st_mode):
            for _, directories, files, directory in os.fwalk(
                    '.', dir_fd=descriptor, follow_symlinks=False, onerror=traversal_error):
                os.fchown(directory, uid, gid)
                for name in directories + files:
                    os.chown(name, uid, gid, dir_fd=directory, follow_symlinks=False)
    # Apply permissions after chown, which can clear set-ID bits. Never chmod children.
    if mode is not None:
        os.fchmod(descriptor, mode)


def bind_path(root, relative, target, *, create=False, uid=-1, gid=-1, mode=None, recursive=False):
    """Bind a pinned file/directory after preparing its requested persistent metadata."""
    descriptor = open_source(root, relative, create=create)
    try:
        source_permissions(descriptor, uid=uid, gid=gid, mode=mode, recursive=recursive)
        target = Path(target)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            target.mkdir(exist_ok=True, mode=0o700)
        else:
            target.touch(mode=0o600, exist_ok=True)
        result = subprocess.run(['mount', '--bind', f'/proc/self/fd/{descriptor}', str(target)],
                                pass_fds=(descriptor,), capture_output=True, text=True, check=False)
        if result.returncode:
            raise RouterError(result.stderr.strip() or f'Cannot bind source {relative}')
        cmd(['mount', '--make-private', str(target)])
    finally:
        os.close(descriptor)


def read_text(root, relative):
    """Read a regular UTF-8 file without traversing symlinks or blocking on a FIFO."""
    parts = relative.split('/')
    if any(part in ('', '.', '..') for part in parts):
        raise ValueError('File path must be relative without empty or parent components')
    directory = open_directory(root, '/'.join(parts[:-1]))
    try:
        descriptor = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise RouterError('File source must be a regular file')
        with os.fdopen(descriptor, 'r', encoding='utf-8') as stream:
            return stream.read()
    finally:
        os.close(directory)
