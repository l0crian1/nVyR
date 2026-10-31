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


def bind_directory(root, relative, target):
    """Bind a pinned source directory and prevent propagation back to its source."""
    descriptor = open_directory(root, relative, create=True)
    try:
        target = Path(target)
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        result = subprocess.run(['mount', '--bind', f'/proc/self/fd/{descriptor}', str(target)],
                                pass_fds=(descriptor,), capture_output=True, text=True, check=False)
        if result.returncode:
            raise RouterError(result.stderr.strip() or f'Cannot bind directory {relative}')
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
