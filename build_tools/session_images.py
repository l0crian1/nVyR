"""Bundle three offline CLI images from the installed, version-matched packages.

This runs during package configuration (also in the ISO chroot). It needs no
registry, Podman daemon or build namespace. One shared filesystem layer keeps
the role images small; configd, not the image's label, enforces authorization.
"""

import hashlib
import compileall
import json
import os
from pathlib import Path
import platform
import py_compile
import re
import shutil
import subprocess
import sysconfig
import tarfile
import tempfile

OUTPUT = Path('/usr/share/nvyr/session-images')
ROLES = ('sys-admin', 'net-admin', 'read-only')


def copy_path(source, root):
    source = Path(source)
    destination = root / source.relative_to('/')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.is_symlink():
        if not destination.is_symlink():
            destination.symlink_to(os.readlink(source))
        # Preserve the target as seen inside the image, including on usr-merged
        # hosts where resolving the parent first would leave /lib symlinks broken.
        target = Path(os.path.abspath(source.parent / os.readlink(source)))
        copy_path(target, root)
    elif source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True, symlinks=True,
                        ignore=shutil.ignore_patterns('__pycache__', 'tests', 'ensurepip', 'idlelib', 'tkinter'))
    else:
        shutil.copy2(source, destination)


def libraries(binary, root):
    result = subprocess.run(['ldd', str(binary)], text=True, capture_output=True, check=True)
    if 'not found' in result.stdout:
        raise RuntimeError(f'Unresolved CLI image dependency: {binary}\n{result.stdout}')
    for path in re.findall(r'(?:=>\s+|^\s*)(/\S+)', result.stdout, re.MULTILINE):
        copy_path(path, root)


def layer_info(info):
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = 'root'
    return info


def build(output=OUTPUT, *, nvyr_source=Path('/usr/lib/python3/dist-packages/nvyr')):
    previous = os.umask(0o022)
    try:
        _build(output, nvyr_source)
    finally:
        os.umask(previous)


def _build(output, nvyr_source):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='nvyr-session-images-') as directory:
        staging = Path(directory)
        root = staging / 'root'
        root.mkdir()
        stdlib = Path(sysconfig.get_path('stdlib'))
        for path in ('/usr/bin/python3', '/usr/bin/less', stdlib):
            copy_path(path, root)
        shutil.copytree(nvyr_source, root / 'usr/lib/python3/dist-packages/nvyr',
                        ignore=shutil.ignore_patterns('__pycache__'))
        for package in ('prompt_toolkit', 'wcwidth', 'tabulate'):
            source = Path('/usr/lib/python3/dist-packages') / package
            if not source.exists():
                source = source.with_suffix('.py')
            copy_path(source, root)
        for binary in [Path('/usr/bin/python3'), Path('/usr/bin/less'), *stdlib.glob('lib-dynload/*.so')]:
            libraries(binary, root)

        for directory in ('etc', 'tmp', 'run/nvyr', 'home/user', 'dev', 'proc', 'sys'):
            (root / directory).mkdir(parents=True, exist_ok=True)
        (root / 'tmp').chmod(0o1777)
        (root / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/false\n')
        (root / 'etc/group').write_text('root:x:0:\n')
        # less/prompt-toolkit need the terminal capability database, not a shell.
        for path in ('/usr/share/terminfo', '/lib/terminfo'):
            if Path(path).exists():
                copy_path(path, root)

        # Keep distribution copyright notices with the copied runtime binaries.
        for path in Path('/usr/share/doc').glob('*/copyright'):
            copy_path(path, root)

        # Hash-based bytecode remains valid after reproducible tar timestamps are
        # normalized and avoids compiling the CLI on every short-lived login.
        if not compileall.compile_dir(root / 'usr/lib', quiet=1,
                                      stripdir=str(root), prependdir='/',
                                      invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH):
            raise RuntimeError('Could not compile the bundled CLI runtime')

        layer = staging / 'layer.tar'
        with tarfile.open(layer, 'w') as archive:
            for path in sorted(root.iterdir()):
                archive.add(path, arcname=path.name, filter=layer_info)
        with layer.open('rb') as stream:
            layer_digest = hashlib.file_digest(stream, 'sha256').hexdigest()

        architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
        manifest, images = [], {}
        for role in ROLES:
            config = {'architecture': architecture, 'os': 'linux',
                      'config': {'Env': ['PATH=/usr/bin', 'LANG=C.UTF-8', 'PYTHONDONTWRITEBYTECODE=1'],
                                 'Entrypoint': ['/usr/bin/python3', '-I', '-m', 'nvyr.session_client'],
                                 'Labels': {'nvyr.internal': 'cli-session', 'nvyr.role': role}},
                      'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + layer_digest]}}
            data = json.dumps(config, sort_keys=True).encode()
            digest = hashlib.sha256(data).hexdigest()
            filename = digest + '.json'
            (staging / filename).write_bytes(data)
            images[role] = 'sha256:' + digest
            manifest.append({'Config': filename, 'RepoTags': [f'localhost/nvyr-cli-{role}:installed'],
                             'Layers': ['layer.tar']})
        (staging / 'manifest.json').write_text(json.dumps(manifest))

        target = output / 'images.tar.tmp'
        with tarfile.open(target, 'w') as archive:
            for path in sorted(staging.iterdir()):
                if path.is_file():
                    archive.add(path, arcname=path.name, filter=layer_info)
        target.replace(output / 'images.tar')
        target = output / 'manifest.json.tmp'
        target.write_text(json.dumps({'images': images}, sort_keys=True) + '\n')
        target.replace(output / 'manifest.json')


if __name__ == '__main__':
    build()
