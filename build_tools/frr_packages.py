"""Build pinned FRR Debian packages with Lua and the reviewed reload ordering fix."""

import argparse
from datetime import datetime, timezone
from email.utils import format_datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'images/frr-sources.lock'
PATCH = ROOT / 'vendor/frr/reload-ordering.patch'
MANIFEST = 'frr-packages.json'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def recipe_digest():
    """Changing any build input invalidates previously cached packages."""
    checksum = hashlib.sha256()
    for path in (Path(__file__), LOCK, PATCH):
        checksum.update(path.read_text(encoding='utf-8').replace('\r\n', '\n').encode())
        checksum.update(b'\0')
    return checksum.hexdigest()


def package_files(lock):
    return {f'{name}_{lock["version"]}_{architecture}.deb': (name, architecture)
            for name, architecture in lock['packages'].items()}


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, **kwargs)


def install(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o644)


def stage(cache, destination):
    """Validate the complete cache before publishing any packages to live-build."""
    lock = json.loads(LOCK.read_text())
    try:
        manifest = json.loads((cache / MANIFEST).read_text())
        if manifest['recipe'] != recipe_digest():
            raise ValueError('FRR package recipe changed')
        if manifest['version'] != lock['version']:
            raise ValueError('FRR package version changed')
        if set(manifest['files']) != set(package_files(lock)):
            raise ValueError('incomplete or unexpected FRR package manifest')
        for name, checksum in manifest['files'].items():
            if digest(cache / name) != checksum:
                raise ValueError(f'checksum mismatch: {name}')
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f'{error}. Rebuild nvyr-image-builder with images/Dockerfile.') from error

    for name in manifest['files']:
        install(cache / name, destination / name)
    install(cache / MANIFEST, destination / MANIFEST)


def prepare_source(work, lock):
    archive = work / 'frr.tar.gz'
    run(['wget', '--https-only', '--timeout=30', '--tries=3', '--no-verbose',
         '-O', str(archive), lock['source']['url']])
    if digest(archive) != lock['source']['sha256']:
        raise RuntimeError('FRR source checksum mismatch')

    source = work / 'source'
    source.mkdir()
    run(['tar', '-xzf', str(archive), '--strip-components=1', '-C', str(source)])
    run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(PATCH)], cwd=source)

    # Keep upstream's Debian options and package layout; change only our revision.
    date = format_datetime(datetime.fromtimestamp(lock['source_date_epoch'], timezone.utc))
    entry = (f'frr ({lock["version"]}) trixie; urgency=medium\n\n'
             '  * Enable Lua scripting and fix BGP list replacement ordering.\n\n'
             f' -- nVyR Router Contributors <maintainers@example.invalid>  {date}\n\n')
    changelog = source / 'debian/changelog'
    changelog.write_text(entry + changelog.read_text(), encoding='utf-8')
    return source


def build(destination):
    """Run only as root in the isolated Debian Trixie builder."""
    if os.geteuid() != 0:
        raise RuntimeError('Build FRR as root inside the isolated image builder')
    architecture = subprocess.check_output(['dpkg', '--print-architecture'], text=True).strip()
    if architecture != 'amd64':
        raise RuntimeError('The pinned FRR build targets amd64 only')
    jobs = int(os.environ.get('NVYR_BUILD_JOBS', '4'))
    if jobs < 1:
        raise ValueError('NVYR_BUILD_JOBS must be positive')

    lock = json.loads(LOCK.read_text())
    profiles = ','.join(lock['profiles'])
    environment = dict(os.environ, SOURCE_DATE_EPOCH=str(lock['source_date_epoch']),
                       DEBIAN_FRONTEND='noninteractive', DEB_BUILD_PROFILES=' '.join(lock['profiles']))
    # Do not inherit host profiles/options that could disable tests or change features.
    environment.pop('DEB_BUILD_OPTIONS', None)

    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='nvyr-frr-build-', dir='/var/tmp') as temporary:
        work = Path(temporary)
        source = prepare_source(work, lock)
        run(['apt-get', 'update'], env=environment)
        run(['apt-get', '-y', '--no-install-recommends', 'build-dep', '-P' + profiles, str(source)], env=environment)
        run(['apt-get', 'install', '-y', '--no-install-recommends', 'autoconf', 'automake', 'libtool'], env=environment)
        run(['./bootstrap.sh'], cwd=source, env=environment)
        run(['dpkg-buildpackage', '-b', '-us', '-uc', '-j' + str(jobs), '-P' + profiles],
            cwd=source, env=environment)

        # A build without Lua must fail here even if its package creation succeeded.
        config = (source / 'build/config.h').read_text()
        if '#define HAVE_SCRIPTING 1' not in config:
            raise RuntimeError('FRR was built without scripting support')

        files = {}
        for filename, (name, arch) in package_files(lock).items():
            artifact = work / filename
            for field, expected in (('Package', name), ('Version', lock['version']), ('Architecture', arch)):
                actual = subprocess.check_output(['dpkg-deb', '-f', str(artifact), field], text=True).strip()
                if actual != expected:
                    raise RuntimeError(f'{filename}: unexpected {field}: {actual}')
            files[filename] = digest(artifact)
        for filename in files:
            install(work / filename, destination / filename)

    manifest = {'recipe': recipe_digest(), 'version': lock['version'], 'files': files}
    (destination / MANIFEST).write_text(json.dumps(manifest, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, help='Stage verified cached packages instead of building')
    parser.add_argument('destination', type=Path)
    arguments = parser.parse_args()
    if arguments.cache:
        stage(arguments.cache, arguments.destination)
    else:
        build(arguments.destination.resolve())


if __name__ == '__main__':
    main()
