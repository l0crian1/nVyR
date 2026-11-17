"""Build Debian Trixie's ulogd with the reviewed ICMP text-formatter correction."""

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
LOCK = ROOT / 'images/ulogd-sources.lock'
PATCH = ROOT / 'vendor/ulogd/icmp-printflow.patch'
MANIFEST = 'ulogd-packages.json'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def recipe_digest():
    checksum = hashlib.sha256()
    for path in (Path(__file__), LOCK, PATCH):
        checksum.update(path.read_text().replace('\r\n', '\n').encode())
        checksum.update(b'\0')
    return checksum.hexdigest()


def package_name(lock):
    return f'ulogd2_{lock["version"]}_amd64.deb'


def install(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o644)


def stage(cache, destination):
    """Reject stale builds before copying any package into an ISO."""
    lock = json.loads(LOCK.read_text())
    try:
        manifest = json.loads((cache / MANIFEST).read_text())
        if manifest['recipe'] != recipe_digest() or manifest['version'] != lock['version']:
            raise ValueError('ulogd package recipe changed')
        if set(manifest['files']) != {package_name(lock)}:
            raise ValueError('unexpected ulogd package manifest')
        for name, checksum in manifest['files'].items():
            if digest(cache / name) != checksum:
                raise ValueError(f'checksum mismatch: {name}')
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f'{error}. Rebuild nvyr-image-builder with images/Dockerfile.') from error

    for name in (*manifest['files'], MANIFEST):
        install(cache / name, destination / name)


def build(destination):
    """Retain Debian's build options, dependencies and package layout."""
    if os.geteuid() != 0:
        raise RuntimeError('Build ulogd as root inside the isolated image builder')
    architecture = subprocess.check_output(['dpkg', '--print-architecture'], text=True).strip()
    if architecture != 'amd64':
        raise RuntimeError('The pinned ulogd build targets amd64 only')
    lock = json.loads(LOCK.read_text())
    environment = dict(os.environ, SOURCE_DATE_EPOCH=str(lock['source_date_epoch']), DEBIAN_FRONTEND='noninteractive')
    environment.pop('DEB_BUILD_OPTIONS', None)
    environment.pop('DEB_BUILD_PROFILES', None)
    destination.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix='nvyr-ulogd-build-', dir='/var/tmp') as folder:
        work = Path(folder)
        source = work / 'source'
        source.mkdir()
        for key, options in (('source', ['--strip-components=1']), ('debian', [])):
            archive = work / (key + '.tar')
            subprocess.run(['wget', '--https-only', '--timeout=30', '--tries=3', '--no-verbose',
                            '-O', str(archive), lock[key]['url']], check=True)
            if digest(archive) != lock[key]['sha256']:
                raise RuntimeError(f'ulogd {key} checksum mismatch')
            subprocess.run(['tar', '-xf', str(archive), *options, '-C', str(source)], check=True)

        subprocess.run(['dpkg-source', '--before-build', str(source)], check=True)
        subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', str(PATCH)], cwd=source, check=True)
        date = format_datetime(datetime.fromtimestamp(lock['source_date_epoch'], timezone.utc))
        changelog = source / 'debian/changelog'
        entry = (f'ulogd2 ({lock["version"]}) trixie; urgency=medium\n\n'
                 '  * Correct swapped ICMP type and code in PRINTFLOW.\n\n'
                 f' -- nVyR Router Contributors <maintainers@example.invalid>  {date}\n\n')
        changelog.write_text(entry + changelog.read_text())
        subprocess.run(['apt-get', 'update'], env=environment, check=True)
        subprocess.run(['apt-get', '-y', '--no-install-recommends', 'build-dep', str(source)], env=environment, check=True)
        subprocess.run(['dpkg-buildpackage', '-b', '-us', '-uc', '-j4'], cwd=source, env=environment, check=True)

        name = package_name(lock)
        artifact = work / name
        for field, expected in (('Package', 'ulogd2'), ('Version', lock['version']), ('Architecture', 'amd64')):
            actual = subprocess.check_output(['dpkg-deb', '-f', str(artifact), field], text=True).strip()
            if actual != expected:
                raise RuntimeError(f'Unexpected ulogd {field}: {actual}')
        manifest = {'recipe': recipe_digest(), 'version': lock['version'], 'files': {name: digest(artifact)}}
        install(artifact, destination / name)
        (destination / MANIFEST).write_text(json.dumps(manifest, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('destination', type=Path)
    arguments = parser.parse_args()
    if arguments.cache:
        stage(arguments.cache, arguments.destination)
    else:
        build(arguments.destination.resolve())


if __name__ == '__main__':
    main()
