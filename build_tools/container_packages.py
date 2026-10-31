"""Build and stage the reviewed amd64 container stack without mixing Debian suites."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'images/container-sources.lock'
MANIFEST = 'container-packages.json'


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def recipe_digest():
    # LF normalization makes the build recipe identical on Windows and Linux checkouts.
    source = Path(__file__).read_text().replace('\r\n', '\n')
    lock = LOCK.read_text().replace('\r\n', '\n')
    return hashlib.sha256((source + '\n' + lock).encode()).hexdigest()


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, **kwargs)


def install(source, destination, mode=0o644):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def stage(cache, destination):
    """Refuse stale builders or damaged artifacts before live-build can install them."""
    try:
        manifest = json.loads((cache / MANIFEST).read_text())
        if manifest['recipe'] != recipe_digest():
            raise ValueError('container package recipe changed')
        expected = json.loads(LOCK.read_text())['packages']
        if manifest['versions'] != expected:
            raise ValueError('container package versions changed')
        if len(manifest['files']) != len(expected):
            raise ValueError('incomplete container package manifest')
        for name, checksum in manifest['files'].items():
            if Path(name).name != name or not name.endswith('.deb'):
                raise ValueError('invalid package filename')
            if digest(cache / name) != checksum:
                raise ValueError(f'checksum mismatch: {name}')
    except (OSError, KeyError, ValueError) as error:
        raise RuntimeError(f'{error}. Rebuild nvyr-image-builder with images/Dockerfile.') from error

    destination.mkdir(parents=True, exist_ok=True)
    for name in manifest['files']:
        install(cache / name, destination / name)
    install(cache / MANIFEST, destination / MANIFEST)


def package(work, destination, name, version, architecture, dependencies, binaries=()):
    root = work / name
    control = root / 'DEBIAN'
    control.mkdir(parents=True, exist_ok=True)
    if binaries:
        # Calculate ABI dependencies against Trixie rather than guessing library versions.
        result = run(['dpkg-shlibdeps', '-O', *['-e' + str(path) for path in binaries]],
                     cwd=work, text=True, capture_output=True)
        libraries = result.stdout.strip().removeprefix('shlibs:Depends=')
        dependencies = ', '.join(filter(None, (dependencies, libraries)))
    text = (f'Package: {name}\nVersion: {version}\nArchitecture: {architecture}\n'
            'Maintainer: nVyR Router Contributors <maintainers@example.invalid>\n'
            'Section: admin\nPriority: optional\n'
            f'Description: {name} container runtime component packaged for nVyR\n')
    if dependencies:
        text += f'Depends: {dependencies}\n'
    (control / 'control').write_text(text)
    configs = sorted('/' + str(path.relative_to(root)) for path in (root / 'etc').rglob('*') if path.is_file())
    if configs:
        (control / 'conffiles').write_text('\n'.join(configs) + '\n')
    artifact = destination / f'{name}_{version}_{architecture}.deb'
    run(['dpkg-deb', '--root-owner-group', '-Zxz', '--build', str(root), str(artifact)])
    return artifact


def build(destination):
    if subprocess.check_output(['dpkg', '--print-architecture'], text=True).strip() != 'amd64':
        raise RuntimeError('The pinned container stack targets amd64 only')
    lock = json.loads(LOCK.read_text())
    destination.mkdir(parents=True, exist_ok=True)
    os.environ['SOURCE_DATE_EPOCH'] = str(lock['source_date_epoch'])

    with tempfile.TemporaryDirectory(prefix='nvyr-container-build-', dir='/var/tmp') as temporary:
        work = Path(temporary)
        for name, archive in lock['archives'].items():
            target = work / name
            run(['wget', '--https-only', '--timeout=30', '--tries=3', '--no-verbose',
                 '-O', str(target), archive['url']])
            if digest(target) != archive['sha256']:
                raise RuntimeError(f'Checksum mismatch: {name}')
            if name.endswith('.tar.gz'):
                run(['tar', '-xzf', str(target), '-C', str(work)])

        source = work / 'podman-6.1.4'
        os.environ['PATH'] = str(work / 'go/bin') + os.pathsep + os.environ['PATH']
        os.environ['GOTOOLCHAIN'] = 'local'
        os.environ['GOFLAGS'] = '-mod=vendor -trimpath'
        os.environ['GOMAXPROCS'] = os.environ.get('NVYR_BUILD_JOBS', '4')
        options = ['PREFIX=/usr', 'LIBEXECDIR=/usr/lib', 'GIT_COMMIT=',
                   'BUILDTAGS=seccomp systemd', 'GOMD2MAN=/usr/bin/go-md2man']
        run(['make', '-j' + os.environ['GOMAXPROCS'], *options,
             'bin/podman', 'bin/quadlet', 'bin/rootlessport', 'docs'], cwd=source)
        podman = work / 'podman'
        run(['make', *options, 'DESTDIR=' + str(podman), 'install.bin', 'install.man', 'install.systemd'], cwd=source)
        install(source / 'LICENSE', podman / 'usr/share/doc/podman/copyright')

        common = work / 'golang-github-containers-common'
        vendor = source / 'vendor/go.podman.io/common'
        install(vendor / 'pkg/config/containers.conf', common / 'usr/share/containers/containers.conf')
        install(vendor / 'pkg/seccomp/seccomp.json', common / 'usr/share/containers/seccomp.json')
        install(vendor / 'LICENSE', common / 'usr/share/doc/golang-github-containers-common/copyright')
        policy = common / 'etc/containers/policy.json'
        policy.parent.mkdir(parents=True)
        policy.write_text(json.dumps({'default': [{'type': 'insecureAcceptAnything'}]}, indent=2) + '\n')

        for name in ('netavark', 'aardvark-dns'):
            root = work / name
            executable = root / 'usr/lib/podman' / name
            executable.parent.mkdir(parents=True)
            with gzip.open(work / (name + '.gz'), 'rb') as compressed:
                executable.write_bytes(compressed.read())
            executable.chmod(0o755)
            run([str(executable), '--version'])
            install(work / (name + '-2.1.0') / 'LICENSE', root / f'usr/share/doc/{name}/copyright')

        # dpkg-shlibdeps expects a Debian source control file even for independently staged packages.
        (work / 'debian').mkdir()
        (work / 'debian/control').write_text('Source: nvyr-containers\nSection: admin\nPriority: optional\n'
                                           'Maintainer: nVyR Router Contributors <maintainers@example.invalid>\n\n'
                                           'Package: podman\nArchitecture: amd64\nDescription: nVyR container stack\n')
        dependencies = {
            'podman': ('conmon (>= 2.1.12), crun (>= 1.21), '
                       'golang-github-containers-common (>= 0.69.2), '
                       'netavark (>= 2.1.0), netavark (<< 3), '
                       'aardvark-dns (>= 2.1.0), aardvark-dns (<< 3), ca-certificates'),
            'netavark': 'nftables (>= 1.1.7)',
            'aardvark-dns': 'netavark (>= 2.1.0), netavark (<< 3)',
            'golang-github-containers-common': '',
        }
        binaries = {
            'podman': [podman / 'usr/bin/podman', podman / 'usr/lib/podman/quadlet', podman / 'usr/lib/podman/rootlessport'],
            'netavark': [work / 'netavark/usr/lib/podman/netavark'],
            'aardvark-dns': [work / 'aardvark-dns/usr/lib/podman/aardvark-dns'],
        }
        files = {}
        for name, version in lock['packages'].items():
            architecture = 'amd64' if name in binaries else 'all'
            artifact = package(work, destination, name, version, architecture, dependencies[name], binaries.get(name, ()))
            files[artifact.name] = digest(artifact)

    manifest = {'recipe': recipe_digest(), 'versions': lock['packages'], 'files': files}
    (destination / MANIFEST).write_text(json.dumps(manifest, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path, help='Stage already built and verified packages instead of compiling')
    parser.add_argument('destination', type=Path)
    arguments = parser.parse_args()
    if arguments.cache:
        stage(arguments.cache, arguments.destination)
    else:
        build(arguments.destination.resolve())


if __name__ == '__main__':
    main()
