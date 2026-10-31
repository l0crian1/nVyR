"""Build the pinned LTS kernel using Debian's general-purpose amd64 configuration."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / 'images/kernel-sources.lock'
MANIFEST = 'kernel-packages.json'
SOURCE_BUNDLE = 'kernel-source.tar'

# Fail the build if configuration evolution drops a feature nVyR relies on.
REQUIRED = (
    'BLK_DEV_INITRD', 'DEVTMPFS', 'EFI', 'EXT4_FS', 'SQUASHFS', 'OVERLAY_FS',
    'VIRTIO_BLK', 'VIRTIO_NET', 'VIRTIO_PCI', 'FUSE_FS', 'CGROUPS', 'NAMESPACES',
    'NET_NS', 'INET', 'IPV6', 'IP_MULTIPLE_TABLES', 'IPV6_MULTIPLE_TABLES', 'IP_ROUTE_MULTIPATH',
    'NET_VRF', 'VETH', 'DUMMY', 'BRIDGE', 'BRIDGE_VLAN_FILTERING',
    'VLAN_8021Q', 'NF_CONNTRACK', 'NF_NAT', 'NF_TABLES', 'NF_TABLES_INET',
    'NF_TABLES_NETDEV', 'NETFILTER_NETLINK_HOOK', 'NF_FLOW_TABLE', 'NF_FLOW_TABLE_INET', 'NFT_FLOW_OFFLOAD',
    'NF_CT_NETLINK', 'NFT_CT', 'NFT_FIB_INET', 'NFT_LOG', 'NFT_LIMIT', 'NFT_QUOTA', 'NFT_NAT',
    'DEBUG_INFO_BTF',
)


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def recipe_digest():
    """Invalidate cached binaries whenever the source pin or build recipe changes."""
    checksum = hashlib.sha256()
    for path in (Path(__file__), LOCK):
        checksum.update(path.read_text(encoding='utf-8').replace('\r\n', '\n').encode())
        checksum.update(b'\0')
    return checksum.hexdigest()


def release(lock):
    return lock['version'] + lock['local_version']


def package_filename(lock):
    return f'linux-image-{release(lock)}_{lock["package_version"]}_amd64.deb'


def install(source, destination):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(0o644)


def stage(cache, destination):
    """Verify all cached artifacts before staging the kernel for ISO assembly."""
    lock = json.loads(LOCK.read_text())
    try:
        manifest = json.loads((cache / MANIFEST).read_text())
        if manifest['recipe'] != recipe_digest():
            raise ValueError('Kernel package recipe changed')
        if manifest['release'] != release(lock):
            raise ValueError('Kernel release changed')
        if set(manifest['files']) != {package_filename(lock), SOURCE_BUNDLE}:
            raise ValueError('incomplete or unexpected kernel package manifest')
        for name, checksum in manifest['files'].items():
            if digest(cache / name) != checksum:
                raise ValueError(f'checksum mismatch: {name}')
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f'{error}. Rebuild nvyr-image-builder with images/Dockerfile.') from error

    for name in manifest['files']:
        install(cache / name, destination / name)
    install(cache / MANIFEST, destination / MANIFEST)


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, **kwargs)


def download(specification, destination):
    """Check pinned inputs before extracting either executable code or config."""
    run(['wget', '--https-only', '--timeout=30', '--tries=3', '--no-verbose',
         '-O', str(destination), specification['url']])
    if digest(destination) != specification['sha256']:
        raise RuntimeError(f'Kernel input checksum mismatch: {destination.name}')


def verify_configuration(path):
    """Check the resolved configuration, including dependencies chosen by Kconfig."""
    settings = set(path.read_text().splitlines())
    missing = []
    for name in REQUIRED:
        # Kconfig can drop a requested feature when one of its dependencies is unavailable.
        if f'CONFIG_{name}=y' not in settings and f'CONFIG_{name}=m' not in settings:
            missing.append(name)

    # Never publish a kernel that cannot boot the image or provide its networking features.
    if missing:
        raise RuntimeError('Kernel configuration is missing: ' + ', '.join(missing))


def configure(source, baseline, lock, environment):
    """Preserve Debian drivers and BTF; replace distribution-specific build identity."""
    shutil.copyfile(baseline, source / '.config')
    run(['scripts/config', '--set-str', 'LOCALVERSION', lock['local_version'],
         '--module', 'NETFILTER_NETLINK_HOOK',
         '--disable', 'LOCALVERSION_AUTO', '--set-str', 'SYSTEM_TRUSTED_KEYS', '',
         '--set-str', 'SYSTEM_REVOCATION_KEYS', '',
         '--set-str', 'MODULE_SIG_KEY', 'certs/signing_key.pem'], cwd=source, env=environment)
    run(['make', 'olddefconfig'], cwd=source, env=environment)
    verify_configuration(source / '.config')
    actual = subprocess.check_output(['make', '-s', 'kernelrelease'], cwd=source,
                                     env=environment, text=True).strip()
    if actual != release(lock):
        raise RuntimeError(f'Unexpected kernel release: {actual}')


def source_bundle(destination, work, baseline, source):
    """Keep exact source, configuration and build instructions beside the binary."""
    with tarfile.open(destination, 'w') as archive:
        for path, name in (
            (work / 'linux.tar.xz', 'linux.tar.xz'),
            (baseline, 'debian.config'),
            (source / '.config', 'kernel.config'),
            (LOCK, 'images/kernel-sources.lock'),
            (Path(__file__), 'build_tools/kernel_packages.py'),
            (ROOT / 'images/Dockerfile', 'images/Dockerfile'),
        ):
            archive.add(path, arcname=name)


def build(destination):
    """Compile once inside the builder; subsequent ISO builds reuse checked packages."""
    if os.geteuid() != 0:
        raise RuntimeError('Build the kernel as root inside the isolated image builder')
    architecture = subprocess.check_output(['dpkg', '--print-architecture'], text=True).strip()
    if architecture != 'amd64':
        raise RuntimeError('The pinned kernel build targets amd64 only')
    jobs = int(os.environ.get('NVYR_BUILD_JOBS', '4'))
    if jobs < 1:
        raise ValueError('NVYR_BUILD_JOBS must be positive')

    # Kernel packaging does not declare every compression/BTF tool as a build dependency.
    missing = [tool for tool in ('zstd', 'xz', 'pahole', 'openssl', 'cpio', 'rsync', 'depmod')
               if shutil.which(tool) is None]
    if missing:
        raise RuntimeError('Kernel build tools are missing: ' + ', '.join(missing))

    lock = json.loads(LOCK.read_text())
    timestamp = datetime.fromtimestamp(lock['source_date_epoch'], timezone.utc).isoformat()
    environment = dict(os.environ, SOURCE_DATE_EPOCH=str(lock['source_date_epoch']),
                       KBUILD_BUILD_TIMESTAMP=timestamp, KBUILD_BUILD_USER='nvyr',
                       KBUILD_BUILD_HOST='builder', KBUILD_BUILD_VERSION='1',
                       KDEB_PKGVERSION=lock['package_version'],
                       KDEB_CHANGELOG_DIST='trixie',
                       KDEB_SOURCENAME='linux-upstream',
                       DEB_BUILD_PROFILES='pkg.linux-upstream.nokerneldbg',
                       DEBFULLNAME='nVyR contributors', DEBEMAIL='maintainers@example.invalid')
    environment.pop('DEB_BUILD_OPTIONS', None)
    environment.pop('LOCALVERSION', None)

    destination.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='nvyr-kernel-build-', dir='/var/tmp'))
    try:
        download(lock['source'], work / 'linux.tar.xz')
        download(lock['configuration'], work / 'baseline.deb')
        run(['dpkg-deb', '-x', str(work / 'baseline.deb'), str(work / 'baseline')])
        baseline = work / 'baseline' / lock['configuration']['path']
        source = work / 'source'
        source.mkdir()
        run(['tar', '-xf', str(work / 'linux.tar.xz'), '--strip-components=1', '-C', str(source)])
        configure(source, baseline, lock, environment)
        run(['make', '-j' + str(jobs), 'bindeb-pkg'], cwd=source, env=environment)

        artifact = work / package_filename(lock)
        for field, expected in (('Package', 'linux-image-' + release(lock)),
                                ('Version', lock['package_version']), ('Architecture', 'amd64')):
            actual = subprocess.check_output(['dpkg-deb', '-f', str(artifact), field], text=True).strip()
            if actual != expected:
                raise RuntimeError(f'Kernel package has unexpected {field}: {actual}')
        install(artifact, destination / artifact.name)
        source_bundle(destination / SOURCE_BUNDLE, work, baseline, source)
    except BaseException:
        print(f'Kernel build failed; working files retained at {work}', file=sys.stderr)
        raise
    else:
        shutil.rmtree(work)

    files = {name: digest(destination / name) for name in (package_filename(lock), SOURCE_BUNDLE)}
    manifest = {'recipe': recipe_digest(), 'release': release(lock), 'files': files}
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
