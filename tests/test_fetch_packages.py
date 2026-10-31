import hashlib
import os
from pathlib import Path
import shutil
import subprocess

import pytest


pytestmark = pytest.mark.skipif(
    not shutil.which('dpkg-deb'), reason='Package downloader tests require Debian tools')
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def downloader(tmp_path):
    package = tmp_path / 'package'
    (package / 'DEBIAN').mkdir(parents=True)
    (package / 'DEBIAN/control').write_text(
        'Package: example\nVersion: 1.0\nArchitecture: all\n'
        'Maintainer: Test <test@example.org>\nDescription: Test package\n')
    artifact = tmp_path / 'example.deb'
    subprocess.run(['dpkg-deb', '--build', str(package), str(artifact)],
                   check=True, capture_output=True)
    shutil.copyfile(ROOT / 'images/fetch-packages.sh', tmp_path / 'fetch-packages.sh')
    tools = tmp_path / 'bin'
    tools.mkdir()
    wget = tools / 'wget'
    wget.write_text('#!/bin/sh\n'
                    'if [ "$DOWNLOAD_STATUS" != 0 ]; then\n'
                    '  echo "ERROR 404: Not Found." >&2\n'
                    '  exit "$DOWNLOAD_STATUS"\nfi\n'
                    'while [ "$1" != -O ]; do shift; done\n'
                    'cp "$ARTIFACT" "$2"\n')
    wget.chmod(0o755)

    def fetch(*, status=0, package='example', version='1.0', architecture='all', checksum=None):
        digest = checksum or hashlib.sha256(artifact.read_bytes()).hexdigest()
        (tmp_path / 'packages.lock').write_text(
            f'{package} {version} {architecture} {digest} https://example.org/example.deb\n')
        env = os.environ | {'PATH': str(tools) + os.pathsep + os.environ['PATH'],
                            'ARTIFACT': str(artifact), 'DOWNLOAD_STATUS': str(status)}

        return subprocess.run(['sh', str(tmp_path / 'fetch-packages.sh'), str(tmp_path / 'out')],
                              env=env, capture_output=True, text=True)

    return fetch


def test_successful_download_is_verified_and_published(downloader, tmp_path):
    result = downloader()

    assert result.returncode == 0, result.stderr
    assert 'Downloading example 1.0 (all)' in result.stdout
    assert (tmp_path / 'out/example.deb').read_bytes() == (tmp_path / 'example.deb').read_bytes()
    assert not (tmp_path / 'out/example.deb.part').exists()


def test_download_failure_is_visible_and_preserves_exit_status(downloader, tmp_path):
    result = downloader(status=8)

    assert result.returncode == 8
    assert 'ERROR 404' in result.stderr
    assert 'Failed to download example from https://example.org/example.deb' in result.stderr
    assert not (tmp_path / 'out/example.deb').exists()


@pytest.mark.parametrize(('field', 'value', 'label'), [
    ('package', 'wrong', 'Package'), ('version', '2.0', 'Version'),
    ('architecture', 'amd64', 'Architecture'),
])
def test_metadata_mismatch_is_reported(downloader, tmp_path, field, value, label):
    result = downloader(**{field: value})

    assert result.returncode == 1
    assert f'{label} mismatch: expected {value}, got ' in result.stderr
    assert not (tmp_path / 'out/example.deb').exists()


def test_checksum_failure_does_not_publish_package(downloader, tmp_path):
    result = downloader(checksum='0' * 64)

    assert result.returncode != 0
    assert 'FAILED' in result.stdout
    assert not (tmp_path / 'out/example.deb').exists()
