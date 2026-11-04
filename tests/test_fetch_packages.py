import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import shutil
import subprocess
from threading import Thread

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

    def fetch(*, status=0, package='example', version='1.0', architecture='all', checksum=None,
              cache=None, url=None):
        digest = checksum or hashlib.sha256(artifact.read_bytes()).hexdigest()
        (tmp_path / 'packages.lock').write_text(
            f'{package} {version} {architecture} {digest} {url or "https://example.org/example.deb"}\n')
        env = os.environ.copy()
        if url is None:
            env.update(PATH=str(tools) + os.pathsep + env['PATH'],
                       ARTIFACT=str(artifact), DOWNLOAD_STATUS=str(status))
        else:
            env['no_proxy'] = '127.0.0.1'

        args = ['sh', str(tmp_path / 'fetch-packages.sh'), str(tmp_path / 'out')]
        if cache is not None:
            args.append(str(cache))
        return subprocess.run(args, env=env, capture_output=True, text=True, timeout=30)

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


def test_cache_survives_builds_and_recovers_from_corruption(downloader, tmp_path):
    cache = tmp_path / 'cache'
    assert downloader(cache=cache).returncode == 0
    shutil.rmtree(tmp_path / 'out')
    assert downloader(cache=cache, status=8).returncode == 0

    entry, = cache.iterdir()
    entry.write_bytes(b'damaged')
    result = downloader(cache=cache)
    assert result.returncode == 0, result.stderr
    assert 'Downloading example' in result.stdout
    assert entry.read_bytes() == (tmp_path / 'example.deb').read_bytes()


@pytest.mark.skipif(not shutil.which('wget'), reason='HTTP retries require GNU Wget')
@pytest.mark.parametrize('responses', [(503, 200), (503, 503, 503), (404,)])
def test_http_retries(downloader, tmp_path, responses):
    requests = []
    artifact = (tmp_path / 'example.deb').read_bytes()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            status = responses[len(requests) - 1]
            self.send_response(status)
            self.end_headers()
            if status == 200:
                self.wfile.write(artifact)

    with HTTPServer(('127.0.0.1', 0), Handler) as server:
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            result = downloader(url=f'http://127.0.0.1:{server.server_port}/example.deb')
        finally:
            server.shutdown()
            thread.join()

    assert requests == ['/example.deb'] * len(responses)
    assert (result.returncode == 0) == (responses[-1] == 200), result.stderr
    assert (tmp_path / 'out/example.deb').exists() == (responses[-1] == 200)
