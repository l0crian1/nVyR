"""Opt-in image pulls inside a disposable privileged Podman test container."""

import json
import os
from pathlib import Path

import pytest

from nvyr.errors import RouterError
from tests.container_harness import ContainerHarness
from nvyr.helpers.process import cmd


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_PODMAN_PULL_TEST') != '1',
                                reason='isolated native image-pull test only')


@pytest.fixture
def runtime(tmp_path):
    instance = ContainerHarness(state=tmp_path / 'managed.json')
    previous = instance.registries.read_bytes() if instance.registries.exists() else None
    try:
        yield instance
    finally:
        if previous is None:
            instance.registries.unlink(missing_ok=True)
        else:
            instance.registries.write_bytes(previous)


def test_native_pull_without_registry_or_tag(runtime):
    """The wrapper must run a real pull, with Podman resolving the short name and latest tag."""
    runtime.pull('busybox')
    assert runtime.image_id('busybox') == runtime.image_id('docker.io/library/busybox:latest')


def test_native_pull_qualified_without_tag_and_refresh(runtime):
    """Qualified untagged names and an explicit latest tag both work on the packaged Podman."""
    runtime.pull('docker.io/library/busybox')
    first = runtime.image_id('docker.io/library/busybox')
    runtime.pull('docker.io/library/busybox:latest')
    assert runtime.image_id('docker.io/library/busybox:latest') == first


def test_native_pull_uses_configured_search_registry(runtime):
    """A connection refusal at the selected registry proves resolution without another public pull."""
    runtime.configuration = {'registry': {'127.0.0.1:9': {'priority': '10'}}}

    with pytest.raises(RouterError, match='127.0.0.1:9/nvyr-probe/not-present:latest'):
        runtime.pull('nvyr-probe/not-present')


def test_native_pull_searches_multiple_registries_in_priority_order(runtime):
    """A refused first registry falls through to the second without an interactive prompt."""
    runtime.configuration = {'registry': {
        'docker.io': {'priority': '20'}, '127.0.0.1:9': {'priority': '10'},
    }}
    runtime.pull('library/busybox:1.37')
    assert runtime.image_id('library/busybox:1.37') == runtime.image_id('docker.io/library/busybox:1.37')


def test_packaged_storage_on_overlay_filesystem(tmp_path):
    """Pull and run using the shipped mount helper on the live ISO's backing filesystem type."""
    assert cmd(['stat', '-f', '-c', '%T', str(tmp_path)]).strip() == 'overlayfs'
    repository = Path(__file__).resolve().parents[1]
    text = (repository / 'packaging/containers-storage.conf').read_text()
    text = text.replace('/config/podman/storage', str(tmp_path / 'graph'))
    text = text.replace('/run/containers/storage', str(tmp_path / 'run'))
    storage = tmp_path / 'storage.conf'
    storage.write_text(text)
    podman = ['env', f'CONTAINERS_STORAGE_CONF={storage}', 'podman']

    info = json.loads(cmd([*podman, 'info', '--format=json']))
    assert info['store']['graphDriverName'] == 'overlay'
    assert info['store']['graphStatus']['Backing Filesystem'] == 'overlayfs'
    assert 'overlay.mount_program' in info['store']['graphOptions']

    cmd([*podman, 'pull', 'docker.io/library/alpine'], timeout=120)
    result = cmd([*podman, 'run', '--rm', '--network=none', '--cgroups=disabled',
                  'docker.io/library/alpine', 'sh', '-c', 'echo writable > /probe && cat /probe'], timeout=60)
    assert result.strip() == 'writable'
