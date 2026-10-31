"""The ISO must reject stale or corrupted prebuilt container packages."""

import json

import pytest

from build_tools import container_packages


@pytest.fixture
def cache(tmp_path):
    root = tmp_path / 'cache'
    root.mkdir()
    versions = json.loads(container_packages.LOCK.read_text())['packages']
    files = {}
    for name, version in versions.items():
        path = root / f'{name}_{version}_amd64.deb'
        path.write_bytes(name.encode())
        files[path.name] = container_packages.digest(path)
    manifest = {'recipe': container_packages.recipe_digest(), 'versions': versions, 'files': files}
    (root / container_packages.MANIFEST).write_text(json.dumps(manifest))
    return root


def test_stage_verified_packages_and_manifest(cache, tmp_path):
    output = tmp_path / 'output'
    container_packages.stage(cache, output)
    assert sorted(path.name for path in output.iterdir()) == sorted(path.name for path in cache.iterdir())
    for path in cache.iterdir():
        assert (output / path.name).read_bytes() == path.read_bytes()


def test_stale_builder_is_rejected_before_publishing(cache, tmp_path):
    path = cache / container_packages.MANIFEST
    manifest = json.loads(path.read_text())
    manifest['recipe'] = 'old recipe'
    path.write_text(json.dumps(manifest))
    with pytest.raises(RuntimeError, match='Rebuild nvyr-image-builder'):
        container_packages.stage(cache, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_corrupt_artifact_is_rejected_before_publishing(cache, tmp_path):
    next(cache.glob('*.deb')).write_bytes(b'corrupt')
    with pytest.raises(RuntimeError, match='checksum mismatch'):
        container_packages.stage(cache, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_missing_builder_packages_have_rebuild_instruction(tmp_path):
    with pytest.raises(RuntimeError, match='Rebuild nvyr-image-builder'):
        container_packages.stage(tmp_path / 'missing', tmp_path / 'output')


def test_incomplete_manifest_is_rejected(cache, tmp_path):
    path = cache / container_packages.MANIFEST
    manifest = json.loads(path.read_text())
    manifest['files'].pop(next(iter(manifest['files'])))
    path.write_text(json.dumps(manifest))
    with pytest.raises(RuntimeError, match='incomplete'):
        container_packages.stage(cache, tmp_path / 'output')
