"""Reject stale or incomplete Lua-enabled FRR packages before ISO assembly."""

import json
from pathlib import Path

import pytest

from build_tools import frr_packages


@pytest.fixture
def cache(tmp_path):
    directory = tmp_path / 'cache'
    directory.mkdir()
    lock = json.loads(frr_packages.LOCK.read_text())
    files = {}
    for name in frr_packages.package_files(lock):
        artifact = directory / name
        artifact.write_bytes(name.encode())
        files[name] = frr_packages.digest(artifact)
    manifest = {'recipe': frr_packages.recipe_digest(), 'version': lock['version'], 'files': files}
    (directory / frr_packages.MANIFEST).write_text(json.dumps(manifest))
    return directory


def test_stage_complete_verified_cache(cache, tmp_path):
    destination = tmp_path / 'output'
    frr_packages.stage(cache, destination)

    assert sorted(path.name for path in destination.iterdir()) == sorted(path.name for path in cache.iterdir())
    for path in cache.iterdir():
        assert (destination / path.name).read_bytes() == path.read_bytes()


def test_changed_patch_invalidates_cached_build(cache, tmp_path, monkeypatch):
    patch = tmp_path / 'patch'
    patch.write_text(frr_packages.PATCH.read_text() + '\n')
    monkeypatch.setattr(frr_packages, 'PATCH', patch)

    with pytest.raises(RuntimeError, match='recipe changed.*Rebuild nvyr-image-builder'):
        frr_packages.stage(cache, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_cache_rejects_corrupt_binary(cache, tmp_path):
    next(cache.glob('*.deb')).write_bytes(b'corrupt')

    with pytest.raises(RuntimeError, match='checksum mismatch'):
        frr_packages.stage(cache, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_cache_rejects_missing_package(cache, tmp_path):
    next(cache.glob('*.deb')).unlink()

    with pytest.raises(RuntimeError, match='Rebuild nvyr-image-builder'):
        frr_packages.stage(cache, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_cache_rejects_manifest_substitution(cache, tmp_path):
    path = cache / frr_packages.MANIFEST
    manifest = json.loads(path.read_text())
    checksum = manifest['files'].pop(next(iter(manifest['files'])))
    manifest['files']['../foreign.deb'] = checksum
    path.write_text(json.dumps(manifest))

    with pytest.raises(RuntimeError, match='unexpected FRR package manifest'):
        frr_packages.stage(cache, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_empty_cache_has_rebuild_instruction(tmp_path):
    with pytest.raises(RuntimeError, match='Rebuild nvyr-image-builder'):
        frr_packages.stage(tmp_path / 'missing', tmp_path / 'output')


def test_recipe_hash_ignores_checkout_line_endings(tmp_path, monkeypatch):
    expected = frr_packages.recipe_digest()
    lock = tmp_path / 'lock'
    patch = tmp_path / 'patch'
    lock.write_bytes(frr_packages.LOCK.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
    patch.write_bytes(frr_packages.PATCH.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
    monkeypatch.setattr(frr_packages, 'LOCK', lock)
    monkeypatch.setattr(frr_packages, 'PATCH', patch)

    assert frr_packages.recipe_digest() == expected


def test_router_requires_the_built_package_revision():
    lock = json.loads(frr_packages.LOCK.read_text())
    control = (frr_packages.ROOT / 'packaging/debian/control').read_text()

    for name in lock['packages']:
        assert f'{name} (= {lock["version"]})' in control
    assert lock['profiles'] == ['pkg.frr.lua']
    binary_lock = (frr_packages.ROOT / 'images/packages.lock').read_text().splitlines()
    assert not any(line.startswith(('frr ', 'frr-pythontools ')) for line in binary_lock)


def test_source_checksum_fails_before_extraction(tmp_path, monkeypatch):
    calls = []

    def download(arguments, **kwargs):
        calls.append(arguments)
        Path(arguments[arguments.index('-O') + 1]).write_bytes(b'not the pinned source')

    monkeypatch.setattr(frr_packages, 'run', download)
    lock = json.loads(frr_packages.LOCK.read_text())
    with pytest.raises(RuntimeError, match='source checksum mismatch'):
        frr_packages.prepare_source(tmp_path, lock)
    assert len(calls) == 1
    assert not (tmp_path / 'source').exists()
