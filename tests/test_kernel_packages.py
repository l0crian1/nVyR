"""Keep ISO kernels pinned, reject stale caches, and retain required networking support."""

import json
from pathlib import Path

import pytest

from build_tools import kernel_packages as kernel


@pytest.fixture
def cache(tmp_path):
    directory = tmp_path / 'cache'
    directory.mkdir()
    lock = json.loads(kernel.LOCK.read_text())
    files = {}
    for name in (kernel.package_filename(lock), kernel.SOURCE_BUNDLE):
        artifact = directory / name
        artifact.write_bytes(name.encode())
        files[name] = kernel.digest(artifact)
    manifest = {'recipe': kernel.recipe_digest(), 'release': kernel.release(lock), 'files': files}
    (directory / kernel.MANIFEST).write_text(json.dumps(manifest))
    return directory


def test_stage_verified_binary_and_corresponding_source(cache, tmp_path):
    destination = tmp_path / 'output'
    kernel.stage(cache, destination)

    assert sorted(path.name for path in destination.iterdir()) == sorted(path.name for path in cache.iterdir())
    for path in cache.iterdir():
        assert (destination / path.name).read_bytes() == path.read_bytes()


def test_changed_source_pin_invalidates_cached_build(cache, tmp_path, monkeypatch):
    lock = tmp_path / 'lock'
    lock.write_text(kernel.LOCK.read_text() + '\n')
    monkeypatch.setattr(kernel, 'LOCK', lock)

    with pytest.raises(RuntimeError, match='recipe changed.*Rebuild nvyr-image-builder'):
        kernel.stage(cache, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_corrupt_binary_is_not_staged(cache, tmp_path):
    next(cache.glob('*.deb')).write_bytes(b'corrupt')

    with pytest.raises(RuntimeError, match='checksum mismatch'):
        kernel.stage(cache, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_missing_corresponding_source_is_not_staged(cache, tmp_path):
    (cache / kernel.SOURCE_BUNDLE).unlink()

    with pytest.raises(RuntimeError, match='Rebuild nvyr-image-builder'):
        kernel.stage(cache, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_manifest_cannot_substitute_other_packages(cache, tmp_path):
    path = cache / kernel.MANIFEST
    manifest = json.loads(path.read_text())
    checksum = manifest['files'].pop(next(iter(manifest['files'])))
    manifest['files']['../other.deb'] = checksum
    path.write_text(json.dumps(manifest))

    with pytest.raises(RuntimeError, match='unexpected kernel package manifest'):
        kernel.stage(cache, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_empty_cache_explains_builder_rebuild(tmp_path):
    with pytest.raises(RuntimeError, match='Rebuild nvyr-image-builder'):
        kernel.stage(tmp_path / 'missing', tmp_path / 'output')


def test_recipe_ignores_checkout_line_endings(tmp_path, monkeypatch):
    expected = kernel.recipe_digest()
    lock = tmp_path / 'lock'
    lock.write_bytes(kernel.LOCK.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n'))
    monkeypatch.setattr(kernel, 'LOCK', lock)

    assert kernel.recipe_digest() == expected


def test_corrupt_download_fails_before_extraction(tmp_path, monkeypatch):
    def download(arguments, **kwargs):
        Path(arguments[arguments.index('-O') + 1]).write_bytes(b'not the pinned source')

    monkeypatch.setattr(kernel, 'run', download)
    specification = json.loads(kernel.LOCK.read_text())['source']

    with pytest.raises(RuntimeError, match='input checksum mismatch'):
        kernel.download(specification, tmp_path / 'linux.tar.xz')


def test_missing_compressor_fails_before_downloading_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(kernel.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(kernel.subprocess, 'check_output', lambda *args, **kwargs: 'amd64\n')
    monkeypatch.setattr(kernel.shutil, 'which', lambda tool: None if tool == 'zstd' else '/usr/bin/' + tool)

    with pytest.raises(RuntimeError, match='Kernel build tools are missing: zstd'):
        kernel.build(tmp_path / 'output')

    assert not (tmp_path / 'output').exists()


def test_resolved_config_requires_flow_offload_and_vrf(tmp_path):
    config = tmp_path / '.config'
    config.write_text('\n'.join(f'CONFIG_{name}=m' for name in kernel.REQUIRED))
    kernel.verify_configuration(config)

    config.write_text(config.read_text().replace('CONFIG_NFT_FLOW_OFFLOAD=m', '# CONFIG_NFT_FLOW_OFFLOAD is not set'))
    with pytest.raises(RuntimeError, match='NFT_FLOW_OFFLOAD'):
        kernel.verify_configuration(config)


def test_image_assembly_excludes_distribution_kernel_metapackage():
    packages = (kernel.ROOT / 'images/router.list.chroot').read_text().splitlines()
    assembly = (kernel.ROOT / 'images/assemble.sh').read_text()
    hook = (kernel.ROOT / 'images/0100-router.hook.chroot').read_text()

    assert 'linux-image-amd64' not in packages
    assert '--linux-packages linux-image --linux-flavours "$kernel_release"' in assembly
    assert '--cache /opt/nvyr-kernel-packages' in assembly
    assert 'kernel-source.tar' in assembly
    assert "images != ['vmlinuz-' + release]" in hook
