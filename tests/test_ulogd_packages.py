"""Do not stage an unpatched or corrupt connection-log collector."""

import json

import pytest

from build_tools import ulogd_packages as packages


@pytest.fixture
def cache(tmp_path):
    cache = tmp_path / 'cache'
    cache.mkdir()
    lock = json.loads(packages.LOCK.read_text())
    name = packages.package_name(lock)
    (cache / name).write_bytes(b'collector package')
    manifest = {'recipe': packages.recipe_digest(), 'version': lock['version'],
                'files': {name: packages.digest(cache / name)}}
    (cache / packages.MANIFEST).write_text(json.dumps(manifest))
    return cache


def test_stage_validated_collector(cache, tmp_path):
    destination = tmp_path / 'output'
    packages.stage(cache, destination)
    assert {path.name for path in destination.iterdir()} == {path.name for path in cache.iterdir()}


@pytest.mark.parametrize('failure', ['recipe', 'checksum', 'missing'])
def test_invalid_collector_cache_is_not_staged(cache, tmp_path, monkeypatch, failure):
    if failure == 'recipe':
        monkeypatch.setattr(packages, 'recipe_digest', lambda: 'changed')
    elif failure == 'checksum':
        next(cache.glob('*.deb')).write_bytes(b'corrupt')
    else:
        next(cache.glob('*.deb')).unlink()
    destination = tmp_path / 'output'
    with pytest.raises(RuntimeError, match='Rebuild nvyr-image-builder'):
        packages.stage(cache, destination)
    assert not destination.exists()
