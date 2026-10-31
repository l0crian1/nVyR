"""Read-only Linux command integration: NVYR_SYSTEM_NATIVE=1 python3 -m pytest this_file."""

import json
import os
from pathlib import Path
import sys
import tarfile

import pytest

from nvyr.helpers import diagnostics
from nvyr.op_scripts import system


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_SYSTEM_NATIVE') != '1',
                                reason='Opt-in native Linux system observations')


def test_native_storage_includes_root():
    records = json.loads(system.storage(raw=True))
    root = next(item for item in records if item['target'] == '/')
    assert root['size'] > 0 and root['fstype']
    assert 'Inode %' in system.storage()


def test_native_packages():
    """Read the actual Debian database and select an architecture-qualified identifier."""
    records = json.loads(system.packages(raw=True))
    package = next(item for item in records if item['package'].split(':')[0] == 'dpkg')
    assert package['version'] and package['architecture'] and package['description']
    assert json.loads(system.packages(package['package'], raw=True)) == [package]


def test_native_processes_sort_and_find_self():
    records = json.loads(system.processes(raw=True))
    current = next(item for item in records if item['pid'] == os.getpid())
    assert current['resident_bytes'] > 0 and current['name']
    cpu = json.loads(system.processes('cpu', raw=True))
    assert [item['cpu_percent'] for item in cpu] == sorted((item['cpu_percent'] for item in cpu), reverse=True)
    memory = json.loads(system.processes('memory', raw=True))
    assert [item['resident_bytes'] for item in memory] == sorted((item['resident_bytes'] for item in memory), reverse=True)


def test_native_inventory_archive(tmp_path):
    # Run source entry points without requiring package installation in the test container.
    scripts = Path(system.__file__).parent
    inventory = []
    for name, argv in diagnostics.reports():
        if argv[0].endswith('.nvyr.op'):
            argv = [sys.executable, str(scripts / (argv[0].removesuffix('.nvyr.op') + '.py')), *argv[1:]]
        inventory.append((name, argv))
    path, manifest = diagnostics.collect(directory=tmp_path / 'diagnostics', inventory=inventory)
    records = {item['name']: item for item in manifest['reports']}
    for name in ('version', 'kernel', 'uptime', 'cpu', 'memory', 'storage', 'processes'):
        assert records[name]['status'] == 'ok', records[name]
    # Containers and managed services need not exist on a build host; their failures remain visible.
    assert len(records) == len(inventory)
    assert sum(item['bytes'] for item in records.values()) <= diagnostics.TOTAL_BYTES
    with tarfile.open(path) as archive:
        assert json.load(archive.extractfile('manifest.json')) == manifest
        assert b'CPU % (lifetime)' in archive.extractfile('processes.txt').read()
