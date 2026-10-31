"""Collection bounds, archive integrity and CLI permissions without a router."""

import json
import os
import stat
import sys
import tarfile
import time

import pytest

from nvyr.errors import OperationalError, RouterError
from nvyr.helpers import access, diagnostics
from nvyr.op_scripts import diagnostics as operations


@pytest.fixture
def root_directory_metadata(monkeypatch):
    """Model root-owned storage while exercising real file I/O as an ordinary user."""
    original = os.fstat

    def metadata(descriptor):
        fields = list(original(descriptor))
        fields[stat.ST_UID] = 0
        return os.stat_result(fields)

    monkeypatch.setattr(diagnostics.os, 'fstat', metadata)


def test_diagnostics_requires_network_admin_and_streams(controller, session):
    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError, match='requires net-admin'):
            controller.execute('generate system diagnostics')
    finally:
        access.role.reset(token)

    token = access.role.set('net-admin')
    try:
        result = controller.execute('run generate system diagnostics', session)
    finally:
        access.role.reset(token)
    assert result['event'] == 'command'
    assert result['argv'] == ['diagnostics.nvyr.op', 'generate']


def test_worker_has_deadline_and_host_namespace(monkeypatch):
    calls = []
    monkeypatch.setattr(operations, 'call', lambda argv, **options: calls.append((argv, options)) or 0)
    operations.generate()
    argv, options = calls[0]
    assert argv[0] == 'systemd-run'
    assert '--property=RuntimeMaxSec=75' in argv
    assert '--property=KillMode=control-group' in argv
    assert argv[-1] == 'nvyr.helpers.diagnostics'
    assert options['timeout'] == 80
    monkeypatch.setattr(operations, 'call', lambda *args, **kwargs: 1)
    with pytest.raises(SystemExit) as error:
        operations.generate()
    assert error.value.code == 1


def test_capture_success_error_and_missing_executable():
    data, result = diagnostics.capture([sys.executable, '-c', 'print("ready")'], timeout=2, maximum=128)
    assert data == b'ready\n' and result['status'] == 'ok' and result['returncode'] == 0
    data, result = diagnostics.capture([sys.executable, '-c',
                                       'import sys; print("failed", file=sys.stderr); sys.exit(3)'],
                                      timeout=2, maximum=128)
    assert data == b'failed\n' and result['status'] == 'error' and result['returncode'] == 3
    data, result = diagnostics.capture(['/nonexistent/nvyr-diagnostic-test'], timeout=2, maximum=128)
    assert data == b'' and result['status'] == 'error' and result['error']


def test_capture_stops_unlimited_output():
    data, result = diagnostics.capture([sys.executable, '-c',
                                       'import os\nwhile True: os.write(1, b"x" * 65536)'],
                                      timeout=2, maximum=1024)
    assert data == b'x' * 1024 and result['status'] == 'truncated'
    assert result['seconds'] < 2


def test_capture_exact_size_is_not_truncated():
    data, result = diagnostics.capture([sys.executable, '-c', 'import os; os.write(1, b"x" * 32)'],
                                      timeout=2, maximum=32)
    assert data == b'x' * 32 and result['status'] == 'ok'


def test_timeout_kills_descendants_even_when_parent_exited(tmp_path):
    marker = tmp_path / 'escaped'
    child = f'import time; from pathlib import Path; time.sleep(0.8); Path({str(marker)!r}).touch()'
    parent = f'import subprocess, sys; subprocess.Popen([sys.executable, "-c", {child!r}])'
    data, result = diagnostics.capture([sys.executable, '-c', parent], timeout=0.2, maximum=128)
    assert result['status'] == 'timed-out'
    time.sleep(0.9)
    assert not marker.exists()


def test_closed_stdout_does_not_bypass_deadline():
    command = 'import os, time; os.close(1); os.close(2); time.sleep(10)'
    data, result = diagnostics.capture([sys.executable, '-c', command], timeout=0.2, maximum=128)
    assert result['status'] == 'timed-out' and result['seconds'] < 2


def test_archive_total_budget_and_manifest(tmp_path, root_directory_metadata):
    inventory = [('first', [sys.executable, '-c', 'print("abcdefghij")']),
                 ('second', [sys.executable, '-c', 'print("abcdefghij")']),
                 ('third', ['must-not-run'])]
    path, manifest = diagnostics.collect(directory=tmp_path / 'diagnostics', inventory=inventory,
                                         report_bytes=10, total_bytes=15, progress=lambda *args, **kwargs: None)
    assert [item['status'] for item in manifest['reports']] == ['truncated', 'truncated', 'skipped']
    assert sum(item['bytes'] for item in manifest['reports']) == 15
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with tarfile.open(path) as archive:
        assert archive.getnames() == ['first.txt', 'second.txt', 'manifest.json']
        assert archive.extractfile('first.txt').read() == b'abcdefghij'
        assert archive.extractfile('second.txt').read() == b'abcde'
        assert json.load(archive.extractfile('manifest.json')) == manifest
    assert list(path.parent.iterdir()) == [path]


def test_collection_deadline_skips_later_reports(tmp_path, root_directory_metadata):
    inventory = [('slow', [sys.executable, '-c', 'import time; time.sleep(10)']),
                 ('later', ['must-not-run'])]
    path, manifest = diagnostics.collect(directory=tmp_path / 'diagnostics', inventory=inventory,
                                         total_timeout=0.1, progress=lambda *args, **kwargs: None)
    assert [item['status'] for item in manifest['reports']] == ['timed-out', 'skipped']
    assert manifest['reports'][1]['reason'] == 'Collection time limit'


def test_incomplete_collection_keeps_other_reports(tmp_path, root_directory_metadata):
    inventory = [('missing', ['/nonexistent/command']), ('next', [sys.executable, '-c', 'print("ok")'])]
    path, manifest = diagnostics.collect(directory=tmp_path / 'diagnostics', inventory=inventory,
                                         progress=lambda *args, **kwargs: None)
    assert [item['status'] for item in manifest['reports']] == ['error', 'ok']


def test_archive_failure_removes_partial_file(tmp_path, monkeypatch, root_directory_metadata):
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    directory = tmp_path / 'diagnostics'
    monkeypatch.setattr(diagnostics, 'capture', interrupted)
    with pytest.raises(KeyboardInterrupt):
        diagnostics.collect(directory=directory, inventory=[('test', ['test'])],
                            progress=lambda *args, **kwargs: None)
    assert list(directory.iterdir()) == []


def test_rejects_symlink_and_writable_destination(tmp_path, root_directory_metadata):
    target = tmp_path / 'target'
    target.mkdir()
    linked = tmp_path / 'linked'
    linked.symlink_to(target)
    with pytest.raises(OSError):
        diagnostics.collect(directory=linked, inventory=[])
    target.chmod(0o777)
    with pytest.raises(OperationalError, match='not writable'):
        diagnostics.collect(directory=target, inventory=[])
    assert list(target.iterdir()) == []


def test_rejects_non_root_destination(tmp_path, monkeypatch):
    original = os.fstat

    def metadata(descriptor):
        fields = list(original(descriptor))
        fields[stat.ST_UID] = 1000
        return os.stat_result(fields)

    monkeypatch.setattr(diagnostics.os, 'fstat', metadata)
    with pytest.raises(OperationalError, match='root-owned'):
        diagnostics.collect(directory=tmp_path / 'diagnostics', inventory=[])


def test_inventory_does_not_collect_logs_config_or_process_arguments():
    inventory = dict(diagnostics.reports())
    assert 'services' in inventory and 'failed-units' in inventory and 'container-networks' in inventory
    assert inventory['containers'][-1] == 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Networks}}'
    for arguments in inventory.values():
        assert 'journalctl' not in arguments and 'dmesg' not in arguments
        assert 'inspect' not in arguments and 'logs' not in arguments
        assert 'show running-configuration' not in arguments
