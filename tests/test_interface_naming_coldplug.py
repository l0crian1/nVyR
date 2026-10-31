"""Cover naming discovery races without depending on boot timing."""

import errno
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nvyr import interface_naming
from nvyr.errors import RouterError


class Finished(Exception):
    """Stop the serving loop once the test has observed readiness."""


@pytest.fixture
def discovery(monkeypatch):
    """Keep the real coldplug and startup loop; isolate udev and the coordinator."""
    monitor = Mock()
    monkeypatch.setattr('pyudev.Context', Mock())
    monkeypatch.setattr('pyudev.Monitor.from_netlink', Mock(return_value=monitor))
    coordinator = Mock()
    coordinator.reconcile.return_value = True
    monkeypatch.setattr(interface_naming, 'Coordinator', Mock(return_value=coordinator))
    notices = []
    monkeypatch.setattr(interface_naming, 'notify', notices.append)
    clock = [0.0]
    monkeypatch.setattr(interface_naming.time, 'monotonic', lambda: clock[0])

    def wait(monitor, timeout):
        if any(notice.startswith('READY=1') for notice in notices):
            raise Finished

        clock[0] += timeout

    monkeypatch.setattr(interface_naming, 'wait_for_change', wait)
    return SimpleNamespace(coordinator=coordinator, notices=notices, clock=clock)


def test_coldplug_rescans_after_rename_before_open(tmp_path, monkeypatch, discovery):
    """A vanished path delays readiness until the renamed device is triggered."""
    old = tmp_path / 'old'
    old.mkdir()
    (old / 'uevent').touch()
    new = tmp_path / 'new'
    scans = []

    def paths():
        scans.append(True)

        if len(scans) == 1:
            old.rename(new)
            yield old
        else:
            assert discovery.coordinator.reconcile.call_count == 0
            assert not any(notice.startswith('READY=1') for notice in discovery.notices)
            yield new

    monkeypatch.setattr(interface_naming, 'physical_paths', paths)

    with pytest.raises(Finished):
        interface_naming.serve(tmp_path / 'state', tmp_path / 'ready', 3)

    assert len(scans) == 2
    assert (new / 'uevent').read_text() == 'change\n'
    assert discovery.coordinator.reconcile.call_count == 1
    assert discovery.notices[-1].startswith('READY=1')


def test_coldplug_rescans_after_hot_unplug(tmp_path, monkeypatch, discovery):
    """A removed device must not leave a permanently pending trigger."""
    missing = tmp_path / 'removed'
    scans = iter([[missing], []])
    monkeypatch.setattr(interface_naming, 'physical_paths', lambda: next(scans))

    with pytest.raises(Finished):
        interface_naming.serve(tmp_path / 'state', tmp_path / 'ready', 3)

    assert discovery.coordinator.reconcile.call_count == 1
    assert discovery.notices[-1].startswith('READY=1')


def test_trigger_uses_open_device_after_rename(tmp_path, monkeypatch):
    """Renaming after open must not send the event to a replacement path."""
    old = tmp_path / 'old'
    old.mkdir()
    (old / 'uevent').touch()
    new = tmp_path / 'new'
    original_open = Path.open

    def rename_after_open(path, *args, **kwargs):
        stream = original_open(path, *args, **kwargs)

        if path == old / 'uevent' and args == ('w',):
            old.rename(new)
            old.mkdir()
            (old / 'uevent').touch()

        return stream

    monkeypatch.setattr(Path, 'open', rename_after_open)
    interface_naming.trigger_change(old)

    assert (new / 'uevent').read_text() == 'change\n'
    assert (old / 'uevent').read_text() == ''


def test_coldplug_failure_remains_visible_and_blocks_readiness(tmp_path, monkeypatch, discovery, caplog):
    """Persistent write errors must time out, never silently skip discovery."""
    monkeypatch.setattr(interface_naming, 'physical_paths', lambda: [tmp_path])

    def denied(path):
        raise PermissionError(errno.EACCES, 'denied', str(path / 'uevent'))

    monkeypatch.setattr(interface_naming, 'trigger_change', denied)

    with pytest.raises(RouterError, match='could not complete before startup.*denied'):
        interface_naming.serve(tmp_path / 'state', tmp_path / 'ready', 2)

    assert discovery.coordinator.reconcile.call_count == 0
    assert not any(notice.startswith('READY=1') for notice in discovery.notices)
    assert 'Ethernet naming pending' in caplog.text
    assert discovery.clock[0] == 3


def test_successful_coldplug_is_not_repeated_while_waiting_for_handoff(tmp_path, monkeypatch, discovery):
    """Pending udev handoff must not create a new stream of discovery events."""
    (tmp_path / 'uevent').touch()
    paths = Mock(return_value=[tmp_path])
    monkeypatch.setattr(interface_naming, 'physical_paths', paths)
    discovery.coordinator.reconcile.side_effect = [False, True]

    with pytest.raises(Finished):
        interface_naming.serve(tmp_path / 'state', tmp_path / 'ready', 3)

    assert paths.call_count == 1
    assert discovery.coordinator.reconcile.call_count == 2
