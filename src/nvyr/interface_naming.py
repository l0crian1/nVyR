"""Persistent physical Ethernet naming before handoff to nvyr-netlinkd."""

import argparse
import errno
import fcntl
import logging
import os
from pathlib import Path
import socket
import time

from nvyr.errors import RouterError
from nvyr.helpers.interface_names import Assignments, Coordinator, Port, location, udev_ready

log = logging.getLogger(__name__)
RUNTIME = Path('/run/nvyr-naming/ready')


def physical_paths(root=Path('/sys/class/net')):
    """Read class symlinks without constructing udev devices for virtual links."""
    with os.scandir(root) as entries:
        for entry in entries:
            try:
                path = Path(os.path.normpath(os.path.join(root, os.readlink(entry.path))))
                if '/devices/virtual/net/' not in str(path) and (path / 'device').exists():
                    yield path
            except FileNotFoundError:
                continue  # Hot-unplug during inventory.


def inventory(context):
    import pyudev

    result = []

    for path in physical_paths():
        try:
            device = pyudev.Devices.from_sys_path(context, str(path))
        except pyudev.DeviceNotFoundError:
            continue

        if not (path / 'device').exists() or (path / 'wireless').exists() or device.properties.get('DEVTYPE') in {'wlan', 'wwan'}:
            continue

        def attribute(name, default=''):
            try:
                return (path / name).read_text().strip()
            except OSError:
                return default

        if attribute('type') != '1':
            continue

        attached = str((path / 'device').resolve())
        properties = dict(device.properties)

        # An initialized device can be processing a later move/change event.
        # Its database then exposes partial properties, including missing slot
        # IDs. Never allocate from that intermediate view of physical identity.
        initialized = (device.is_initialized and properties.get('NVYR_ETHERNET') == '1'
                       and properties.get('ID_PROCESSING') != '1')
        identity = location(properties, device_path=attached, port=attribute('dev_port', '0'),
                            physical_port=attribute('phys_port_name')) if initialized else ''
        index = attribute('ifindex')
        if not index:
            # Hot-unplug may remove sysfs halfway through enumeration. The next
            # scan removes the stale lease; never invent an index for this port.
            continue

        result.append(Port(int(index), device.sys_name, identity, attached, initialized,
                          properties.get('NVYR_NAME_READY') == '1'))

    return result


def wait_for_change(monitor, timeout):
    """Ignore virtual-link storms and bound physical-event burst coalescing.

    The deadline also guarantees a safety inventory after lost notifications;
    continuous irrelevant events must not postpone it.
    """
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        try:
            device = monitor.poll(timeout=max(0, deadline - time.monotonic()))
        except OSError as error:
            if error.errno != errno.ENOBUFS:
                raise

            log.warning('Udev notifications lost; rescanning physical interfaces')

            return

        if device is None:
            return

        # Removal events no longer have sysfs attributes. Classify using the
        # event's device path, without reading attributes or walking ancestors.
        if '/devices/virtual/net/' not in device.sys_path:
            log.debug('Physical interface event: %s', device.sys_path)
            deadline = min(deadline, time.monotonic() + .2)


def notify(message):
    target = os.environ.get('NOTIFY_SOCKET')
    if target:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
            channel.connect('\0' + target[1:] if target.startswith('@') else target)
            channel.sendall(message.encode())


def trigger_change(path):
    """Request a udev change event through a descriptor that survives renames."""
    # Opening pins this device's event file. A later rename cannot redirect the
    # write to another interface or invalidate the open event descriptor.
    with (path / 'uevent').open('w') as event:
        event.write('change\n')


def coldplug():
    """Replay physical device events; callers must rescan if discovery races."""
    # Avoid a global trigger/settle over thousands of unrelated virtual links.
    for path in physical_paths():
        trigger_change(path)


def release(port, runtime):
    # Resolve the kernel's CURRENT name: pre-rename sysfs paths are stale.
    # Recheck the handoff lease in case the device disappeared/reused an index.
    path = (Path('/sys/class/net') / socket.if_indextoname(port.index)).resolve()
    if not udev_ready(path, runtime):
        raise RouterError(f'Interface {port.index} changed during naming; retrying')

    trigger_change(path)


def serve(state, runtime, timeout):
    import pyudev

    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context, source='udev')
    monitor.filter_by(subsystem='net')
    monitor.start()  # Subscribe before enumeration/coldplug; periodic scans cover lost events.
    coordinator = Coordinator(Assignments(state), runtime, inventory=lambda: inventory(context),
                              release=lambda port: release(port, runtime))

    started, ready, last_error = time.monotonic(), False, None
    coldplug_pending = True

    while True:
        try:
            # Udev can rename or remove a port before its event file opens.
            # Retry a fresh inventory within the startup deadline, and never
            # report readiness while a required coldplug trigger has failed.
            if coldplug_pending:
                coldplug()
                coldplug_pending = False

            complete = coordinator.reconcile()
            if complete:
                if not ready:
                    notify('READY=1\nSTATUS=Ethernet naming complete')
                    ready = True
                elif last_error:
                    notify('STATUS=Ethernet naming complete')

                last_error = None
        except (OSError, RouterError, pyudev.DeviceNotFoundError) as error:
            complete = False

            if str(error) != last_error:
                log.error('Ethernet naming pending: %s', error)
                notify('STATUS=Ethernet naming pending; see journal')
                last_error = str(error)

        if not ready and time.monotonic() - started > timeout:
            raise RouterError('Ethernet naming could not complete before startup; ' + (last_error or 'udev initialization is pending'))

        # Retry pending handoffs/conflicts promptly; healthy ports need only
        # physical events and an infrequent safety audit, not a one-second scan.
        wait_for_change(monitor, 60 if complete else 1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, default=Path('/var/lib/nvyr/interface-names.json'))
    parser.add_argument('--runtime', type=Path, default=RUNTIME)
    parser.add_argument('--timeout', type=float, default=60)
    parser.add_argument('--udev-properties', metavar='SYS_PATH')
    parser.add_argument('--debug', action='store_true', help='Log detailed naming diagnostics')
    args = parser.parse_args()
    if args.udev_properties:
        ready = udev_ready(args.udev_properties, args.runtime)
        print('NVYR_NAME_READY=' + ('1' if ready else '0'))
        print('ID_NET_MANAGED_BY=' + ('io.nvyr.Netlink' if ready else 'io.nvyr.Naming'))

        return

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    args.state.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    with args.state.with_suffix('.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        serve(args.state, args.runtime, args.timeout)


if __name__ == '__main__':
    main()
