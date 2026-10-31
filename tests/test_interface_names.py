from dataclasses import replace
import errno
import json

import pytest

from nvyr.errors import RouterError
from nvyr.helpers.interface_names import Assignments, Coordinator, Port, location, udev_ready


def test_location_uses_connector_not_adapter_or_usb_interface():
    first = {'ID_PATH': 'pci-0000:00:14.0-usbv3-0:2.4:1.0', 'ID_SERIAL': 'old', 'ID_NET_NAME_MAC': 'enx001122334455'}
    replacement = dict(first, ID_PATH='pci-0000:00:14.0-usbv3-0:2.4:2.3', ID_SERIAL='new', ID_NET_NAME_MAC='enxaabbccddeeff')

    assert location(first, device_path='unused') == location(replacement, device_path='different')
    assert location(first, device_path='unused') != location(dict(first, ID_PATH='pci-0000:00:14.0-usbv3-0:2.5:1.0'), device_path='unused')

    # Distinct root hubs must not be silently merged, even with the same port number.
    assert location(first, device_path='unused') != location(dict(first, ID_PATH='pci-0000:00:14.0-usbv2-0:2.4:1.0'), device_path='unused')

    legacy = dict(first, ID_PATH='pci-0000:00:14.0-usb-0:2.4:1.0',
                  ID_PATH_WITH_USB_REVISION=first['ID_PATH'])

    assert location(legacy, device_path='unused') == location(first, device_path='unused')
    assert location(dict(legacy, ID_PATH_WITH_USB_REVISION='pci-0000:00:14.0-usbv2-0:2.4:1.0'), device_path='unused') != location(first, device_path='unused')


def test_pci_onboard_slot_function_and_port_identity():
    assert location({'ID_NET_NAME_SLOT':'ens3f0', 'ID_PATH':'pci-0000:01:00.0'}, device_path='unused') == location(
        {'ID_NET_NAME_SLOT':'ens3f0', 'ID_PATH':'pci-0000:08:00.0'}, device_path='unused')
    assert location({'ID_NET_NAME_ONBOARD':'eno1', 'ID_NET_NAME_SLOT':'ens3'}, device_path='unused') == 'ID_NET_NAME_ONBOARD:eno1'

    p = {'ID_PATH':'pci-0000:01:00.0'}

    assert location(p, device_path='unused', port='0') != location(p, device_path='unused', port='1')
    assert location({}, device_path='/sys/devices/pci0000:00/0000:00:03.0/virtio1') == location(
        {}, device_path='/sys/devices/pci0000:00/0000:00:03.0/virtio9')

    with pytest.raises(RouterError, match='USB path_id'):
        location({}, device_path='/sys/devices/pci0000:00/usb1/1-2/1-2:1.0')


class Host:
    def __init__(self, root, ports, foreign=None):
        self.ports = {p.index:p for p in ports}
        self.names = {p.index:p.name for p in ports} | (foreign or {})
        self.store = Assignments(root / 'names.json')
        self.events = []
        self.coordinator = Coordinator(self.store, root / 'ready', inventory=self.inventory,
                                       links=lambda:list(self.names.items()), change=self.change, release=self.release)

    def inventory(self):
        return [replace(p, name=self.names[p.index]) for p in self.ports.values()]

    def change(self, index, *, name=None, down=False):
        assert self.store.path.exists(), 'Persist before changing live names'

        self.events.append((index, name, down))

        if name:
            if name in self.names.values():
                raise OSError(errno.EEXIST, 'name occupied')

            self.names[index] = name

    def release(self, port):
        self.ports[port.index] = replace(port, managed=True)

    def converge(self):
        for _ in range(3):
            if self.coordinator.reconcile():
                return

        pytest.fail('Naming did not converge')


def port(index, name, identity):
    return Port(index, name, identity, '/sys/devices/' + identity)


def test_reversed_discovery_replacement_hotplug_and_reservations(tmp_path):
    host = Host(tmp_path, [port(8,'eth0','slotB'), port(2,'eth1','slotA')])
    host.converge()

    assert host.names == {8:'eth1',2:'eth0'}
    assert host.store.read() == {'slotA':'eth0','slotB':'eth1'}

    # Reboot with different discovery order, ifindices and adapter identity.
    host = Host(tmp_path, [port(20,'eth0','slotA'), port(4,'eth1','slotB')])
    host.converge()

    assert host.names == {20:'eth0',4:'eth1'}

    del host.ports[20], host.names[20]
    host.ports[30] = port(30,'eth0','slotC')
    host.names[30] = 'eth0'
    host.converge()

    assert host.names[30] == 'eth2' and host.store.read()['slotA'] == 'eth0'

    host.ports[40] = port(40,'nvn40','slotA')
    host.names[40] = 'nvn40'
    host.converge()

    assert host.names[40] == 'eth0'
    assert not (tmp_path/'ready/20.json').exists()

    host.events.clear()
    host.converge()

    assert host.events == [], 'Do not cycle healthy configured links'


def test_new_names_skip_unmanaged_interfaces_and_conflicts_fail_closed(tmp_path):
    host = Host(tmp_path, [port(5,'nvn5','slotA')], {99:'eth0'})
    host.converge()

    assert host.names[5] == 'eth1'

    host = Host(tmp_path, [port(6,'nvn6','slotA')], {99:'eth1'})

    with pytest.raises(RouterError, match='occupied by an unmanaged'):
        host.coordinator.reconcile()

    assert host.events == []


def test_ambiguous_identity_corrupt_database_and_uninitialized_ports(tmp_path):
    host = Host(tmp_path, [port(1,'eth0','slotA'),port(2,'eth1','slotA')])

    with pytest.raises(RouterError, match='same physical location'):
        host.coordinator.reconcile()

    assert host.events == []

    host.store.path.write_text('{broken')

    with pytest.raises(RouterError, match='Cannot read'):
        host.store.read()

    host.store.path.write_text(json.dumps({'version':1,'ports':{'A':'eth0','B':'eth0'}}))

    with pytest.raises(RouterError, match='duplicate'):
        host.store.read()

    host.store.path.write_text('{"version":1,"ports":{"A":"eth0","A":"eth1"}}')

    with pytest.raises(RouterError, match='Duplicate naming database key'):
        host.store.read()

    host.ports = {1:replace(host.ports[1], initialized=False)}

    assert not host.coordinator.reconcile()


def test_rename_race_retries_using_ifindex_without_remapping(tmp_path):
    host = Host(tmp_path, [port(1,'eth1','slotA'),port(2,'eth0','slotB')])
    original = host.change
    failed = False

    def racing(index, **kw):
        nonlocal failed

        if not failed and kw.get('name') == 'eth0':
            failed = True
            raise OSError(errno.EEXIST, 'kernel name race')

        original(index, **kw)

    host.coordinator.change = racing

    with pytest.raises(OSError):
        host.coordinator.reconcile()

    saved = host.store.read()

    assert all(name.startswith('nvn') for name in host.names.values())

    host.converge()

    assert host.store.read() == saved and host.names == {1:'eth0',2:'eth1'}


def test_write_failure_never_renames_and_managed_wrong_name_is_not_disturbed(tmp_path, monkeypatch):
    host = Host(tmp_path, [port(1,'eth1','slotA')])

    def fail(*args):
        raise OSError('disk full')

    monkeypatch.setattr('nvyr.helpers.interface_names.atomic_json', fail)

    with pytest.raises(OSError, match='disk full'):
        host.coordinator.reconcile()

    assert not host.events

    monkeypatch.undo()
    host.ports[1] = replace(host.ports[1], managed=True)

    with pytest.raises(RouterError, match='already managed'):
        host.coordinator.reconcile()

    assert not host.events


def test_ready_handoff_matches_name_device_and_index(tmp_path):
    sys_path = tmp_path/'sys/eth0'
    sys_path.mkdir(parents=True)
    (sys_path/'ifindex').write_text('42')
    device = tmp_path/'physical'
    device.mkdir()
    (sys_path/'device').symlink_to(device, target_is_directory=True)
    runtime = tmp_path/'ready'
    runtime.mkdir()

    assert not udev_ready(sys_path, runtime)

    lease = runtime/'42.json'
    lease.write_text(json.dumps({'name':'eth0','device':str(device),'ifindex':42}))

    assert udev_ready(sys_path, runtime)

    (sys_path/'ifindex').write_text('43')

    assert not udev_ready(sys_path, runtime)

    (sys_path/'ifindex').write_text('42')
    lease.write_text(json.dumps({'name':'eth1','device':str(device),'ifindex':42}))

    assert not udev_ready(sys_path, runtime)


def test_pending_physical_name_blocks_ethernet_verification_and_apply(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from nvyr.config_scripts import interface_ethernet
    from nvyr.helpers import interfaces

    (tmp_path/'run/nvyr-naming/ready').mkdir(parents=True)
    physical = tmp_path/'sys/devices/pci/net/eth0'
    physical.mkdir(parents=True)
    (physical/'ifindex').write_text('2')
    (physical/'device').mkdir()
    (tmp_path/'sys/class/net').mkdir(parents=True)
    (tmp_path/'sys/class/net/eth0').symlink_to(physical, target_is_directory=True)

    def redirected(path):
        return tmp_path/str(path).lstrip('/')

    monkeypatch.setattr(interfaces, 'Path', redirected)
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)

    for recovery in (False, True):
        context = SimpleNamespace(recovery=recovery, effective={'interfaces': {'ethernet': {'eth0': {}}}})
        with pytest.raises(RouterError, match='naming is pending'):
            interface_ethernet.verify(interface_ethernet.get_config(context), context)

    # The backend rechecks when applying, even after verification has run.
    from nvyr.helpers.link_manager import Manager

    kernel = SimpleNamespace(device=lambda name: {'index': 2, 'kind': '', 'attributes': {}})
    manager = Manager(kernel, None, tmp_path/'state', boot='test', naming=interfaces.require_named)

    with pytest.raises(RouterError, match='naming is pending'):
        manager.validate('ethernet', {'eth0': {'kind': 'ethernet'}})


def test_udev_release_uses_current_kernel_name_and_rechecks_device(tmp_path, monkeypatch):
    from nvyr import interface_naming

    path = tmp_path/'eth1'
    path.mkdir()
    (path/'ifindex').write_text('3')
    (path/'device').mkdir()
    runtime = tmp_path/'ready'
    runtime.mkdir()
    lease = runtime/'3.json'
    lease.write_text(json.dumps({'name':'eth1','device':str(path/'device'),'ifindex':3}))
    monkeypatch.setattr(interface_naming, 'Path', lambda _: tmp_path)
    monkeypatch.setattr(interface_naming.socket, 'if_indextoname', lambda index: 'eth1')
    calls = []
    monkeypatch.setattr(interface_naming, 'trigger_change', calls.append)
    before_rename = port(3, 'nvn3', 'slotB')
    interface_naming.release(before_rename, runtime)

    assert calls == [path]

    lease.write_text(json.dumps({'name':'eth1','device':'/different/device','ifindex':3}))

    with pytest.raises(RouterError, match='changed during naming'):
        interface_naming.release(before_rename, runtime)

    assert len(calls) == 1


def test_inventory_waits_for_complete_udev_properties_even_after_initialization(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from nvyr.interface_naming import inventory

    path = tmp_path/'eth0'
    path.mkdir()
    (path/'device').mkdir()
    (path/'type').write_text('1')
    (path/'ifindex').write_text('2')
    properties = {'NVYR_ETHERNET':'1', 'ID_PATH':'pci-0000:00:03.0', 'ID_PROCESSING':'1'}
    device = SimpleNamespace(sys_path=str(path), sys_name='eth0', is_initialized=True, properties=properties)
    context = object()
    monkeypatch.setattr('nvyr.interface_naming.physical_paths', lambda: [path])
    monkeypatch.setattr('pyudev.Devices.from_sys_path', lambda context, path: device)
    pending = inventory(context)[0]

    assert not pending.initialized and not pending.location

    del properties['ID_PROCESSING']
    properties['ID_NET_NAME_SLOT'] = 'ens3'

    assert inventory(context)[0].location == 'ID_NET_NAME_SLOT:ens3'

    (path/'ifindex').unlink()  # removed partway through an enumeration

    assert inventory(context) == []


def test_inventory_does_not_construct_udev_devices_for_virtual_interfaces(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from nvyr import interface_naming

    root = tmp_path/'sys/class/net'
    root.mkdir(parents=True)

    for number in range(4000):
        # Dangling virtual symlinks: no attributes or ancestor walk is needed.
        (root/f'dum{number}').symlink_to(f'../../devices/virtual/net/dum{number}')

    physical = tmp_path/'sys/devices/pci/net/eth0'
    (physical/'device').mkdir(parents=True)
    (physical/'type').write_text('1')
    (physical/'ifindex').write_text('2')
    (root/'eth0').symlink_to(physical, target_is_directory=True)
    paths = list(interface_naming.physical_paths(root))

    assert paths == [physical]

    monkeypatch.setattr(interface_naming, 'physical_paths', lambda: paths)
    calls = []

    def device(context, path):
        calls.append(path)
        return SimpleNamespace(sys_name='eth0', is_initialized=True,
                               properties={'NVYR_ETHERNET': '1', 'ID_PATH': 'pci-0'})

    monkeypatch.setattr('pyudev.Devices.from_sys_path', device)

    assert len(interface_naming.inventory(object())) == 1
    assert calls == [str(physical)]


@pytest.mark.parametrize('physical', [False, True])
def test_naming_event_storm_does_not_postpone_audit_or_physical_handoff(monkeypatch, physical):
    from types import SimpleNamespace
    from nvyr import interface_naming

    now = [0.0]
    monkeypatch.setattr(interface_naming.time, 'monotonic', lambda: now[0])

    class Event:
        @property
        def sys_path(self):
            return '/sys/devices/pci/net/eth0' if physical else '/sys/devices/virtual/net/dum0'

        @property
        def properties(self):
            pytest.fail('Event filtering must not load udev properties or sysfs attributes')

    calls = []

    def poll(timeout):
        calls.append(timeout)
        now[0] += min(timeout, .01)

        return Event()

    interface_naming.wait_for_change(SimpleNamespace(poll=poll), 60)

    assert now[0] == pytest.approx(.21 if physical else 60)
    assert len(calls) <= (22 if physical else 6001)


def test_naming_notification_loss_triggers_rescan(monkeypatch):
    from types import SimpleNamespace
    from nvyr import interface_naming

    def poll(timeout):
        raise OSError(errno.ENOBUFS, 'overflow')

    interface_naming.wait_for_change(SimpleNamespace(poll=poll), 60)
