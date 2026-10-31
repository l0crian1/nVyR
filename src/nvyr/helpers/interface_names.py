"""Physical-port identity, durable allocations and collision-safe link naming."""

from dataclasses import dataclass
import errno
import json
from pathlib import Path
import re
import socket
import struct

from nvyr.errors import RouterError
from nvyr.storage import atomic_json


NAME = re.compile(r'eth(?:0|[1-9][0-9]{0,10})\Z')


def _unique_object(pairs):
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate naming database key: {key}')

        result[key] = value

    return result


def location(properties, *, device_path, port='0', physical_port=''):
    """Version-one identity: location first, never a MAC or USB serial number."""
    # systemd 257 also exports a revision-qualified USB path separately from
    # legacy ID_PATH. Without it USB2/USB3 root-hub ports can collide.
    path = properties.get('ID_PATH_WITH_USB_REVISION') or properties.get('ID_PATH', '')
    if '-usb' in path:
        # path_id removes unstable USB bus numbers and distinguishes root-hub
        # revisions. Drop USB configuration/interface numbers: they identify the
        # adapter implementation, not the connector on which it was plugged in.
        path = re.sub(r'(:[0-9]+\.[0-9]+)$', '', path)
        return f'usb:{path}|port:{port}'

    for key in ('ID_NET_NAME_ONBOARD', 'ID_NET_NAME_SLOT'):
        if properties.get(key):
            return f'{key}:{properties[key]}'

    if path:
        return f'path:{path}|port:{physical_port or port}'

    # Virtual PCI NICs and less common buses may not export path_id. Their sysfs
    # device ancestry still identifies the attachment, with no netdev name in it.
    # virtio numbers are allocated globally and can change with discovery order.
    path = re.sub(r'/virtio[0-9]+(?=/|$)', '/virtio', device_path)
    if not path.startswith('/sys/devices/') or '/virtual/' in path:
        raise RouterError(f'No physical attachment identity for {device_path}')

    if re.search(r'/usb[0-9]+/', path):
        raise RouterError(f'USB path_id is missing for {device_path}; refusing an unstable identity')

    return f'sysfs:{path}|port:{physical_port or port}'


@dataclass(frozen=True)
class Port:
    index: int
    name: str
    location: str
    device: str
    initialized: bool = True
    managed: bool = False


class Assignments:
    def __init__(self, path):
        self.path = Path(path)

    def read(self):
        try:
            document = json.loads(self.path.read_text(), object_pairs_hook=_unique_object)
        except FileNotFoundError:
            return {}
        except (ValueError, OSError) as error:
            raise RouterError(f'Cannot read interface naming assignments: {error}') from error

        if not isinstance(document, dict) or document.get('version') != 1 or not isinstance(document.get('ports'), dict):
            raise RouterError('Unsupported or corrupt interface naming assignments')

        ports = document['ports']
        if any(not isinstance(key, str) or not key or not isinstance(name, str) or not NAME.fullmatch(name)
               for key, name in ports.items()) or len(set(ports.values())) != len(ports):
            raise RouterError('Invalid or duplicate persistent Ethernet names')

        return ports

    def allocate(self, ports, occupied):
        identities = [port.location for port in ports]
        if len(set(identities)) != len(identities):
            raise RouterError('Multiple Ethernet ports report the same physical location; refusing ambiguous assignments')

        assignments = self.read()
        result = dict(assignments)

        # Never recycle absent ports. Also avoid names held by unmanaged devices.
        used = set(result.values()) | set(occupied)
        number = 0

        for identity in sorted(set(identities) - result.keys()):
            while f'eth{number}' in used:
                number += 1

            result[identity] = f'eth{number}'
            used.add(f'eth{number}')

        if result != assignments or not self.path.exists():
            # The mapping must be durable BEFORE the first live rename.
            atomic_json(self.path, {'version': 1, 'ports': result})

        return result


def set_link(index, *, name=None, down=False):
    """Address RTM_NEWLINK by ifindex, avoiding lookup/rename races on names."""
    payload = struct.pack('=BBHiII', socket.AF_UNSPEC, 0, 0, index, 0, 1 if down else 0)

    if name is not None:
        encoded = name.encode('ascii') + b'\0'
        if len(encoded) > 16:
            raise ValueError('Interface name exceeds kernel limit')

        length = 4 + len(encoded)
        payload += struct.pack('=HH', length, 3) + encoded + b'\0' * (-length % 4)  # IFLA_IFNAME

    packet = struct.pack('=IHHII', 16 + len(payload), 16, 5, 1, 0) + payload

    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as channel:
        channel.settimeout(3)
        channel.bind((0, 0))
        channel.sendto(packet, (0, 0))

        while True:
            response = channel.recv(65536)
            offset = 0

            while offset + 16 <= len(response):
                length, kind, _, seq, _ = struct.unpack_from('=IHHII', response, offset)
                if length < 16 or offset + length > len(response):
                    raise RouterError('Malformed Netlink acknowledgement while naming interfaces')

                if kind == 2 and seq == 1:  # NLMSG_ERROR, zero means ACK
                    error = -struct.unpack_from('=i', response, offset + 16)[0]
                    if error:
                        raise OSError(error, errno.errorcode.get(error, 'Netlink error'))

                    return

                offset += (length + 3) & ~3


class Coordinator:
    def __init__(self, assignments, runtime, *, inventory, links=socket.if_nameindex,
                 change=set_link, release=lambda port: None):
        self.assignments, self.runtime = assignments, Path(runtime)
        self.inventory, self.links, self.change, self.release = inventory, links, change, release

    def reconcile(self):
        ports = self.inventory()
        if any(not port.initialized for port in ports):
            return False

        indices = {port.index for port in ports}
        links = dict(self.links())
        foreign = {name for index, name in links.items() if index not in indices}
        assignments = self.assignments.allocate(ports, foreign)

        for port in ports:
            target = assignments[port.location]
            if target in foreign:
                raise RouterError(f'{target} is occupied by an unmanaged interface; reserved for {port.location}')

            if port.managed and links.get(port.index) != target:
                raise RouterError(f'{port.name} is already managed under the wrong name; stop network management before renaming')

        # Prune stale handoff records so a reused ifindex cannot inherit readiness.
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)

        for record in self.runtime.glob('*.json'):
            if record.stem not in {str(index) for index in indices}:
                record.unlink()

        pending = [port for port in ports if links.get(port.index) != assignments[port.location]]

        # Stage ALL conflicting managed physical ports before assigning ethN. New
        # kernel links can still race; an EEXIST is retried from a fresh inventory.
        for port in pending:
            self.change(port.index, down=True)
            temporary = f'nvn{port.index}'
            if any(name == temporary and index != port.index for index, name in self.links()):
                raise RouterError(f'Temporary name {temporary} is occupied')

            if dict(self.links()).get(port.index) != temporary:
                self.change(port.index, name=temporary)

        for port in pending:
            self.change(port.index, name=assignments[port.location])

        current = dict(self.links())

        for port in ports:
            target = assignments[port.location]
            if current.get(port.index) != target:
                return False

            record = {'name': target, 'device': port.device, 'ifindex': port.index}
            path = self.runtime / f'{port.index}.json'

            try:
                previous = json.loads(path.read_text())
            except (FileNotFoundError, ValueError):
                previous = None

            if previous != record or not port.managed:
                atomic_json(path, record)
                self.release(port)

        return all(port.managed for port in ports) and not pending


def udev_ready(sys_path, runtime):
    """Fast read-only handoff check; a missing/corrupt lease keeps a link blocked."""
    try:
        path = Path(sys_path)
        index = int((path / 'ifindex').read_text())
        record = json.loads((Path(runtime) / f'{index}.json').read_text())

        return (record == {'name': path.name, 'device': str((path / 'device').resolve()), 'ifindex': index}
                and NAME.fullmatch(path.name) is not None)
    except (OSError, ValueError, TypeError):
        return False
