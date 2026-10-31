"""Direct rtnetlink operations and the interface-type extension registry.

Keymaps translate attributes; drivers implement device-specific lifecycle steps.
They do not own persistence, DHCP, commits, or the daemon transport.
"""

import errno
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import ipaddress
import logging
from pathlib import Path
import re
import socket
import time

from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import dhcp_options, vrf_rules, interface_ip

log = logging.getLogger(__name__)


def interface_name(value):
    # Names are also filesystem components and systemd instance identifiers.
    # This transport guard is independent of the CLI's ethN/dumN policies.
    if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_.-]{0,14}', value):
        raise ValidationError(f'Invalid kernel interface name {value!r}')

    return value


@dataclass(frozen=True)
class NetlinkKey:
    """Kernel transport metadata, not a configuration schema or validator."""

    write: str
    read: tuple
    operation: str = 'link'
    missing: object = None
    requires_down: bool = False


LINK_KEYMAP = {
    'mtu': NetlinkKey('mtu', ('IFLA_MTU',)),
    'mac': NetlinkKey('address', ('IFLA_ADDRESS',), requires_down=True),
    'description': NetlinkKey('ifalias', ('IFLA_IFALIAS',), missing=''),
    'vrf': NetlinkKey('master', ('IFLA_MASTER',), missing=0),
    'link-group': NetlinkKey('group', ('IFLA_GROUP',), missing=0),
}


def read_attributes(message, keymap):
    """Use the same mapping for observation, baseline capture and comparison."""
    result = {}

    for name, entry in keymap.items():
        value = message

        for attribute in entry.read:
            value = value.get_attr(attribute) if value is not None else None

        result[name] = entry.missing if value is None else value

    return result


class LinkType:
    """Extend the keymap and override lifecycle hooks for a new link type."""

    virtual = False
    kernel_kind = None
    keymap = LINK_KEYMAP

    def companions(self, spec):
        """Links created and removed together, without an ordering dependency."""
        return ()

    def attachments(self, spec):
        """Member-to-master relationships managed by this driver's owner."""
        return {}

    def validate(self, spec, links, previous=None):
        pass

    def validate_device(self, kernel, spec):
        pass

    def dependencies(self, spec):
        vrf = spec['attributes'].get('vrf')
        return (vrf,) if vrf else ()

    def matches(self, device):
        return device['kind'] in ('', None, 'veth') if not self.virtual else device['kind'] == self.kernel_kind

    def create(self, kernel, spec):
        if not self.virtual:
            raise RouterError(f"Interface {spec['name']} does not exist")

        kernel.ipr.link('add', ifname=spec['name'], kind=self.kernel_kind)

    def snapshot(self, kernel, spec, device):
        """Capture JSON-safe original attributes before first configuration.

        The keymap captures added attributes automatically; the common journal
        persists them without knowing their field names.
        """
        return read_attributes(device['message'], self.keymap)

    def configure(self, kernel, spec, baseline):
        attrs = baseline | spec['attributes']
        vrf = attrs.get('vrf')

        if isinstance(vrf, str):
            master = kernel.device(vrf) if vrf else None
            # A dependency with this name must be a VRF, not another link type.
            if vrf and (master is None or master['kind'] != 'vrf'):
                raise ValidationError(f"{spec['name']}: VRF {vrf!r} does not exist")

            attrs['vrf'] = master['index'] if master else 0

        # Master-owning drivers declare attachments centrally. Ordinary member
        # reconciliation must retain them instead of treating an empty VRF as detach.
        attached = getattr(kernel, 'attachments', {}).get(spec['name'])
        if attached and not vrf:
            master = kernel.device(attached)
            attrs['vrf'] = master['index'] if master else 0

        device = kernel.device(spec['name'])
        current = read_attributes(device['message'], self.keymap)
        changes = {key: value for key, value in attrs.items() if current.get(key) != value}

        if 'vrf' in changes:
            # Switching masters requires detaching first. Refresh even after a
            # failed attachment so rollback observes the actual intermediate state.
            log.debug('%s: set VRF master %s', spec['name'], vrf or 'default')
            try:
                if current['vrf']:
                    kernel.ipr.link('set', index=device['index'], master=0)

                if changes['vrf']:
                    kernel.ipr.link('set', index=device['index'], master=changes['vrf'])
            finally:
                kernel.refresh(spec['name'])

        # Changing MAC may require a down transition. Do not flap for unchanged values.
        if device['up'] and any(self.keymap[key].requires_down for key in changes):
            kernel.state(spec['name'], False)

        operations = {}

        for key, value in changes.items():
            if key == 'vrf':
                continue

            entry = self.keymap[key]
            operations.setdefault(entry.operation, {})[entry.write] = value

        for operation, arguments in operations.items():
            log.debug('%s: %s attributes %s', spec['name'], operation, arguments)
            try:
                getattr(kernel.ipr, operation)('set', index=device['index'], **arguments)
            except Exception:
                # A rejected multi-attribute request may still have changed a
                # preceding attribute. Compensation must read that actual state.
                kernel.refresh(spec['name'])
                raise

        return bool(changes)

    def remove(self, kernel, name):
        if self.virtual:
            kernel.ipr.link('del', index=kernel.device(name)['index'])
        else:
            kernel.state(name, False)

    def addresses(self, spec):
        """Return the complete desired address list for an owned link."""
        return [] if spec['disabled'] else list(spec['addresses'])

    def release(self, kernel, spec, baseline):
        """Remove owned configuration before releasing a permanent device."""
        kernel.set_addresses(spec['name'], [], disabled=True)
        self.configure(kernel, dict(spec, attributes={}), baseline)

    def remove_many(self, kernel, names):
        """Remove independent links; drivers may opt into parallel teardown."""
        for name in names:
            self.remove(kernel, name)


def virtual_mac(name):
    """Assign a stable local unicast MAC before udev can replace a random one."""
    octets = bytearray(hashlib.sha256(name.encode()).digest()[:6])
    octets[0] = (octets[0] & 0xfe) | 2
    return ':'.join(f'{value:02x}' for value in octets)


class Loopback(LinkType):
    keymap = {'description': LINK_KEYMAP['description']}
    system_addresses = ('127.0.0.1/8', '::1/128')

    def validate(self, spec, links, previous=None):
        # Linux has one permanent loopback device in this network namespace.
        if spec['name'] != 'lo':
            raise ValidationError('The system loopback interface must be named lo')

        # DHCP and administrative shutdown would break the loopback contract.
        if spec['disabled'] or spec['dhcp4'] or spec['dhcp-options'] != dhcp_options.normalize({}):
            raise ValidationError('Loopback does not support DHCP or disabling')

        for prefix in spec['addresses']:
            address = ipaddress.ip_interface(prefix)
            # The built-in host addresses must retain their system prefix lengths.
            if str(address.ip) in {'127.0.0.1', '::1'} and str(address) not in self.system_addresses:
                raise ValidationError('System loopback addresses must use 127.0.0.1/8 and ::1/128')

    def matches(self, device):
        return device['message'].get('ifi_type') == 772  # ARPHRD_LOOPBACK

    def addresses(self, spec):
        return list(dict.fromkeys([*self.system_addresses, *spec['addresses']]))

    def configure(self, kernel, spec, baseline):
        # Removing the configured description clears the alias, never changes other attributes.
        return super().configure(kernel, spec, {'description': ''})

    def release(self, kernel, spec, baseline):
        kernel.set_addresses(spec['name'], self.system_addresses)
        self.configure(kernel, dict(spec, attributes={}), baseline)

    def remove(self, kernel, name):
        kernel.state(name, True)


class Dummy(LinkType):
    virtual = True
    kernel_kind = 'dummy'

    def create(self, kernel, spec):
        kernel.ipr.link('add', ifname=spec['name'], kind=self.kernel_kind,
                        address=virtual_mac(spec['name']), mtu=1500)

    def remove_many(self, kernel, names):
        kernel.delete_links({name: kernel.device(name) for name in names})


class VirtualEthernet(LinkType):
    virtual = True
    kernel_kind = 'veth'
    keymap = LINK_KEYMAP | {'peer-name': NetlinkKey('peer', ('IFLA_LINK',))}

    def companions(self, spec):
        return (spec['attributes']['peer-name'],)

    def validate(self, spec, links, previous=None):
        peer = spec['attributes'].get('peer-name')

        # Both endpoints must be explicit, distinct members of one reciprocal pair.
        interface_name(peer)
        if peer == spec['name']:
            raise ValidationError(f"{spec['name']}: an interface cannot be its own peer")

        other = links.get(peer, {})
        if (other.get('kind') != 'virtual-ethernet'
                or other.get('attributes', {}).get('peer-name') != spec['name']):
            raise ValidationError(f"{spec['name']}: configure virtual-ethernet {peer} with peer-name {spec['name']}")

        # Re-pairing destroys both endpoints, so require a separately committed deletion.
        if previous and previous['attributes']['peer-name'] != peer:
            raise ValidationError(f"{spec['name']}: peer-name cannot be changed in place; "
                                  'delete and commit the pair before recreating it')

    def validate_device(self, kernel, spec):
        device = kernel.device(spec['name'])
        peer = kernel.device(spec['attributes']['peer-name'])

        # Never configure or delete an endpoint wired to an unexpected device.
        if device and (peer is None or device['message'].get_attr('IFLA_LINK') != peer['index']
                       or peer['message'].get_attr('IFLA_LINK') != device['index']):
            raise ValidationError(f"{spec['name']}: kernel peer does not match the configured pair")

    def create(self, kernel, spec):
        # Set both addresses at creation so udev cannot race baseline capture.
        peer = spec['attributes']['peer-name']
        kernel.ipr.link('add', ifname=spec['name'], kind='veth',
                        address=virtual_mac(spec['name']),
                        peer={'ifname': peer, 'address': virtual_mac(peer)})

    def snapshot(self, kernel, spec, device):
        return read_attributes(device['message'], LINK_KEYMAP)

    def configure(self, kernel, spec, baseline):
        attributes = {key: value for key, value in spec['attributes'].items() if key != 'peer-name'}
        return super().configure(kernel, dict(spec, attributes=attributes), baseline)

    def remove_many(self, kernel, names):
        for name in names:
            # Deleting the first endpoint also deletes its peer in the kernel.
            kernel.refresh(name)
            if kernel.device(name) is not None:
                self.remove(kernel, name)


class VLAN(LinkType):
    """802.1Q child of any Ethernet-compatible parent driver."""

    virtual = True
    kernel_kind = 'vlan'
    keymap = LINK_KEYMAP | {
        'parent': NetlinkKey('link', ('IFLA_LINK',)),
        'vlan': NetlinkKey('vlan_id', ('IFLA_LINKINFO', 'IFLA_INFO_DATA', 'IFLA_VLAN_ID')),
    }

    def dependencies(self, spec):
        return (*super().dependencies(spec), spec['attributes']['parent'])

    def validate(self, spec, links, previous=None):
        attributes = spec['attributes']

        # Every VLAN needs a valid parent and a usable 802.1Q identifier.
        interface_name(attributes.get('parent'))
        vlan = attributes.get('vlan')
        if type(vlan) is not int or not 1 <= vlan <= 4094:
            raise ValidationError(f"{spec['name']}: VLAN ID must be between 1 and 4094")

        # Topology is immutable; a changed parent/tag requires explicit recreation.
        if previous and any(previous['attributes'][key] != attributes[key] for key in ('parent', 'vlan')):
            raise ValidationError(f"{spec['name']}: VLAN parent and ID cannot change in place")

    def validate_device(self, kernel, spec):
        device = kernel.device(spec['name'])
        parent = kernel.device(spec['attributes']['parent'])
        current = read_attributes(device['message'], self.keymap) if device else {}

        # Do not adopt or remove a VLAN whose underlying topology has changed.
        if device and (parent is None or current['parent'] != parent['index']
                       or current['vlan'] != spec['attributes']['vlan']):
            raise ValidationError(f"{spec['name']}: kernel VLAN parent or ID differs from configuration")

    def create(self, kernel, spec):
        parent = kernel.device(spec['attributes']['parent'])
        kernel.ipr.link('add', ifname=spec['name'], kind='vlan', link=parent['index'],
                        vlan_id=spec['attributes']['vlan'])

    def snapshot(self, kernel, spec, device):
        return read_attributes(device['message'], LINK_KEYMAP)

    def configure(self, kernel, spec, baseline):
        attributes = {key: value for key, value in spec['attributes'].items() if key not in ('parent', 'vlan')}
        parent = kernel.device(spec['attributes']['parent'])
        parent_mtu = parent['attributes']['mtu']
        attributes.setdefault('mtu', parent_mtu)

        # A child cannot carry packets larger than its parent's payload MTU.
        if attributes['mtu'] > parent_mtu:
            raise ValidationError(f"{spec['name']}: MTU cannot exceed parent MTU {parent_mtu}")

        return super().configure(kernel, dict(spec, attributes=attributes), baseline)


class VRF(LinkType):
    virtual = True
    kernel_kind = 'vrf'
    keymap = {
        'table': NetlinkKey('vrf_table', ('IFLA_LINKINFO', 'IFLA_INFO_DATA', 'IFLA_VRF_TABLE')),
    }

    def create(self, kernel, spec):
        arguments = {self.keymap[key].write: value for key, value in spec['attributes'].items()}
        kernel.ipr.link('add', ifname=spec['name'], kind=self.kernel_kind, **arguments)

    def configure(self, kernel, spec, baseline):
        current = read_attributes(kernel.device(spec['name'])['message'], self.keymap)
        if current['table'] != spec['attributes']['table']:
            raise ValidationError(f"VRF {spec['name']}: table cannot be changed in place; "
                                  'delete and commit the VRF before recreating it with another table')

        kernel.vrf_rules()
        return False


class Bridge(LinkType):
    virtual = True
    kernel_kind = 'bridge'
    keymap = LINK_KEYMAP | {'bridge': NetlinkKey('', ('NVYR_BRIDGE_SETTINGS',), missing=None)}

    def attachments(self, spec):
        return {name: spec['name'] for name in spec['attributes']['bridge'].get('member', {}).get('interface', {})}

    def dependencies(self, spec):
        return (*super().dependencies(spec), *self.attachments(spec))

    def validate(self, spec, links, previous=None):
        values = spec['attributes'].get('bridge')
        # Structured bridge intent is required; an absent payload cannot reset port policy.
        if not isinstance(values, dict):
            raise ValidationError(f"{spec['name']}: bridge settings must be an object")
        for name in self.attachments(spec):
            # Member identities must be safe kernel interface names at the RPC boundary.
            interface_name(name)
            # Self-membership would create a dependency cycle rather than a usable port.
            if name == spec['name']:
                raise ValidationError('A bridge cannot be its own member')

    def create(self, kernel, spec):
        values = spec['attributes']['bridge']
        # Suppress implicit VLAN 1 at creation when default-pvid is zero.
        kernel.ipr.link('add', ifname=spec['name'], kind='bridge', address=virtual_mac(spec['name']),
                        br_vlan_default_pvid=int(values.get('default-pvid', 1)))

    def snapshot(self, kernel, spec, device):
        return read_attributes(device['message'], LINK_KEYMAP)

    def configure(self, kernel, spec, baseline):
        from nvyr.helpers.bridge_netlink import (
            bridge_data, set_bridge_options, query, reconcile_vlans, reconcile_port,
            reconcile_vlan_options, reconcile_fdb, reconcile_mdb,
        )
        from nvyr.helpers import bridge_config as config

        name = spec['name']
        values = spec['attributes']['bridge']
        members = values.get('member', {}).get('interface', {})
        attributes = {key: value for key, value in spec['attributes'].items() if key != 'bridge'}
        changed = super().configure(kernel, dict(spec, attributes=attributes), baseline)
        desired = config.bridge_options(values)
        present = bridge_data(name)

        # Linux requires empty port VLAN tables before toggling per-port VLAN statistics.
        if present.get('vlan_stats_per_port', 0) != desired['vlan_stats_per_port']:
            for port in query('bridge', '-j', 'link', 'show', 'master', name):
                reconcile_vlans(port['ifname'], {})
        changed |= set_bridge_options(name, desired)

        # Native multicast entries require an operational bridge device. Disabled
        # profiles keep their intent and install memberships on the next enable.
        if not spec['disabled']:
            kernel.state(name, True)

        for port in query('bridge', '-j', 'link', 'show', 'master', name):
            if port['ifname'] not in members:
                kernel.ipr.link('set', index=port['ifindex'], master=0)
                kernel.refresh(port['ifname'])

        master = kernel.device(name)['index']
        for member in members:
            device = kernel.device(member)
            current = device['attributes']['vrf']
            # Never steal an interface from a foreign bridge, bond or VRF.
            if current and current != master and current not in getattr(kernel, 'owned_master_indices', set()):
                raise ValidationError(f'{member}: already attached to an unmanaged master')
            if current != master:
                if current:
                    kernel.ipr.link('set', index=device['index'], master=0)
                kernel.ipr.link('set', index=device['index'], master=master)
                kernel.refresh(member)

        for member, settings in members.items():
            reconcile_port(kernel, member, settings)
            reconcile_vlans(member, config.vlan_memberships(settings, bridge=values))
        reconcile_vlans(name, config.vlan_memberships(values, local=True), local=True)
        reconcile_vlan_options(name, values, members)
        reconcile_fdb(kernel, name, values)
        if not spec['disabled']:
            reconcile_mdb(name, values)
        return changed


TYPES = {'ethernet': LinkType(), 'dummy': Dummy(), 'loopback': Loopback(), 'vrf': VRF(),
         'virtual-ethernet': VirtualEthernet(), 'vlan': VLAN(), 'bridge': Bridge()}


def register_type(name, driver):
    """Register an interface driver at daemon startup, before accepting requests."""
    if name in TYPES:
        raise ValueError(f'Interface type {name!r} already registered')

    TYPES[name] = driver


def normalize(links, types=None):
    types = TYPES if types is None else types

    if not isinstance(links, dict):
        raise ValidationError('links must be a mapping keyed by interface name')

    result = {}

    for name, spec in links.items():
        interface_name(name)

        if not isinstance(spec, dict) or set(spec) - {'kind', 'attributes', 'addresses', 'dhcp4', 'disabled', 'dhcp-options', 'ip-options'}:
            raise ValidationError(f'{name}: invalid link definition')

        kind = spec.get('kind')
        if not isinstance(kind, str) or kind not in types:
            raise ValidationError(f'{name}: unsupported interface type {kind!r}')

        attrs = spec.get('attributes', {})
        addresses = spec.get('addresses', [])
        if not isinstance(attrs, dict) or not isinstance(addresses, list):
            raise ValidationError(f'{name}: attributes must be a mapping and addresses a list')

        if any(type(spec.get(key, False)) is not bool for key in ('dhcp4', 'disabled')):
            raise ValidationError(f'{name}: dhcp4 and disabled must be booleans')

        if any(not isinstance(value, str) for value in addresses):
            raise ValidationError(f'{name}: addresses must contain strings')

        unknown = set(attrs) - types[kind].keymap.keys()
        if unknown:
            raise ValidationError(f'{name}: unsupported Netlink attributes: {sorted(unknown)}')

        # VRF names are resolved at apply time; never accept raw master indices over RPC.
        if 'vrf' in attrs and not isinstance(attrs['vrf'], str):
            raise ValidationError(f'{name}: vrf must be an interface name or empty')

        # An empty name requests detachment; nonempty names follow kernel naming rules.
        if attrs.get('vrf'):
            interface_name(attrs['vrf'])

        # IFLA_GROUP is an unsigned 32-bit identifier, including the default group zero.
        if 'link-group' in attrs and (type(attrs['link-group']) is not int
                                      or not 0 <= attrs['link-group'] <= 4294967295):
            raise ValidationError(f'{name}: link-group must be between 0 and 4294967295')

        item = {'kind': kind, 'attributes': dict(attrs), 'addresses': list(addresses),
                'dhcp4': spec.get('dhcp4', False), 'disabled': spec.get('disabled', False),
                'dhcp-options': dhcp_options.normalize(spec.get('dhcp-options', {})),
                'ip-options': interface_ip.normalize(spec.get('ip-options', {}), addresses=addresses, kind=kind)}
        result[name] = item

    for name, spec in result.items():
        types[spec['kind']].validate(dict(spec, name=name), result)

    return result


class Kernel:
    def __init__(self):
        from pyroute2 import IPRoute

        # Strict dumps let Linux filter by ifindex instead of pyroute2 filtering
        # a host-wide dump in Python. Debian's supported kernels provide this.
        self.ipr = IPRoute(ext_ack=True, strict_check=True)
        self._links = self._addresses = self._routes = None
        self._expected = {}
        self._address_dirty = False
        self._stale_addresses = set()
        self._vrf_rules_checked = False
        self.ip_controller = interface_ip.Controller()

    @staticmethod
    def dump(method, **arguments):
        # Kernel inventories can be interrupted by concurrent link/address
        # changes. Never use a partial dump as evidence that objects are absent.
        from pyroute2.netlink.exceptions import NetlinkDumpInterrupted

        for attempt in range(3):
            try:
                return tuple(method(**arguments))
            except NetlinkDumpInterrupted as error:
                if attempt == 2:
                    raise RouterError('Kernel inventory kept changing during the dump; retry') from error

    @contextmanager
    def snapshot(self, names=None):
        """One inventory per pass; mutations invalidate only the affected link.

        The cache never outlives a serialized request/reconciliation. Notifications
        are hints, not an authoritative cache of kernel state.
        """
        if self._links is not None:

            yield
            return

        try:
            self._bulk = names is None or len(names) > 64
            self._links = ({m.get_attr('IFLA_IFNAME'): self.decode_link(m) for m in self.dump(self.ipr.get_links)}
                           if self._bulk else {name: self._device(name) for name in names})
            self._expected = {}
            self._address_dirty = False
            self._stale_addresses = set()
            self.refresh_addresses()
            self._routes = None  # Most interfaces never own routes; load lazily.

            yield
        finally:
            self._links = self._addresses = self._routes = None
            self._vrf_rules_checked = False
            self._expected = {}
            self._address_dirty = False
            self._stale_addresses = set()

    def vrf_rules(self):
        """Audit shared VRF rules once per serialized reconciliation, before links go up."""
        if not self._vrf_rules_checked:
            vrf_rules.reconcile(self.ipr, self.dump)
            self._vrf_rules_checked = self._links is not None

    def refresh_addresses(self):
        self._addresses = {}

        if self._bulk:
            for message in self.dump(self.ipr.get_addr):
                self._addresses.setdefault(message['index'], []).append(message)
        else:
            for device in self._links.values():
                if device is not None:
                    self._addresses[device['index']] = self.address_dump(device['index'])

        self._stale_addresses.clear()

    def address_dump(self, index):
        # get_addr(index=...) is only a userspace filter in pyroute2 0.7.7.
        # Explicit match=None keeps index in the actual RTM_GETADDR request.
        return self.dump(self.ipr.addr, command='dump', index=index, match=None)

    def flush_addresses(self, *, verify=True):
        """Verify a batch of acknowledged address writes with one fresh dump."""
        expected, self._expected = self._expected, {}

        if not self._address_dirty:
            return

        self.refresh_addresses()
        self._address_dirty = False

        if verify:
            for name, desired in expected.items():
                if not desired <= self.addresses(name).keys():
                    raise RouterError(f'{name}: configured addresses did not remain installed')

    def refresh(self, name):
        self._routes = None  # Master/state changes can move or remove routes.
        if self._links is not None:
            self._address_dirty = True  # Link down/MTU changes can remove IPv6 addresses.
            previous = self._links.get(name)
            if previous and self._addresses.get(previous['index']):
                self._stale_addresses.add(previous['index'])

            self._links.pop(name, None)

            # A missing key must be queried after create/delete/attribute writes.
            self._links[name] = self._device(name)

    @staticmethod
    def decode_link(link):
        info = link.get_attr('IFLA_LINKINFO')
        return {'index': link['index'], 'kind': info.get_attr('IFLA_INFO_KIND') if info else '',
                'up': bool(link['flags'] & 1), 'carrier': bool(link['flags'] & 0x10000),
                'message': link, 'attributes': read_attributes(link, LINK_KEYMAP)}

    def close(self):
        self.ipr.close()

    def delete_links(self, devices):
        """Overlap kernel teardown waits, with separate sockets and per-link ACKs.

        The caller has journaled intent and checked ownership. No worker touches
        its cache or journal. Joining ALL workers, even on failure, is essential:
        rollback must never race an outstanding deletion.
        """
        items = list(devices.items())
        if not items:
            return

        workers = min(8, len(items))

        def delete(chunk):
            kernel = Kernel()

            try:
                for name, expected in chunk:
                    current = kernel.device(name)
                    if current is None:
                        continue

                    if (current['index'], current['kind']) != (expected['index'], expected['kind']):
                        raise RouterError(f'{name}: refusing to delete an interface that replaced the owned device')

                    kernel.ipr.link('del', index=current['index'])
            finally:
                kernel.close()

        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(delete, [items[i::workers] for i in range(workers)]))

    def device(self, name):
        if self._links is not None:
            if name not in self._links:
                self._links[name] = self._device(name)

            return self._links[name]

        return self._device(name)

    def _device(self, name):
        # link_lookup dumps every link in pyroute2 0.7.7. RTM_GETLINK by name
        # performs a single kernel lookup even with thousands of devices.
        try:
            messages = self.ipr.link('get', ifname=name)
        except Exception as error:
            if getattr(error, 'code', None) == errno.ENODEV:
                return None

            raise

        if not messages or messages[0].get_attr('IFLA_IFNAME') != name:
            raise RouterError(f'Interface {name} changed during apply; retry')

        return self.decode_link(messages[0])

    def state(self, name, up):
        device = self.device(name)
        if device['up'] != up:
            log.debug('%s: set administrative state %s', name, 'up' if up else 'down')
            self.ipr.link('set', index=device['index'], state='up' if up else 'down')
            self.refresh(name)

    def ip_policy(self, name, options, globals):
        self.ip_controller.apply(self, name, options, globals)

    def ip_profile(self, owners, globals):
        return self.ip_controller.profile_transaction(owners, globals)

    def ipv6_token(self, name, token):
        """IFLA_INET6_TOKEN selects the host bits for SLAAC, not static addresses."""
        device = self.device(name)
        message = device['message']
        families = message.get_attr('IFLA_AF_SPEC')
        ipv6 = families.get_attr('AF_INET6') if families else None
        previous = ipv6.get_attr('IFLA_INET6_TOKEN') if ipv6 else None
        if previous is not None and ipaddress.IPv6Address(previous) == ipaddress.IPv6Address(token):
            return
        if previous is None and token == '::':
            return
        self.ipr.link('set', index=device['index'], af_spec={
            'attrs': [('AF_INET6', {'attrs': [('IFLA_INET6_TOKEN', token)]})]})
        self.refresh(name)
        self.refresh_addresses()

    def ipv6_ra_routes(self, name, *, default_only):
        """Withdraw learned RA routes when their acceptance policy is removed."""
        index = self.device(name)['index']
        for route in self.ipr.get_routes(family=socket.AF_INET6):
            if route['proto'] != 9 or route.get_attr('RTA_OIF') != index:
                continue
            if default_only and route['dst_len'] != 0:
                continue
            arguments = {
                'family': socket.AF_INET6, 'oif': index,
                'dst': f"{route.get_attr('RTA_DST') or '::'}/{route['dst_len']}",
                'table': route.get_attr('RTA_TABLE') or route['table'],
                'priority': route.get_attr('RTA_PRIORITY'),
            }
            gateway = route.get_attr('RTA_GATEWAY')
            if gateway:
                arguments['gateway'] = gateway
            try:
                self.ipr.route('del', **arguments)
            except Exception as error:
                if getattr(error, 'code', None) != errno.ESRCH:
                    raise

    def addresses(self, name, *, fresh=False):
        device = self.device(name)
        if device is None:
            return {}

        result = {}
        index = device['index']
        if (self._addresses is None or fresh or index in self._stale_addresses
                or (not self._bulk and index not in self._addresses)):
            messages = self.address_dump(index)

            if self._addresses is not None:
                self._addresses[index] = messages
                self._stale_addresses.discard(index)
        else:
            messages = self._addresses.get(index, [])

        for addr in messages:
            value = addr.get_attr('IFA_LOCAL') or addr.get_attr('IFA_ADDRESS')
            prefix = str(ipaddress.ip_interface(f"{value}/{addr['prefixlen']}"))
            cache = addr.get_attr('IFA_CACHEINFO') or {}
            result[prefix] = {'scope': addr['scope'], 'flags': addr.get_attr('IFA_FLAGS') or addr['flags'],
                              'valid_lft': cache.get('ifa_valid', 0xffffffff)}

        return result

    def set_addresses(self, name, desired, *, disabled=False, lease=None, ip_options=None):
        """Reconcile a claimed link's addresses while preserving enabled IPv6 link-local.

        Lease lifetimes apply only to the supplied DHCP address. Batched callers
        record expected addresses here and verify them when flushing the batch.
        """
        # Conversion to kernel address/prefix fields, not CLI value validation.
        desired = {str(ipaddress.ip_interface(value)) for value in desired}

        if self._addresses is not None:
            self._expected[name] = desired

        current = self.addresses(name)
        changed = False
        removed_ipv4 = False

        # Only claimed interfaces are passed here. Their configured addresses are
        # exclusive, but IPv6 link-local is kernel-owned while the link is enabled.
        for prefix, state in list(current.items()):
            ipv6 = (ip_options or {}).get('ipv6', {})
            is_ipv6 = ipaddress.ip_interface(prefix).version == 6
            keep_local = (is_ipv6 and state['scope'] == 253 and not disabled and 'disable' not in ipv6
                          and not {'no-default-link-local', 'link-local-address'} & ipv6.keys())
            # Infinite-lifetime SLAAC can also carry PERMANENT; MANAGETEMPADDR
            # still identifies its kernel-managed public address.
            dynamic = not state['flags'] & 128 or state['flags'] & 0x101
            temporary = state['flags'] & 1
            keep_dynamic = (is_ipv6 and dynamic and 'autoconf' in ipv6 and not disabled
                            and (not temporary or ipv6.get('temporary-addresses', 'disable') != 'disable'))
            if prefix not in desired and not keep_local and not keep_dynamic:
                value = ipaddress.ip_interface(prefix)

                if self._addresses is not None:
                    self._address_dirty = True

                try:
                    log.debug('%s: remove address %s', name, prefix)
                    self.ipr.addr('del', index=self.device(name)['index'], address=str(value.ip), prefixlen=value.network.prefixlen)
                except Exception as error:
                    # Deleting a primary IPv4 address can remove secondaries.
                    # An ACK saying already absent is sufficient; no new dump.
                    if getattr(error, 'code', None) not in (errno.EADDRNOTAVAIL, errno.ENOENT, errno.ESRCH):
                        raise

                current.pop(prefix)
                removed_ipv4 |= value.version == 4
                changed = True

        if removed_ipv4:
            # Reassert desired IPv4 addresses once after a primary deletion,
            # regardless of the host's promote_secondaries policy.
            current = {prefix: state for prefix, state in current.items()
                       if ipaddress.ip_interface(prefix).version != 4}

        for prefix in desired:
            value = ipaddress.ip_interface(prefix)
            seconds = 0xffffffff

            if lease and prefix == lease['address']:
                seconds = max(1, int(lease['expires'] - time.monotonic()))
                if (self._addresses is not None and prefix in current
                        and abs(current[prefix]['valid_lft'] - seconds) > 2):
                    # A large audit/apply can age the bulk snapshot. Confirm
                    # lease drift with a cheap per-interface read before
                    # refreshing an unchanged lease and generating more events.
                    current = self.addresses(name, fresh=True)
                    seconds = max(1, int(lease['expires'] - time.monotonic()))

            # pyroute2 encodes lifetimes through IFA_CACHEINFO. Top-level
            # valid_lft/preferred_lft are silently ignored, leaving a permanent
            # address and causing an endless replace/notification repair loop.
            lifetime = {'cacheinfo': {'valid': seconds, 'preferred': seconds}}

            if value.version == 4 and value.network.prefixlen < 31:
                lifetime['broadcast'] = str(value.network.broadcast_address)

            # Refresh on lease renewal, not on our own address notifications.
            if prefix not in current or abs(current[prefix]['valid_lft'] - seconds) > 2:
                log.debug('%s: install address %s (lifetime %s)', name, prefix, seconds)

                if self._addresses is not None:
                    self._address_dirty = True

                self.ipr.addr('replace', index=self.device(name)['index'], address=str(value.ip),
                              prefixlen=value.network.prefixlen, **lifetime)
                changed = True

        if changed and self._addresses is not None:
            self._expected[name] = desired
        elif not desired <= (self.addresses(name, fresh=True) if changed else current).keys():
            raise RouterError(f'{name}: configured addresses did not remain installed')

    def ready(self, name):
        device = self.device(name)

        for prefix, address in self.addresses(name).items():
            if address['flags'] & 8:
                raise RouterError(f'{name}: duplicate address detection failed for {prefix}')

            if device['carrier'] and address['flags'] & 64:
                return False

        return True

    def routes(self, name):
        device = self.device(name)
        if device is None:
            return []

        result = []

        if self._links is None or not self._bulk:
            messages = self.dump(self.ipr.route, command='dump', family=socket.AF_INET,
                                 table=0, oif=device['index'], match=None)
        else:
            if self._routes is None:
                self._routes = {}

                for message in self.dump(self.ipr.get_routes, family=socket.AF_INET):
                    self._routes.setdefault(message.get_attr('RTA_OIF'), []).append(message)

            messages = self._routes.get(device['index'], [])

        for route in messages:
            if route.get_attr('RTA_OIF') != device['index']:
                continue

            result.append({'dst': f"{route.get_attr('RTA_DST') or '0.0.0.0'}/{route['dst_len']}",
                           'gateway': route.get_attr('RTA_GATEWAY'), 'metric': route.get_attr('RTA_PRIORITY') or 0,
                           'protocol': route['proto']})
            table = route.get_attr('RTA_TABLE') or route['table']
            if table != 254:
                result[-1]['table'] = table

        return result

    def route(self, operation, name, route):
        device = self.device(name)
        if device is None:
            return

        args = {'dst': route['dst'], 'oif': device['index'], 'table': route.get('table', 254),
                'proto': route['protocol'], 'priority': route['metric']}

        if route['gateway']:
            args.update(gateway=route['gateway'], flags=4)  # Gateway on-link, including /32 leases.
        else:
            args['scope'] = 253

        try:
            log.debug('%s: %s route %s', name, operation, route)
            self.ipr.route(operation, **args)
            self._routes = None
        except Exception as error:
            code = getattr(error, 'code', getattr(error, 'errno', None))
            if operation != 'del' or code not in (errno.ENOENT, errno.ESRCH):
                raise
