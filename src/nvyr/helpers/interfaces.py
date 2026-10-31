"""Shared interface configuration model, inventory helpers and netlinkd client."""

from dataclasses import dataclass, field
import ipaddress
import json
from pathlib import Path
import socket

from nvyr.errors import RecoveryError, RouterError, ValidationError
from nvyr.helpers.process import cmd
from nvyr.helpers import dhcp_options, interface_ip
from nvyr.tree import lookup


def visible_link(device):
    """Exclude infrastructure devices using native metadata, never name prefixes."""
    link_type = device.get('link_type')
    kind = device.get('linkinfo', {}).get('info_kind')
    # PIM register devices have no kind; Ethernet tunnels still need kind checks.
    return link_type not in {'pimreg', 'ipip', 'tunnel', 'tunnel6', 'gre', 'ipgre', 'ip6gre'} and kind not in {
        'vrf', 'ipip', 'gre', 'gretap', 'erspan', 'ip6gre', 'ip6gretap', 'ip6erspan',
    }


def exists(name):
    """Query the current network namespace, without a shell or cached device list."""
    try:
        socket.if_nametoindex(name)
        return True
    except OSError:
        return False


def interface_vrfs(devices):
    """Resolve routing domains through bridge/bond masters using one kernel snapshot."""
    by_name = {device['ifname']: device for device in devices}
    by_index = {device['ifindex']: device for device in devices}
    result = {}

    for name, device in by_name.items():
        visited = set()
        current = device
        while True:
            if current['ifindex'] in visited:
                raise RouterError(f'Cycle in interface master relationships for {name!r}')
            visited.add(current['ifindex'])

            if current.get('linkinfo', {}).get('info_kind') == 'vrf':
                result[name] = current['ifname']
                break

            master = current.get('master')
            if master is None:
                result[name] = 'default'
                break
            current = by_index.get(master) if isinstance(master, int) else by_name.get(master)
            if current is None:
                raise RouterError(f'Interface topology changed while resolving {name!r}; retry')

    return result


def require_named(name):
    """Do not apply an Ethernet profile to a kernel name awaiting assignment."""
    from nvyr.helpers.interface_names import udev_ready

    runtime = Path('/run/nvyr-naming/ready')
    path = Path('/sys/class/net') / name
    if (runtime.parent.exists() and (path / 'device').exists()
            and not udev_ready(path.resolve(), runtime)):
        raise ValidationError(f'Interface {name}: persistent Ethernet naming is pending; check nvyr-interface-naming.service')


def local_addresses(vrf=None):
    """Assigned addresses, optionally limited to a Linux VRF in this namespace.

None means all VRFs for callers that need a host-wide inventory. 'default'
excludes VRF devices and their descendants, including bridge/bond members.
"""
    links = json.loads(cmd(['ip', '-j', 'address', 'show']))

    if vrf is not None:
        devices = json.loads(cmd(['ip', '-d', '-j', 'link', 'show']))
        by_name = {device['ifname']: device for device in devices}
        by_index = {device['ifindex']: device for device in devices}
        vrfs = {device['ifname'] for device in devices
                if device.get('linkinfo', {}).get('info_kind') == 'vrf'}
        if vrf != 'default' and vrf not in vrfs:
            raise ValidationError(f'VRF {vrf!r} does not exist on the local system')

        def instance(name):
            visited = set()
            device = by_name.get(name)

            while device is not None:
                if device['ifindex'] in visited:
                    raise RouterError(f'Cycle in interface master relationships for {name!r}')

                visited.add(device['ifindex'])

                if device['ifname'] in vrfs:
                    return device['ifname']

                master = device.get('master')
                if master is None:
                    return 'default'

                device = by_index.get(master) if isinstance(master, int) else by_name.get(master)

            raise RouterError(f'Interface topology changed while checking VRF membership for {name!r}; retry')

        links = [link for link in links if instance(link['ifname']) == vrf]

    return {ipaddress.ip_address(item['local']) for link in links
            for item in link.get('addr_info', []) if 'local' in item}


@dataclass(frozen=True)
class Link:
    name: str
    addresses: tuple = ()
    dhcp: bool = False
    disabled: bool = False
    mac: str | None = None
    mtu: int | None = None
    description: str | None = None
    vrf: str = ''
    link_group: int = 0
    dhcp_options: dict = field(default_factory=dict)
    ip_options: dict = field(default_factory=dict)


def settings(configuration):
    """Format schema-validated interface settings; native preflight verifies relationships."""
    result = {}

    for name, values in configuration.items():
        addresses = tuple(dict.fromkeys(str(ipaddress.ip_interface(value))
                                       for value in values.get('address', ()) if value != 'dhcp'))
        result[name] = Link(name, addresses, 'dhcp' in values.get('address', ()), 'disable' in values,
                            values.get('mac', '').lower() or None,
                            int(values['mtu']) if 'mtu' in values else None, values.get('description'),
                            values.get('vrf', ''), int(values.get('link-group', 0)),
                            dhcp_options.format_options(values.get('dhcp-options', {})),
                            interface_ip.format_options({key: values[key] for key in ('ip', 'ipv6') if key in values}))

    return result


def bridge_members(configuration):
    """Collect switched ports from the proposed interface configuration."""
    return {
        member for bridge in lookup(configuration, ('interfaces', 'bridge'), {}).values()
        for member in lookup(bridge, ('member', 'interface'), {})}


def verify_membership(configuration, *, vrfs, bridge_members):
    for name, values in instances(configuration):
        # Membership must resolve in the proposed configuration, including new VRFs.
        if 'vrf' in values and values['vrf'] not in vrfs:
            raise ValidationError(f"Interface {name}: VRF {values['vrf']!r} is not configured")

        # A switched port cannot acquire L3 or child VLAN configuration through its own owner.
        if name in bridge_members and (values.get('address') or 'vrf' in values or values.get('vif')
                                       or values.get('ip') or values.get('ipv6')):
            raise ValidationError(f'Interface {name}: bridge member cannot have addresses, DHCP, VRF, VIFs or IP options')


def instances(configuration):
    """Enumerate interface profiles and their VLAN children by kernel name."""
    for name, values in configuration.items():
        yield name, values
        for vlan, child in values.get('vif', {}).items():
            yield f'{name}.{vlan}', child


def configured(configuration):
    """Shared inventory for interface consumers, independent of parent type."""
    for profiles in configuration.get('interfaces', {}).values():
        yield from instances(profiles)


def vlan_definitions(configuration):
    """Flatten VLAN children into the same owner transaction as their parents."""
    result = {}

    for parent, values in configuration.items():
        children = {f'{parent}.{vlan}': child for vlan, child in values.get('vif', {}).items()}
        definitions = NetlinkManager.definitions('vlan', settings(children))
        for vlan in values.get('vif', {}):
            definitions[f'{parent}.{vlan}']['attributes'].update(parent=parent, vlan=int(vlan))
        result.update(definitions)

    return result


def verify_vifs(configuration):
    from nvyr.helpers.netlink import interface_name

    for parent, values in configuration.items():
        for vlan, child in values.get('vif', {}).items():
            name = f'{parent}.{vlan}'

            # The complete generated name must fit Linux's interface-name limit.
            interface_name(name)

            # Explicit child MTUs cannot exceed the configured parent payload MTU.
            if 'mtu' in child and 'mtu' in values and int(child['mtu']) > int(values['mtu']):
                raise ValidationError(f'Interface {name}: MTU cannot exceed parent {parent} MTU')


class NetlinkManager:
    """Configuration-script client; no kernel state or service policy lives here."""

    def __init__(self, path='/run/nvyr-netlink/control.sock', *, timeout=600):
        self.path, self.timeout = str(path), timeout

    def request(self, operation, **arguments):
        from nvyr.protocol import encode, receive

        sent = False

        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(self.path)
                sent = True
                connection.sendall(encode(dict(version=1, operation=operation, **arguments)))
                response = receive(connection)
                if response.get('version') != 1 or ('error' not in response and not isinstance(response.get('result'), dict)):
                    raise ValueError('Invalid or unsupported netlinkd response')
        except (OSError, EOFError, ValueError, RouterError) as error:
            exception = RecoveryError if sent and operation in ('replace', 'replace-dns', 'replace-kernel-settings') else RouterError
            raise exception(f'Cannot communicate with nvyr-netlinkd: {error}. Check nvyr-netlinkd.service; '
                            'a lost apply reply requires configd recovery.') from error

        if 'error' in response:
            exception = RecoveryError if response.get('recovery') else RouterError
            raise exception(response['error'])

        return response['result']

    @staticmethod
    def definitions(kind, links):
        return {name: {'kind': kind, 'addresses': list(link.addresses), 'dhcp4': link.dhcp,
                       'disabled': link.disabled, 'dhcp-options': link.dhcp_options,
                       'ip-options': link.ip_options,
                       'attributes': {'vrf': link.vrf, 'link-group': link.link_group}
                                     | {key: getattr(link, key) for key in ('mac', 'mtu', 'description')
                                        if getattr(link, key) is not None}}
                for name, link in links.items()}

    def validate(self, owner, links, *, recovery=False):
        return self.request('validate', owner=owner, links=self.definitions(owner, links), recovery=recovery)

    def replace(self, owner, definitions, *, recovery=False):
        """Generic API for new scripts: replace an owner's complete link mapping.

        Attribute dictionaries belong to registered link drivers; this transport
        does not need new methods or fields when drivers expose more attributes.
        """
        return self.request('replace', owner=owner, links=definitions, recovery=recovery)

    def apply(self, owner, links, *, recovery=False):
        # Even an empty owner must be sent: the daemon may have orphaned runtime
        # objects after interrupted configd application or configuration removal.
        return self.replace(owner, self.definitions(owner, links), recovery=recovery)


manager = NetlinkManager()
