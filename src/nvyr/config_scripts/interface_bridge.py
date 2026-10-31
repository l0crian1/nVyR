"""Bridge configuration lifecycle; shared netlinkd owns native apply and rollback."""

import ipaddress
from collections.abc import Mapping

from nvyr.errors import ValidationError
from nvyr.helpers import bridge_config, interfaces, netlink
from nvyr.tree import lookup

ROOT = ('interfaces', 'bridge')


def get_config(context):
    return {
        'bridges': lookup(context.effective, ROOT, {}),
        'inventory': dict(interfaces.configured(context.effective)),
        'vrfs': lookup(context.effective, ('vrf', 'name'), {}),
    }


def _transport_value(value):
    """Copy immutable configuration views into the daemon's JSON wire contract."""
    if isinstance(value, Mapping):
        return {key: _transport_value(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_transport_value(child) for child in value]
    return value


def link_definitions(configuration):
    """Build the daemon payload for read-only preflight and the generate stage."""
    links = interfaces.NetlinkManager.definitions('bridge', interfaces.settings(configuration))
    for name, values in configuration.items():
        links[name]['attributes']['bridge'] = _transport_value(values)
    return links | interfaces.vlan_definitions(configuration)


def verify_vlans(configuration, path, *, local=False):
    pvids = []
    for identifier, options in lookup(configuration, ('vlan',), {}).items():
        values = lookup(options, ('local',), {}) if local else options
        if 'pvid' in values:
            pvids.append(identifier)

    # Untagged ingress can be classified into only one VLAN on each port.
    if len(pvids) > 1:
        raise ValidationError(f'{path}: only one VLAN may be the pvid')


def verify_multicast(configuration, path):
    options = bridge_config.multicast_options(configuration)
    # Query responses must fit within the query cadence to avoid overlapping rounds.
    if options['mcast_query_response_interval'] >= options['mcast_query_interval']:
        raise ValidationError(f'{path}: query-response-interval must be less than query-interval')

    # Membership should not expire before a normal query and its response window.
    if options['mcast_membership_interval'] <= options['mcast_query_interval']:
        raise ValidationError(f'{path}: membership-interval must exceed query-interval')


def verify(configuration, context):
    bridges = configuration['bridges']
    inventory = configuration['inventory']

    for name, values in interfaces.instances(bridges):
        # Bridges and their VIFs may only join a VRF in the proposed configuration.
        if 'vrf' in values and values['vrf'] not in configuration['vrfs']:
            raise ValidationError(f"Interface {name}: VRF {values['vrf']!r} is not configured")

    # Child VLAN names and MTUs must fit their parent and kernel limits.
    interfaces.verify_vifs(bridges)

    owners = {}
    for bridge, values in bridges.items():
        path = f'interfaces bridge {bridge}'
        members = lookup(values, ('member', 'interface'), {})
        filtering = 'vlan-filtering' in values
        options = bridge_config.bridge_options(values)
        multicast = lookup(values, ('multicast',), {})
        verify_vlans(values, path, local=True)
        verify_multicast(multicast, path + ' multicast')

        # IEEE STP timers must satisfy both bounds before enabling the state machine.
        if 'spanning-tree' in values and not (
                2 * (options['hello_time'] + 1) <= options['max_age']
                <= 2 * (options['forward_delay'] - 1)):
            raise ValidationError(f'{path}: STP requires 2*(hello-time+1) <= max-age <= 2*(forward-delay-1)')

        # VLAN controls have no switching effect when filtering is disabled.
        if not filtering and ('vlan' in values or 'vlan-snooping' in multicast
                              or any('vlan' in member for member in members.values())):
            raise ValidationError(f'{path}: VLAN membership and VLAN snooping require vlan-filtering')

        # Existing VIFs use 802.1Q; an 802.1ad filtering bridge cannot admit that tag protocol.
        if filtering and lookup(values, ('vlan-protocol',), None) == '802.1ad' and lookup(values, ('vif',), None):
            raise ValidationError(f'{path}: 802.1Q VIFs cannot use an 802.1ad filtering bridge')

        # Per-port VLAN counters require the underlying per-VLAN accounting facility.
        if 'vlan-statistics-per-port' in values and 'vlan-statistics' not in values:
            raise ValidationError(f'{path}: vlan-statistics-per-port requires vlan-statistics')

        for identifier, vlan in lookup(values, ('vlan',), {}).items():
            # Per-VLAN multicast configuration needs independent VLAN snooping contexts.
            if 'multicast' in vlan and 'vlan-snooping' not in multicast:
                raise ValidationError(f'{path} vlan {identifier}: multicast requires multicast vlan-snooping')
            verify_multicast(lookup(vlan, ('multicast',), {}), f'{path} vlan {identifier} multicast')

        for name, member in members.items():
            member_path = f'{path} member interface {name}'
            # Each port has exactly one bridge master, and a bridge cannot contain itself.
            if name == bridge or name in owners:
                raise ValidationError(f'{member_path}: interface already belongs to a bridge or is the bridge itself')
            owners[name] = bridge

            # Only configured interfaces are managed; never claim Podman or foreign devices.
            if name not in inventory:
                raise ValidationError(f'{member_path}: member interface must be configured')

            # Nested bridge masters and bridge-derived VLANs introduce unsupported cycles.
            if name in bridges or any(name.startswith(parent + '.') for parent in bridges):
                raise ValidationError(f'{member_path}: bridge interfaces and their VIFs cannot be bridge members')

            profile = inventory[name]
            # L3 configuration belongs on the bridge or its VIF, not on a switched port.
            if lookup(profile, ('address',), None) or 'vrf' in profile:
                raise ValidationError(f'{member_path}: member cannot have addresses, DHCP or a direct VRF assignment')

            # A VLAN must not be handled both by a port VIF and bridge VLAN switching.
            if lookup(profile, ('vif',), None):
                raise ValidationError(f'{member_path}: member cannot also have configured VIFs')

            parent = lookup(inventory, (name.rsplit('.', 1)[0],), {})
            member_mtu = int(lookup(profile, ('mtu',), lookup(parent, ('mtu',), 1500)))
            # Enslaving a smaller port would silently reduce the bridge's requested MTU.
            if int(lookup(values, ('mtu',), 1500)) > member_mtu:
                raise ValidationError(f'{member_path}: member MTU must be at least the bridge MTU')

            verify_vlans(member, member_path)
            backup = lookup(member, ('backup-interface',), None)
            # Backup forwarding must stay within this bridge and cannot point back to itself.
            if backup and (backup == name or backup not in members):
                raise ValidationError(f'{member_path}: backup-interface must be a different member of this bridge')

            visited = {name}
            while backup:
                # A failover cycle has no usable terminal port when its links are down.
                if backup in visited:
                    raise ValidationError(f'{member_path}: backup-interface cycle')
                visited.add(backup)
                backup = lookup(members, (backup, 'backup-interface'), None)

            # Per-VLAN ARP/ND suppression needs its port-level facility enabled.
            if 'neighbor-vlan-suppression' in member and 'neighbor-suppression' not in member:
                raise ValidationError(f'{member_path}: neighbor-vlan-suppression requires neighbor-suppression')

            for identifier, vlan in lookup(member, ('vlan',), {}).items():
                # Per-VLAN multicast port controls require VLAN-specific snooping contexts.
                if 'multicast' in vlan and 'vlan-snooping' not in multicast:
                    raise ValidationError(f'{member_path} vlan {identifier}: multicast requires multicast vlan-snooping')
                # Individual suppression entries only take effect in per-VLAN mode.
                if 'neighbor-suppression' in vlan and 'neighbor-vlan-suppression' not in member:
                    raise ValidationError(f'{member_path} vlan {identifier}: requires neighbor-vlan-suppression')

        for mac, entry in lookup(values, ('static-mac',), {}).items():
            # A MAC entry needs an output; a bare key has no forwarding meaning.
            if 'interface' not in entry and not lookup(entry, ('vlan',), None):
                raise ValidationError(f'{path} static-mac {mac}: interface or VLAN interface is required')

            # VLAN-aware forwarding requires an explicit VLAN, avoiding implicit VLAN zero.
            if filtering and 'interface' in entry:
                raise ValidationError(f'{path} static-mac {mac}: use vlan <id> interface with vlan-filtering')

            # VLAN-specific forwarding cannot be installed in an unaware bridge.
            if not filtering and lookup(entry, ('vlan',), None):
                raise ValidationError(f'{path} static-mac {mac}: VLAN entries require vlan-filtering')

            for identifier, forwarding in [(None, entry), *lookup(entry, ('vlan',), {}).items()]:
                if identifier is None and 'interface' not in forwarding:
                    continue
                target = lookup(forwarding, ('interface',), None)
                # Static forwarding cannot target a device outside the bridge.
                if target not in members:
                    raise ValidationError(f'{path} static-mac {mac}: interface must be a bridge member')
                # VLAN forwarding must use a port admitting that VLAN.
                if identifier and int(identifier) not in bridge_config.vlan_memberships(members[target], bridge=values):
                    raise ValidationError(f'{path} static-mac {mac}: interface does not admit VLAN {identifier}')

        keys = set()
        for name, entry in lookup(multicast, ('static-group',), {}).items():
            group_path = f'{path} multicast static-group {name}'
            # An MDB entry requires a multicast destination and at least one receiving port.
            if not lookup(entry, ('address',), None) or not lookup(entry, ('interface',), None):
                raise ValidationError(f'{group_path}: address and interface are required')
            address = ipaddress.ip_address(entry['address'])
            source = lookup(entry, ('source',), None)
            # Source-specific membership must use the same address family as its group.
            if source:
                source_address = ipaddress.ip_address(source)
                if source_address.version != address.version:
                    raise ValidationError(f'{group_path}: source must be a unicast address of the same family')
            identifier = int(lookup(entry, ('vlan',), 0))
            # A VLAN-aware MDB entry must identify its VLAN; unaware bridges must not.
            if bool(identifier) != filtering:
                raise ValidationError(f'{group_path}: VLAN is required only with vlan-filtering')
            for target in entry['interface']:
                # Membership and VLAN admission must hold for every receiving port.
                if target not in members or (identifier and identifier not in bridge_config.vlan_memberships(members[target], bridge=values)):
                    raise ValidationError(f'{group_path}: interface must admit the group VLAN and belong to this bridge')
                key = (str(address), source, identifier, target)
                # Different labels must not attempt to own the same native MDB entry.
                if key in keys:
                    raise ValidationError(f'{group_path}: duplicate multicast membership')
                keys.add(key)

    # Preflight the same link definitions used by apply, including native ownership checks.
    links = link_definitions(bridges)
    netlink.normalize(links)
    interfaces.manager.request('validate', owner='bridge', links=links, recovery=context.recovery)


def generate(configuration, context):
    return link_definitions(configuration['bridges'])


def apply(links, context):
    interfaces.manager.replace('bridge', links, recovery=context.recovery)
