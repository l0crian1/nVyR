"""Linux bonding configuration, applied by netlinkd alongside other interfaces."""

from nvyr.errors import ValidationError
from nvyr.helpers import interfaces, netlink
from nvyr.helpers.bond_config import options, member_options, PRIMARY_MODES, PROBE_MODES
from nvyr.tree import lookup


def get_config(context):
    tree = context.effective
    return {
        'bonds': lookup(tree, ('interfaces', 'bond'), {}),
        'inventory': dict(interfaces.configured(tree)),
        'eligible': {port for kind in ('ethernet', 'dummy', 'virtual-ethernet')
                     for port, _ in interfaces.instances(lookup(tree, ('interfaces', kind), {}))},
        'vrfs': lookup(tree, ('vrf', 'name'), {}),
        'bridge-members': interfaces.bridge_members(tree),
    }


def link_definitions(bonds):
    links = interfaces.NetlinkManager.definitions('bond', interfaces.settings(bonds))
    for name, values in bonds.items():
        ports = lookup(values, ('member', 'interface'), {})
        links[name]['attributes']['bond'] = {
            'options': options(values),
            'primary': lookup(values, ('primary',), ''),
            'members': {port: member_options(settings) for port, settings in ports.items()},
        }
    return links | interfaces.vlan_definitions(bonds)


def verify(configuration, context):
    bonds = configuration['bonds']
    inventory = configuration['inventory']
    bridge_ports = configuration['bridge-members']
    claimed = set(bridge_ports)
    interfaces.verify_vifs(bonds)
    interfaces.verify_membership(bonds, vrfs=configuration['vrfs'], bridge_members=bridge_ports)

    for name, values in bonds.items():
        mode = lookup(values, ('mode',), 'balance-rr')
        ports = lookup(values, ('member', 'interface'), {})
        settings = options(values)
        primary = lookup(values, ('primary',), None)
        monitor = lookup(values, ('link-monitor',), {})
        targets = lookup(monitor, ('probe',), {})
        lacp_port = any('lacp' in port for port in ports.values())

        # LACP negotiation and actor priority only exist on an 802.3ad bond.
        if ('lacp' in values or lacp_port) and mode != '802.3ad':
            raise ValidationError(f'{name}: LACP settings require mode 802.3ad')
        # The preferred device must be attached to this bond.
        if primary and primary not in ports:
            raise ValidationError(f'{name}: primary {primary} must be a member of this bond')
        # Only the three modes with an active port implement preference and reselection.
        if mode not in PRIMARY_MODES and (primary or 'primary-reselect' in values or
                                          any('priority' in port for port in ports.values())):
            raise ValidationError(f'{name}: member priority and primary selection require an active-member mode')
        # The driver silently ignores these controls outside the modes which consume them.
        for key, modes in [('fail-over-mac', {'active-backup'}), ('peer-notifications', {'active-backup'}),
                           ('packets-per-member', {'balance-rr'}),
                           ('learning-packet-interval', {'balance-alb', 'balance-tlb'}),
                           ('disable-dynamic-load-balancing', {'balance-alb', 'balance-tlb'}),
                           ('transmit-hash-policy', {'802.3ad', 'balance-xor', 'balance-tlb', 'balance-alb'})]:
            if key in values and mode not in modes:
                raise ValidationError(f'{name}: {key} requires one of {", ".join(sorted(modes))}')
        # The driver can run only one monitor and supports neighbor probing in four modes.
        if 'probe' in monitor and ('mii' in monitor or mode not in PROBE_MODES):
            raise ValidationError(f'{name}: probe monitoring conflicts with MII monitoring or mode {mode}')
        # Probe monitoring needs an interval and at least one usable target, up to 16 per family.
        if 'probe' in monitor and ('interval' not in targets or not ('ipv4-target' in targets or 'ipv6-target' in targets)):
            raise ValidationError(f'{name}: probe requires interval and at least one IPv4 or IPv6 target')
        for key in ('ipv4-target', 'ipv6-target'):
            if len(lookup(targets, (key,), ())) > 16:
                raise ValidationError(f'{name}: at most 16 {key} addresses are supported')
        # All-target reachability is a selection policy for the active-backup monitor.
        if 'target-policy' in targets and mode != 'active-backup':
            raise ValidationError(f'{name}: probe target-policy requires active-backup')
        # The kernel counts delays in monitor ticks; reject values that would be rounded down.
        interval = settings.get('MIIMON', 0)
        for key in ('UPDELAY', 'DOWNDELAY', 'PEER_NOTIF_DELAY'):
            delay = settings.get(key, 0)
            if delay and (not interval or delay % interval):
                raise ValidationError(f'{name}: {key.lower()} requires a multiple of the configured MII interval')
        # Each member must have its own managed link and exactly one L2 master.
        queues = set()
        for port, policy in ports.items():
            if port in claimed or port not in configuration['eligible']:
                raise ValidationError(f'{name}: {port} must be an available configured member interface')
            claimed.add(port)
            # Queue zero is shared; a nonzero ID identifies one transmit port.
            queue = int(lookup(policy, ('queue-id',), 0))
            if queue and queue in queues:
                raise ValidationError(f'{name}: queue-id {queue} is assigned to multiple members')
            queues.add(queue)
            profile = inventory[port]
            # The bond owns member MTU and IP traffic, including child VLAN and DHCP clients.
            if any(key in profile for key in interfaces.BOND_MEMBER_CONFLICTS):
                raise ValidationError(f'{name}: configure routing, DHCP, MTU, MAC and VIFs on the bond instead of {port}')

    # Delegation may target a routed bond or VIF, but must never target a member port.
    interfaces.verify_pd(inventory, claimed)
    links = link_definitions(bonds)
    netlink.normalize(links)
    interfaces.manager.request('validate', owner='bond', links=links, recovery=context.recovery)


def generate(configuration, context):
    return link_definitions(configuration['bonds'])


def apply(links, context):
    interfaces.manager.replace('bond', links, recovery=context.recovery)
