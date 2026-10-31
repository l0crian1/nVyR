"""Automatic conntrack isolation for every configured routing domain."""

from nvyr.errors import ValidationError
from nvyr.helpers import interfaces, nftables, vrf_conntrack
from nvyr.helpers.container_config import bridge_name
from nvyr.helpers.template import render
from nvyr.tree import lookup

MAX_ZONE = 65535


def get_config(context):
    path, boot, ledger = vrf_conntrack.read_ledger(context.state_directory)
    return {
        'vrfs': lookup(context.effective, ('vrf', 'name'), {}),
        'interfaces': lookup(context.effective, ('interfaces',), {}),
        'networks': lookup(context.effective, ('container', 'network'), {}),
        'path': path, 'boot': boot, 'ledger': ledger,
    }


def current_zones(configuration):
    """Only the current boot's reservations can reference live connections."""
    ledger = configuration['ledger']
    return ledger.get('zones') if ledger.get('boot') == configuration['boot'] else {}


def zone_identity(name, values):
    return f'{name}:{int(values["table"])}'


def verify(configuration, context):
    # Malformed durable state must not silently collapse isolated VRFs into one zone.
    if not isinstance(configuration['ledger'], dict):
        raise ValidationError('Invalid VRF conntrack zone ledger')

    zones = current_zones(configuration)
    # Reserved identities must have distinct, nonzero, 16-bit zone identifiers.
    if (not isinstance(zones, dict) or any(type(zone) is not int or not 1 <= zone <= MAX_ZONE
                                         for zone in zones.values())
            or len(set(zones.values())) != len(zones)):
        raise ValidationError('Invalid VRF conntrack zone ledger')

    required = 0
    for name, values in configuration['vrfs'].items():
        # This owner runs before VRF creation, so it must check identity completeness itself.
        if 'table' not in values:
            raise ValidationError(f'VRF {name}: a routing table is required')
        if zone_identity(name, values) not in zones:
            required += 1

    # Deleted reservations remain occupied until reboot; never wrap or fill old gaps.
    if max(zones.values(), default=0) + required > MAX_ZONE:
        raise ValidationError('VRF conntrack zone IDs exhausted for this boot; reboot to reclaim deleted IDs')


def members(configuration):
    """Resolve L3 devices, including independently assigned VIFs and container bridges.

    Bridge ports use their bridge's L3 device. Include VRF masters for the
    preliminary locally generated OUTPUT pass as well as their member links.
    """
    vrfs = configuration['vrfs']
    result = {name: name for name in vrfs}
    for name, options in interfaces.configured({'interfaces': configuration['interfaces']}):
        if lookup(options, ('vrf',), None) in vrfs:
            result[name] = options['vrf']

    for name, options in configuration['networks'].items():
        if lookup(options, ('vrf',), None) in vrfs:
            result[bridge_name(name)] = options['vrf']
    return result


def generate(configuration, context):
    zones = dict(current_zones(configuration))
    assigned = {}
    next_zone = max(zones.values(), default=0) + 1
    for name, values in sorted(configuration['vrfs'].items()):
        identity = zone_identity(name, values)
        if identity not in zones:
            zones[identity] = next_zone
            next_zone += 1
        assigned[name] = zones[identity]

    ledger = {'boot': configuration['boot'], 'zones': zones}
    allocation = vrf_conntrack.Allocation(configuration['path'], ledger, assigned)
    rendered = render('vrf/conntrack.nft.j2', {
        'members': members(configuration), 'zones': assigned,
    })
    return rendered, allocation


def apply(generated, context):
    rendered, allocation = generated
    vrf_conntrack.reserve(allocation)
    nftables.manager.apply(rendered, context.state_directory, owner='vrf_conntrack')
