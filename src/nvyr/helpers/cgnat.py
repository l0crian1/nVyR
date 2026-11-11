"""Deterministic CGN allocation arithmetic, shared by rendering and inspection."""

import ipaddress

from nvyr.errors import RouterError
from nvyr.helpers.container_config import bridge_name
from nvyr.helpers.nftables_singletons import included_members
from nvyr.tree import lookup


PATH = ('nat', 'cgnat')
CHAIN = 'ipv4_cgnat'


def map_name(number):
    return 'cgnat_allocation_' + number


def bounds(value):
    if '-' in value:
        first, last = value.split('-')
        return int(ipaddress.IPv4Address(first)), int(ipaddress.IPv4Address(last))
    network = ipaddress.IPv4Network(value, strict=False)
    return int(network.network_address), int(network.broadcast_address)


def intervals(values):
    """Union inclusive address ranges without expanding subscribers or pool addresses."""
    result = []
    for first, last in sorted(bounds(value) for value in values):
        if result and first <= result[-1][1] + 1:
            result[-1] = result[-1][0], max(result[-1][1], last)
        else:
            result.append((first, last))
    return result


def count(ranges):
    return sum(last - first + 1 for first, last in ranges)


def address_at(ranges, index):
    for first, last in ranges:
        length = last - first + 1
        if index < length:
            return first + index
        index -= length
    raise IndexError('CGN allocation exceeds public address pool')


def ports(pool):
    values = pool['port-range'].split('-')
    return int(values[0]), int(values[-1])


def slots(pool):
    first, last = ports(pool)
    return (last - first + 1) // int(pool['block-size'])


def capacity(pool):
    return count(intervals(pool['public-address'])) * slots(pool)


def subscribers(configuration, rule):
    values = lookup(rule, ('source-address',), ())
    if 'source-address-group' in rule:
        groups = lookup(configuration, ('firewall', 'group', 'address-group', 'ipv4'), {})
        values = included_members(groups, rule['source-address-group'], 'address')
    return intervals(values)


def enabled(configuration):
    rules = lookup(configuration, (*PATH, 'rule'), {})
    ordered = sorted(rules.items(), key=lambda item: int(item[0]))
    return [(number, rule) for number, rule in ordered if 'disable' not in rule]


def interface_vrfs(configuration):
    from nvyr.helpers import interfaces

    result = {name: lookup(options, ('vrf',), 'default') for name, options in interfaces.configured(configuration)}
    result.update({name: name for name in lookup(configuration, ('vrf', 'name'), {})})
    result.update({bridge_name(name): lookup(options, ('vrf',), 'default')
                   for name, options in lookup(configuration, ('container', 'network'), {}).items()})
    return result


def zone_numbers(configuration, directory):
    from nvyr.helpers import vrf_conntrack

    names = {lookup(rule, ('vrf',), 'default') for _, rule in enabled(configuration)} - {'default'}
    result = {'default': 0}
    if not names:
        return result
    _, boot, ledger = vrf_conntrack.read_ledger(directory)
    if lookup(ledger, ('boot',), None) != boot:
        raise RouterError('CGN requires the current VRF conntrack allocations to be installed first')
    for name in names:
        table = lookup(configuration, ('vrf', 'name', name, 'table'))
        identity = f'{name}:{int(table)}'
        if identity not in ledger['zones']:
            raise RouterError(f'CGN requires a conntrack zone for VRF {name}')
        result[name] = ledger['zones'][identity]
    return result


def segments(configuration, rule):
    """Yield contiguous subscriber slices on one public IP, not one record per host.

    Each tuple is (public IP, first port, last port, first subscriber, block size).
    This supports capacity/conflict checks and inverse lookups without expanding maps.
    """
    pool = lookup(configuration, (*PATH, 'pool', rule['pool']))
    public = intervals(pool['public-address'])
    block = int(pool['block-size'])
    first_port, _ = ports(pool)
    per_address = slots(pool)
    offset = int(rule['allocation-offset'])
    for first, last in subscribers(configuration, rule):
        while first <= last:
            address_index, slot = divmod(offset, per_address)
            length = min(last - first + 1, per_address - slot)
            low = first_port + slot * block
            yield address_at(public, address_index), low, low + length * block - 1, first, block
            first += length
            offset += length


def elements(configuration, rule):
    for public, low, high, source, block in segments(configuration, rule):
        for port in range(low, high + 1, block):
            yield f'{ipaddress.IPv4Address(source)} : {ipaddress.IPv4Address(public)} . {port}-{port + block - 1}'
            source += 1


def overlaps(first, second):
    """Whether two allocation slices assign an intersecting port to different owners."""
    _, low, high, source, block = first
    _, other_low, other_high, other_source, other_block = second
    start = max(low, other_low)
    if start > min(high, other_high):
        return False
    return (block != other_block or (low - other_low) % block != 0
            or source + (start - low) // block != other_source + (start - other_low) // block)
