#!/usr/bin/env python3
"""Display ARP and IPv6 neighbor observations with their routing domains."""

import ipaddress
import json

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers.interfaces import interface_vrfs
from nvyr.helpers.process import cmd


def records(family, interface=None, vrf=None):
    """Read all neighbor states, including unresolved and permanently configured entries."""
    links = json.loads(cmd(['ip', '-j', '-d', 'link', 'show']))
    domains = interface_vrfs(links)
    vrfs = {link['ifname'] for link in links if link.get('linkinfo', {}).get('info_kind') == 'vrf'}

    if interface is not None and interface not in domains:
        raise OperationalError(f'Interface {interface} does not exist.')
    if vrf is not None and vrf != 'default' and vrf not in vrfs:
        raise OperationalError(f'VRF {vrf} does not exist.')

    arguments = ['ip', '-j', '-4' if family == 'ipv4' else '-6', 'neighbor', 'show', 'nud', 'all']
    if interface is not None:
        arguments.extend(['dev', interface])
    neighbors = json.loads(cmd(arguments))
    result = []

    for neighbor in neighbors:
        # iproute2 omits dev from each record when the query already selects one device.
        device = neighbor.get('dev', interface)
        if device not in domains:
            raise OperationalError('Interface topology changed while reading neighbors; retry.')

        domain = domains[device]
        if vrf is not None and domain != vrf:
            continue

        states = neighbor.get('state', [])
        if isinstance(states, str):
            states = states.split(',')
        state = ', '.join('No ARP' if value == 'NOARP' else value.capitalize() for value in states)
        result.append({'address': neighbor['dst'], 'mac': neighbor.get('lladdr'),
                       'interface': device, 'vrf': domain, 'state': state or '—'})

    return sorted(result, key=lambda item: (item['vrf'], item['interface'], int(ipaddress.ip_address(item['address']))))


@opmode.command
def show(line: str, raw: bool = False):
    """Keep scoped and unscoped views in the same table format."""
    options = {}

    def select(name):
        def record(value):
            if name in options:
                raise OperationalError(f'{name} can only be specified once.')
            options[name] = value
            return []

        return record

    path, _ = opmode.command_arguments(line, {'interface': select('interface'), 'vrf': select('vrf')})
    family = 'ipv4' if tuple(path) == ('show', 'arp') else 'ipv6'
    try:
        values = records(family, **options)
    except (ValueError, KeyError, TypeError) as error:
        raise OperationalError(f'Cannot interpret neighbor data: {error}') from None

    if raw:
        return json.dumps(values)
    if not values:
        return 'No matching ARP entries.\n' if family == 'ipv4' else 'No matching IPv6 neighbors.\n'

    rows = [[item['address'], item['mac'] or '—', item['interface'], item['vrf'], item['state']] for item in values]
    return tabulate(rows, headers=['Address', 'MAC address', 'Interface', 'VRF', 'State'], disable_numparse=True) + '\n'


if __name__ == '__main__':
    opmode.run()
