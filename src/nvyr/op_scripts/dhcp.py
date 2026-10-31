#!/usr/bin/env python3
"""DHCPv4 client observations and control through the authoritative interface manager."""

import json
import time

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers import dhcp, kea
from nvyr.helpers.interfaces import manager
from nvyr.helpers.output import elapsed_time
from nvyr.helpers.process import cmd
from nvyr.op_scripts import services


def client_records(interface=None):
    """Join owned client intent, generation-fenced leases and installed kernel state."""
    status = manager.request('status')
    selected = []
    for owner, links in status['owners'].items():
        for name, spec in links.items():
            if spec['dhcp4'] and (interface is None or name == interface):
                selected.append((name, spec, owner in status['pending']))
    if not selected:
        if interface is not None:
            raise OperationalError(f'{interface}: DHCPv4 is not configured.')
        return []

    links = json.loads(cmd(['ip', '-j', '-d', 'address', 'show']))
    devices = {link['ifname']: link for link in links}
    topology = kea.inventory()
    routes = json.loads(cmd(['ip', '-j', '-4', 'route', 'show', 'table', 'all', 'proto', 'dhcp']))
    units = [f'nvyr-dhcp4@{name}.service' for name, _, _ in selected]
    properties = services.unit_properties(units)
    leases = dhcp.DHCP()
    now = time.monotonic()
    records = []
    for name, spec, pending in sorted(selected):
        device = devices.get(name)
        lease = leases.lease(name, device['ifindex']) if device and not spec['disabled'] and not pending else None
        process = properties[f'nvyr-dhcp4@{name}.service']
        state = 'Bound' if lease else 'Seeking'
        if spec['disabled']:
            state = 'Disabled'
        elif pending:
            state = 'Recovery required'
        elif device is None:
            state = 'Interface missing'
        elif process.get('ActiveState') != 'active':
            state = 'Failed' if process.get('ActiveState') == 'failed' else 'Stopped'

        options = spec.get('dhcp-options', {})
        received_routes = lease.get('routes', []) if lease else []
        default = next((route for route in received_routes if route['dst'] == '0.0.0.0/0'), None)
        gateway = default['gateway'] if default else None
        vrf = topology.get(name, {}).get('vrf', spec['attributes'].get('vrf') or 'default')
        table = devices.get(vrf, {}).get('linkinfo', {}).get('info_data', {}).get('table', 254)
        distance = options.get('default-route-distance', 210)
        metric = (distance << 24) | (default['metric'] & 0xffffff) if default else None
        installed = any(route.get('dev') == name and route.get('dst') == 'default'
                        and route.get('gateway') == gateway and route.get('metric') == metric
                        and route.get('table', 254) in (table, 'main' if table == 254 else str(table))
                        for route in routes) if default else False
        route_state = 'Installed' if installed else 'Not installed'
        if 'no-default-route' in options:
            route_state = 'Suppressed by no-default-route' + (' (still installed)' if installed else '')
        elif default is None:
            route_state = 'Not received'
        assigned = {f"{address['local']}/{address['prefixlen']}" for address in (device or {}).get('addr_info', [])}
        records.append({
            'interface': name, 'vrf': vrf,
            'state': state, 'address': lease['address'] if lease else None,
            'address_installed': bool(lease and lease['address'] in assigned),
            'server': lease.get('server') if lease else None, 'gateway': gateway,
            'default_route': route_state, 'distance': distance,
            'name_servers': lease.get('dns', []) if lease else [],
            'dns_selected': name in (status.get('dns') or {}).get('sources', []),
            'domain': lease.get('domain') if lease else None,
            'duration': lease.get('duration') if lease else None,
            'expires_in': max(0, int(lease['expires'] - now)) if lease else None,
        })
    return records


@opmode.command
def show(interface: str | None = None, detail: bool = False, raw: bool = False):
    try:
        records = client_records(interface)
    except (OSError, ValueError, KeyError) as error:
        raise OperationalError(f'Cannot read DHCP client state: {error}. Retry the command.') from error
    if raw:
        return json.dumps(records)
    if not records:
        return 'No DHCPv4 clients configured.\n'
    if detail:
        blocks = []
        for record in records:
            rows = [
                ('Interface', record['interface']), ('VRF', record['vrf']), ('State', record['state']),
                ('Address', record['address']), ('Address installed', 'Yes' if record['address_installed'] else 'No'),
                ('DHCP server', record['server']), ('Received gateway', record['gateway']),
                ('Default route', record['default_route']), ('Default route distance', record['distance']),
                ('Received name servers', ', '.join(record['name_servers']) or None),
                ('Selected for system DNS', 'Yes' if record['dns_selected'] else 'No'),
                ('Domain name', record['domain']), ('Lease duration', elapsed_time(record['duration'])),
                ('Renewal in', '—'), ('Rebinding in', '—'),
                ('Expires in', elapsed_time(record['expires_in'])),
            ]
            blocks.append(tabulate([(key, '—' if value is None else value) for key, value in rows],
                                   tablefmt='presto', disable_numparse=True))
        return '\n\n'.join(blocks) + '\n\nRenewal/rebinding countdowns are not exposed by udhcpc.\n'
    rows = [[record['interface'], record['vrf'], record['state'], record['address'] or '—',
             record['server'] or '—', record['gateway'] or '—', elapsed_time(record['expires_in'])]
            for record in records]
    return tabulate(rows, headers=['Interface', 'VRF', 'State', 'Address', 'DHCP server',
                                  'Received gateway', 'Expires in'], disable_numparse=True) + '\n'


@opmode.command
def release(interface: str):
    manager.request('dhcp-release', interface=interface)
    print(f'DHCPv4 release requested on {interface}.')


@opmode.command
def renew(interface: str):
    manager.request('dhcp-renew', interface=interface)
    print(f'DHCPv4 renewal requested on {interface}.')


if __name__ == '__main__':
    opmode.run()
