#!/usr/bin/env python3
"""Bridge inventory and learned-MAC cleanup using native Netlink tools."""

import json

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers.netlink import interface_name
from nvyr.helpers.process import cmd


def inventory(bridge=None):
    devices = json.loads(cmd(['ip', '-d', '-j', 'link', 'show', 'type', 'bridge']))
    devices = [device for device in devices if device.get('linkinfo', {}).get('info_kind') == 'bridge']
    if bridge:
        interface_name(bridge)
        devices = [device for device in devices if device['ifname'] == bridge]
        if not devices:
            raise OperationalError(f'Bridge {bridge} does not exist')
    return devices


def native(bridge, section, member=None):
    if section == 'member':
        arguments = ['bridge', '-d', '-j', 'link', 'show', 'master', bridge]
        if member:
            interface_name(member)
            arguments += ['dev', member]
    elif section == 'mac':
        arguments = ['bridge', '-j', 'fdb', 'show', 'br', bridge]
    elif section == 'multicast':
        arguments = ['bridge', '-j', 'mdb', 'show', 'dev', bridge]
    elif section == 'vlan':
        # Include the bridge's local port and every enslaved port.
        ports = native(bridge, 'member')
        names = {bridge, *(port['ifname'] for port in ports)}
        return [entry for entry in json.loads(cmd(['bridge', '-j', 'vlan', 'show']))
                if entry['ifname'] in names]
    else:
        raise OperationalError(f'Unknown bridge view {section}')
    records = json.loads(cmd(arguments))
    if section == 'member':
        # Hardware-switch records can be returned despite the native master filter.
        return [record for record in records if record.get('master') == bridge
                and (member is None or record['ifname'] == member)]
    return records


def table(data, columns):
    rows = [[entry.get(key, '—') for key, label in columns] for entry in data]
    return tabulate(rows, headers=[label for key, label in columns]) if rows else 'No entries.'


@opmode.command
def show(bridge: str = None, section: str = None, member: str = None, raw: bool = False):
    devices = inventory(bridge)
    if not section:
        if raw:
            return json.dumps(devices)
        rows = []
        for device in devices:
            options = device['linkinfo']['info_data']
            rows.append({'name': device['ifname'], 'state': 'up' if 'UP' in device['flags'] else 'down',
                         'mtu': device['mtu'], 'stp': 'on' if options['stp_state'] else 'off',
                         'vlan': 'on' if options['vlan_filtering'] else 'off',
                         'description': device.get('ifalias', '')})
        print(table(rows, [('name', 'Bridge'), ('state', 'State'), ('mtu', 'MTU'),
                           ('stp', 'STP'), ('vlan', 'VLAN filtering'), ('description', 'Description')]))
        return

    if section == 'spanning-tree':
        data = devices[0]['linkinfo']['info_data']
        if raw:
            return json.dumps(data)
        data = dict(data)
        for timer in ('hello_time', 'max_age', 'forward_delay'):
            data[timer] /= 100
        print(table([data], [('stp_state', 'Enabled'), ('bridge_id', 'Bridge ID'), ('root_id', 'Root ID'),
                            ('root_port', 'Root port'), ('root_path_cost', 'Root cost'),
                            ('hello_time', 'Hello (s)'), ('max_age', 'Max age (s)'),
                            ('forward_delay', 'Forward delay (s)')]))
        return

    data = native(bridge, section, member)
    if raw:
        return json.dumps(data)
    if section == 'member':
        print(table(data, [('ifname', 'Interface'), ('state', 'STP state'), ('cost', 'Cost'),
                          ('priority', 'Priority'), ('learning', 'Learning'), ('isolated', 'Isolated')]))
    elif section == 'mac':
        print(table(data, [('mac', 'MAC'), ('ifname', 'Interface'), ('vlan', 'VLAN'), ('state', 'State')]))
    elif section == 'vlan':
        rows = []
        for device in data:
            for entry in device.get('vlans', []):
                rows.append(dict(entry, ifname=device['ifname'], flags=', '.join(entry.get('flags', []))))
        print(table(rows, [('ifname', 'Interface'), ('vlan', 'VLAN'), ('flags', 'Flags')]))
    elif section == 'multicast':
        rows = [entry for device in data for entry in device.get('mdb', [])]
        print(table(rows, [('grp', 'Group'), ('src', 'Source'), ('port', 'Interface'),
                          ('vid', 'VLAN'), ('state', 'State')]))


@opmode.command
def clear(bridge: str, member: str = None, vlan: int = None):
    inventory(bridge)
    arguments = ['bridge', 'fdb', 'flush', 'dev', bridge, 'self', 'dynamic']
    if member:
        interface_name(member)
        ports = native(bridge, 'member')
        if member not in {port['ifname'] for port in ports}:
            raise OperationalError(f'{member} is not a member of {bridge}')
        arguments += ['brport', member]
    if vlan is not None:
        if not 1 <= vlan <= 4094:
            raise OperationalError('VLAN must be between 1 and 4094')
        arguments += ['vlan', str(vlan)]
    cmd(arguments)


if __name__ == '__main__':
    opmode.run()
