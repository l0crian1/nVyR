#!/usr/bin/env python3
"""Display native VXLAN settings, tunnel destinations and bridge mappings."""

import json

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers import vxlan
from nvyr.helpers.bridge_netlink import query
from nvyr.helpers.netlink import interface_name


def details(device):
    data = device['linkinfo']['info_data']
    ports = data['port_range']
    ttl = data.get('ttl', 'inherit')
    tos = int(str(data.get('tos', 0)), 0)
    rows = [('Interface', device['ifname']), ('Mode', 'external' if data['external'] else 'fixed'),
            ('VNI', '—' if data['external'] else data['id']), ('MTU', device['mtu']),
            ('Underlay interface', data.get('link', '—')),
            ('Local address', data.get('local') or data.get('local6', '—')),
            ('Remote address', data.get('remote') or data.get('remote6', '—')),
            ('Multicast group', data.get('group') or data.get('group6', '—')),
            ('Destination port', data['port']),
            ('Source ports', f"{ports['low']}–{ports['high']}" if ports['high'] else 'auto'),
            ('TTL', ttl or 'auto'), ('TOS', 'inherit' if tos == 1 else tos), ('DF', data['df']),
            ('Flow label', int(str(data.get('label', 0)), 0)), ('Ageing time (s)', data['ageing']),
            ('Maximum learned entries', data.get('limit') or 'unlimited')]
    for key, label in (('learning', 'Learning'), ('vnifilter', 'VNI filter'), ('proxy', 'ARP proxy'),
                       ('rsc', 'Route short circuit'), ('l2miss', 'L2 miss notifications'),
                       ('l3miss', 'L3 miss notifications'), ('udp_csum', 'IPv4 UDP checksum'),
                       ('udp_zero_csum6_tx', 'IPv6 zero-checksum transmit'),
                       ('udp_zero_csum6_rx', 'IPv6 zero-checksum receive')):
        rows.append((label, 'on' if data.get(key) else 'off'))
    return rows


@opmode.command
def show(interface: str = None, section: str = None, raw: bool = False):
    devices = [row for row in query('ip', '-j', '-d', 'link', 'show', 'type', 'vxlan')
               if row.get('linkinfo', {}).get('info_kind') == 'vxlan']
    if interface:
        interface_name(interface)
        devices = [dev for dev in devices if dev['ifname'] == interface]
        if not devices:
            raise OperationalError(f'VXLAN interface {interface} does not exist')
    if section and not interface:
        raise OperationalError(f'Select an interface for {section}')

    rows = []
    records = devices
    headers = ('Interface', 'Mode', 'VNI', 'Local', 'Remote/group', 'UDP port', 'MTU')
    for device in devices:
        data = device['linkinfo']['info_data']
        if section == 'fdb':
            records = query('bridge', '-j', 'fdb', 'show', 'dev', interface)
            headers = ('MAC', 'Remote VTEP', 'VNI', 'State', 'Flags')
            rows = [(r['mac'], r.get('dst', '—'), r.get('src_vni', r.get('vni', data['id'])),
                     r.get('state', '—'), ', '.join(r.get('flags', []))) for r in records]
        elif section == 'vni':
            mappings = vxlan.mappings(interface) if device.get('master') else {}
            allowed = vxlan.admitted_vnis(interface) if data.get('vnifilter') else set()
            records = [{'vlan': vid, 'vni': vni, 'admitted': vni in allowed} for vid, vni in sorted(mappings.items())]
            records.extend({'vni': vni, 'admitted': True} for vni in sorted(allowed - set(mappings.values())))
            if not data['external']:
                records.append({'vni': data['id']})
            headers = ('VLAN', 'VNI', 'VNI filter')
            rows = [(r.get('vlan', '—'), r['vni'], ('yes' if r.get('admitted') else 'no')
                     if data.get('vnifilter') else 'off') for r in records]
        elif interface:
            headers = ('Setting', 'Value')
            rows = details(device)
        else:
            rows.append((device['ifname'], 'external' if data['external'] else 'fixed',
                         '—' if data['external'] else data['id'], data.get('local') or data.get('local6', '—'),
                         data.get('remote') or data.get('remote6') or data.get('group') or data.get('group6', '—'),
                         data['port'], device['mtu']))
    if raw:
        return json.dumps(records)
    print(tabulate(rows, headers=headers) if rows else 'No entries.')


if __name__ == '__main__':
    opmode.run()
