#!/usr/bin/env python3
"""Inspect and control the DHCPv6 clients managed by netlinkd."""

import json
import time

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers.interfaces import manager


@opmode.command
def show(interface: str | None = None, detail: bool = False, raw: bool = False):
    records = manager.request('dhcp6-status')
    if interface:
        if interface not in records:
            raise OperationalError(f'{interface}: DHCPv6 is not configured')
        records = {interface: records[interface]}
    if raw:
        return json.dumps(records)
    if not records:
        return 'No DHCPv6 clients configured.\n'

    now = time.monotonic()
    rows, notes = [], []
    for name, lease in sorted(records.items()):
        state = 'Seeking'
        if lease['disabled']:
            state = 'Disabled'
        elif lease['released']:
            state = 'Released'
        entries = [*lease.get('entries', ()), *lease.get('lans', ())]
        for item in entries:
            rows.append([name, lease['vrf'], item.get('interface', item['type']), item['id'],
                         item.get('address', item['prefix']), max(0, int(item['preferred'] - now)),
                         max(0, int(item['valid'] - now))])
        if lease['address'] and not any(e['type'] == 'IA_NA' for e in entries):
            rows.append([name, lease['vrf'], 'IA_NA', '0', state, '-', '-'])
        for iaid in lease['requests']:
            if not any(e['type'] == 'IA_PD' and e['id'] == iaid for e in entries):
                rows.append([name, lease['vrf'], 'IA_PD', iaid, state, '-', '-'])
        if not entries and not lease['requests'] and not lease['address']:
            rows.append([name, lease['vrf'], '-', '-', 'Bound' if 'received' in lease else state, '-', '-'])
        notes.extend(lease.get('errors', ()))
        if detail:
            notes.append(f"{name} DUID {lease.get('duid', '-')}, server {lease.get('server') or '-'}")
    return '\n'.join([tabulate(rows, headers=['WAN', 'VRF', 'IA / LAN', 'IAID', 'Address / prefix',
                                              'Preferred (s)', 'Valid (s)'], disable_numparse=True), *notes]) + '\n'


@opmode.command
def release(interface: str):
    manager.request('dhcp6-release', interface=interface)
    print(f'DHCPv6 release requested on {interface}.')


@opmode.command
def renew(interface: str):
    manager.request('dhcp6-renew', interface=interface)
    print(f'DHCPv6 renewal requested on {interface}.')


if __name__ == '__main__':
    opmode.run()
