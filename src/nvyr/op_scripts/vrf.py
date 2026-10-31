#!/usr/bin/env python3
"""Display kernel VRF devices and their directly attached members."""

import json

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers.process import cmd


@opmode.command
def show(name: str | None = None, raw: bool = False):
    """Show all VRFs, or retain the same columns for a single named VRF."""
    links = json.loads(cmd(['ip', '-j', '-d', 'link', 'show']))
    records = []

    for link in sorted(links, key=lambda item: item['ifname']):
        if link.get('linkinfo', {}).get('info_kind') != 'vrf':
            continue
        if name is not None and link['ifname'] != name:
            continue

        members = sorted(member['ifname'] for member in links
                         if member.get('master') == link['ifname'])
        # VRF devices normally report operstate UNKNOWN; UP is their admin state.
        state = 'up' if 'UP' in link.get('flags', []) else 'down'
        records.append({
            'name': link['ifname'],
            'state': state,
            'mac': link.get('address', 'n/a'),
            'interfaces': members,
        })

    if name is not None and not records:
        raise OperationalError(f'VRF {name} does not exist.')
    if raw:
        return json.dumps(records)
    if not records:
        return 'No VRFs configured.\n'

    rows = [[record['name'], record['state'], record['mac'],
             ', '.join(record['interfaces']) or 'n/a'] for record in records]
    return tabulate(rows, headers=['Name', 'State', 'MAC address', 'Interfaces']) + '\n'


if __name__ == '__main__':
    opmode.run()
