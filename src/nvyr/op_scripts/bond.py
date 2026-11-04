#!/usr/bin/env python3
"""Bond carrier, member selection, LACP negotiation and manual failover."""

from pathlib import Path

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers.bond_config import PRIMARY_MODES
from nvyr.helpers.netlink import interface_name
from nvyr.helpers.process import cmd


def report(name):
    path = Path('/proc/net/bonding') / interface_name(name)
    if not path.is_file():
        raise OperationalError(f'Bond {name} does not exist')
    summary, members = {}, []
    section = summary
    for line in path.read_text().splitlines():
        key, sep, value = line.strip().partition(':')
        if not sep:
            continue
        if key == 'Slave Interface':
            section = {}
            members.append(section)
        elif key.startswith('details ') and key.endswith(' lacp pdu'):
            section = members[-1].setdefault(key.split()[1], {})
            continue
        section[key] = value.strip()
    return summary, members


LACP_FORWARDING = ((8, 'S'), (16, 'C'), (32, 'D'))


def lacp_flags(pdu):
    if 'port state' not in pdu:
        return 'Unknown'
    state = int(pdu['port state'])
    return ''.join(letter if state & bit else '-' for bit, letter in LACP_FORWARDING)


def lacp_detail(port):
    sides = (port.get('actor', {}), port.get('partner', {}))
    rows = [
        ('System MAC', *(pdu.get('system mac address') for pdu in sides)),
        ('System priority', *(pdu.get('system priority') for pdu in sides)),
        ('Key', *(pdu.get('port key', pdu.get('oper key')) for pdu in sides)),
        ('Port number', *(pdu.get('port number') for pdu in sides)),
        ('Port priority', *(pdu.get('port priority') for pdu in sides)),
    ]
    states = [int(pdu['port state']) if 'port state' in pdu else None for pdu in sides]
    for bit, label, on, off in (
        (1, 'Activity', 'Active', 'Passive'),
        (2, 'Timeout', 'Short', 'Long'),
        (4, 'Aggregatable', 'Yes', 'No'),
        (8, 'Synchronized', 'Yes', 'No'),
        (16, 'Collecting', 'Yes', 'No'),
        (32, 'Distributing', 'Yes', 'No'),
        (64, 'Defaulted', 'Yes', 'No'),
        (128, 'Expired', 'Yes', 'No'),
    ):
        row = [label]
        for state in states:
            if state is None:
                row.append('Unknown')
            else:
                row.append(on if state & bit else off)
        rows.append(row)

    heading = f"{port['Slave Interface']} (aggregator {port.get('Aggregator ID', 'Unknown')})"
    return heading + '\n' + tabulate(rows, headers=['Field', 'Actor', 'Partner'], missingval='Unknown')


@opmode.command
def show(bond: str = None, section: str = None, member: str = None, detail: bool = False):
    if not bond:
        rows = []
        for path in sorted(Path('/proc/net/bonding').glob('*')):
            data, ports = report(path.name)
            rows.append([path.name, data.get('Bonding Mode'), data.get('MII Status'), len(ports)])
        return tabulate(rows, headers=['Bond', 'Mode', 'Carrier', 'Members']) if rows else 'No bond interfaces.'
    summary, ports = report(bond)
    if member:
        ports = [port for port in ports if port['Slave Interface'] == member]
        if not ports:
            raise OperationalError(f'{member} is not a member of {bond}')
    if section == 'lacp':
        if '802.3ad' not in summary.get('Bonding Mode', ''):
            raise OperationalError(f'{bond} is not in 802.3ad mode')
        if not ports:
            return f'{bond} has no members.'
        if detail:
            return '\n\n'.join(lacp_detail(port) for port in ports)

        rows = []
        for port in ports:
            partner = port.get('partner', {})
            rows.append([port['Slave Interface'], port.get('Aggregator ID'), partner.get('system mac address'),
                         lacp_flags(port.get('actor', {})), lacp_flags(partner)])

        table = tabulate(rows, headers=['Member', 'Aggregator', 'Partner system', 'Actor', 'Partner'], missingval='Unknown')
        return table + '\n\nS = synchronized, C = collecting, D = distributing, - = flag not set'

    active = summary.get('Currently Active Slave')
    rows = [[port['Slave Interface'], port.get('MII Status'), port.get('Speed'), port.get('Duplex'),
             ('active' if port['Slave Interface'] == active else 'backup') if active else '-',
             port.get('Link Failure Count')] for port in ports]
    monitor = summary.get('MII Polling Interval (ms)', '0')
    info = [('Bond', bond), ('Mode', summary.get('Bonding Mode')), ('Carrier', summary.get('MII Status')),
            ('MII interval (ms)', monitor), ('Probe interval (ms)', summary.get('ARP Polling Interval (ms)', '0'))]
    return tabulate(info, tablefmt='presto') + '\n\n' + tabulate(
        rows, headers=['Member', 'Link', 'Speed', 'Duplex', 'Role', 'Link failures'])


@opmode.command
def select(bond: str, member: str):
    directory = Path('/sys/class/net') / interface_name(bond) / 'bonding'
    if not directory.is_dir():
        raise OperationalError(f'Bond {bond} does not exist')
    mode = (directory / 'mode').read_text().split()[0]
    if mode not in PRIMARY_MODES:
        raise OperationalError(f'{bond}: manual failover is unavailable in {mode} mode')
    if interface_name(member) not in (directory / 'slaves').read_text().split():
        raise OperationalError(f'{member} is not a member of {bond}')
    cmd(['ip', 'link', 'set', 'dev', bond, 'type', 'bond', 'active_slave', member])


if __name__ == '__main__':
    opmode.run()
