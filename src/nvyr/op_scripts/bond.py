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


def lacp_state(value):
    flags = ('active', 'short-timeout', 'aggregatable', 'synchronized',
             'collecting', 'distributing', 'defaulted', 'expired')
    return ', '.join(flag for bit, flag in enumerate(flags) if int(value or 0) & (1 << bit)) or '-'


@opmode.command
def show(bond: str = None, section: str = None, member: str = None):
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
        rows = []
        for port in ports:
            for side in ('actor', 'partner'):
                pdu = port.get(side, {})
                rows.append([port['Slave Interface'], side, port.get('Aggregator ID'), pdu.get('system mac address'),
                             pdu.get('system priority'), pdu.get('port key', pdu.get('oper key')),
                             pdu.get('port number'), pdu.get('port priority'), lacp_state(pdu.get('port state'))])
        return tabulate(rows, headers=['Member', 'Side', 'Aggregator', 'System MAC', 'System priority',
                                       'Key', 'Port', 'Port priority', 'State'])

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
