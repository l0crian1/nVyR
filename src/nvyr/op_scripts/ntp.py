#!/usr/bin/env python3
"""Chrony status through its local control socket, with structured API results."""

import csv
from datetime import datetime, timezone
import json
from pathlib import Path

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import RouterError
from nvyr.helpers.ntp import SOCKET
from nvyr.helpers.process import cmd


SERVER_STAT_FIELDS = (
    'NTP requests received', 'NTP requests rate-limited',
    'Command requests received', 'Command requests rate-limited',
    'Client records dropped', 'NTS-KE connections accepted', 'NTS-KE connections rate-limited',
    'Authenticated NTP requests', 'Interleaved NTP requests',
    'NTP timestamps held', 'NTP timestamp span (s)',
    'NTP daemon RX timestamps', 'NTP daemon TX timestamps',
    'NTP kernel RX timestamps', 'NTP kernel TX timestamps',
    'NTP hardware RX timestamps', 'NTP hardware TX timestamps',
)
SERVER_SUMMARY_FIELDS = (
    'NTP requests received', 'NTP requests rate-limited',
    'Authenticated NTP requests', 'Interleaved NTP requests', 'Client records dropped',
)


def report(command, *, no_resolve=False):
    """Request CSV without reverse DNS or a fallback to an unrelated daemon."""
    if not Path(SOCKET).exists():
        raise RouterError('NTP is not running. Configure system ntp first.')

    names = '-n' if no_resolve else '-N'
    output = cmd(['chronyc', '-h', SOCKET, '-c', names, *command], timeout=5)
    return list(csv.reader(output.splitlines()))


@opmode.command
def tracking(raw: bool = False):
    """Display synchronization state; unsynchronized is valid daemon state."""
    rows = report(['tracking'])
    if len(rows) != 1 or len(rows[0]) != 14:
        raise RouterError('Unexpected Chrony tracking response')

    fields = rows[0]
    timestamp = float(fields[3])
    data = {
        'Status': fields[13],
        'Source': fields[1] or fields[0],
        'Stratum': int(fields[2]),
        'Reference time (UTC)': datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp else 'Never',
        'System offset (s)': float(fields[4]),
        'Last offset (s)': float(fields[5]),
        'RMS offset (s)': float(fields[6]),
        'Frequency (ppm)': float(fields[7]),
        'Root delay (s)': float(fields[10]),
        'Root dispersion (s)': float(fields[11]),
    }
    if raw:
        return json.dumps(data)

    return tabulate(data.items(), tablefmt='presto', disable_numparse=True) + '\n'


@opmode.command
def sources(raw: bool = False, no_resolve: bool = False):
    """Show every source, including pool members and unresolved hostnames."""
    states = {'*': 'Selected', '+': 'Combined', '-': 'Excluded', '?': 'Unavailable',
              'x': 'Falseticker', '~': 'Variable'}
    modes = {'^': 'Server', '=': 'Peer', '#': 'Reference clock'}
    data = []
    for fields in report(['sources', '-a'], no_resolve=no_resolve):
        if len(fields) != 10:
            raise RouterError('Unexpected Chrony sources response')

        data.append({
            'Source': fields[2],
            'Mode': modes.get(fields[0], fields[0]),
            'State': states.get(fields[1], fields[1]),
            'Stratum': int(fields[3]),
            'Poll (s)': 2 ** int(fields[4]),
            'Reach': fields[5],
            'Last received (s)': None if fields[6] == '4294967295' else int(fields[6]),
            'Offset (s)': float(fields[7]),
            'Error (s)': float(fields[9]),
        })

    if raw:
        return json.dumps(data)
    if not data:
        return 'No NTP sources configured.\n'

    return tabulate(data, headers='keys', missingval='Never', disable_numparse=True) + '\n'


def _counter(value):
    """Reject malformed counters rather than presenting invented zero values."""
    number = int(value)
    if number < 0:
        raise ValueError('Negative Chrony counter')
    return number


def _client_interval(value):
    """Chrony's CSV uses a base-two exponent, with 127 meaning unknown."""
    exponent = int(value)
    if exponent == 127:
        return None
    if not -128 <= exponent < 127:
        raise ValueError('Invalid Chrony client interval')
    return 2 ** exponent


@opmode.command
def clients(raw: bool = False):
    """Show recorded NTP clients numerically, excluding command-only visitors."""
    data = []
    for fields in report(['clients'], no_resolve=True):
        if len(fields) != 10:
            raise RouterError('Unexpected Chrony clients response')

        try:
            requests = _counter(fields[1])
            dropped = _counter(fields[2])
            interval = _client_interval(fields[3])
            last_seen = _counter(fields[5])
        except ValueError as error:
            raise RouterError('Unexpected Chrony clients response') from error

        if requests == 0:
            continue

        data.append({
            'Client': fields[0],
            'Requests': requests,
            'Rate-limited': dropped,
            'Interval (s)': interval,
            'Last seen (s)': None if last_seen == 4294967295 else last_seen,
        })

    if raw:
        return json.dumps(data)
    if not data:
        return 'No NTP clients recorded.\n'

    return tabulate(data, headers='keys', missingval='—', disable_numparse=True) + '\n'


@opmode.command
def server_statistics(raw: bool = False, detail: bool = False):
    """Read counters without resetting them; raw results include all fields."""
    rows = report(['serverstats'], no_resolve=True)
    if len(rows) != 1 or len(rows[0]) != len(SERVER_STAT_FIELDS):
        raise RouterError('Unexpected Chrony server statistics response')

    try:
        data = dict(zip(SERVER_STAT_FIELDS, (_counter(value) for value in rows[0])))
    except ValueError as error:
        raise RouterError('Unexpected Chrony server statistics response') from error

    if raw:
        return json.dumps(data)

    fields = SERVER_STAT_FIELDS if detail else SERVER_SUMMARY_FIELDS
    output = [(field, data[field]) for field in fields]
    return tabulate(output, tablefmt='presto', disable_numparse=True) + '\n'


if __name__ == '__main__':
    opmode.run()
