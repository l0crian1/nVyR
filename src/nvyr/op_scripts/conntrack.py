#!/usr/bin/env python3
"""Inspect tracked connections and NAT translations, or explicitly clear them."""

import json

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers import conntrack as tracking
from nvyr.helpers.output import detailed_output
from nvyr.helpers.process import cmd


MISSING = '—'


def _options(line):
    """Consume schema-parsed anchored filters without defining another command tree."""
    options = {}

    def select(name):
        def record(value):
            if name in options:
                raise OperationalError(f'{name.replace("_", "-")} can only be specified once.')
            options[name] = value
            return []
        return record

    def family(name):
        def record(value):
            if 'family' in options:
                raise OperationalError('Choose only one of ipv4 and ipv6.')
            options['family'] = name
            return []
        return record

    mapping = {name.replace('_', '-'): select(name) for name in
               ('protocol', 'state', 'source_address', 'destination_address', 'detail', 'statistics')}
    mapping.update({'ipv4': family('ipv4'), 'ipv6': family('ipv6')})
    path, _ = opmode.command_arguments(line, mapping)
    return path, options


def _endpoint(record, direction):
    address = record.get(direction + '-address', MISSING)
    port = record.get(direction + '-port')
    if port is None:
        return address
    if ':' in address:
        return f'[{address}]:{port}'
    return f'{address}:{port}'


def _translated(record):
    """Reverse the reply tuple only on sides actually translated by NAT."""
    translated = dict(record['original'])
    for kind, destination, source in (('snat', 'source', 'destination'), ('dnat', 'destination', 'source')):
        if kind not in record['nat']:
            continue
        for suffix in ('address', 'port'):
            field = source + '-' + suffix
            if field in record['reply']:
                translated[destination + '-' + suffix] = record['reply'][field]
    return translated


def _detail(record):
    """Keep both directions and optional kernel metadata visible in detailed output."""
    labels = ['Family', 'Protocol', 'State', 'Timeout (s)', 'NAT', 'Status', 'Status mask', 'Mark', 'Zone', 'ID']
    values = [record['family'].replace('ip', 'IP'), record['protocol'], record.get('state', MISSING),
              record['timeout'], ', '.join(record['nat']) or MISSING, ', '.join(record['status']) or MISSING,
              hex(record['status-mask']), record['mark'], record['zone'], record['id']]
    if 'helper' in record:
        labels.append('Helper')
        values.append(record['helper'])

    for direction in ('original', 'reply'):
        for field, value in record[direction].items():
            labels.append(direction.capitalize() + ' ' + field.replace('-', ' '))
            values.append(value if value is not None else MISSING)
    if 'labels' in record:
        labels.append('Labels (bit positions)')
        values.append(', '.join(str(bit) for bit in record['labels']) or MISSING)
    detailed_output([values], labels)


@opmode.command
def show(line: str, raw: bool = False):
    """Show connections or translations with the same original-tuple filters."""
    path, options = _options(line)
    if options.pop('statistics', False):
        # Table-wide statistics cannot be narrowed to an individual connection filter.
        if options:
            raise OperationalError('Statistics cannot be combined with connection filters or detail.')
        return statistics(raw=raw)
    detail = options.pop('detail', False)
    translations = tuple(path[:2]) == ('show', 'nat')
    records = tracking.read(**options)
    if translations:
        required = {'source': 'snat', 'destination': 'dnat'}.get(path[2])
        records = [record for record in records if record['nat'] and (required is None or required in record['nat'])]
    if raw:
        return json.dumps(records)
    if not records:
        print('No matching NAT translations.' if translations else 'No matching connections.')
        return
    if detail:
        for record in records:
            _detail(record)
        return

    headers = ['Family', 'Protocol', 'Source', 'Destination']
    if translations:
        headers.extend(['Translated source', 'Translated destination', 'NAT'])
    headers.extend(['State', 'Timeout (s)'])
    rows = []
    for record in records:
        row = [record['family'].replace('ip', 'IP'), record['protocol'],
               _endpoint(record['original'], 'source'), _endpoint(record['original'], 'destination')]
        if translations:
            translated = _translated(record)
            row.extend([_endpoint(translated, 'source'), _endpoint(translated, 'destination'),
                        '+'.join(record['nat']).upper()])
        row.extend([record.get('state', MISSING), record['timeout']])
        rows.append(row)
    print(tabulate(rows, headers=headers, disable_numparse=True))


@opmode.command
def statistics(raw: bool = False):
    """Show table occupancy and summed kernel diagnostics, not connection counts per CPU."""
    result = tracking.statistics()
    if raw:
        return json.dumps(result)
    utilization = result['utilization']
    labels = ['Current entries', 'Maximum entries', 'Utilization']
    values = [result['entries'], result['maximum'], f'{utilization:.2f}%' if utilization is not None else MISSING]
    for name, value in result['counters'].items():
        labels.append(name.replace('_', ' ').capitalize())
        values.append(value)
    detailed_output([values], labels)


@opmode.command
def clear():
    """Flush the connection table, leaving the firewall configuration intact."""
    answer = input('Clear all tracked connections and NAT state? [y/N] ')
    if answer.strip().lower() not in {'y', 'yes'}:
        return 'Command cancelled.\n'

    return cmd(['conntrack', '-F'])


if __name__ == '__main__':
    opmode.run()
