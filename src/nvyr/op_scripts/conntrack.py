#!/usr/bin/env python3
"""Inspect tracked connections and NAT translations, or explicitly clear them."""

import ipaddress
import json

from tabulate import tabulate

from nvyr import opmode
from nvyr.helpers.strip_private import mask_fields, strip_ip
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
               ('protocol', 'state', 'source_address', 'destination_address', 'offload', 'accounting',
                'sort_by', 'reverse', 'detail', 'statistics')}
    mapping.update({'ipv4': family('ipv4'), 'ipv6': family('ipv6')})
    path, _ = opmode.command_arguments(line, mapping)
    return path, options


def _endpoint(record, direction):
    address = record.get(direction + '-address', MISSING)
    port = record.get(direction + '-port')
    if port is None:
        return address
    if ':' in address or address == '<ipv6>':
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


def _total(record, field):
    """Do not present an incomplete directional count as a combined total."""
    original = record['original'].get(field)
    reply = record['reply'].get(field)
    if original is None or reply is None:
        return None
    return original + reply


def _ordered(records, value, descending):
    """Sort available values while keeping missing values last in either order."""
    present = []
    missing = []
    for record in records:
        key = value(record)
        if key is None:
            missing.append(record)
        else:
            present.append((key, record))
    present.sort(key=lambda item: item[0], reverse=descending)
    return [record for _, record in present] + missing


def _sort(records, field, reverse):
    descending = (field in ('packets', 'bytes', 'timeout')) != reverse
    if field in ('source', 'destination'):
        def address(record):
            text = record['original'].get(field + '-address')
            if text is None:
                return None
            parsed = ipaddress.ip_address(text)
            return parsed.version, int(parsed)

        # Stable passes keep numeric ports ordered within each numeric address.
        records = _ordered(records, lambda record: record['original'].get(field + '-port'), descending)
        return _ordered(records, address, descending)
    if field in ('packets', 'bytes'):
        return _ordered(records, lambda record: _total(record, field), descending)
    return _ordered(records, lambda record: record.get(field), descending)


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
def show(line: str, raw: bool = False, strip_private: str = None):
    """Show connections or translations with the same original-tuple filters."""
    path, options = _options(line)
    if options.pop('statistics', False):
        # Table-wide statistics cannot be narrowed to an individual connection filter.
        if options:
            raise OperationalError('Statistics cannot be combined with connection filters or detail.')
        return statistics(raw=raw)
    detail = options.pop('detail', False)
    sort_by = options.pop('sort_by', None)
    reverse = options.pop('reverse', False)
    if reverse and sort_by is None:
        raise OperationalError('reverse requires sort-by.')
    accounting_columns = options.get('accounting', False) or sort_by in ('packets', 'bytes')
    translations = tuple(path[:2]) == ('show', 'nat')
    records = tracking.read(**options)
    if translations:
        required = {'source': 'snat', 'destination': 'dnat'}.get(path[2])
        records = [record for record in records if record['nat'] and (required is None or required in record['nat'])]
    if sort_by:
        records = _sort(records, sort_by, reverse)
    records = mask_fields(records, strip_private, {'source-address': strip_ip, 'destination-address': strip_ip})
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
    headers.extend(['Packets', 'Bytes'] if accounting_columns else ['State', 'Timeout (s)'])
    rows = []
    for record in records:
        row = [record['family'].replace('ip', 'IP'), record['protocol'],
               _endpoint(record['original'], 'source'), _endpoint(record['original'], 'destination')]
        if translations:
            translated = _translated(record)
            row.extend([_endpoint(translated, 'source'), _endpoint(translated, 'destination'),
                        '+'.join(record['nat']).upper()])
        if accounting_columns:
            for field in ('packets', 'bytes'):
                total = _total(record, field)
                row.append(total if total is not None else MISSING)
        else:
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
