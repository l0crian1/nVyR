"""Read Kea's memfile journal without changing leases or requiring hook libraries."""

import csv
import io
import ipaddress
from pathlib import Path
import time

from nvyr.errors import OperationalError


def fingerprint(paths):
    result = []
    for path in paths:
        try:
            status = path.stat()
            result.append((status.st_ino, status.st_size, status.st_mtime_ns))
        except FileNotFoundError:
            result.append(None)
    return result


def read_journal(filename, family):
    """Newest records win; a completed cleanup replaces both older input files.

    Retry if append or LFC rotation overlaps the read. Never interpret a missing
    database, a partial append, or malformed CSV as an empty pool.
    """
    base = Path(filename)
    paths = [Path(str(base) + suffix) for suffix in ('.completed', '.2', '.1', '')]
    for attempt in range(3):
        before = fingerprint(paths)
        selected = [0, 3] if before[0] is not None else [1, 2, 3]
        contents = []
        try:
            for index in selected:
                if before[index] is not None:
                    contents.append(paths[index].read_text(encoding='utf-8'))
        except FileNotFoundError:
            continue
        if before != fingerprint(paths):
            continue
        if not contents:
            raise OperationalError(f'Kea lease database is unavailable: {base}')
        if any(content and not content.endswith('\n') for content in contents):
            continue

        records = {}
        try:
            for content in contents:
                reader = csv.DictReader(io.StringIO(content), strict=True)
                required = {'address', 'valid_lifetime', 'expire', 'subnet_id', 'state'}
                if not required <= set(reader.fieldnames or ()):
                    raise ValueError('missing lease columns')
                for row in reader:
                    if None in row or any(value is None for value in row.values()):
                        raise ValueError('incomplete lease row')
                    address = ipaddress.ip_address(row['address'])
                    if address.version != family:
                        raise ValueError('lease address family does not match database')
                    record = dict(row, address=str(address))
                    for key in ('valid_lifetime', 'expire', 'subnet_id', 'state'):
                        record[key] = int(row[key])
                    if family == 6:
                        record['lease_type'] = int(row['lease_type'])
                        record['iaid'] = int(row['iaid'])
                    key = (str(address), record.get('lease_type', 0))
                    records[key] = record
        except (ValueError, KeyError, csv.Error) as error:
            raise OperationalError(f'Invalid Kea lease database {base}: {error}') from error
        return list(records.values())
    raise OperationalError('Kea lease database changed while reading; retry the command.')


def current_leases(filename, family, now=None):
    """Released/reclaimed/expired records never resurrect an older active lease."""
    now = time.time() if now is None else now
    records = []
    for record in read_journal(filename, family):
        infinite = record['valid_lifetime'] == 0xffffffff
        if record['valid_lifetime'] == 0 or record['state'] not in (0, 1):
            continue
        if not infinite and record['expire'] <= now:
            continue
        record['expires_in'] = None if infinite else max(0, int(record['expire'] - now))
        record['infinite'] = infinite
        record['status'] = 'Declined' if record['state'] == 1 else 'Active'
        records.append(record)
    return sorted(records, key=lambda record: int(ipaddress.ip_address(record['address'])))


def pool_bounds(value):
    if '/' in value:
        network = ipaddress.ip_network(value.strip())
        return int(network.network_address), int(network.broadcast_address)
    first, separator, last = value.partition('-')
    first = int(ipaddress.ip_address(first.strip()))
    return first, int(ipaddress.ip_address(last.strip())) if separator else first
