#!/usr/bin/env python3
"""Package inventory and processor, filesystem and process observations."""

import json
from importlib.resources import files
import os
from pathlib import Path
import time

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers import packages as package_inventory
from nvyr.helpers import cpu_settings
from nvyr.helpers.process import cmd


@opmode.command
def script_priority(raw: bool = False):
    """Read the packaged build-time inventory of explicit script owners."""
    try:
        records = json.loads(files('nvyr').joinpath('schemas/script-priorities.json').read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise OperationalError(f'Cannot read configuration script inventory: {error}') from error

    if raw:
        return json.dumps(records)
    if not records:
        return 'No configuration scripts registered.\n'

    rows = [[record['script'], record['priority'], '\n'.join(record['paths'])]
            for record in records]
    return tabulate(rows, headers=['Script', 'Priority', 'Paths'], disable_numparse=True) + '\n'


@opmode.command
def packages(name: str = '', raw: bool = False):
    """Display Debian package versions, optionally selecting one exact identifier."""
    records = package_inventory.inventory()
    if name:
        records = [record for record in records if record['package'] == name]
        if not records:
            raise OperationalError(f'Package {name!r} was not found.')

    if raw:
        return json.dumps(records)
    if not records:
        return 'No packages found.\n'

    rows = [[record['package'], record['version'], record['architecture'],
             record['description']] for record in records]
    return tabulate(rows, headers=['Package', 'Version', 'Architecture', 'Description'],
                    disable_numparse=True) + '\n'


@opmode.command
def cpu(raw: bool = False):
    """Show topology without lscpu's cache, vulnerability and instruction lists."""
    environment = dict(os.environ, LC_ALL='C')
    summary = json.loads(cmd(['lscpu', '--json', '--hierarchic=never'], env=environment))
    fields = {item['field'].rstrip(':'): item['data'] for item in summary['lscpu']}
    topology = json.loads(cmd(['lscpu', '--json', '--all', '--extended=CPU,CORE,SOCKET'],
                              env=environment))
    cores = set()
    sockets = set()
    for processor in topology['cpus']:
        socket = processor.get('socket')
        core = processor.get('core')
        if socket is not None:
            sockets.add(socket)
        if socket is not None and core is not None:
            cores.add((socket, core))

    data = {
        'Model': fields.get('Model name', 'Unknown'),
        'Architecture': fields.get('Architecture', 'Unknown'),
        'Sockets': len(sockets) if sockets else 'Unknown',
        'Cores': len(cores) if cores else 'Unknown',
        'Threads': fields.get('CPU(s)', 'Unknown'),
        'Online CPUs': fields.get('On-line CPU(s) list', 'Unknown'),
        'Virtualization': fields.get('Hypervisor vendor') or 'None detected',
    }
    policies = cpu_settings.inventory()
    for label, field in [('Frequency driver', 'driver'), ('Governor', 'governor'),
                         ('Energy preference', 'energy-performance')]:
        values = sorted({record[field].replace('_', '-') if field == 'energy-performance' else record[field]
                         for record in policies if record[field] is not None})
        data[label] = ', '.join(values) if values else 'Not exposed'
    if raw:
        return json.dumps(data)

    return tabulate(data.items(), tablefmt='presto') + '\n'


def _cpu_times():
    """Read CPU accounting without double-counting guest time inside user/nice."""
    readings = {}
    for line in Path('/proc/stat').read_text().splitlines():
        fields = line.split()
        if fields and (fields[0] == 'cpu' or fields[0].startswith('cpu') and fields[0][3:].isdigit()):
            readings[fields[0]] = [int(value) for value in fields[1:9]]

    return readings


def _usage_rows(before, after):
    """Calculate interval percentages; skip CPUs brought online during sampling."""
    rows = []
    for name in sorted(before.keys() & after.keys(), key=lambda name: -1 if name == 'cpu' else int(name[3:])):
        # I/O wait can decrease; clamp deltas rather than emit negative usage.
        delta = [max(0, end - start) for start, end in zip(before[name], after[name])]
        total = sum(delta)
        if not total:
            continue

        user = delta[0] + delta[1]
        system = delta[2] + delta[5] + delta[6]
        values = [user, system, delta[4], delta[7], delta[3]]
        rows.append(['Total' if name == 'cpu' else name[3:],
                     *[100 * value / total for value in values]])

    return rows


@opmode.command
def cpu_usage(raw: bool = False):
    """Sample aggregate and per-CPU utilization over one second."""
    before = _cpu_times()
    time.sleep(1)
    rows = _usage_rows(before, _cpu_times())
    headers = ['CPU', 'User %', 'System %', 'I/O wait %', 'Steal %', 'Idle %']
    if raw:
        return json.dumps([dict(zip(headers, row)) for row in rows])

    return tabulate(rows, headers=headers, floatfmt='.1f') + '\n'


def _size(value):
    """Format byte counts while keeping unsupported filesystem statistics unknown."""
    if value is None:
        return '—'
    amount = float(value)
    for unit in ('B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB'):
        if abs(amount) < 1024 or unit == 'PiB':
            return f'{amount:.1f} {unit}'
        amount /= 1024


@opmode.command
def storage(raw: bool = False):
    """Show space and inode exhaustion together, excluding pseudo filesystems."""
    columns = 'SOURCE,TARGET,FSTYPE,SIZE,USED,AVAIL,USE%,INO.TOTAL,INO.USED,INO.AVAIL,INO.USE%'
    # findmnt --df excludes overlayfs, including the live router's writable root.
    excluded = ('noproc,sysfs,devpts,cgroup,cgroup2,debugfs,tracefs,securityfs,configfs,'
                'fusectl,mqueue,bpf,binfmt_misc,pstore,efivarfs,nsfs,autofs,rpc_pipefs')
    # Use the host mount table instead of configd's extra sandbox bind mounts.
    output = cmd(['findmnt', '--task', '1', '--json', '--list', '--bytes', '--types', excluded, '--output', columns],
                 env=dict(os.environ, LC_ALL='C'))
    records = json.loads(output).get('filesystems', [])
    if raw:
        return json.dumps(records)

    rows = []
    for item in records:
        rows.append([item['source'], item['target'], item['fstype'],
                     _size(item.get('size')), _size(item.get('used')), _size(item.get('avail')),
                     item.get('use%'), item.get('ino.total'), item.get('ino.used'),
                     item.get('ino.avail'), item.get('ino.use%')])
    headers = ['Filesystem', 'Mount', 'Type', 'Size', 'Used', 'Available', 'Use %',
               'Inodes', 'Used inodes', 'Free inodes', 'Inode %']
    rows = [['—' if value is None else value for value in row] for row in rows]
    return tabulate(rows, headers=headers, disable_numparse=True) + '\n'


@opmode.command
def processes(sort: str = 'pid', raw: bool = False):
    """Use executable names only; ps CPU percentages are lifetime averages."""
    if sort not in ('pid', 'cpu', 'memory'):
        raise OperationalError('Process sorting must be pid, cpu or memory.')

    output = cmd(['ps', '-ww', '-eo', 'pid=,euser:32=,stat=,pcpu=,rss=,comm='],
                 env=dict(os.environ, LC_ALL='C'))
    records = []
    for line in output.splitlines():
        if not line.strip():
            continue
        pid, user, state, cpu_percent, rss, name = line.split(None, 5)
        records.append({'pid': int(pid), 'user': user, 'name': name, 'state': state,
                        'cpu_percent': float(cpu_percent), 'resident_bytes': int(rss) * 1024})

    if sort == 'cpu':
        records.sort(key=lambda item: (-item['cpu_percent'], item['pid']))
    elif sort == 'memory':
        records.sort(key=lambda item: (-item['resident_bytes'], item['pid']))
    else:
        records.sort(key=lambda item: item['pid'])
    if raw:
        return json.dumps(records)

    rows = [[item['pid'], item['user'], item['name'], item['state'],
             f"{item['cpu_percent']:.1f}", _size(item['resident_bytes'])] for item in records]
    return tabulate(rows, headers=['PID', 'User', 'Process', 'State', 'CPU % (lifetime)', 'Resident'],
                    disable_numparse=True) + '\n'


if __name__ == '__main__':
    opmode.run()
