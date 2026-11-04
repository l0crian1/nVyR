#!/usr/bin/env python3
"""Inspect scheduler-owned services and timers without displaying shell command bodies."""

from datetime import datetime
import json
import os
import shutil
import sys

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers import access, build_metadata, task_schedule
from nvyr.helpers.process import cmd, run


def inventory():
    records = {}
    for path in sorted(task_schedule.UNITS.glob('nvyr-task-*-*-*.service')):
        owner, kind, name = path.stem.removeprefix('nvyr-task-').split('-', 2)
        records[(owner, name)] = (kind, path.stem)
    return records


def selected(name):
    owner, sep, short = name.partition(':')
    key = (owner, short) if sep else ('system', name)
    try:
        return inventory()[key]
    except KeyError:
        raise OperationalError(f'Task {name!r} is not configured') from None


def authorize(kind):
    required = 'sys-admin' if kind == 'exec' else 'net-admin'
    if not access.allows(required, current=os.environ.get('NVYR_CALLER_ROLE', 'read-only')):
        raise OperationalError(f'This task requires {required} access')


def clock_time(microseconds):
    if not microseconds or microseconds == (1 << 64) - 1:
        return '-'
    return datetime.fromtimestamp(microseconds / 1_000_000).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')


@opmode.command
def show(name: str = ''):
    records = inventory()
    if name:
        selected(name)
        records = {key: record for key, record in records.items()
                   if ':'.join(key) == name or (key[0] == 'system' and key[1] == name)}
    if not records:
        return 'No scheduled tasks configured.'

    timers = json.loads(cmd(['systemctl', 'list-timers', '--output=json', 'nvyr-task-*.timer']))
    times = {row['unit']: row for row in timers}
    services = [stem + '.service' for _, stem in records.values()]
    detail = cmd(['systemctl', 'show', '-p', 'Id,Result,ExecMainStartTimestamp,ActiveState', *services])
    properties_by_id = {}
    for section in detail.strip().split('\n\n'):
        values = dict(line.split('=', 1) for line in section.splitlines() if '=' in line)
        if 'Id' in values:
            properties_by_id[values['Id']] = values

    rows = []
    for (owner, short), (kind, stem) in records.items():
        timer = stem + '.timer'
        properties = properties_by_id.get(stem + '.service', {})
        last = properties.get('ExecMainStartTimestamp') or '-'
        result = 'Running' if properties.get('ActiveState') in ('activating', 'active') else (
            properties.get('Result', '-') if last != '-' else '-')
        state = 'Disabled' if not (task_schedule.UNITS / timer).exists() else ('Armed' if timer in times else 'Inactive')
        rows.append([short, owner, kind, state, clock_time(times.get(timer, {}).get('next')), last, result])
    return tabulate(rows, headers=['Task', 'Owner', 'Action', 'State', 'Next run', 'Last started', 'Result'])


@opmode.command
def start(name):
    kind, stem = selected(name)
    authorize(kind)
    if run(['systemctl', 'is-active', '--quiet', stem + '.timer']):
        raise OperationalError(f'Task {name!r} is disabled or its timer is inactive')
    cmd(['systemctl', 'start', '--no-block', stem + '.service'])
    return f'Start requested for {name}.'


@opmode.command
def logs(name):
    kind, stem = selected(name)
    authorize(kind)
    path = task_schedule.LOGS / (stem + '.log')
    try:
        with path.open(errors='replace') as source:
            if not os.fstat(source.fileno()).st_size:
                return 'No task output recorded.'
            shutil.copyfileobj(source, sys.stdout)
    except FileNotFoundError:
        return 'No task output recorded.'


@opmode.command
def identity(action):
    if action == 'version':
        return build_metadata.format_version(build_metadata.read())
    if action == 'license':
        return build_metadata.read_license()
    raise OperationalError('Unknown identity command')


if __name__ == '__main__':
    opmode.run()
