#!/usr/bin/env python3
"""Inspect managed service processes and service-specific readiness without mutations."""

from contextlib import closing
import json
import os
import time

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError, RouterError
from nvyr.helpers import kea
from nvyr.helpers.container_config import enabled, pod_unit_name, unit_name
from nvyr.helpers.ntp import UNIT as NTP_UNIT
from nvyr.helpers.output import elapsed_time
from nvyr.helpers.process import cli_cmd
from nvyr.op_scripts import ntp
from nvyr.protocol import Client


CORE = {'configd': 'nvyr-configd.service', 'netlinkd': 'nvyr-netlinkd.service', 'frr': 'frr.service'}
SERVICES = (*CORE, 'ssh', 'ntp', 'dhcp-server', 'dhcpv6-server', 'container')
PROPERTIES = (
    'Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'Result',
    'ExecMainCode', 'ExecMainStatus', 'ExecMainStartTimestamp',
    'ExecMainStartTimestampMonotonic', 'NRestarts',
)


def running_configuration():
    with closing(Client('/run/nvyr/configd.sock')) as client:
        response = client.request('execute', text='show running-configuration')
    return json.loads(response['text'])


def instance(service, unit, *, vrfs=(), name=None, disabled=False):
    return {'service': service, 'unit': unit, 'vrfs': list(vrfs), 'instance': name, 'disabled': disabled}


def inventory(configuration):
    """Include configured-but-stopped instances, not only units systemd has loaded."""
    result = [instance(service, unit) for service, unit in CORE.items()]
    if 'ssh' in configuration.get('service', {}):
        result.append(instance('ssh', 'nvyr-ssh@default.service', vrfs=['default']))

    ntp_configuration = configuration.get('system', {}).get('ntp')
    if ntp_configuration is not None:
        result.append(instance('ntp', NTP_UNIT, vrfs=[ntp_configuration.get('vrf', 'default')]))

    scopes = {'default': configuration}
    scopes.update(configuration.get('vrf', {}).get('name', {}))
    for vrf, scope in sorted(scopes.items()):
        for family, service in ((4, 'dhcp-server'), (6, 'dhcpv6-server')):
            section = scope.get('service', {}).get(service)
            if section is not None:
                native = kea.instance_name(family, vrf)
                result.append(instance(service, f'nvyr-kea@{native}.service', vrfs=[vrf],
                                       disabled='disable' in section))

    containers = configuration.get('container', {})
    networks = containers.get('network', {})
    instances = [(name, section, unit_name(name), not enabled(section, containers))
                 for name, section in sorted(containers.get('name', {}).items())]
    instances.extend((name, section, pod_unit_name(name), 'disable' in section)
                     for name, section in sorted(containers.get('pod', {}).items()))
    for name, section, unit, disabled in instances:
        network_owner = containers.get('pod', {}).get(section.get('pod'), section)
        vrfs = set()
        for network in network_owner.get('network', {}):
            vrfs.add(networks.get(network, {}).get('vrf', 'default'))
        if 'allow-host-networking' in network_owner:
            vrfs.add('default')
        result.append(instance('container', unit + '.service', vrfs=sorted(vrfs),
                               name=name, disabled=disabled))

    return result


def unit_properties(units):
    """Read machine-readable properties in one call, keeping stderr out of the parser."""
    response = cli_cmd(['systemctl', 'show', '--no-pager', '--property=' + ','.join(PROPERTIES), *units],
                       env=dict(os.environ, LC_ALL='C'), timeout=10)
    if response.returncode:
        raise OperationalError(response.stderr.strip() or 'Cannot read system service state.')

    records = {}
    for block in response.stdout.strip().split('\n\n'):
        properties = {}
        for line in block.splitlines():
            key, separator, value = line.partition('=')
            if separator:
                properties[key] = value
        if 'Id' in properties:
            records[properties['Id']] = properties

    missing = set(units) - records.keys()
    if missing:
        raise OperationalError('Systemd returned no state for: ' + ', '.join(sorted(missing)))
    return records


def process_record(item, properties, now):
    """Process state is separate from protocol readiness and configuration intent."""
    active = properties.get('ActiveState', 'unknown')
    substate = properties.get('SubState', 'unknown')
    pid = int(properties.get('MainPID', '0'))
    running = active == 'active' and pid > 0
    state = {'active': 'Running' if running else 'Active', 'inactive': 'Stopped',
             'failed': 'Failed', 'activating': 'Starting', 'deactivating': 'Stopping',
             'reloading': 'Reloading'}.get(active, 'Unknown')
    detail = ''
    result = properties.get('Result', 'success')
    code = int(properties.get('ExecMainCode', '0'))
    status = int(properties.get('ExecMainStatus', '0'))

    if substate == 'auto-restart':
        state = 'Restarting'
    if result != 'success':
        detail = 'Service result: ' + result
    if code == 1 and status != 0:
        detail = f'Exited with status {status}'
    elif code in (2, 3):
        detail = f'Terminated by signal {status}'

    if properties.get('LoadState') == 'not-found':
        state, detail = 'Missing', 'Service unit is not installed'
    if item['disabled']:
        if active in ('active', 'activating', 'reloading'):
            detail = 'Configured disabled, but service is still active'
        elif active == 'inactive':
            state, detail = 'Disabled', ''
        elif properties.get('LoadState') == 'not-found':
            state, detail = 'Disabled', ''

    started = int(properties.get('ExecMainStartTimestampMonotonic', '0'))
    uptime = max(0, int(now - started / 1_000_000)) if running and started else None
    return item | {
        'state': state, 'process': 'Running' if running else state,
        'pid': pid or None, 'started': properties.get('ExecMainStartTimestamp') or None,
        'uptime_seconds': uptime, 'restarts': int(properties.get('NRestarts', '0')),
        'detail': detail, 'listeners': [], 'ready': None,
    }


def dhcp_readiness(record):
    """Use Kea's bound-socket status; a live process alone does not imply readiness."""
    family = 4 if record['service'] == 'dhcp-server' else 6
    native = kea.instance_name(family, record['vrfs'][0])
    configuration = json.loads((kea.RUNTIME / f'{native}.json').read_text())
    listeners = configuration[f'Dhcp{family}']['interfaces-config']['interfaces']
    record['listeners'] = listeners
    status = kea.control(kea.RUNTIME / f'{native}.sock', 'status-get', timeout=2)
    sockets = status.get('arguments', {}).get('sockets', {})
    state = sockets.get('status')
    record['ready'] = state == 'ready'
    if record['ready']:
        record['detail'] = 'Listening on ' + ', '.join(listeners)
        return

    waiting = kea.waiting_for_carrier(status, listeners)
    if waiting:
        record['state'] = 'Waiting for carrier'
        record['detail'] = ', '.join(waiting) + ' has no carrier'
    else:
        record['state'] = 'Not ready'
        errors = sockets.get('errors', [])
        record['detail'] = '; '.join(str(error) for error in errors) or f'Listener state: {state or "unknown"}'


def readiness(record):
    """Read-only probes never turn an unreachable service into a healthy result."""
    if record['process'] != 'Running' or record['disabled']:
        return

    try:
        if record['service'] in ('dhcp-server', 'dhcpv6-server'):
            dhcp_readiness(record)
        elif record['service'] == 'ntp':
            tracking = json.loads(ntp.tracking(raw=True))
            synchronized = tracking['Status'] == 'Normal'
            record['ready'] = synchronized
            record['detail'] = 'Synchronized' if synchronized else 'Not synchronized: ' + tracking['Status']
    except (OSError, RouterError, ValueError, KeyError) as error:
        record['state'] = 'Health unavailable'
        record['ready'] = None
        record['detail'] = str(error)


def detail_output(record):
    rows = [('Service', record['service'])]
    if record['instance'] is not None:
        rows.append(('Instance', record['instance']))
    rows.extend([
        ('VRF', ', '.join(record['vrfs']) or '—'), ('State', record['state']),
        ('Process', record['process']), ('PID', record['pid'] or '—'),
        ('Started', record['started'] or '—'), ('Uptime', elapsed_time(record['uptime_seconds'])),
        ('Restarts', record['restarts']),
    ])
    if record['listeners']:
        rows.append(('Listeners', ', '.join(record['listeners'])))
    if record['ready'] is not None:
        rows.append(('Ready', 'Yes' if record['ready'] else 'No'))
    if record['detail']:
        rows.append(('Reason', record['detail']))
    return tabulate(rows, tablefmt='presto', disable_numparse=True)


@opmode.command
def show(service: str | None = None, vrf: str | None = None, name: str | None = None,
         detail: bool = False, raw: bool = False):
    """Display core services and configured instances, optionally scoped to one service."""
    if service is not None and service not in SERVICES:
        raise OperationalError(f'Unknown managed service: {service}')
    if name is not None and service != 'container':
        raise OperationalError('A named instance is only available for container services.')

    items = []
    for item in inventory(running_configuration()):
        if service is not None and item['service'] != service:
            continue
        if vrf is not None and vrf not in item['vrfs']:
            continue
        if name is not None and item['instance'] != name:
            continue
        items.append(item)

    if not items:
        if vrf is not None or name is not None:
            raise OperationalError('No configured service instance matches that selection.')
        return '[]' if raw else 'No configured instances of this service.\n'

    properties = unit_properties([item['unit'] for item in items])
    records = []
    now = time.monotonic()
    for item in items:
        record = process_record(item, properties[item['unit']], now)
        readiness(record)
        records.append(record)

    if raw:
        return json.dumps(records)
    note = '\nRestarts: automatic restarts since systemd last reset the counter.\n'
    if detail or vrf is not None or name is not None:
        return '\n\n'.join(detail_output(record) for record in records) + '\n' + note

    rows = []
    for record in records:
        row = [', '.join(record['vrfs']) or '—', record['state'], elapsed_time(record['uptime_seconds'])]
        if service is None:
            row = [record['service'], record['instance'] or '—', *row]
        else:
            if service == 'container':
                row.insert(0, record['instance'])
            row.extend([record['restarts'], ', '.join(record['listeners']) or '—'])
        rows.append([*row, record['detail']])

    headers = ['VRF', 'State', 'Uptime']
    if service is None:
        headers = ['Service', 'Instance', *headers, 'Detail']
    else:
        if service == 'container':
            headers.insert(0, 'Instance')
        headers.extend(['Restarts', 'Listeners', 'Detail'])
    return tabulate(rows, headers=headers, disable_numparse=True) + '\n' + (note if service else '')


if __name__ == '__main__':
    opmode.run()
