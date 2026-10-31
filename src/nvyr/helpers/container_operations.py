"""Whitelisted Podman observations for daemon-executed operational commands."""

from datetime import datetime, timezone
import fcntl
import json
import shlex
import sys
import time
from types import SimpleNamespace

from tabulate import tabulate

from nvyr.errors import OperationalError
from nvyr.helpers.container_config import enabled, pod_unit_name, unit_name
from nvyr.config_scripts import container as container_script
from nvyr.helpers.container_config import RUNTIME
from nvyr.helpers.filesystem import protected_directory
from nvyr.helpers.output import elapsed_time
from nvyr.helpers.process import cli_cmd
from nvyr.op_scripts import services


def read_output(argv, *, timeout=15):
    """Keep native/systemd warnings visible without mixing them into JSON responses."""
    response = cli_cmd(argv, timeout=timeout)
    if response.returncode:
        raise OperationalError(response.stderr.strip() or response.stdout.strip()
                               or f'{argv[0]} failed (exit status {response.returncode}).')
    if response.stderr:
        print(response.stderr, file=sys.stderr, end='' if response.stderr.endswith('\n') else '\n')
    return response.stdout


def configured_state():
    """Use configd for intent and the native inventory only for pinned image IDs."""
    configuration = services.running_configuration().get('container', {})
    return {'configuration': configuration, 'images': container_script.read_state()['images']}


def observations():
    """Give inventory readers only native observation and saved-state access."""
    state = configured_state()
    return SimpleNamespace(execute=read_output, read=lambda: state,
                           pending=container_script.STATE.with_suffix('.pending.json'))


def display(view, **options):
    """Read native state directly without waiting behind pulls or apply operations."""
    protected_directory(RUNTIME)
    with (RUNTIME / 'lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise OperationalError('A container operation is in progress; retry the command.') from None

        return show(observations(), view, **options)


def native_containers(runtime, name=None):
    """Resolve IDs first so names cannot become command-line options."""
    listed = json.loads(runtime.execute(['podman', 'ps', '-a', '--format=json']))
    if name is not None:
        listed = [item for item in listed if name in item['Names']]

    result = []
    for offset in range(0, len(listed), 64):
        ids = [item['Id'] for item in listed[offset:offset + 64]]
        result.extend(json.loads(runtime.execute(['podman', 'container', 'inspect', '--', *ids])))

    return result


def connect_command(runtime, name, command=None):
    """Resolve only a configured, managed, running container to its immutable ID."""
    if name not in runtime.read()['configuration'].get('name', {}):
        raise OperationalError(f'Container {name} is not configured.')

    items = json.loads(runtime.execute(['podman', 'container', 'inspect', '--', name]))
    item = items[0]
    if (item.get('Config', {}).get('Labels') or {}).get('nvyr.managed') != 'true':
        raise OperationalError(f'Container {name} exists outside nVyR management.')
    if not item.get('State', {}).get('Running'):
        raise OperationalError(f'Container {name} is not running; use show containers name {name}.')

    if command is None:
        return ['podman', 'exec', '--interactive', '--tty', item['Id'], '/bin/sh']
    if not command.strip():
        raise OperationalError('Specify a nonempty container command.')
    return ['podman', 'exec', item['Id'], '/bin/sh', '-c', command]


def uptime(started, running):
    if not running or not started or started.startswith('0001-'):
        return None

    timestamp = datetime.fromisoformat(started.replace('Z', '+00:00'))
    return max(0, int((datetime.now(timezone.utc) - timestamp).total_seconds()))


def connections(item):
    result = []
    for name, network in (item.get('NetworkSettings', {}).get('Networks') or {}).items():
        # Podman also puts these namespace modes in Networks; they are not network attachments.
        if name in ('none', 'host'):
            continue

        addresses = []
        for field, prefix in (('IPAddress', 'IPPrefixLen'), ('GlobalIPv6Address', 'GlobalIPv6PrefixLen')):
            if network.get(field):
                addresses.append(f"{network[field]}/{network[prefix]}")
        result.append({'network': name, 'addresses': addresses, 'mac': network.get('MacAddress')})
    return result


def container_records(runtime, name=None):
    configuration = runtime.read()['configuration']
    configured = configuration.get('name', {})
    native = {item['Name']: item for item in native_containers(runtime, name) if not item.get('IsInfra')}
    names = configured.keys() | native.keys()

    if name is not None:
        if name not in names:
            raise OperationalError(f'Container {name} does not exist and is not configured.')
        names = {name}

    units = [unit_name(value) + '.service' for value in names if value in configured]
    properties = services.unit_properties(units) if units else {}
    records = []
    for value in sorted(names):
        item = native.get(value, {})
        section = configured.get(value, {})
        state = item.get('State', {})
        managed = value in configured
        service = None
        if managed:
            unit = unit_name(value) + '.service'
            service = services.process_record(services.instance('container', unit, name=value,
                                              disabled=not enabled(section, configuration)), properties[unit], time.monotonic())

        status = state.get('Status', 'not created').capitalize()
        reason = state.get('Error') or ''
        if service and service['state'] in ('Failed', 'Restarting', 'Starting', 'Disabled', 'Missing'):
            status = service['state']
        if service and service['detail']:
            reason = service['detail']
        if state.get('OOMKilled'):
            reason = 'Killed after exceeding the memory limit'
        exited = bool(state.get('FinishedAt') and not state['FinishedAt'].startswith('0001-'))
        if exited and not state.get('Running') and not reason:
            reason = f"Exited with status {state.get('ExitCode', 'unknown')}"
        if runtime.pending.exists() and managed:
            reason = 'Container operation requires recovery' + (': ' + reason if reason else '')

        started = state.get('StartedAt')
        if started and started.startswith('0001-'):
            started = None

        host = item.get('HostConfig', {})
        native_config = item.get('Config', {})
        mounts = [{'source': mount.get('Source'), 'destination': mount.get('Destination'),
                   'type': mount.get('Type'), 'read_only': not mount.get('RW', False)}
                  for mount in item.get('Mounts', [])]
        records.append({
            'name': value, 'managed': managed, 'id': item.get('Id'),
            'image': item.get('ImageName') or section.get('image'), 'image_id': item.get('Image'),
            'state': status, 'service_state': service['state'] if service else None,
            'reason': reason, 'created': item.get('Created'), 'started': started,
            'finished': state.get('FinishedAt') if exited else None,
            'uptime': uptime(state.get('StartedAt'), state.get('Running')),
            'exit_code': state.get('ExitCode') if exited else None,
            'restarts': service['restarts'] if service else item.get('RestartCount'),
            'command': [item['Path'], *item.get('Args', [])] if item.get('Path') else [],
            'networks': connections(item), 'network_mode': host.get('NetworkMode'), 'mounts': mounts,
            'memory_limit': host.get('Memory'), 'cpu_quota': host.get('CpuQuota'),
            'cpu_period': host.get('CpuPeriod'), 'process_limit': host.get('PidsLimit'),
            'hostname': native_config.get('Hostname'),
            'pod': section.get('pod') or item.get('Pod') or None,
        })
    return records


def pod_records(runtime, name=None):
    """Combine configured pods, native infra attachments and member service health."""
    configuration = runtime.read()['configuration']
    configured = configuration.get('pod', {})
    listed = json.loads(runtime.execute(['podman', 'pod', 'ps', '--format=json']))
    native = {item['Name']: item for item in listed}
    names = configured.keys() | native.keys()
    if name is not None:
        if name not in names:
            raise OperationalError(f'Pod {name} does not exist and is not configured.')
        names = {name}

    units = [pod_unit_name(value) + '.service' for value in names if value in configured]
    properties = services.unit_properties(units) if units else {}
    members = container_records(runtime) if names else []
    records = []
    for value in sorted(names):
        section = configured.get(value, {})
        item = {}
        infra = {}
        if value in native:
            data = json.loads(runtime.execute(['podman', 'pod', 'inspect', native[value]['Id']]))
            item = data[0] if isinstance(data, list) else data
            if item.get('InfraContainerID'):
                infra = json.loads(runtime.execute(['podman', 'container', 'inspect', item['InfraContainerID']]))[0]

        state = item.get('State', 'Not created')
        reason = ''
        if value in configured:
            unit = pod_unit_name(value) + '.service'
            service = services.process_record(services.instance('container', unit, name=value,
                                              disabled='disable' in section), properties[unit], time.monotonic())
            if service['state'] in ('Failed', 'Restarting', 'Starting', 'Disabled', 'Missing'):
                state = service['state']
            reason = service['detail']
        if runtime.pending.exists() and value in configured:
            reason = 'Container operation requires recovery' + (': ' + reason if reason else '')
        pod_members = [member for member in members if member['pod'] == value
                       or item.get('Id') and member['pod'] == item['Id']]
        records.append({'name': value, 'id': item.get('Id'), 'managed': value in configured,
                        'state': state, 'reason': reason, 'description': section.get('description', ''),
                        'hostname': infra.get('Config', {}).get('Hostname'),
                        'networks': connections(infra),
                        'network_mode': infra.get('HostConfig', {}).get('NetworkMode'),
                        'ports': infra.get('NetworkSettings', {}).get('Ports') or {}, 'members': pod_members})
    return records


def pods_output(records, detail=False):
    if not records:
        return 'No pods configured or present.\n'
    if not detail:
        rows = [[item['name'], item['state'], ', '.join(member['name'] for member in item['members']) or '—',
                 ', '.join(network['network'] for network in item['networks']) or item['network_mode'] or '—',
                 item['reason']] for item in records]
        return tabulate(rows, headers=['Pod', 'State', 'Containers', 'Networks', 'Detail'], disable_numparse=True) + '\n'

    item = records[0]
    rows = [('Pod', item['name']), ('State', item['state']), ('Description', item['description']),
            ('Managed', 'Yes' if item['managed'] else 'No'), ('Pod ID', item['id']),
            ('Hostname', item['hostname']), ('Network mode', item['network_mode']), ('Detail', item['reason'])]
    output = tabulate([(key, value or '—') for key, value in rows], tablefmt='presto', disable_numparse=True) + '\n'
    if item['networks']:
        output += '\n' + tabulate([[network['network'], ', '.join(network['addresses']) or '—', network['mac'] or '—']
                                    for network in item['networks']], headers=['Network', 'Addresses', 'MAC address']) + '\n'
    ports = [[binding['HostIp'], binding['HostPort'], destination]
             for destination, bindings in item['ports'].items() for binding in bindings or []]
    if ports:
        output += '\n' + tabulate(ports, headers=['Host address', 'Host port', 'Destination'], disable_numparse=True) + '\n'
    return output + '\n' + summary(item['members'])


def size(value):
    if value is None:
        return '—'
    amount = float(value)
    for suffix in ('B', 'KiB', 'MiB', 'GiB', 'TiB'):
        if abs(amount) < 1024 or suffix == 'TiB':
            return f'{amount:.1f} {suffix}'
        amount /= 1024


def summary(records):
    if not records:
        return 'No containers configured or present.\n'
    rows = [[item['name'], item['image'] or '—', 'Yes' if item['managed'] else 'No',
             item['state'], elapsed_time(item['uptime']), item['reason']] for item in records]
    return tabulate(rows, headers=['Name', 'Image', 'Managed', 'State', 'Uptime', 'Detail'],
                    disable_numparse=True) + '\n'


def detail_output(record):
    quota, period = record['cpu_quota'], record['cpu_period']
    cpus = '—'
    if quota is not None:
        cpus = quota / period if quota > 0 and period else 'Unlimited'

    rows = [('Name', record['name']), ('Managed', 'Yes' if record['managed'] else 'No'),
            ('Pod', record.get('pod')),
            ('State', record['state']), ('Service', record['service_state']), ('Reason', record['reason']),
            ('Container ID', record['id']), ('Image', record['image']), ('Image ID', record['image_id']),
            ('Command', shlex.join(record['command'])), ('Hostname', record['hostname']),
            ('Created', record['created']), ('Started', record['started']), ('Finished', record['finished']),
            ('Uptime', elapsed_time(record['uptime'])), ('Exit code', record['exit_code']),
            ('Restarts', record['restarts']), ('Network mode', record['network_mode']),
            ('Memory limit', 'Unlimited' if record['memory_limit'] == 0 else size(record['memory_limit'])),
            ('CPU limit', cpus),
            ('Process limit', 'Unlimited' if record['process_limit'] in (0, -1) else record['process_limit'])]
    output = tabulate([(key, '—' if value is None or value == '' else value) for key, value in rows],
                      tablefmt='presto', disable_numparse=True) + '\n'
    if record['networks']:
        output += '\n' + tabulate([[item['network'], ', '.join(item['addresses']) or '—', item['mac'] or '—']
                                   for item in record['networks']], headers=['Network', 'Addresses', 'MAC address']) + '\n'
    if record['mounts']:
        output += '\n' + tabulate([[item['source'] or '—', item['destination'], item['type'],
                                    'Read only' if item['read_only'] else 'Read/write'] for item in record['mounts']],
                                   headers=['Source', 'Destination', 'Type', 'Access']) + '\n'
    output += '\nRestarts: systemd automatic restarts for managed containers; Podman restarts otherwise.\n'
    return output


def network_records(runtime, name=None):
    configuration = runtime.read()['configuration']
    configured = configuration.get('network', {})
    infra_names = {pod + '-infra': pod for pod in configuration.get('pod', {})}
    listed = json.loads(runtime.execute(['podman', 'network', 'ls', '--format=json']))
    native = {item['name']: item for item in listed}
    names = configured.keys() | native.keys()

    if name is not None:
        if name not in names:
            raise OperationalError(f'Container network {name} does not exist and is not configured.')
        names = {name}

    containers = native_containers(runtime)
    result = []
    for value in sorted(names):
        item = {}
        if value in native:
            item = json.loads(runtime.execute(['podman', 'network', 'inspect', '--', native[value]['id']]))[0]

        section = configured.get(value, {})
        attachments = []
        for container in containers:
            for attachment in connections(container):
                if attachment['network'] == value:
                    owner = container['Name']
                    if container.get('IsInfra') and owner in infra_names:
                        owner = 'pod ' + infra_names[owner]
                    attachments.append({'container': owner, **attachment})
        result.append({'name': value, 'state': 'Present' if item else 'Missing',
                       'managed': value in configured, 'interface': item.get('network_interface'),
                       'driver': item.get('driver'), 'vrf': item.get('options', {}).get('vrf', section.get('vrf', 'default')),
                       'subnets': item.get('subnets', []), 'attachments': attachments,
                       'dns': item.get('dns_enabled'), 'internal': item.get('internal'),
                       'mtu': item.get('options', {}).get('mtu')})
    return result


def networks_output(records, detail):
    if not records:
        return 'No container networks configured or present.\n'
    rows = [[item['name'], item['interface'] or '—', item['driver'] or '—', item['vrf'], item['state'],
             '\n'.join(subnet['subnet'] for subnet in item['subnets']) or '—',
             '\n'.join(subnet.get('gateway', '—') for subnet in item['subnets']) or '—',
             ', '.join(attachment['container'] for attachment in item['attachments']) or 'None'] for item in records]
    output = tabulate(rows, headers=['Network', 'Interface', 'Driver', 'VRF', 'State', 'Subnets', 'Gateways', 'Containers'],
                      disable_numparse=True) + '\n'
    if detail:
        for item in records:
            rows = [[attachment['container'], ', '.join(attachment['addresses']) or '—', attachment['mac'] or '—']
                    for attachment in item['attachments']]
            output += '\n' + (tabulate(rows, headers=['Container', 'Addresses', 'MAC address'])
                               if rows else 'No containers attached.') + '\n'
    return output


def image_records(runtime):
    listed = json.loads(runtime.execute(['podman', 'images', '--format=json']))
    containers = native_containers(runtime)
    records = []
    for item in listed:
        identifier = item['Id'].removeprefix('sha256:')
        users = [container['Name'] for container in containers
                 if container['Image'].removeprefix('sha256:') == identifier]
        records.append({'id': item['Id'], 'names': item.get('Names') or [],
                        'size': item.get('Size'), 'containers': sorted(users)})
    return records


def statistics(runtime, name=None):
    listed = json.loads(runtime.execute(['podman', 'ps', '-a', '--format=json']))
    if name is not None:
        item = next((item for item in listed if name in item['Names']), None)
        if item is None or item['State'] != 'running':
            raise OperationalError(f'Container {name} is not running; use show containers name {name}.')
        arguments = [item['Id']]
    else:
        arguments = [item['Id'] for item in listed if item['State'] == 'running']
    if not arguments:
        return []

    records = json.loads(runtime.execute(['podman', 'stats', '--no-stream', '--no-reset', '--format=json', *arguments], timeout=15))
    if not records:
        raise OperationalError('Podman returned no statistics for the running containers.')
    return records


def statistics_output(records):
    if not records:
        return 'No running containers.\n'
    fields = [('Name', 'name'), ('CPU', 'cpu_percent'), ('Memory / limit', 'mem_usage'),
              ('Memory', 'mem_percent'), ('Network I/O', 'net_io'), ('Block I/O', 'block_io'), ('Processes', 'pids')]
    rows = [[item.get(key, '—') for _, key in fields] for item in records]
    return tabulate(rows, headers=[label for label, _ in fields], disable_numparse=True) + '\n'


def show(runtime, view, *, name=None, detail=False, raw=False):
    if view == 'pods':
        records = pod_records(runtime, name)
        output = pods_output(records, name is not None)
    elif view == 'containers':
        records = container_records(runtime, name)
        output = '\n'.join(detail_output(record) for record in records) if detail else summary(records)
    elif view == 'networks':
        records = network_records(runtime, name)
        output = networks_output(records, name is not None)
    elif view == 'images':
        records = image_records(runtime)
        rows = [['\n'.join(item['names']) or '<none>', item['id'][:12], size(item['size']),
                 ', '.join(item['containers']) or 'None'] for item in records]
        output = tabulate(rows, headers=['Image / tag', 'Image ID', 'Size', 'Containers']) + '\n' if rows else 'No images installed.\n'
    elif view == 'statistics':
        records = statistics(runtime, name)
        output = statistics_output(records)
    else:
        raise OperationalError('Unknown container display.')
    return json.dumps(records) if raw else output
