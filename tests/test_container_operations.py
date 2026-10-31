"""Operational inventory, native data contracts, service failures, and managed restarts."""

from tests.container_harness import ContainerHarness

import json
from types import SimpleNamespace

import pytest

from nvyr.errors import OperationalError, RecoveryError, RouterError
from nvyr.helpers import container_operations as views
from nvyr.helpers.container_config import unit_name
from nvyr.helpers.process import CommandResult
from nvyr.op_scripts import containers as commands
from tests.test_login import as_role


@pytest.mark.parametrize(('line', 'arguments'), [
    ('show containers', ['show']),
    ('show containers name DNS', ['show', '--name', 'DNS']),
    ('show containers name DNS detail', ['show', '--name', 'DNS', '--detail']),
    ('show containers statistics', ['statistics']),
    ('show containers statistics name DNS', ['statistics', '--name', 'DNS']),
    ('show containers networks', ['networks']),
    ('show containers networks name LAN', ['networks', '--name', 'LAN']),
    ('show containers images', ['images']),
])
def test_show_dispatch_and_permissions(controller, session, monkeypatch, line, arguments):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'output\n')
    with as_role('read-only'):
        controller.execute(line)
    controller.execute('run ' + line, session)

    assert calls == [['containers.nvyr.op', *arguments]] * 2


def test_restart_and_follow_dispatch(controller):
    with as_role('read-only'):
        with pytest.raises(RouterError, match='net-admin'):
            controller.execute('restart container DNS')
        with pytest.raises(RouterError, match='net-admin'):
            controller.authorize_terminal('restart container DNS', None)
        result = controller.execute('show containers statistics name DNS follow')
        assert result['argv'] == ['containers.nvyr.op', 'statistics', '--name', 'DNS', '--follow']
        controller.authorize_terminal('show containers statistics name DNS follow', None)

    with as_role('net-admin'):
        result = controller.execute('restart container DNS')
        assert result['argv'] == ['containers.nvyr.op', 'restart', 'DNS']
        controller.authorize_terminal('restart container DNS', None)


def test_connect_dispatch_and_permissions(controller, session):
    line = 'connect container DNS send-command "printf hello; hostname"'
    with as_role('read-only'):
        with pytest.raises(RouterError, match='net-admin'):
            controller.execute(line)
        with pytest.raises(RouterError, match='net-admin'):
            controller.authorize_terminal('connect container DNS', None)

    with as_role('net-admin'):
        assert controller.execute('connect container DNS')['argv'] == ['containers.nvyr.op', 'connect', 'DNS']
        for prefix, mode in [('', None), ('run ', session)]:
            result = controller.execute(prefix + line, mode)
            assert result['argv'] == ['containers.nvyr.op', 'connect', 'DNS', '--send-command', 'printf hello; hostname']


def test_connect_resolves_id_and_keeps_shell_command_inside_container():
    item = {'Id': 'abc123', 'Config': {'Labels': {'nvyr.managed': 'true'}}, 'State': {'Running': True}}
    runtime = SimpleNamespace(read=lambda: {'configuration': {'name': {'DNS': {}}}},
                              execute=lambda argv: json.dumps([item]))
    assert views.connect_command(runtime, 'DNS') == ['podman', 'exec', '--interactive', '--tty', 'abc123', '/bin/sh']
    assert views.connect_command(runtime, 'DNS', 'echo hello; hostname') == [
        'podman', 'exec', 'abc123', '/bin/sh', '-c', 'echo hello; hostname']

    item['State']['Running'] = False
    with pytest.raises(OperationalError, match='not running'):
        views.connect_command(runtime, 'DNS')
    item['State']['Running'] = True
    item['Config']['Labels'] = {}
    with pytest.raises(OperationalError, match='outside nVyR'):
        views.connect_command(runtime, 'DNS')
    with pytest.raises(OperationalError, match='not configured'):
        views.connect_command(runtime, 'FOREIGN')


def test_connect_allocates_tty_only_for_interactive_shell(monkeypatch):
    calls = []
    monkeypatch.setattr(commands, 'call', lambda argv, **kwargs: calls.append(argv) or 0)
    commands.connect('DNS')
    commands.connect('DNS', send_command='hostname')
    assert '--pty' in calls[0] and '--pipe' not in calls[0]
    assert '--pipe' in calls[1] and '--pty' not in calls[1]


def test_name_suggestions_and_deferred_logs(controller, session):
    controller.execute('set container name DNS image alpine', session)
    controller.execute('set container network LAN subnet 192.0.2.0/24', session)

    for prefix in ('run show containers name ', 'run show containers statistics name ',
                   'run restart container ', 'run connect container '):
        assert 'DNS' in dict(controller.completion(prefix, session)['candidates'])
    assert 'LAN' in dict(controller.completion('run show containers networks name ', session)['candidates'])
    assert 'logs' not in dict(controller.completion('run show containers name DNS ', session)['candidates'])


def native(name, status='running'):
    """Podman 6.1.4 inspect field names, including data that must never reach a display."""
    return {
        'Id': name + '-id', 'Name': name, 'Image': 'sha256:' + 'a' * 64,
        'ImageName': 'alpine:latest', 'Created': '2026-10-24T10:00:00Z',
        'State': {'Status': status, 'Running': status == 'running', 'ExitCode': 7,
                  'StartedAt': '2026-10-24T10:00:01.123456789Z',
                  'FinishedAt': '0001-01-01T00:00:00Z' if status == 'running' else '2026-10-24T10:01:00Z'},
        'Path': 'sleep', 'Args': ['infinity'],
        'Config': {'Hostname': name, 'Env': ['PASSWORD=secret'], 'Labels': {'secret': 'hidden'}},
        'HostConfig': {'Memory': 536870912, 'CpuQuota': 100000, 'CpuPeriod': 100000,
                       'PidsLimit': 256, 'NetworkMode': 'bridge'},
        'NetworkSettings': {'Networks': {'LAN': {'IPAddress': '192.0.2.10', 'IPPrefixLen': 24,
                            'GlobalIPv6Address': '2001:db8::10', 'GlobalIPv6PrefixLen': 64,
                            'MacAddress': '02:00:00:00:00:01'}}},
        'Mounts': [{'Source': '/config/containers/data', 'Destination': '/data', 'Type': 'bind', 'RW': False}],
    }


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    data = SimpleNamespace(
        native=[native('DNS'), native('STOPPED', 'exited')],
        configuration={'name': {'DNS': {'image': 'alpine', 'environment': {'SECRET': {'value': 'hidden'}}},
                                 'FAILED': {'image': 'alpine'}, 'DISABLED': {'image': 'alpine', 'disable': True}},
                       'network': {'LAN': {'vrf': 'BLUE'}, 'MISSING': {}}},
        networks=[{'name': 'LAN', 'id': 'network-id', 'network_interface': 'pd-LAN', 'driver': 'bridge',
                   'subnets': [{'subnet': '192.0.2.0/24', 'gateway': '192.0.2.1'}],
                   'options': {'vrf': 'BLUE', 'mtu': '1400'}, 'dns_enabled': False}],
        stats=[{'name': 'DNS', 'cpu_percent': '2.00%', 'mem_usage': '1 MB / 512 MB',
                'mem_percent': '0.20%', 'net_io': '1 kB / 2 kB', 'block_io': '0 B / 0 B', 'pids': '1'}],
        calls=[], pending=tmp_path / 'pending.json',
    )

    def execute(argv, **kwargs):
        data.calls.append(argv)
        if argv[:3] == ['podman', 'ps', '-a']:
            return json.dumps([{'Id': item['Id'], 'Names': [item['Name']], 'State': item['State']['Status']}
                               for item in data.native])
        if argv[:3] == ['podman', 'container', 'inspect']:
            return json.dumps([item for item in data.native if item['Id'] in argv[4:]])
        if argv[:3] == ['podman', 'network', 'ls']:
            return json.dumps(data.networks)
        if argv[:3] == ['podman', 'network', 'inspect']:
            return json.dumps([item for item in data.networks if item['id'] in argv[4:]])
        if argv[:2] == ['podman', 'images']:
            return json.dumps([{'Id': 'a' * 64, 'Names': ['alpine:latest', 'alpine:test'], 'Size': 1048576},
                               {'Id': 'b' * 64, 'Names': None, 'Size': 1024}])
        if argv[:2] == ['podman', 'stats']:
            return json.dumps(data.stats)
        raise AssertionError(argv)

    def properties(units):
        result = {}
        for unit in units:
            state = 'failed' if unit == unit_name('FAILED') + '.service' else 'inactive'
            if unit == unit_name('DNS') + '.service':
                state = 'active'
            result[unit] = {'LoadState': 'loaded', 'ActiveState': state, 'SubState': 'running',
                            'MainPID': '42' if state == 'active' else '0', 'NRestarts': '3',
                            'ExecMainCode': '1', 'ExecMainStatus': '125' if state == 'failed' else '0'}
        return result

    data.execute = execute
    data.read = lambda: {'configuration': data.configuration, 'images': {}}
    monkeypatch.setattr(views.services, 'unit_properties', properties)
    return data


def test_summary_keeps_exited_disabled_and_precreation_failures(runtime):
    records = {item['name']: item for item in views.container_records(runtime)}
    assert records['STOPPED']['state'] == 'Exited'
    assert records['STOPPED']['exit_code'] == 7
    assert records['STOPPED']['managed'] is False
    assert records['FAILED']['state'] == 'Failed'
    assert records['FAILED']['id'] is None
    assert records['FAILED']['reason'] == 'Exited with status 125'
    assert records['DISABLED']['state'] == 'Disabled'
    assert records['DNS']['uptime'] is not None
    assert records['DNS']['restarts'] == 3
    output = views.show(runtime, 'containers')
    assert 'FAILED' in output and 'STOPPED' in output
    assert 'Exited with status 125' in output


def test_detail_and_raw_are_whitelisted(runtime):
    raw = views.show(runtime, 'containers', name='DNS', raw=True)
    records = json.loads(raw)
    assert len(records) == 1
    assert records[0]['networks'][0]['addresses'] == ['192.0.2.10/24', '2001:db8::10/64']
    output = views.show(runtime, 'containers', name='DNS', detail=True)
    assert '512.0 MiB' in output and 'Read only' in output and 'sleep infinity' in output
    assert 'State' in output and '|' in output
    for secret in ('PASSWORD', 'secret', 'hidden', 'Env', 'Labels'):
        assert secret not in raw and secret not in output


def test_named_container_only_inspects_its_own_id(runtime):
    views.container_records(runtime, 'DNS')
    inspections = [argv for argv in runtime.calls if argv[:3] == ['podman', 'container', 'inspect']]
    assert inspections == [['podman', 'container', 'inspect', '--', 'DNS-id']]


def test_configured_missing_container_does_not_inspect_other_containers(runtime):
    records = views.container_records(runtime, 'FAILED')
    assert records[0]['state'] == 'Failed'
    assert not any(argv[:3] == ['podman', 'container', 'inspect'] for argv in runtime.calls)


def test_recovery_and_oom_visible(runtime):
    runtime.pending.touch()
    runtime.native[0]['State']['OOMKilled'] = True
    record = views.container_records(runtime, 'DNS')[0]
    assert record['reason'] == 'Container operation requires recovery: Killed after exceeding the memory limit'


def test_namespace_modes_are_not_named_networks_and_zero_timestamps_are_absent(runtime):
    runtime.native[0]['NetworkSettings']['Networks'] = {'none': {}}
    runtime.native[0]['State']['StartedAt'] = '0001-01-01T00:00:00Z'
    record = views.container_records(runtime, 'DNS')[0]
    assert record['networks'] == []
    assert record['started'] is None and record['uptime'] is None


def test_unknown_filters_are_errors(runtime):
    with pytest.raises(OperationalError, match='does not exist'):
        views.container_records(runtime, '--all')
    with pytest.raises(OperationalError, match='does not exist'):
        views.network_records(runtime, 'absent')
    with pytest.raises(OperationalError, match='not running'):
        views.statistics(runtime, 'STOPPED')
    assert not any(call[:2] == ['podman', 'stats'] for call in runtime.calls)


def test_network_inventory_and_scoped_attachments(runtime):
    records = json.loads(views.show(runtime, 'networks', raw=True))
    assert records[1]['name'] == 'MISSING' and records[1]['state'] == 'Missing'
    network = records[0]
    assert network['interface'] == 'pd-LAN' and network['vrf'] == 'BLUE'
    assert network['subnets'][0]['gateway'] == '192.0.2.1'
    assert len(network['attachments']) == 2
    output = views.show(runtime, 'networks', name='LAN')
    assert '192.0.2.10/24' in output and '2001:db8::10/64' in output
    assert 'MISSING' not in output


def test_images_match_ids_not_tags_and_keep_untagged(runtime):
    records = views.image_records(runtime)
    assert records[0]['containers'] == ['DNS', 'STOPPED']
    assert records[0]['names'] == ['alpine:latest', 'alpine:test']
    assert records[1]['containers'] == []
    assert '<none>' in views.show(runtime, 'images')


def test_network_without_attachments_has_readable_empty_value(runtime):
    runtime.native = []

    output = views.show(runtime, 'networks', name='LAN')
    row = next(line for line in output.splitlines() if line.startswith('LAN '))
    assert row.split()[-1] == 'None'
    assert output.isascii()
    assert 'No containers attached.' in output
    assert json.loads(views.show(runtime, 'networks', name='LAN', raw=True))[0]['attachments'] == []


def test_images_without_containers_have_readable_empty_values(runtime):
    runtime.native = []

    output = views.show(runtime, 'images')
    row = next(line for line in output.splitlines() if line.startswith('alpine:latest '))
    assert row.split()[-1] == 'None'
    assert output.isascii()
    assert all(item['containers'] == [] for item in json.loads(views.show(runtime, 'images', raw=True)))


def test_statistics_native_fields_and_running_filter(runtime):
    output = views.show(runtime, 'statistics', name='DNS')
    assert '2.00%' in output and '1 MB / 512 MB' in output and '1 kB / 2 kB' in output
    assert runtime.calls[-1] == ['podman', 'stats', '--no-stream', '--no-reset', '--format=json', 'DNS-id']
    views.statistics(runtime)
    assert runtime.calls[-1][-1] == 'DNS-id'


def test_missing_statistics_are_not_reported_as_no_running_containers(runtime):
    runtime.stats = []
    with pytest.raises(OperationalError, match='returned no statistics'):
        views.statistics(runtime)
    runtime.native = []
    assert views.show(runtime, 'statistics') == 'No running containers.\n'


def test_native_failures_are_not_silently_empty(runtime):
    def fail(*args, **kwargs):
        raise RouterError('storage unavailable')

    runtime.execute = fail
    with pytest.raises(RouterError, match='storage unavailable'):
        views.show(runtime, 'containers')


def test_direct_display_and_follow_interrupt(tmp_path, runtime, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(views, 'RUNTIME', tmp_path)
    monkeypatch.setattr(views, 'observations', lambda **kwargs: runtime)
    monkeypatch.setattr(views, 'protected_directory', lambda path: None)
    monkeypatch.setattr(commands, 'worker_command', lambda *args, **kwargs: pytest.fail('Display started a worker'))

    result = json.loads(commands.show(name='DNS', detail=True, raw=True))
    assert [item['name'] for item in result] == ['DNS']
    assert runtime.calls[1] == ['podman', 'container', 'inspect', '--', 'DNS-id']

    def interrupt(seconds):
        # A streaming sample must release the shared lock before sleeping.
        with (tmp_path / 'lock').open('a') as lock:
            views.fcntl.flock(lock, views.fcntl.LOCK_EX | views.fcntl.LOCK_NB)
            calls.append('released')
        raise KeyboardInterrupt

    monkeypatch.setattr(commands.time, 'sleep', interrupt)
    assert commands.statistics(name='DNS', follow=True) is None
    assert 'DNS' in capsys.readouterr().out
    assert calls == ['released']


def test_native_warnings_do_not_corrupt_structured_output(monkeypatch, capsys):
    monkeypatch.setattr(views, 'cli_cmd', lambda *args, **kwargs: CommandResult('[{}]', 'native warning\n', 0))
    assert json.loads(views.read_output(['podman', 'images', '--format=json'])) == [{}]
    assert capsys.readouterr().err == 'native warning\n'

    monkeypatch.setattr(views, 'cli_cmd', lambda *args, **kwargs: CommandResult('', 'storage unavailable', 125))
    with pytest.raises(OperationalError, match='storage unavailable'):
        views.read_output(['podman', 'images', '--format=json'])


def test_observations_read_configuration_from_configd_once(monkeypatch):
    calls = []
    configuration = {'container': {'name': {'DNS': {'image': 'alpine', 'disable': True}}}}
    monkeypatch.setattr(views.services, 'running_configuration', lambda: calls.append('read') or configuration)
    monkeypatch.setattr(views.container_script, 'read_state', lambda: {'images': {'DNS': 'pinned'}})

    observed = views.observations()
    assert observed.read()['configuration'] == configuration['container']
    assert observed.read()['images'] == {'DNS': 'pinned'}
    assert calls == ['read']


@pytest.fixture
def restart_runtime(tmp_path):
    state = tmp_path / 'managed.json'
    state.write_text(json.dumps({'objects': {'name': ['DNS']}, 'interfaces': {},
                                'images': {'DNS': 'pinned'}, 'inputs': {}}))
    quadlets = tmp_path / 'quadlets'
    quadlets.mkdir()
    (quadlets / (unit_name('DNS') + '.container')).write_text('Image=pinned\n')
    events = []
    runtime = ContainerHarness(state=state, quadlets=quadlets,
                                 execute=lambda argv, **kwargs: events.append(argv) or '', report=events.append)
    runtime.owned = lambda kind, name: False
    runtime.configuration = {'name': {'DNS': {'image': 'alpine'}}}
    runtime.events = events
    return runtime


def test_restart_retries_precreation_failure_without_mutating_config_or_digest(restart_runtime):
    before = restart_runtime.state.read_bytes()
    restart_runtime.restart('DNS')
    unit = unit_name('DNS') + '.service'
    assert restart_runtime.events == [['systemctl', 'reset-failed', unit], ['systemctl', 'restart', unit],
                                      'Container DNS service restarted.']
    assert restart_runtime.state.read_bytes() == before


def test_restart_rejects_disabled_unknown_and_recovery(restart_runtime):
    with pytest.raises(RouterError, match='not configured'):
        restart_runtime.restart('foreign')
    restart_runtime.configuration['name']['DNS']['disable'] = True
    with pytest.raises(RouterError, match='disabled'):
        restart_runtime.restart('DNS')
    restart_runtime.pending.touch()
    with pytest.raises(RecoveryError, match='needs recovery'):
        restart_runtime.restart('DNS')
    assert not restart_runtime.events


def test_restart_rejects_foreign_native_name_and_missing_unit(restart_runtime):
    def foreign(*args):
        raise RouterError('container DNS exists outside nVyR management')

    restart_runtime.owned = foreign
    with pytest.raises(RouterError, match='outside'):
        restart_runtime.restart('DNS')
    restart_runtime.owned = lambda *args: False
    (restart_runtime.quadlets / (unit_name('DNS') + '.container')).unlink()
    with pytest.raises(RouterError, match='no generated service'):
        restart_runtime.restart('DNS')
    assert not restart_runtime.events


def test_restart_failure_is_propagated_without_success_message(restart_runtime):
    def execute(argv, **kwargs):
        if argv[1] == 'restart':
            raise RouterError('service startup failed')
        return ''

    restart_runtime.execute = execute
    with pytest.raises(RouterError, match='startup failed'):
        restart_runtime.restart('DNS')
    assert not restart_runtime.events


def test_direct_display_rejects_busy_apply_without_waiting(tmp_path, monkeypatch):
    monkeypatch.setattr(views, 'RUNTIME', tmp_path)
    monkeypatch.setattr(views, 'protected_directory', lambda path: None)
    monkeypatch.setattr(views, 'observations', lambda **kwargs: pytest.fail('Busy display queried Podman'))
    with (tmp_path / 'lock').open('a') as lock:
        views.fcntl.flock(lock, views.fcntl.LOCK_EX | views.fcntl.LOCK_NB)
        with pytest.raises(OperationalError, match='operation is in progress'):
            commands.show()
