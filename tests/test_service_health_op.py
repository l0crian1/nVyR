"""Login and managed-service displays remain read-only and expose unhealthy states."""

import asyncio
from contextlib import closing
import json
from pathlib import Path

import pytest

from nvyr.errors import OperationalError
from nvyr.helpers import access
from nvyr.helpers.process import CommandResult
from nvyr.op_scripts import services, users
from nvyr.daemon import Server
from nvyr.protocol import Client


@pytest.fixture(autouse=True)
def login_accounting(tmp_path, monkeypatch):
    path = tmp_path / 'utmp'
    path.touch()
    monkeypatch.setattr(users, 'ACCOUNTING', path)


@pytest.mark.parametrize(('line', 'arguments'), [
    ('show users', ['users.nvyr.op', 'show']),
    ('show system services', ['services.nvyr.op', 'show']),
    ('show system services configd', ['services.nvyr.op', 'show', '--service', 'configd']),
    ('show system services configd detail', ['services.nvyr.op', 'show', '--service', 'configd', '--detail']),
    ('show system services dhcp-server vrf BLUE', ['services.nvyr.op', 'show', '--service', 'dhcp-server', '--vrf', 'BLUE']),
    ('show system services dhcpv6-server vrf default', ['services.nvyr.op', 'show', '--service', 'dhcpv6-server', '--vrf', 'default']),
    ('show system services container name DNS', ['services.nvyr.op', 'show', '--service', 'container', '--name', 'DNS']),
])
def test_health_commands_are_available_to_operator(controller, session, monkeypatch, line, arguments):
    """Both operational mode and run preserve fixed executables and exact argument positions."""
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'output\n')
    role = access.role.set('read-only')
    try:
        controller.execute(line)
    finally:
        access.role.reset(role)

    controller.execute('run ' + line, session)
    assert calls == [arguments, arguments]


def test_service_scope_completions(controller, session):
    controller.execute('set vrf name BLUE table 101', session)
    controller.execute('set container name DNS image alpine', session)
    choices = dict(controller.completion('run show system services ', session, explicit=True)['candidates'])
    assert {'configd', 'netlinkd', 'frr', 'ssh', 'ntp', 'container', 'dhcp-server', 'dhcpv6-server'} <= choices.keys()
    assert 'log' in dict(controller.completion('run show ', session, explicit=True)['candidates'])


def test_users_preserves_multiple_logins_and_ipv6(monkeypatch):
    """Each terminal is independent even when both username and source are shared."""
    monkeypatch.setattr(users, 'idle_seconds', lambda terminal, now: {'pts/0': 3, 'pts/1': 3661, 'tty1': None}[terminal])
    monkeypatch.setattr(users, 'session_alive', lambda pid: True)
    monkeypatch.setenv('NVYR_SESSION_TTY', '/dev/pts/1')
    output = ('nvyr pts/0 2026-10-24 14:32 . 1234 (2001:db8::10)\n'
              'nvyr pts/1 2026-10-24 14:10 01:01 2345 (2001:db8::10)\n'
              'admin tty1 2026-10-24 13:48 old 3456\n')
    calls = []
    monkeypatch.setattr(users, 'cmd', lambda argv, **kwargs: calls.append((argv, kwargs)) or output)

    records = json.loads(users.show(raw=True))
    assert len(records) == 3
    assert records[0]['source'] == records[1]['source'] == '2001:db8::10'
    assert records[2]['source'] == 'Console'
    assert [record['current_session'] for record in records] == [False, True, False]
    text = users.show()
    assert '01:01:01' in text and '00:00:03' in text
    assert 'User' in text and 'Login time' in text
    assert text.count('(this session)') == 1
    assert 'nvyr (this session)' in text
    assert calls[0][0] == ['who', '--users', str(users.ACCOUNTING)]
    assert calls[0][1]['env']['LC_ALL'] == 'C.UTF-8'


def test_users_terminal_is_scoped_to_calling_context(controller, monkeypatch):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(kwargs['env']) or '')
    token = access.terminal.set('/dev/pts/7')
    try:
        controller.execute('show users')
    finally:
        access.terminal.reset(token)
    controller.execute('show users')
    assert [env['NVYR_SESSION_TTY'] for env in calls] == ['/dev/pts/7', '']


def test_daemon_preserves_each_callers_terminal(engine, tmp_path, monkeypatch):
    """Concurrent RPC clients cannot mark each other's terminal as the current login."""
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: kwargs['env']['NVYR_SESSION_TTY'])

    async def scenario():
        origins = iter(['/dev/pts/7 (pid 70, uid 0)', '/dev/pts/8 from 192.0.2.8 (pid 80, uid 0)', 'local-script'])
        server = Server(engine, identity=lambda writer: ('root', next(origins)))
        path = tmp_path / 'origin.sock'
        listener = await asyncio.start_unix_server(server.handle, path=str(path))

        def query():
            with closing(Client(path)) as client:
                return client.request('execute', text='show users').get('text', '')

        async with listener:
            results = await asyncio.gather(asyncio.to_thread(query), asyncio.to_thread(query))
            assert sorted(results) == ['/dev/pts/7', '/dev/pts/8']
            assert await asyncio.to_thread(query) == ''

    asyncio.run(scenario())


def test_users_empty_and_invalid_accounting(monkeypatch):
    monkeypatch.setattr(users, 'cmd', lambda *args, **kwargs: '')
    assert users.show() == 'No users logged in.\n'
    assert json.loads(users.show(raw=True)) == []

    with pytest.raises(OperationalError, match='login accounting'):
        users.login_records('unexpected output', 10)

    users.ACCOUNTING.unlink()
    with pytest.raises(OperationalError, match='accounting is unavailable'):
        users.show()


def test_package_creates_accounting_without_truncating_sessions():
    root = Path(__file__).resolve().parents[1]
    lines = (root / 'packaging/nvyr-network.conf').read_text().splitlines()
    assert 'f /run/utmp 0664 root utmp -' in lines


def test_stale_login_records_are_omitted(monkeypatch):
    def exited(pid, signal):
        assert signal == 0
        raise ProcessLookupError()

    monkeypatch.setattr(users.os, 'kill', exited)
    assert users.login_records('nvyr pts/0 2026-10-24 14:32 . 1234 (192.0.2.1)', 0) == []


def test_disconnected_tty_and_clock_change(monkeypatch):
    """A disappearing terminal is unknown; wall-clock correction cannot give negative idle."""
    def disconnected(path):
        raise FileNotFoundError()

    monkeypatch.setattr(users.Path, 'stat', disconnected)
    assert users.idle_seconds('pts/0', 100) is None
    assert users.idle_seconds('../../etc/shadow', 100) is None

    from types import SimpleNamespace
    monkeypatch.setattr(users.Path, 'stat', lambda path: SimpleNamespace(st_atime=200))
    assert users.idle_seconds('pts/0', 100) == 0


def configuration():
    return {
        'service': {'ssh': {}, 'dhcp-server': {}},
        'system': {'ntp': {'vrf': 'BLUE'}},
        'vrf': {'name': {'BLUE': {'service': {'dhcp-server': {}, 'dhcpv6-server': {'disable': {}}}}}},
        'container': {'network': {'LAN': {'vrf': 'BLUE'}, 'WAN': {}}, 'name': {
            'DNS': {'network': {'LAN': {}, 'WAN': {}}}, 'OFF': {'disable': {}},
            'HOST': {'allow-host-networking': {}},
        }},
    }


def properties(unit, **changes):
    return {
        'Id': unit, 'LoadState': 'loaded', 'ActiveState': 'active', 'SubState': 'running',
        'MainPID': '123', 'Result': 'success', 'ExecMainCode': '0', 'ExecMainStatus': '0',
        'ExecMainStartTimestamp': 'Sat 2026-10-24 14:34:02 UTC',
        'ExecMainStartTimestampMonotonic': '10000000', 'NRestarts': '2', **changes,
    }


def test_inventory_uses_configured_instances_and_native_names():
    records = services.inventory(configuration())
    assert [row['service'] for row in records[:3]] == ['configd', 'netlinkd', 'frr']
    dhcp = [row for row in records if row['service'] == 'dhcp-server']
    assert {row['vrfs'][0] for row in dhcp} == {'BLUE', 'default'}
    assert dhcp[0]['unit'] == 'nvyr-kea@4-424c5545.service'
    assert next(row for row in records if row['service'] == 'dhcpv6-server')['disabled']
    dns = next(row for row in records if row['instance'] == 'DNS')
    assert dns['unit'] == 'nvyr-container-444e53.service'
    assert dns['vrfs'] == ['BLUE', 'default']
    assert next(row for row in records if row['instance'] == 'OFF')['vrfs'] == []
    assert next(row for row in records if row['instance'] == 'HOST')['vrfs'] == ['default']


@pytest.mark.parametrize(('changes', 'state', 'reason'), [
    ({}, 'Running', ''),
    ({'ActiveState': 'inactive', 'MainPID': '0'}, 'Stopped', ''),
    ({'ActiveState': 'failed', 'MainPID': '0', 'Result': 'exit-code', 'ExecMainCode': '1', 'ExecMainStatus': '1'}, 'Failed', 'Exited with status 1'),
    ({'ActiveState': 'activating', 'SubState': 'auto-restart', 'MainPID': '0', 'Result': 'signal', 'ExecMainCode': '2', 'ExecMainStatus': '9'}, 'Restarting', 'Terminated by signal 9'),
    ({'LoadState': 'not-found', 'ActiveState': 'inactive', 'MainPID': '0'}, 'Missing', 'not installed'),
])
def test_systemd_state_and_process_uptime(changes, state, reason):
    record = services.process_record(services.instance('frr', 'frr.service'), properties('frr.service', **changes), 30)
    assert record['state'] == state
    assert reason in record['detail']
    assert record['uptime_seconds'] == (20 if state == 'Running' else None)
    assert record['restarts'] == 2


def test_disabled_service_does_not_hide_unexpected_running_process():
    item = services.instance('container', 'example.service', disabled=True)
    active = services.process_record(item, properties('example.service'), 30)
    assert active['state'] == 'Running'
    assert 'still active' in active['detail']
    inactive = services.process_record(item, properties('example.service', LoadState='not-found', ActiveState='inactive', MainPID='0'), 30)
    assert inactive['state'] == 'Disabled'


def test_systemctl_batch_parsing_and_errors(monkeypatch):
    output = 'Id=frr.service\nLoadState=loaded\n\nId=missing.service\nLoadState=not-found\n'
    calls = []
    monkeypatch.setattr(services, 'cli_cmd', lambda argv, **kwargs: calls.append(argv) or CommandResult(output, '', 0))
    result = services.unit_properties(['frr.service', 'missing.service'])
    assert result['missing.service']['LoadState'] == 'not-found'
    assert calls[0][-2:] == ['frr.service', 'missing.service']
    assert calls[0][:2] == ['systemctl', 'show']
    with pytest.raises(OperationalError, match='no state'):
        services.unit_properties(['other.service'])

    monkeypatch.setattr(services, 'cli_cmd', lambda *args, **kwargs: CommandResult('', 'Bus unavailable', 1))
    with pytest.raises(OperationalError, match='Bus unavailable'):
        services.unit_properties(['frr.service'])


@pytest.fixture
def dhcp_record(tmp_path, monkeypatch):
    monkeypatch.setattr(services.kea, 'RUNTIME', tmp_path)
    (tmp_path / '4-424c5545.json').write_text(json.dumps({'Dhcp4': {'interfaces-config': {'interfaces': ['eth2']}}}))
    monkeypatch.setattr(services.kea, 'inventory', lambda: {'eth2': {'up': True, 'running': False}})
    item = services.instance('dhcp-server', 'nvyr-kea@4-424c5545.service', vrfs=['BLUE'])
    return services.process_record(item, properties(item['unit']), 30)


def test_dhcp_waiting_for_carrier_and_detail(dhcp_record, monkeypatch):
    monkeypatch.setattr(services.kea, 'control', lambda *args, **kwargs: {
        'arguments': {'sockets': {'status': 'retrying', 'errors': ['the interface eth2 is not running']}}})
    services.readiness(dhcp_record)
    assert dhcp_record['state'] == 'Waiting for carrier'
    assert dhcp_record['process'] == 'Running'
    assert dhcp_record['ready'] is False
    text = services.detail_output(dhcp_record)
    assert ' | ' in text and 'eth2 has no carrier' in text


def test_dhcp_socket_failure_is_not_carrier_wait(dhcp_record, monkeypatch):
    monkeypatch.setattr(services.kea, 'control', lambda *args, **kwargs: {
        'arguments': {'sockets': {'status': 'failed', 'errors': ['Address already in use']}}})
    services.readiness(dhcp_record)
    assert dhcp_record['state'] == 'Not ready'
    assert dhcp_record['detail'] == 'Address already in use'


def test_dhcp_ready_and_unreachable(dhcp_record, monkeypatch):
    monkeypatch.setattr(services.kea, 'control', lambda *args, **kwargs: {'arguments': {'sockets': {'status': 'ready'}}})
    services.readiness(dhcp_record)
    assert dhcp_record['ready'] is True
    assert dhcp_record['detail'] == 'Listening on eth2'

    def unreachable(*args, **kwargs):
        raise OSError('Control socket unavailable')

    monkeypatch.setattr(services.kea, 'control', unreachable)
    services.readiness(dhcp_record)
    assert dhcp_record['state'] == 'Health unavailable'
    assert dhcp_record['ready'] is None
    assert dhcp_record['process'] == 'Running'


def test_ntp_sync_is_separate_from_process(monkeypatch):
    record = services.process_record(services.instance('ntp', 'nvyr-ntp.service'), properties('nvyr-ntp.service'), 30)
    monkeypatch.setattr(services.ntp, 'tracking', lambda **kwargs: json.dumps({'Status': 'Not synchronised'}))
    services.readiness(record)
    assert record['state'] == 'Running' and record['ready'] is False

    monkeypatch.setattr(services.ntp, 'tracking', lambda **kwargs: json.dumps({'Status': 'Normal'}))
    services.readiness(record)
    assert record['ready'] is True and record['detail'] == 'Synchronized'


def test_filtered_service_health_and_missing_instance(monkeypatch):
    monkeypatch.setattr(services, 'running_configuration', configuration)
    calls = []
    monkeypatch.setattr(services, 'unit_properties', lambda units: calls.append(units) or {unit: properties(unit) for unit in units})
    monkeypatch.setattr(services, 'readiness', lambda record: None)
    text = services.show(service='dhcp-server', vrf='BLUE')
    assert ' | ' in text and 'BLUE' in text and 'default' not in text
    assert calls == [['nvyr-kea@4-424c5545.service']]

    records = json.loads(services.show(service='container', name='DNS', raw=True))
    assert len(records) == 1 and records[0]['instance'] == 'DNS'
    assert 'Instance' in services.show(service='container')
    assert 'Service' in services.show()
    with pytest.raises(OperationalError, match='matches'):
        services.show(service='dhcp-server', vrf='UNKNOWN')
    with pytest.raises(OperationalError, match='Unknown managed'):
        services.show(service='arbitrary.service')


def test_unconfigured_service_and_stopped_probe(monkeypatch):
    monkeypatch.setattr(services, 'running_configuration', lambda: {})
    assert services.show(service='dhcp-server') == 'No configured instances of this service.\n'
    assert json.loads(services.show(service='container', raw=True)) == []
    record = services.process_record(services.instance('ntp', 'ntp.service'), properties('ntp.service', ActiveState='inactive', MainPID='0'), 30)
    monkeypatch.setattr(services.ntp, 'tracking', lambda **kwargs: pytest.fail('Stopped service must not be probed'))
    services.readiness(record)
    assert record['state'] == 'Stopped'
