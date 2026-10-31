"""System/VRF displays and conntrack authorization without host mutations."""

import json

import pytest

from nvyr import opmode
from nvyr.errors import OperationalError, RouterError
from nvyr.helpers import access
from nvyr.op_scripts import bridge, conntrack, system, users, vrf


@pytest.mark.parametrize(('line', 'arguments'), [
    ('show date', ['date']),
    ('show system uptime', ['uptime']),
    ('show uptime', ['uptime']),
    ('show system memory', ['free', '-h']),
    ('show system cpu', ['system.nvyr.op', 'cpu']),
    ('show system config script-priority', ['system.nvyr.op', 'script_priority']),
    ('show system packages', ['system.nvyr.op', 'packages']),
    ('show system packages frr', ['system.nvyr.op', 'packages', '--name', 'frr']),
    ('show system packages libc6:amd64', ['system.nvyr.op', 'packages', '--name', 'libc6:amd64']),
    ('show system cpu usage', ['system.nvyr.op', 'cpu_usage']),
    ('show system storage', ['system.nvyr.op', 'storage']),
    ('show system processes', ['system.nvyr.op', 'processes']),
    ('show system processes cpu', ['system.nvyr.op', 'processes', '--sort', 'cpu']),
    ('show system processes memory', ['system.nvyr.op', 'processes', '--sort', 'memory']),
    ('show vrf', ['vrf.nvyr.op', 'show']),
    ('show vrf BLUE', ['vrf.nvyr.op', 'show', '--name', 'BLUE']),
])
def test_show_commands_available_to_operator(controller, session, monkeypatch, line, arguments):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'output\n')
    token = access.role.set('read-only')
    try:
        controller.execute(line)
    finally:
        access.role.reset(token)

    token = access.role.set('net-admin')
    try:
        controller.execute('run ' + line, session)
    finally:
        access.role.reset(token)

    assert calls == [arguments, arguments]


def test_clear_conntrack_access_and_terminal_prompt(controller, session):
    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError, match='requires net-admin'):
            controller.execute('clear conntrack')
    finally:
        access.role.reset(token)

    token = access.role.set('net-admin')
    try:
        result = controller.execute('run clear conntrack', session)
    finally:
        access.role.reset(token)

    assert result['event'] == 'command'
    assert result['argv'] == ['conntrack.nvyr.op', 'clear']


@pytest.mark.parametrize('answer', ['', 'no', 'n', 'YES', 'y'])
def test_conntrack_only_flushes_after_confirmation(monkeypatch, answer):
    calls = []
    monkeypatch.setattr('builtins.input', lambda prompt: answer)
    monkeypatch.setattr(conntrack, 'cmd', lambda argv: calls.append(argv) or 'Flushed\n')

    output = conntrack.clear()
    if answer in {'YES', 'y'}:
        assert calls == [['conntrack', '-F']]
        assert output == 'Flushed\n'
    else:
        assert not calls
        assert output == 'Command cancelled.\n'


def test_conntrack_failure_remains_visible(monkeypatch):
    monkeypatch.setattr('builtins.input', lambda prompt: 'yes')

    def fail(arguments):
        raise RouterError('Kernel rejected flush')

    monkeypatch.setattr(conntrack, 'cmd', fail)
    with pytest.raises(RouterError, match='Kernel rejected flush'):
        conntrack.clear()


def test_vrf_table_and_filter_use_kernel_membership(monkeypatch):
    links = [
        {'ifname': 'BLUE', 'flags': ['UP'], 'operstate': 'UNKNOWN', 'address': '02:00:00:00:00:01',
         'linkinfo': {'info_kind': 'vrf'}},
        {'ifname': 'RED', 'flags': [], 'linkinfo': {'info_kind': 'vrf'}},
        {'ifname': 'eth2', 'master': 'BLUE'},
        {'ifname': 'eth1', 'master': 'BLUE'},
        {'ifname': 'eth3', 'master': 'br0'},
    ]
    monkeypatch.setattr(vrf, 'cmd', lambda argv: json.dumps(links))

    output = vrf.show()
    assert 'MAC address' in output
    assert 'Flags' not in output and 'Table' not in output
    assert 'eth1, eth2' in output and 'eth3' not in output
    assert 'RED' in output and 'n/a' in output
    assert 'RED' not in vrf.show('BLUE')
    records = json.loads(vrf.show('BLUE', raw=True))
    assert records == [{'name': 'BLUE', 'state': 'up', 'mac': '02:00:00:00:00:01',
                        'interfaces': ['eth1', 'eth2']}]

    with pytest.raises(OperationalError, match='does not exist'):
        vrf.show('eth1')


def test_empty_vrf_display(monkeypatch):
    monkeypatch.setattr(vrf, 'cmd', lambda argv: '[]')
    assert vrf.show() == 'No VRFs configured.\n'
    assert json.loads(vrf.show(raw=True)) == []


def test_cpu_summary_counts_socket_core_pairs_and_omits_noise(monkeypatch):
    summary = {'lscpu': [
        {'field': 'Model name:', 'data': 'Test CPU'},
        {'field': 'Architecture:', 'data': 'x86_64'},
        {'field': 'CPU(s):', 'data': 4},
        {'field': 'On-line CPU(s) list:', 'data': '0-3'},
        {'field': 'Hypervisor vendor:', 'data': 'KVM'},
        {'field': 'Flags:', 'data': 'unwanted instruction flags'},
    ]}
    topology = {'cpus': [{'cpu': 0, 'core': 0, 'socket': 0},
                         {'cpu': 1, 'core': 0, 'socket': 0},
                         {'cpu': 2, 'core': 0, 'socket': 1},
                         {'cpu': 3, 'core': 0, 'socket': 1}]}

    def command(arguments, **options):
        assert options['env']['LC_ALL'] == 'C'
        return json.dumps(topology if '--all' in arguments else summary)

    monkeypatch.setattr(system, 'cmd', command)
    data = json.loads(system.cpu(raw=True))
    assert data['Cores'] == 2 and data['Sockets'] == 2 and data['Threads'] == 4
    assert data['Virtualization'] == 'KVM'
    output = system.cpu()
    assert 'Test CPU' in output and '|' in output
    assert 'instruction' not in output


def test_cpu_sampling_excludes_double_counted_guest_time(monkeypatch):
    monkeypatch.setattr(system.Path, 'read_text', lambda path: (
        'cpu 10 2 3 80 1 1 2 1 9 2\ncpu0 10 2 3 80 1 1 2 1 9 2\nintr 1234\n'))
    readings = system._cpu_times()
    assert readings == {'cpu': [10, 2, 3, 80, 1, 1, 2, 1],
                        'cpu0': [10, 2, 3, 80, 1, 1, 2, 1]}

    before = {name: [0] * 8 for name in readings}
    rows = system._usage_rows(before, readings)
    assert rows == [['Total', 12.0, 6.0, 1.0, 1.0, 80.0],
                    ['0', 12.0, 6.0, 1.0, 1.0, 80.0]]
    assert system._usage_rows(readings, readings) == []


def test_cpu_usage_samples_and_formats(monkeypatch):
    readings = iter([{'cpu': [0] * 8}, {'cpu': [20, 0, 10, 70, 0, 0, 0, 0]}])
    sleeps = []
    monkeypatch.setattr(system, '_cpu_times', lambda: next(readings))
    monkeypatch.setattr(system.time, 'sleep', sleeps.append)

    output = system.cpu_usage()
    assert sleeps == [1]
    assert 'Total' in output and '70.0' in output and 'Idle %' in output


def test_storage_preserves_mount_spaces_and_unknown_statistics(monkeypatch):
    records = [{'source': '/dev/test', 'target': '/mount with spaces', 'fstype': 'ext4',
                'size': 2048, 'used': 1024, 'avail': 512, 'use%': '50%',
                'ino.total': '10', 'ino.used': '8', 'ino.avail': '2', 'ino.use%': '80%'},
               {'source': 'overlay', 'target': '/', 'fstype': 'overlay', 'size': None}]

    def execute(argv, **options):
        assert '--json' in argv and '--bytes' in argv and '--df' not in argv
        assert options['env']['LC_ALL'] == 'C'
        return json.dumps({'filesystems': records})

    monkeypatch.setattr(system, 'cmd', execute)
    assert json.loads(system.storage(raw=True)) == records
    output = system.storage()
    assert '/mount with spaces' in output and 'overlay' in output
    assert '2.0 KiB' in output and '80%' in output and '—' in output


def test_process_sorting_names_and_memory_units(monkeypatch):
    def execute(argv, **options):
        assert argv == ['ps', '-ww', '-eo', 'pid=,euser:32=,stat=,pcpu=,rss=,comm=']
        return ' 30 root S 1.0 200 program with spaces\n 10 nvyr Sl 20.0 100 sshd\n 20 root R 20.0 300 busy\n'

    monkeypatch.setattr(system, 'cmd', execute)
    assert [item['pid'] for item in json.loads(system.processes(raw=True))] == [10, 20, 30]
    assert [item['pid'] for item in json.loads(system.processes('cpu', raw=True))] == [10, 20, 30]
    memory = json.loads(system.processes('memory', raw=True))
    assert [item['pid'] for item in memory] == [20, 30, 10]
    assert memory[0]['resident_bytes'] == 300 * 1024
    assert memory[1]['name'] == 'program with spaces'
    assert 'CPU % (lifetime)' in system.processes()
    with pytest.raises(OperationalError, match='sorting'):
        system.processes('arguments')


@pytest.mark.parametrize('module,arguments', [
    (system, ['cpu']), (system, ['storage']), (system, ['processes']),
    (vrf, ['show']), (bridge, ['show']), (users, ['show']),
])
def test_native_failure_is_a_readable_error_not_an_empty_table(monkeypatch, tmp_path, capsys, module, arguments):
    """The actual script dispatcher preserves backend failures and does not print a traceback."""
    accounting = tmp_path / 'utmp'
    accounting.touch()
    monkeypatch.setattr(users, 'ACCOUNTING', accounting)

    def unavailable(*args, **kwargs):
        raise OperationalError('Observation backend unavailable')

    monkeypatch.setattr(module, 'cmd', unavailable)
    with pytest.raises(SystemExit) as result:
        opmode.run(arguments, namespace=vars(module))

    output = capsys.readouterr()
    assert result.value.code == 1
    assert output.out == ''
    assert output.err == 'Observation backend unavailable\n'
