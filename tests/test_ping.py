"""Ping option translation, anchored discovery and real streaming execution."""

import itertools
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from build_tools.op_scripts import install_scripts
from nvyr.cli import CLI, TreeSuggestion
from nvyr.errors import RouterError
from nvyr.helpers import access
from nvyr.helpers.process import CommandError
from nvyr.op_scripts import ping


@pytest.mark.parametrize('option,expected', [
    ('adaptive', ['-A']), ('allow-broadcast', ['-b']), ('audible', ['-a']),
    ('bypass-route', ['-r']), ('count 5', ['-c', '5']), ('deadline 10', ['-w', '10']),
    ('do-not-fragment', ['-M', 'do']), ('flood', ['-f']), ('interface eth0', ['-I', 'eth0']),
    ('interval .01', ['-i', '.01']), ('ipv4', ['-4']), ('ipv6', ['-6']),
    ('mark 123', ['-m', '123']), ('no-loopback', ['-L']), ('numeric', ['-n']),
    ('pattern ff00', ['-p', 'ff00']), ('quiet', ['-q']), ('record-route', ['-R']),
    ('size 1000', ['-s', '1000']), ('source-address 192.0.2.1', ['-I', '192.0.2.1']),
    ('timestamp', ['-D']), ('tos 0xb8', ['-Q', '0xb8']), ('ttl 15', ['-t', '15']),
    ('dscp 46', ['-Q', '184']), ('dscp 0', ['-Q', '0']), ('dscp 63', ['-Q', '252']),
    ('verbose', ['-v']),
])
def test_each_requested_mapping(option, expected):
    assert ping._argv('ping 1.1.1.1 ' + option) == ['ping', *expected, '--', '1.1.1.1']


def test_option_order_abbreviations_and_quoted_values():
    for options in itertools.permutations(('cou 5', 'interv "0.5"', 'num')):
        line = 'ru pi "2001:db8::1" ' + ' '.join(options) + ' | count'
        expected = []

        for option in options:
            expected.extend({'cou 5': ['-c', '5'], 'interv "0.5"': ['-i', '0.5'], 'num': ['-n']}[option])

        assert ping._argv(line) == ['ping', *expected, '--', '2001:db8::1']

    assert ping._argv('ping fe80::1%eth0 interface eth0 source-address fe80::2') == [
        'ping', '-I', 'eth0', '-I', 'fe80::2', '--', 'fe80::1%eth0']
    assert ping._argv('ping example.com') == ['ping', '--', 'example.com']


@pytest.mark.parametrize('line', [
    '', 'run', 'run show version', 'ping', 'ping 1.1.1.1 count',
    'ping 1.1.1.1 count 0', 'ping 1.1.1.1 deadline -1', 'ping 1.1.1.1 interval nan',
    'ping 1.1.1.1 interval -1', 'ping 1.1.1.1 size 65528', 'ping 1.1.1.1 ttl 0',
    'ping 1.1.1.1 ttl 256', 'ping 1.1.1.1 tos 256', 'ping 1.1.1.1 mark 4294967296',
    'ping 1.1.1.1 dscp 64', 'ping 1.1.1.1 dscp -1', 'ping 1.1.1.1 dscp 1.5',
    'ping 1.1.1.1 pattern xyz', 'ping 1.1.1.1 pattern ' + 'ff' * 17,
    'ping 1.1.1.1 source-address 192.0.2.1/24', 'ping 1.1.1.1 interface "eth0 eth1"',
    'ping 1.1.1.1 i eth0', 'ping 1.1.1.1 unknown', 'ping 1.1.1.1 numeric extra',
    'ping --help', 'ping "$(touch unwanted)"',
])
def test_invalid_commands_never_execute(line, monkeypatch):
    monkeypatch.setattr(ping, 'call', lambda *a, **kw: pytest.fail('Invalid input executed'))

    with pytest.raises(RouterError):
        ping.ping(line)


def test_uses_call_with_shared_process_group(monkeypatch):
    calls = []
    monkeypatch.setattr(ping, 'call', lambda *a, **kw: calls.append((a, kw)) or 0)

    with pytest.raises(SystemExit) as success:
        ping.ping('ping 1.1.1.1 count 5 interval 0.5 numeric')

    assert success.value.code == 0
    assert calls == [((['ping', '-c', '5', '-i', '0.5', '-n', '--', '1.1.1.1'],),
                      {'new_process_group': False})]


@pytest.mark.parametrize('suffix', ['tos 184 dscp 46', 'dscp 46 tos 184', 'ds 46 to 184'])
def test_dscp_and_tos_are_mutually_exclusive(monkeypatch, suffix):
    monkeypatch.setattr(ping, 'call', lambda *a, **kw: pytest.fail('Conflicting options executed'))
    with pytest.raises(RouterError, match='Cannot combine tos and dscp'):
        ping.ping('ping 127.0.0.1 ' + suffix)


@pytest.mark.parametrize('status', [1, 2, 130])
def test_preserves_linux_failure_and_interrupt_status(status, monkeypatch):
    def fail(*args, **kwargs):
        return status

    monkeypatch.setattr(ping, 'call', fail)

    with pytest.raises(SystemExit) as error:
        ping.ping('ping 127.0.0.1')

    assert error.value.code == status


def test_spawn_errors_remain_readable(monkeypatch):
    def fail(*args, **kwargs):
        raise CommandError('command not found')

    monkeypatch.setattr(ping, 'call', fail)

    with pytest.raises(CommandError, match='command not found'):
        ping.ping('ping 127.0.0.1')


def test_cli_dispatch_and_discovery(controller, session):
    from prompt_toolkit.document import Document
    from types import SimpleNamespace

    line = '  pi "1.1.1.1" cou 5 interv .5 num'

    for prefix, mode in [('', None), ('run ', session)]:
        event = controller.execute(prefix + line, mode)

        assert event['argv'] == ['ping.nvyr.op', 'ping', prefix + line]
        assert event['event'] == 'command' and event['timeout'] is None

        result = controller.completion(prefix + 'ping 1.1.1.1 count 5 numeric ', mode, explicit=True)

        assert (set(ping.OPTIONS) - {'count', 'numeric'}) | {'<Enter>'} <= dict(result['candidates']).keys()
        assert {'count', 'numeric'}.isdisjoint(dict(result['candidates']))
        assert controller.completion(prefix + 'ping 1.1.1.1 count 5 interfa', mode, tab=True)['replacement'] == 'interface'
        assert controller.completion(prefix + 'ping 1.1.1.1 count 5 num', mode, space=True)['replacement'] == 'numeric'
        assert '<Enter>' not in dict(controller.completion(prefix + 'ping 1.1.1.1 count 0', mode, explicit=True)['candidates'])

    controller.operational.suggestors['interfaces'] = lambda: ['eth0', 'lo']

    assert 'eth0' in dict(controller.completion('ping 1.1.1.1 interface ', explicit=True)['candidates'])
    assert ('x:x:x:x:x:x', 'Local IPv6 address') in controller.completion(
        'ping 1.1.1.1 source-address ', explicit=True)['hints']

    client = SimpleNamespace(request=lambda operation, **kw: controller.completion(kw['text']))

    assert TreeSuggestion(CLI(client)).get_suggestion(None, Document('ping 1.1.1.1 count 5 num')).text == 'eric'

    token = access.role.set('read-only')

    try:
        assert controller.execute('ping 127.0.0.1 count 1')['event'] == 'command'
    finally:
        access.role.reset(token)


@pytest.fixture
def installed_ping(tmp_path, monkeypatch):
    source, bindir = tmp_path / 'op_scripts', tmp_path / 'bin'
    source.mkdir()
    shutil.copyfile(ping.__file__, source / 'ping.py')
    install_scripts(source, bindir)
    monkeypatch.setenv('PATH', str(bindir) + os.pathsep + os.environ['PATH'])

    return bindir


def test_installed_dispatch_pipeline_and_exit_status(installed_ping, controller):
    executable = installed_ping / 'ping'
    executable.write_text('#!' + sys.executable + '\nimport sys\nprint("FIRST", flush=True)\n'
                          'print("LAST", flush=True)\nraise SystemExit(2 if "-q" in sys.argv else 0)\n')
    executable.chmod(0o755)

    for suffix, status in [('count 2', 0), ('quiet', 2)]:
        result = subprocess.run(['ping.nvyr.op', 'ping', 'ping 127.0.0.1 ' + suffix],
                                text=True, capture_output=True, timeout=10)

        assert result.returncode == status
        assert result.stdout == 'FIRST\nLAST\n' and 'Traceback' not in result.stderr

    with pytest.raises(RouterError, match='not supported on streaming commands'):
        controller.execute('ping 127.0.0.1 count 2 | count')


def test_captured_timeout_stops_underlying_ping(installed_ping):
    from nvyr.helpers.process import cmd

    marker = installed_ping / 'ping.pid'
    executable = installed_ping / 'ping'
    executable.write_text('#!' + sys.executable + '\nimport os,time\n'
                          f'open({str(marker)!r}, "w").write(str(os.getpid()))\n'
                          'time.sleep(30)\n')
    executable.chmod(0o755)

    try:
        with pytest.raises(CommandError, match='did not finish'):
            cmd(['ping.nvyr.op', 'ping', 'ping 127.0.0.1'], timeout=1)

        pid = int(marker.read_text())
        state = Path(f'/proc/{pid}/stat')

        assert not state.exists() or state.read_text().split()[2] == 'Z'
    finally:
        if marker.exists():
            try:
                os.kill(int(marker.read_text()), 9)
            except ProcessLookupError:
                pass


def test_live_output_interrupt_and_terminal_restoration(installed_ping):
    from tests.test_process import spawn_terminal, read_until, cleanup

    executable = installed_ping / 'ping'
    executable.write_text('#!' + sys.executable + '\nimport time,signal\n'
                          'signal.signal(signal.SIGINT, lambda *args: exit(130))\n'
                          'print("FIRST_REPLY",flush=True)\ntime.sleep(20)\nprint("LAST_REPLY")\n')
    executable.chmod(0o755)
    source = ('import os; from nvyr.helpers.process import run; '
              'status=run(["ping.nvyr.op","ping","ping 127.0.0.1"],stream=True,timeout=None); '
              'print("RETURNED",status,os.tcgetpgrp(0)==os.getpgrp(),flush=True)')
    pid, descriptor = spawn_terminal(source)

    try:
        output = read_until(descriptor, b'FIRST_REPLY')

        assert b'LAST_REPLY' not in output and b'RETURNED' not in output

        os.write(descriptor, b'\x03')
        output += read_until(descriptor, b'RETURNED 130 True')

        assert b'Traceback' not in output
    finally:
        cleanup(pid, descriptor)


@pytest.mark.parametrize('destination,family', [('127.0.0.1', 'ipv4'), ('::1', 'ipv6')])
def test_real_loopback_ping(destination, family):
    if not shutil.which('ping'):
        pytest.skip('requires iputils-ping')

    result = subprocess.run([sys.executable, ping.__file__, 'ping',
                             f'ping {destination} {family} count 1 deadline 2 numeric'],
                            capture_output=True, text=True, timeout=5)

    assert result.returncode == 0, result.stderr
    assert '1 received' in result.stdout
