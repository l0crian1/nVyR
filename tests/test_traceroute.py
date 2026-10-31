"""Traceroute translation, constraints, anchored discovery and streaming."""

import itertools
import os
import shutil
import subprocess
import sys

import pytest

from build_tools.op_scripts import install_scripts
from nvyr.errors import RouterError
from nvyr.helpers import access
from nvyr.op_scripts import traceroute


@pytest.mark.parametrize('option,expected', [
    ('ipv4', ['-4']), ('ipv6', ['-6']), ('icmp', ['-I']), ('tcp', ['-T']),
    ('udp', ['-U']), ('do-not-fragment', ['-F']), ('interface eth0', ['-i', 'eth0']),
    ('max-ttl 15', ['-m', '15']), ('first-ttl 5', ['-f', '5']), ('no-resolve', ['-n']),
    ('port 443', ['-p', '443']), ('tos 0xb8', ['-t', '0xb8']), ('tos 255', ['-t', '255']),
    ('dscp 46', ['-t', '184']), ('dscp 0', ['-t', '0']), ('dscp 63', ['-t', '252']),
    ('source-address 192.0.2.1', ['-s', '192.0.2.1']),
    ('mark 4294967295', ['--fwmark=4294967295']), ('probes 10', ['-q', '10']),
    ('wait 1', ['-w', '1']), ('wait .5', ['-w', '.5']), ('wait 0', ['-w', '0']),
    ('backward-hops', ['--back']), ('direct', ['-r']),
])
def test_option_mapping(option, expected):
    assert traceroute._argv('traceroute example.com ' + option) == [
        'traceroute', *expected, '--', 'example.com']


def test_size_is_positional_and_options_remain_order_independent():
    for options in itertools.permutations(('size 1000', 'ds 46', 'no-r')):
        expected = [word for option in options for word in
                    {'size 1000': [], 'ds 46': ['-t', '184'], 'no-r': ['-n']}[option]]
        line = 'ru tr "2001:db8::1" ' + ' '.join(options)

        assert traceroute._argv(line) == ['traceroute', *expected, '--', '2001:db8::1', '1000']

    assert traceroute._argv('traceroute example.com size 0 size 100')[-2:] == ['example.com', '100']
    assert traceroute._argv('traceroute example.com') == ['traceroute', '--', 'example.com']


@pytest.mark.parametrize('options,message', [
    ('ipv4 ipv6', 'ipv4 and ipv6'), ('icmp tcp', 'icmp and tcp'),
    ('icmp udp', 'icmp and udp'), ('tcp udp', 'tcp and udp'),
    ('icmp tcp udp', 'icmp and tcp and udp'),
    ('tos 184 dscp 46', 'tos and dscp'), ('dscp 46 tos 184', 'tos and dscp'),
    ('first-ttl 31', r'first-ttl \(31\).*max-ttl \(30\)'),
    ('max-ttl 3 first-ttl 4', r'first-ttl \(4\).*max-ttl \(3\)'),
    ('first-ttl 4 max-ttl 3', r'first-ttl \(4\).*max-ttl \(3\)'),
])
def test_constraints_fail_before_execution(monkeypatch, options, message):
    monkeypatch.setattr(traceroute, 'call', lambda *a, **kw: pytest.fail('Invalid options executed'))

    with pytest.raises(RouterError, match=message):
        traceroute.traceroute('traceroute example.com ' + options)


@pytest.mark.parametrize('line,message', [
    ('traceroute ::1 ipv4', 'Destination ::1 is not an IPv4'),
    ('traceroute 127.0.0.1 ipv6', 'Destination 127.0.0.1 is not an IPv6'),
    ('traceroute ::1 source-address 127.0.0.1', 'source-address 127.0.0.1 must use IPv6'),
    ('traceroute example.com ipv4 source-address ::1', 'source-address ::1 must use IPv4'),
    ('traceroute fe80::1%eth0 source-address 192.0.2.1', 'must use IPv6'),
])
def test_known_address_family_mismatches(line, message):
    with pytest.raises(RouterError, match=message):
        traceroute._argv(line)


@pytest.mark.parametrize('line', [
    'traceroute ::1 ipv6 source-address ::1',
    'traceroute fe80::1%eth0 ipv6 interface eth0',
    'traceroute example.com source-address ::1',
    'traceroute example.com icmp port 0',
    'traceroute example.com first-ttl 255 max-ttl 255',
    'traceroute example.com first-ttl 30',
    'traceroute example.com ipv4 ipv4',
    'traceroute example.com dscp 1 dscp 2',
])
def test_valid_combinations_and_explicit_repeats(line):
    assert traceroute._argv(line)[0] == 'traceroute'


@pytest.mark.parametrize('suffix', [
    'probes 0', 'probes 11', 'first-ttl 0', 'max-ttl 256', 'size 65001', 'size -1',
    'port 65536', 'tos 256', 'tos 0x100', 'dscp 64', 'dscp -1', 'dscp 1.5',
    'mark 4294967296', 'wait -1', 'wait nan', 'wait 1,2,3', 'wait 1/2/3',
    'source-address 192.0.2.1/24', 'interface "eth0 eth1"', 'unknown', 'probes',
])
def test_schema_rejects_bad_values(controller, suffix):
    line = 'traceroute example.com ' + suffix
    with pytest.raises(RouterError):
        traceroute._argv(line)
    with pytest.raises(RouterError):
        controller.execute(line)


@pytest.mark.parametrize('status', [0, 1, 2, 130])
def test_streaming_uses_existing_process_group_and_preserves_status(monkeypatch, status):
    calls = []
    monkeypatch.setattr(traceroute, 'call', lambda *a, **kw: calls.append((a, kw)) or status)

    with pytest.raises(SystemExit) as result:
        traceroute.traceroute('traceroute 127.0.0.1 icmp probes 1 wait 1')

    assert result.value.code == status
    assert calls == [((['traceroute', '-I', '-q', '1', '-w', '1', '--', '127.0.0.1'],),
                      {'new_process_group': False})]


def test_dispatch_completion_and_permissions(controller, session):
    for prefix, mode in [('', None), ('run ', session)]:
        line = prefix + 'traceroute 192.0.2.1 tcp port 443 size 1000'
        result = controller.execute(line, mode)

        assert result['event'] == 'command' and result['timeout'] is None
        assert result['argv'] == ['traceroute.nvyr.op', 'traceroute', line]
        names = dict(controller.completion(line + ' ', mode, explicit=True)['candidates'])
        assert {'tcp', 'port', 'size'}.isdisjoint(names)
        assert {'<Enter>', 'dscp', 'max-ttl'} <= names.keys()
        assert controller.completion(line + ' max', mode, tab=True)['replacement'] == 'max-ttl'

    controller.operational.suggestors['interfaces'] = lambda: ['eth0']
    assert 'eth0' in dict(controller.completion('traceroute ::1 interface ')['candidates'])
    assert controller.completion('traceroute ::1 source-address ', explicit=True)['hints']

    token = access.role.set('read-only')
    try:
        assert controller.execute('traceroute 127.0.0.1')['event'] == 'command'
    finally:
        access.role.reset(token)

    with pytest.raises(RouterError, match='not supported on streaming commands'):
        controller.execute('traceroute 127.0.0.1 | count')


@pytest.fixture
def installed_traceroute(tmp_path, monkeypatch):
    source, bindir = tmp_path / 'op_scripts', tmp_path / 'bin'
    source.mkdir()
    shutil.copyfile(traceroute.__file__, source / 'traceroute.py')
    install_scripts(source, bindir)
    monkeypatch.setenv('PATH', str(bindir) + os.pathsep + os.environ['PATH'])
    return bindir


@pytest.mark.parametrize('options,message', [
    ('first-ttl 31', 'first-ttl (31) cannot be greater than max-ttl (30).'),
    ('tos 184 dscp 46', 'Cannot combine tos and dscp. Choose only one.'),
])
def test_installed_validation_has_no_traceback_or_process_launch(installed_traceroute, options, message):
    result = subprocess.run(['traceroute.nvyr.op', 'traceroute', 'traceroute example.com ' + options],
                            text=True, capture_output=True, timeout=5)
    assert result.returncode == 1
    assert result.stderr == message + '\n'
    assert result.stdout == ''


def test_stream_output_interrupt_and_terminal_restoration(installed_traceroute):
    from tests.test_process import spawn_terminal, read_until, cleanup

    executable = installed_traceroute / 'traceroute'
    executable.write_text('#!' + sys.executable + '\nimport time,signal\n'
                          'signal.signal(signal.SIGINT, lambda *args: exit(130))\n'
                          'print("FIRST_HOP",flush=True)\ntime.sleep(20)\nprint("LAST_HOP")\n')
    executable.chmod(0o755)
    source = ('import os; from nvyr.helpers.process import run; '
              'status=run(["traceroute.nvyr.op","traceroute","traceroute 127.0.0.1"],stream=True,timeout=None); '
              'print("RETURNED",status,os.tcgetpgrp(0)==os.getpgrp(),flush=True)')
    pid, descriptor = spawn_terminal(source)

    try:
        output = read_until(descriptor, b'FIRST_HOP')
        assert b'LAST_HOP' not in output and b'RETURNED' not in output

        os.write(descriptor, b'\x03')
        output += read_until(descriptor, b'RETURNED 130 True')
        assert b'Traceback' not in output
    finally:
        cleanup(pid, descriptor)


@pytest.mark.parametrize('destination,family,method', [
    ('127.0.0.1', 'ipv4', 'icmp'), ('::1', 'ipv6', 'udp'),
])
def test_real_loopback_traceroute(destination, family, method):
    if not shutil.which('traceroute'):
        pytest.skip('requires traceroute')

    line = (f'traceroute {destination} {family} {method} probes 1 wait 1 '
            'max-ttl 1 no-resolve dscp 46 size 100')
    result = subprocess.run([sys.executable, traceroute.__file__, 'traceroute', line],
                            capture_output=True, text=True, timeout=5)

    assert result.returncode == 0, result.stderr
    assert '100 byte packets' in result.stdout
    assert destination in result.stdout.splitlines()[-1]
