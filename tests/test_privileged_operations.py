"""Privileged operational execution, authenticated roles and terminal lifetime."""

import asyncio
import base64
import fcntl
import os
from pathlib import Path
import pwd
import signal
import socket
import struct
import sys
import tempfile
import termios
import time

import pytest

from nvyr.daemon import Server
from nvyr.errors import RouterError
from nvyr.protocol import Client, VERSION, encode, receive
from nvyr.schema import Schema
from tests.test_integration import daemon
from tests.test_process import spawn_terminal, read_until, cleanup


def schema(script, timeout=None):
    command = {'argv': [sys.executable, '-c', script], 'stream': True}

    if timeout is not None:
        command['timeout'] = timeout

    return {'kind': 'node', 'children': {
        'probe': {'kind': 'node', 'command': command},
        'shell': {'kind': 'node', 'command': 'shell'},
    }}


@pytest.mark.parametrize('role', ['sys-admin', 'net-admin', 'read-only'])
def test_real_unprivileged_peer_inherits_daemon_privileges_only_for_authorized_commands(engine, role):
    if os.geteuid() != 0:
        pytest.skip('requires root to create an unprivileged client')

    user = pwd.getpwnam('nobody')
    engine.running = {'system': {'login': {'user': {user.pw_name: {'role': role}}}}}

    # The nested cmd(), not just the operational wrapper, must inherit root and
    # be able to create the raw socket that failed in the original report.
    probe = ('import os,socket; '
             's=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP); '
             'print("PRIVILEGED",os.geteuid()); s.close()')
    wrapper = ('import sys; from nvyr.helpers.process import cmd; '
               f'cmd([sys.executable,"-c",{probe!r}],stream=True,new_process_group=False)')

    async def scenario(path):
        server = Server(engine)  # Real SO_PEERCRED; no claimed user/role is trusted.
        operational = schema(wrapper)
        operational['children']['captured'] = {
            'kind': 'node', 'command': {'argv': [sys.executable, '-c', wrapper]}}
        operational['children']['restricted'] = {
            'kind': 'node', 'access': 'sys-admin', 'command': {'argv': ['/bin/true']}}
        server.controller.operational = Schema(operational)
        listener = await asyncio.start_unix_server(server.handle, path=str(path))
        os.chmod(path, 0o666)
        code = f'''
import os, socket
from nvyr.protocol import Client
from nvyr.errors import RouterError
assert os.geteuid() == {user.pw_uid}
try:
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
except PermissionError:
    pass
else:
    raise AssertionError('test client unexpectedly has raw socket privileges')
c = Client({str(path)!r})
try:
    for name in ('probe', 'captured'):
        r = c.request('execute', text=name, role='sys-admin', argv=['/bin/false'])
        assert 'PRIVILEGED 0' in r['text'], r
        assert 'argv' not in r
    if {role!r} != 'sys-admin':
        try: c.request('execute', text='restricted', role='sys-admin', argv=['/bin/true'])
        except RouterError as e: assert 'Permission denied' in str(e)
        else: raise AssertionError('schema access bypassed by client-provided identity')
    try: c.request('execute', text='shell', role='dev-admin')
    except RouterError as e: assert 'Permission denied' in str(e)
    else: raise AssertionError('shell bypassed role checks')
    if {role!r} == 'read-only':
        try: c.request('open', role='sys-admin')
        except RouterError: pass
        else: raise AssertionError('operator opened configuration')
    else:
        c.request('open')
        assert 'PRIVILEGED 0' in c.request('execute', text='run probe')['text']
    try: c.request('execute', text='/bin/sh')
    except RouterError: pass
    else: raise AssertionError('arbitrary executable accepted')
    print('CHECKED')
finally:
    c.close()
'''

        try:
            process = await asyncio.create_subprocess_exec(
                '/usr/bin/python3', '-c', code, user=user.pw_uid, group=user.pw_gid,
                extra_groups=[], cwd='/', env={'PATH': '/usr/bin:/bin',
                    'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')},
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 10)

            assert process.returncode == 0, stderr.decode()
            assert stdout == b'CHECKED\n'
        finally:
            listener.close()
            await listener.wait_closed()

    with tempfile.TemporaryDirectory(prefix='nvyr-privilege-') as directory:
        os.chmod(directory, 0o755)
        asyncio.run(scenario(Path(directory) / 'configd.sock'))


TERMINAL_PROBE = '''
import os,signal,time
signal.signal(signal.SIGINT, lambda *args: exit(130))
signal.signal(signal.SIGWINCH, lambda *args: print('SIZE', *os.get_terminal_size(), flush=True))
print('READY', os.isatty(0), os.tcgetpgrp(0) == os.getpgrp(), flush=True)
print('GOT', input(), flush=True)
time.sleep(30)
'''


@pytest.mark.parametrize('daemon', [schema(TERMINAL_PROBE)], indirect=True)
def test_privileged_pty_streams_input_resize_ctrl_c_and_restores_cli(daemon):
    source = ('import termios; from nvyr.protocol import Client; from nvyr.cli import CLI; '
              f'c=Client({str(daemon)!r}); cli=CLI(c); before=termios.tcgetattr(0); '
              'cli.execute_line("probe"); '
              'print("RETURNED",cli.returncode,before==termios.tcgetattr(0),flush=True); '
              'print("STATUS", "commit_id" in c.request("status"),flush=True); '
              'print("AFTER",input(),flush=True); c.close()')
    pid, descriptor = spawn_terminal(source)

    try:
        output = read_until(descriptor, b'READY True True')

        assert b'RETURNED' not in output

        os.write(descriptor, b'hello\r')
        read_until(descriptor, b'GOT hello')
        fcntl.ioctl(descriptor, termios.TIOCSWINSZ, struct.pack('HHHH', 43, 132, 0, 0))
        os.kill(pid, signal.SIGWINCH)
        read_until(descriptor, b'SIZE 132 43')
        os.write(descriptor, b'\x03')
        output = read_until(descriptor, b'STATUS True')

        assert b'RETURNED 130 True' in output and b'Traceback' not in output

        os.write(descriptor, b'working\n')
        read_until(descriptor, b'AFTER working')
    finally:
        cleanup(pid, descriptor)


WAIT_PROBE = 'import os,time; print("PID",os.getpid(),flush=True); time.sleep(30)'


def stopped(pid):
    state = Path(f'/proc/{pid}/stat')
    return not state.exists() or state.read_text().split()[2] == 'Z'


@pytest.mark.parametrize('daemon', [schema(WAIT_PROBE, timeout=.3)], indirect=True)
def test_timeout_stops_privileged_process_and_preserves_connection(daemon):
    client, chunks = Client(daemon), []

    try:
        with pytest.raises(RouterError, match='did not finish'):
            client.request('execute', text='probe', on_text=chunks.append)

        pid = int(''.join(chunks).split()[1])

        assert stopped(pid)
        assert 'commit_id' in client.request('status')
    finally:
        client.close()


@pytest.mark.parametrize('daemon', [schema(WAIT_PROBE)], indirect=True)
def test_disconnect_stops_privileged_process(daemon):
    sock = socket.socket(socket.AF_UNIX)
    sock.connect(str(daemon))
    sock.sendall(encode({'version': VERSION, 'id': 1, 'operation': 'execute', 'text': 'probe'}))

    assert receive(sock)['terminal'] is True

    sock.sendall(encode({'id': 1, 'terminal': 'start'}))
    pid = int(receive(sock)['text'].split()[1])
    sock.close()
    deadline = time.monotonic() + 3

    while not stopped(pid) and time.monotonic() < deadline:
        time.sleep(.02)

    assert stopped(pid)

    client = Client(daemon)

    try:
        assert 'commit_id' in client.request('status')
    finally:
        client.close()


@pytest.mark.parametrize('daemon', [schema('print("COMPLETE",flush=True)')], indirect=True)
def test_terminal_finish_drains_late_input_before_next_rpc(daemon):
    sock = socket.socket(socket.AF_UNIX)
    sock.connect(str(daemon))

    try:
        sock.sendall(encode({'version': VERSION, 'id': 1, 'operation': 'execute', 'text': 'probe'}))

        assert receive(sock)['terminal'] is True

        sock.sendall(encode({'id': 1, 'terminal': 'start'}))

        while not receive(sock).get('terminal_end'):
            pass

        sock.sendall(encode({'id': 1, 'terminal': 'input', 'data': base64.b64encode(b'late').decode()}))
        sock.sendall(encode({'id': 1, 'terminal': 'finish'}))

        assert receive(sock)['result']['returncode'] == 0

        sock.sendall(encode({'version': VERSION, 'id': 2, 'operation': 'status'}))

        assert receive(sock)['done'] is True
    finally:
        sock.close()


def test_ping_runs_through_privileged_rpc_with_live_output(daemon):
    client = Client(daemon)

    try:
        for address, family in [('127.0.0.1', 'ipv4'), ('::1', 'ipv6')]:
            chunks = []
            result = client.request('execute', text=f'ping {address} {family} count 1 numeric',
                                    on_text=chunks.append)

            assert result['returncode'] == 0
            assert '1 received' in ''.join(chunks)

        assert 'commit_id' in client.request('status')
    finally:
        client.close()


def test_account_revoked_during_terminal_attach_cannot_launch(engine, tmp_path):
    engine.running = {'system': {'login': {'user': {'reader': {'role': 'read-only'}}}}}
    marker = tmp_path / 'must-not-run'

    async def scenario():
        server = Server(engine, identity=lambda writer: ('reader', 'test-tty'))
        server.controller.operational = Schema(schema(f'open({str(marker)!r}, "w").write("bad")'))
        path = tmp_path / 'rpc.sock'
        listener = await asyncio.start_unix_server(server.handle, path=str(path))

        def client_work():
            sock = socket.socket(socket.AF_UNIX)
            sock.connect(str(path))

            try:
                sock.sendall(encode({'version': VERSION, 'id': 1, 'operation': 'execute', 'text': 'probe'}))

                assert receive(sock)['terminal'] is True

                engine.running['system']['login']['user'].pop('reader')
                sock.sendall(encode({'id': 1, 'terminal': 'start'}))

                assert 'not authorized' in receive(sock)['error']['message']
                assert not marker.exists()
            finally:
                sock.close()

        try:
            await asyncio.to_thread(client_work)
        finally:
            listener.close()
            await listener.wait_closed()

    asyncio.run(scenario())
