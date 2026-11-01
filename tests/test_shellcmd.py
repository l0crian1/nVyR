"""Administrator system commands, opaque argv and privileged-boundary checks."""

import asyncio
import os
from pathlib import Path
import pwd
import socket
import sys
import tempfile

import pytest

from nvyr.daemon import Server
from nvyr.errors import RouterError
from nvyr.helpers import access
from nvyr.helpers.process import CommandError
from nvyr.lexer import quote
from nvyr.op_scripts import shellcmd
from nvyr.protocol import Client, VERSION, encode, receive
from nvyr.schema import Schema
from tests.test_integration import daemon
from tests.test_process import spawn_terminal, read_until, cleanup


@pytest.mark.parametrize('line,expected', [
    ('shellcmd vtysh -c "show ip route"', ['vtysh', '-c', 'show ip route']),
    ('shellcmd sudo nft list ruleset', ['sudo', 'nft', 'list', 'ruleset']),
    ('ru shellc printf "%s" "" "a b"', ['printf', '%s', '', 'a b']),
    (r'shellcmd echo escaped\ space "literal | pipe"', ['echo', 'escaped space', 'literal | pipe']),
    ('shellcmd echo "$(id)" * > file ; echo', ['echo', '$(id)', '*', '>', 'file', ';', 'echo']),
    ('shellcmd echo "a|b" | match a', ['echo', 'a|b']),
    ('shellcmd "a command with spaces" --arg', ['a command with spaces', '--arg']),
])
def test_argv_keeps_original_boundaries(line, expected):
    assert shellcmd._argv(line) == expected


@pytest.mark.parametrize('line', ['', 'run', 'shellcmd', 'shellcmd ""', 'shellcmd "unfinished', 'shellcmd echo "\x00"'])
def test_invalid_input_never_executes(line, monkeypatch):
    monkeypatch.setattr(shellcmd, 'call', lambda *a, **kw: pytest.fail('executed invalid input'))

    with pytest.raises(RouterError):
        shellcmd.execute(line)


def test_uses_call_and_preserves_failure_status(monkeypatch):
    calls = []
    monkeypatch.setattr(shellcmd, 'call', lambda *a, **kw: calls.append((a, kw)) or 0)

    with pytest.raises(SystemExit) as success:
        shellcmd.execute('shellcmd vtysh -c "show ip route"')

    assert success.value.code == 0
    assert calls == [((['vtysh', '-c', 'show ip route'],),
                      {'new_process_group': False})]

    def fail(*args, **kwargs):
        return 7

    monkeypatch.setattr(shellcmd, 'call', fail)

    with pytest.raises(SystemExit) as error:
        shellcmd.execute('shellcmd false')

    assert error.value.code == 7


def test_schema_dispatch_help_and_other_commands_remain_strict(controller, session):
    for prefix, mode in [('', None), ('', session), ('run ', session)]:
        line = prefix + 'shellc vtysh -c "show ip route"'
        event = controller.execute(line, mode)

        assert event['argv'] == ['shellcmd.nvyr.op', 'execute', line]
        assert event['timeout'] is None

        controller.authorize_terminal(line, mode)

        assert '<Enter>' in dict(controller.completion(line, mode, explicit=True)['candidates'])
        assert '<Enter>' not in dict(controller.completion(prefix + 'shellcmd ', mode, explicit=True)['candidates'])
        assert controller.completion(prefix + 'shellc', mode, tab=True)['replacement'] == 'shellcmd'
        assert not controller.completion(prefix + 'shellcmd vtysh -unrecognized arbitrary ', mode, tab=True)['candidates']

        with pytest.raises(RouterError):
            controller.execute(prefix + 'shellcmd', mode)

    for line in ('show version extra', 'show interfaces eth0 statistics extra', 'ping 127.0.0.1 unknown'):
        with pytest.raises(RouterError):
            controller.execute(line)


@pytest.mark.parametrize('role', ['read-only', 'net-admin', 'sys-admin'])
def test_non_admin_denied_before_streaming_or_captured_execution(controller, session, role, monkeypatch):
    monkeypatch.setattr('nvyr.controller.cmd', lambda *a, **kw: pytest.fail('unauthorized execution'))
    token = access.role.set(role)

    try:
        for line in ('shellcmd id', 'shellc id', 'shellcmd id | count', 'shellcmd sh -c "id"'):
            with pytest.raises(RouterError, match='Permission denied'):
                controller.execute(line)

            with pytest.raises(RouterError, match='Permission denied'):
                controller.execute('run ' + line, session)

            with pytest.raises(RouterError, match='Permission denied'):
                controller.execute(line, session)

        assert 'shellcmd' not in dict(controller.completion('', explicit=True)['candidates'])
        assert '<Enter>' not in dict(controller.completion('shellcmd id', explicit=True)['candidates'])
        assert 'shellcmd' not in dict(controller.completion('', session, explicit=True)['candidates'])
        assert '<Enter>' not in dict(controller.completion('shellcmd id', session, explicit=True)['candidates'])
    finally:
        access.role.reset(token)


def test_old_command_removed_in_both_modes(controller, session):
    for prefix, mode in [('', None), ('', session), ('run ', session)]:
        with pytest.raises(RouterError, match='Unknown'):
            controller.execute(prefix + 'sudo id', mode)

        assert 'sudo' not in dict(controller.completion(prefix, mode, explicit=True)['candidates'])

    assert not (Path(__file__).resolve().parents[1] / 'src/nvyr/op_scripts/sudo.py').exists()


@pytest.mark.parametrize('node', [
    {'kind': 'node', 'command': {'argv': ['example']}},
    {'kind': 'leaf_node'},
    {'kind': 'leaf_node', 'valueless': True, 'command': {'argv': ['example']}},
])
def test_rest_requires_a_valued_operational_leaf(node):
    with pytest.raises(ValueError, match='rest requires'):
        Schema(dict(node, rest=True))


def test_installed_shellcmd_streams_argv_and_returns_exit_status(daemon):
    client = Client(daemon)
    program = 'import os,sys,json; print(os.geteuid(),json.dumps(sys.argv[1:])); sys.exit(7)'
    line = f'shellcmd {quote(sys.executable)} -c {quote(program)} "a b" "" "literal | text"'

    try:
        result = client.request('execute', text=line)

        assert result['returncode'] == 7
        assert result['text'].splitlines()[0] == f'{os.geteuid()} ["a b", "", "literal | text"]'
        assert 'Traceback' not in result['text']
        assert 'commit_id' in client.request('status')

        with pytest.raises(RouterError, match='not supported on streaming commands'):
            client.request('execute', text='shellcmd /bin/echo "hello world" | match hello')

        client.request('open')

        assert client.request('execute', text='run shellcmd /bin/true')['returncode'] == 0

        client.request('execute', text='set interfaces dummy dum0 description pending')
        client.request('execute', text='edit interfaces dummy dum0')
        result = client.request('execute', text='shellcmd /bin/echo "hello world"')

        assert result['returncode'] == 0 and result['text'].strip() == 'hello world'
        assert result['edit'] == ['interfaces', 'dummy', 'dum0']
        assert 'pending' in client.request('execute', text='show candidate-configuration')['text']

        with pytest.raises(RouterError, match='not supported on streaming commands'):
            client.request('execute', text='shellcmd /bin/echo test | count')

        result = client.request('execute', text='run shellcmd /not-an-installed-command')

        assert result['returncode'] != 0 and 'command not found' in result['text']
    finally:
        client.close()


@pytest.mark.parametrize('configuration_mode', [False, True])
def test_shellcmd_interactive_input_and_ctrl_c_preserve_session(daemon, configuration_mode):
    program = ('import signal,time; signal.signal(signal.SIGINT, lambda *args: exit(130)); '
               'print("READY",flush=True); print("GOT",input(),flush=True); time.sleep(30)')
    line = f'shellcmd {quote(sys.executable)} -c {quote(program)}'
    source = ('import termios; from nvyr.protocol import Client; from nvyr.cli import CLI; '
              f'client=Client({str(daemon)!r}); cli=CLI(client); before=termios.tcgetattr(0); '
              + ('cli.execute_line("configure"); ' if configuration_mode else '') +
              f'cli.execute_line({line!r}); '
              'print("RETURNED",cli.returncode,before==termios.tcgetattr(0),flush=True); '
              'print("SESSION", "commit_id" in client.request("status"),flush=True); client.close()')
    pid, descriptor = spawn_terminal(source)

    try:
        read_until(descriptor, b'READY')
        os.write(descriptor, b'hello\r')
        read_until(descriptor, b'GOT hello')
        os.write(descriptor, b'\x03')
        output = read_until(descriptor, b'SESSION True')

        assert b'RETURNED 130 True' in output and b'Traceback' not in output
    finally:
        cleanup(pid, descriptor)


@pytest.mark.parametrize('role', ['dev-admin', 'sys-admin', 'net-admin', 'read-only'])
def test_real_unprivileged_peer_cannot_forge_administrator_role(engine, role, monkeypatch):
    monkeypatch.setattr('nvyr.helpers.developer_access.enabled', lambda: True)
    if os.geteuid() != 0:
        pytest.skip('requires root to create an unprivileged client')

    user = pwd.getpwnam('nobody')
    engine.running = {'system': {'login': {'user': {user.pw_name: {'role': role}}}}}

    async def scenario(path):
        server = Server(engine)

        # Same installed script via module form, independent of test PATH symlinks.
        server.controller.operational.root['children']['shellcmd']['command']['argv'] = [
            sys.executable, '-m', 'nvyr.op_scripts.shellcmd', 'execute', '@line']
        listener = await asyncio.start_unix_server(server.handle, path=str(path))
        os.chmod(path, 0o666)
        code = f'''
import os
from nvyr.protocol import Client
from nvyr.errors import RouterError
assert os.geteuid() == {user.pw_uid}
c = Client({str(path)!r})
try:
    for line in ('shellcmd /usr/bin/id -u', 'shellc /usr/bin/id -u | match 0'):
        if {role!r} == 'dev-admin':
            if '|' in line:
                try: c.request('execute', text=line, role='dev-admin')
                except RouterError as e: assert 'not supported on streaming commands' in str(e)
                else: raise AssertionError('streaming pipe accepted')
            else:
                r = c.request('execute', text=line, role='dev-admin')
                assert r['text'].strip() == '0', r
        else:
            try: c.request('execute', text=line, role='dev-admin', user='root')
            except RouterError as e: assert 'Permission denied' in str(e)
            else: raise AssertionError('privilege bypass')
    print('CHECKED')
finally:
    c.close()
'''

        try:
            process = await asyncio.create_subprocess_exec(
                sys.executable, '-c', code, user=user.pw_uid, group=user.pw_gid, extra_groups=[],
                cwd='/', env={'PATH': '/usr/bin:/bin', 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')},
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
            stdout, stderr = await asyncio.wait_for(process.communicate(), 10)

            assert process.returncode == 0, stderr.decode()
            assert stdout == b'CHECKED\n'
        finally:
            listener.close()
            await listener.wait_closed()

    with tempfile.TemporaryDirectory(prefix='nvyr-shellcmd-') as directory:
        os.chmod(directory, 0o755)
        asyncio.run(scenario(Path(directory) / 'rpc.sock'))


@pytest.mark.parametrize('role', ['net-admin', 'read-only'])
@pytest.mark.parametrize('mode', ['operational', 'configuration', 'run'])
def test_demotion_after_attach_is_rechecked_before_privileged_launch(engine, tmp_path, role, mode, monkeypatch):
    monkeypatch.setattr('nvyr.helpers.developer_access.enabled', lambda: True)
    user = {'role': 'dev-admin'}
    engine.running = {'system': {'login': {'user': {'admin': user}}}}
    marker = tmp_path / 'must-not-run'

    async def scenario():
        server = Server(engine, identity=lambda writer: ('admin', 'test'))
        path = tmp_path / 'rpc.sock'
        listener = await asyncio.start_unix_server(server.handle, path=str(path))

        def client_work():
            sock = socket.socket(socket.AF_UNIX)
            sock.connect(str(path))

            try:
                if mode != 'operational':
                    sock.sendall(encode({'version': VERSION, 'id': 0, 'operation': 'open'}))

                    assert receive(sock)['done'] is True

                sock.sendall(encode({'version': VERSION, 'id': 1, 'operation': 'execute',
                                     'text': ('run ' if mode == 'run' else '') + f'shellcmd /usr/bin/touch {quote(str(marker))}'}))

                assert receive(sock)['terminal'] is True

                user['role'] = role
                sock.sendall(encode({'id': 1, 'terminal': 'start'}))

                assert 'Permission denied' in receive(sock)['error']['message']
                assert not marker.exists()
            finally:
                sock.close()

        try:
            await asyncio.to_thread(client_work)
        finally:
            listener.close()
            await listener.wait_closed()

    asyncio.run(scenario())
