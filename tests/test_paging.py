"""Client-local paging, pipeline composition and real terminal behavior."""

import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
from types import SimpleNamespace

import pytest

from nvyr.cli import CLI
from nvyr.errors import RouterError
from nvyr.helpers import pager
from nvyr.protocol import Client, encode, receive
from tests.test_integration import daemon


def read_pager_screen(descriptor):
    """Read a complete screen and wait for less to block for terminal input."""
    from tests.test_process import read_until

    output = read_until(descriptor, b'q: quit')
    process = os.tcgetpgrp(descriptor)
    deadline = time.monotonic() + 5

    # less flushes the prompt before entering its input wait. A signal in that
    # gap can remain pending until another keystroke. On these Linux PTY tests,
    # a sleeping foreground pager after its output was drained is ready for input.
    while time.monotonic() < deadline:
        state = Path(f'/proc/{process}/stat').read_text().rsplit(')', 1)[1].split()[0]
        if state == 'S':
            return output

        time.sleep(.001)

    pytest.fail('Pager did not become ready for terminal input')


@pytest.mark.parametrize('modifier,enabled', [('more', True), ('no-more', False)])
def test_paging_modifiers_preserve_config_and_operational_output(controller, session, modifier, enabled):
    controller.execute('set system host-name paged-router', session)
    for command, mode in [('show | commands', session), ('compare | commands', session),
                          ('show version', None), ('run show version', session)]:
        original = controller.execute(command, mode)
        result = controller.execute(command + ' | ' + modifier, mode)
        assert result['text'] == original['text']
        assert result['paging'] is enabled

    result = controller.execute('show | commands | match paged-router | count | ' + modifier, session)
    assert result['text'] == '1\n'
    assert result['paging'] is enabled
    assert controller.completion('show version | ' + modifier + ' | ', explicit=True)['candidates'] == []


@pytest.mark.parametrize('suffix', ['more | count', 'no-more | more', 'more | export file',
                                  'export file | more', 'more extra'])
def test_paging_is_a_terminal_modifier(controller, suffix):
    with pytest.raises(RouterError):
        controller.execute('show version | ' + suffix)


def test_paging_completion_and_stream_rejection(controller, session):
    assert {'more', 'no-more'} <= dict(controller.completion('show version | ')['candidates']).keys()
    assert controller.completion('show version | no', tab=True)['replacement'] == 'no-more'
    for modifier in ('more', 'no-more'):
        with pytest.raises(RouterError, match='streaming commands'):
            controller.execute('ping 127.0.0.1 | ' + modifier)
        with pytest.raises(RouterError, match='configuration-changing'):
            controller.execute('set system host-name router | ' + modifier, session)


def test_terminal_length_dispatch_validation_and_completion(controller, session):
    from tests.test_login import as_role

    with as_role('read-only'):
        result = controller.execute('set terminal length 20')
        assert result['event'] == 'terminal-length' and result['length'] == 20
        assert result['text'] == ''

        with pytest.raises(RouterError, match='net-admin'):
            controller.execute('set system boot image test-image')

    with as_role('net-admin'):
        result = controller.execute('set system boot image test-image')
        assert result['event'] == 'command'
        assert result['argv'] == ['images.nvyr.op', 'select', 'test-image']

    result = controller.execute('run set terminal length 0', session)
    assert result['event'] == 'terminal-length' and result['length'] == 0
    assert 'terminal' in dict(controller.completion('set ')['candidates'])
    assert controller.completion('set terminal l', tab=True)['replacement'] == 'length'
    assert controller.completion('set terminal length ', explicit=True)['hints']

    for value in ('', '-1', '1.5', 'abc', '10 extra'):
        with pytest.raises(RouterError):
            controller.execute('set terminal length ' + value)

    with pytest.raises(RouterError, match='cannot be piped'):
        controller.execute('set terminal length 20 | more')


@pytest.mark.parametrize('length', [0, 5, 20])
@pytest.mark.parametrize('paging', [None, True, False])
def test_terminal_length_controls_session_output(controller, monkeypatch, capsys, length, paging):
    monkeypatch.setattr(pager, 'interactive', lambda: True)
    pages = []
    monkeypatch.setattr(pager, 'show', lambda path, **kw: pages.append(kw['length']))

    def request(operation, *, text, on_text, **kwargs):
        if text.startswith('set terminal'):
            return controller.execute(text)

        on_text('output\n')
        return {'paging': paging}

    cli = CLI(SimpleNamespace(request=request))
    cli.execute_line(f'set terminal length {length}')
    assert cli.terminal_length == length
    should_page = paging is not False and (length != 0 or paging is True)

    for mode, command in [(None, 'show version'), ('normal', 'show')]:
        cli.mode = mode
        cli.execute_line(command)
        assert capsys.readouterr().out == ('' if should_page else 'output\n')

    assert pages == ([length or None] * 2 if should_page else [])
    assert CLI(SimpleNamespace(request=request)).terminal_length is None


def test_explicit_pager_length_overrides_environment(monkeypatch):
    monkeypatch.setenv('LESS_LINES', '99')
    calls = []
    monkeypatch.setattr(pager, 'call', lambda argv, **kw: calls.append(kw) or 0)
    pager.show('/tmp/output', length=20)
    assert calls[0]['env']['LESS_LINES'] == '21'


@pytest.mark.parametrize('length', [1, 5, 20])
def test_real_pager_uses_configured_output_line_count(tmp_path, length):
    from tests.test_process import spawn_terminal, read_until, cleanup

    if not shutil.which('less'):
        pytest.skip('requires less')

    version = subprocess.check_output(['less', '--version'], text=True).split()[1]
    if int(version) < 668:
        pytest.skip('requires packaged dependency less >= 668 for LESS_LINES')

    path = tmp_path / 'output'
    path.write_text(''.join(f'ROW_{i:03d}\n' for i in range(100)))
    source = ('import os,fcntl,termios,struct; from nvyr.helpers.pager import show; '
              'os.environ["TERM"]="xterm"; '
              'fcntl.ioctl(0,termios.TIOCSWINSZ,struct.pack("HHHH",30,80,0,0)); '
              f'show({str(path)!r}, length={length}); print("RETURNED",flush=True)')
    pid, descriptor = spawn_terminal(source)
    try:
        first = read_pager_screen(descriptor)
        assert f'ROW_{length - 1:03d}'.encode() in first
        assert f'ROW_{length:03d}'.encode() not in first
        os.write(descriptor, b'q')
        read_until(descriptor, b'RETURNED')
    finally:
        cleanup(pid, descriptor)


@pytest.mark.parametrize('enabled', [None, True, False])
def test_cli_pages_only_after_request_completes_and_cleans_up(monkeypatch, capsys, enabled):
    monkeypatch.setattr(pager, 'interactive', lambda: True)
    completed, files = [], []

    def request(operation, *, on_text, on_terminal, **kwargs):
        on_text('first\n')
        on_text('last\n')
        completed.append(True)
        return {'paging': enabled}

    def show(path, *, length=None):
        assert completed
        assert Path(path).stat().st_mode & 0o777 == 0o600
        assert Path(path).read_text() == 'first\nlast\n'
        files.append(path)

    monkeypatch.setattr(pager, 'show', show)
    CLI(SimpleNamespace(request=request)).execute_line('show version')

    assert capsys.readouterr().out == ('first\nlast\n' if enabled is False else '')
    assert bool(files) is (enabled is not False)
    assert all(not Path(path).exists() for path in files)


def test_redirected_output_and_commit_feedback_bypass_paging(monkeypatch, capsys):
    monkeypatch.setattr(pager, 'show', lambda path, **kwargs: pytest.fail('Unexpected pager'))
    monkeypatch.setattr(pager, 'interactive', lambda: False)

    def request(operation, *, on_text, **kwargs):
        on_text('output\n')
        return {'paging': True}

    cli = CLI(SimpleNamespace(request=request))
    cli.execute_line('show version | more')
    assert capsys.readouterr().out == 'output\n'

    monkeypatch.setattr(pager, 'interactive', lambda: True)
    cli.mode = 'normal'
    cli.execute_line('commit')
    assert capsys.readouterr().out == 'output\n'


def test_streaming_text_bypasses_paging(monkeypatch, capsys):
    monkeypatch.setattr(pager, 'interactive', lambda: True)
    monkeypatch.setattr(pager, 'show', lambda path, **kwargs: pytest.fail('Unexpected pager'))

    def request(operation, *, on_terminal, **kwargs):
        on_terminal('FIRST_REPLY\n')
        assert capsys.readouterr().out == 'FIRST_REPLY\n'
        return {'event': 'command', 'returncode': 0}

    CLI(SimpleNamespace(request=request)).execute_line('ping 127.0.0.1')


def test_protocol_separates_terminal_text_without_changing_default_callers(monkeypatch):
    from nvyr.helpers import terminal

    client, server = socket.socketpair()
    rpc = Client.__new__(Client)
    rpc.socket, rpc.counter = client, 0

    def attach(sock, request_id, output):
        output('live\n')
        return {'id': request_id, 'done': True, 'result': {'event': 'command', 'returncode': 0}}

    monkeypatch.setattr(terminal, 'attach', attach)
    try:
        for callback in (False, True):
            regular, live = [], []
            server.sendall(encode({'id': rpc.counter + 1, 'terminal': True}))
            result = rpc._request('execute', text='ping 127.0.0.1', on_text=regular.append,
                                  on_terminal=live.append if callback else None)
            request = receive(server)
            assert 'on_terminal' not in request
            assert result['returncode'] == 0
            assert regular == ([] if callback else ['live\n'])
            assert live == (['live\n'] if callback else [])
    finally:
        client.close()
        server.close()


def test_rpc_remains_usable_after_pager_quits_and_export_skips_pager(daemon, tmp_path, monkeypatch):
    monkeypatch.setattr(pager, 'interactive', lambda: True)
    pages = []
    monkeypatch.setattr(pager, 'show', lambda path, **kwargs: pages.append(Path(path).read_text()))
    client = Client(daemon)
    try:
        cli = CLI(client)
        cli.execute_line('show version | more')
        cli.execute_line('show version')
        assert len(pages) == 2 and pages[0] == pages[1]
        target = tmp_path / 'export.txt'
        cli.execute_line(f'show version | export {target}')
        assert target.read_text() == pages[0]
        assert len(pages) == 2
        assert 'commit_id' in client.request('status')
    finally:
        client.close()


def test_pager_environment_does_not_allow_user_overrides(monkeypatch):
    for key in ('LESS', 'LESSOPEN', 'LESSCLOSE', 'LESSKEY_CONTENT', 'LESSSECURE_ALLOW'):
        monkeypatch.setenv(key, 'unwanted')
    calls = []
    monkeypatch.setattr(pager, 'call', lambda argv, **kw: calls.append((argv, kw)) or 0)
    pager.show('/tmp/output')
    argv, options = calls[0]
    assert argv[0] == 'less' and argv[-2:] == ['--', '/tmp/output']
    assert {key: value for key, value in options['env'].items() if key.startswith('LESS')} == {
        'LESSSECURE': '1', 'LESSHISTFILE': '-'}


@pytest.mark.parametrize('status', [0, 2, 130, 1])
def test_pager_quit_and_error_status(monkeypatch, status):
    monkeypatch.setattr(pager, 'call', lambda *a, **kw: status)
    if status == 1:
        with pytest.raises(RouterError, match='no-more'):
            pager.show('/tmp/output')
    else:
        pager.show('/tmp/output')


@pytest.mark.parametrize('quit_key', [b'q', b'\x03'])
def test_real_pager_search_resize_and_clean_quit(tmp_path, quit_key):
    import fcntl
    import struct
    import termios
    from tests.test_process import spawn_terminal, read_until, cleanup

    if not shutil.which('less'):
        pytest.skip('requires less')
    path = tmp_path / 'output'
    path.write_text(''.join(f'ROW_{i:03d}\n' for i in range(200)))
    source = ('import os,fcntl,termios,struct; from nvyr.helpers.pager import show; '
              'os.environ["TERM"]="xterm"; '
              'fcntl.ioctl(0,termios.TIOCSWINSZ,struct.pack("HHHH",10,80,0,0)); '
              f'show({str(path)!r}); '
              'print("RETURNED",os.tcgetpgrp(0)==os.getpgrp(),flush=True); '
              'print("INPUT",input(),flush=True)')
    pid, descriptor = spawn_terminal(source)
    try:
        first = read_pager_screen(descriptor)
        assert b'ROW_000' in first and b'ROW_199' not in first

        os.write(descriptor, b'/ROW_150\n')
        searched = read_pager_screen(descriptor)
        assert b'ROW_151' in searched

        fcntl.ioctl(descriptor, termios.TIOCSWINSZ, struct.pack('HHHH', 15, 100, 0, 0))
        resized = read_pager_screen(descriptor)
        assert b'ROW_163' in resized

        os.write(descriptor, quit_key)
        output = read_until(descriptor, b'RETURNED True')
        assert b'Traceback' not in output
        os.write(descriptor, b'after-pager\n')
        read_until(descriptor, b'INPUT after-pager')
    finally:
        cleanup(pid, descriptor)


@pytest.mark.parametrize('end_key', [b' ', b'G'])
def test_real_pager_final_page_returns_without_quit(tmp_path, end_key):
    from tests.test_process import spawn_terminal, read_until, cleanup

    if not shutil.which('less'):
        pytest.skip('requires less')

    path = tmp_path / 'output'
    path.write_text(''.join(f'ROW_{i:03d}\n' for i in range(16)))
    source = ('import os,fcntl,termios,struct; from nvyr.helpers.pager import show; '
              'os.environ["TERM"]="xterm"; '
              'fcntl.ioctl(0,termios.TIOCSWINSZ,struct.pack("HHHH",10,80,0,0)); '
              f'show({str(path)!r}); '
              'print("RETURNED",os.tcgetpgrp(0)==os.getpgrp(),flush=True); '
              'print("INPUT",input(),flush=True)')
    pid, descriptor = spawn_terminal(source)
    try:
        first = read_pager_screen(descriptor)
        assert b'ROW_000' in first and b'ROW_015' not in first

        os.write(descriptor, end_key)
        output = read_until(descriptor, b'RETURNED True')
        assert b'ROW_015' in output and b'Traceback' not in output

        os.write(descriptor, b'after-pager\n')
        read_until(descriptor, b'INPUT after-pager')
    finally:
        cleanup(pid, descriptor)


def test_real_pager_short_output_exits_without_input(tmp_path):
    from tests.test_process import spawn_terminal, read_until, cleanup

    if not shutil.which('less'):
        pytest.skip('requires less')
    path = tmp_path / 'short'
    path.write_text('SHORT_OUTPUT\n')
    pid, descriptor = spawn_terminal(
        'import os; from nvyr.helpers.pager import show; os.environ["TERM"]="xterm"; '
        f'show({str(path)!r}); print("RETURNED",flush=True)')
    try:
        assert b'SHORT_OUTPUT' in read_until(descriptor, b'RETURNED')
    finally:
        cleanup(pid, descriptor)
