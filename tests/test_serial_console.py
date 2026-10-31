"""Console transport checks; no special CLI implementation for serial sessions."""

import fcntl
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import struct
import subprocess
import sys
import termios
import time

import pytest

from nvyr.protocol import Client
from tests.test_integration import daemon  # Reuse the isolated, real configd fixture.

ROOT = Path(__file__).resolve().parents[1]


def test_installed_grub_settings_preserve_other_kernel_arguments():
    path = ROOT/'packaging/20-nvyr-console.cfg'
    result = subprocess.run(['sh', '-c', 'GRUB_CMDLINE_LINUX=root=UUID=test; . "$1"; '
                             'printf "%s\\n" "$GRUB_CMDLINE_LINUX" "$GRUB_TERMINAL_INPUT" '
                             '"$GRUB_TERMINAL_OUTPUT" "$GRUB_SERIAL_COMMAND"', 'test', str(path)],
                            check=True, text=True, capture_output=True)
    lines = result.stdout.splitlines()

    assert lines[0] == 'root=UUID=test console=tty0 console=ttyS0,115200n8'
    assert lines[1:3] == ['console serial', 'console serial']
    assert lines[3] == 'serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1'


@pytest.mark.skipif(os.geteuid() != 0 or shutil.which('agetty') is None,
                    reason='requires root and the standard Linux getty')
def test_serial_getty_login_prompt_and_115200_8n1():
    lines = (ROOT/'packaging/20-nvyr-serial.conf').read_text().splitlines()
    command = next(line.removeprefix('ExecStart=-') for line in lines if line.startswith('ExecStart=-'))

    # systemd unescapes the literal backslash before passing agetty's login options.
    args = shlex.split(command.replace('\\\\', '\\'))
    master, slave = os.openpty()
    process = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
    data = bytearray()

    try:
        deadline = time.monotonic()+5

        while b'login:' not in data:
            assert process.poll() is None, data.decode(errors='replace')
            assert time.monotonic() < deadline, data.decode(errors='replace')

            if select.select([master], [], [], .1)[0]:
                data.extend(os.read(master, 65536))

        settings = termios.tcgetattr(slave)

        assert settings[4:6] == [termios.B115200, termios.B115200]
        assert settings[2] & termios.CSIZE == termios.CS8
        assert not settings[2] & (termios.PARENB | termios.CSTOPB | termios.CRTSCTS)
        assert args[-1] == 'vt100' and '--autologin' not in args
    finally:
        process.terminate()
        process.wait(timeout=5)
        os.close(master)
        os.close(slave)


@pytest.mark.parametrize('terminal', ['vt100', 'linux'])
def test_actual_cli_pty_completion_modes_history_and_terminal_restore(daemon, tmp_path, terminal):
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
    original = termios.tcgetattr(slave)
    process = subprocess.Popen([sys.executable, '-m', 'nvyr.cli', '--socket', str(daemon),
                                '--history-directory', str(tmp_path/'history')],
                               stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
                               env=dict(os.environ, TERM=terminal))
    output = bytearray()

    def pump():
        if select.select([master], [], [], .05)[0]:
            chunk = os.read(master, 65536)
            output.extend(chunk)

            # A serial VT100 emulator responds to cursor-position queries. PTYs
            # have no emulator attached, so provide that standard response here.
            if b'\x1b[6n' in chunk:
                os.write(master, b'\x1b[1;1R')

    def until(predicate):
        deadline = time.monotonic() + 8

        while not predicate():
            pump()

            assert process.poll() is None, output.decode(errors='replace')
            assert time.monotonic() < deadline, output.decode(errors='replace')

    def send(value):
        os.write(master, value)

    client = Client(daemon)

    try:
        until(lambda: b':~$' in output)
        output.clear()
        send(b'sho\tversion\r')
        until(lambda: b'Build date |' in output)
        output.clear()
        send(b'configure\r')
        until(lambda: b'#' in output)
        output.clear()
        send(b'set system host-na\tserial-test\r')
        until(lambda: b'serial-test' in output)

        # Commands are per-session; a commit verifies completion actually produced
        # a valid mutation in this CLI's session, not just plausible screen output.
        send(b'commit\r')
        until(lambda: json.loads(client.request('execute', text='show running-configuration')['text']).get('system', {}).get('host-name') == 'serial-test')
        output.clear()
        send(b'\x1b[A\r')  # Arrow-up history recalls commit without needing a GUI.
        until(lambda: b'#' in output)
        output.clear()
        send(b'exit\r')
        until(lambda: b':~$' in output)
        send(b'\x04')
        deadline = time.monotonic()+5

        while process.poll() is None and time.monotonic() < deadline:
            pump()

        assert process.wait(timeout=2) == 0
        assert termios.tcgetattr(slave) == original
        assert b'Traceback' not in output
    finally:
        client.close()

        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)

        os.close(master)
        os.close(slave)
