"""Opt-in end-to-end installation in disposable QEMU guests; never host disks.

NVYR_INSTALL_BOOT_TEST=1 NVYR_INSTALL_ISO=/path/nvyr.iso pytest -s tests/test_installation_boot_live.py
Requires QEMU, OVMF and a freshly built ISO. Artifacts/transcripts stay in pytest's tmp_path.
"""

import os
from pathlib import Path
import re
import select
import socket
import subprocess
import time

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_INSTALL_BOOT_TEST') != '1',
                                reason='requires a built ISO and disposable QEMU guests')


class Guest:
    def __init__(self, directory, iso, disk, *, firmware, live):
        self.directory = directory
        directory.mkdir()
        self.buffer = bytearray()
        self.log = (directory/'console.log').open('wb')
        self.errors = (directory/'qemu.log').open('w')
        serial = directory/'serial.sock'
        command = ['qemu-system-x86_64', '-accel', os.environ.get('NVYR_QEMU_ACCEL', 'tcg'), '-m', '1536', '-smp', '2',
                   '-display', 'none', '-nic', 'none', '-no-reboot',
                   '-drive', f'file={disk},format=raw,if=none,id=system',
                   '-device', f'virtio-blk-pci,drive=system,bootindex={2 if live else 1}',
                   '-drive', f'file={iso},format=raw,if=none,id=iso,media=cdrom,readonly=on',
                   '-device', f'ide-cd,drive=iso,bootindex={1 if live else 2}',
                   '-boot', 'd' if live else 'c', '-serial', f'unix:{serial},server=on,wait=on']

        if firmware == 'uefi':
            command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd']

        self.process = subprocess.Popen(command, stdout=self.errors, stderr=self.errors)
        deadline = time.monotonic()+15

        while not serial.exists():
            assert self.process.poll() is None
            assert time.monotonic() < deadline

            time.sleep(.05)

        self.serial = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.serial.connect(str(serial))

    def until(self, marker, timeout=360):
        deadline = time.monotonic()+timeout

        while marker not in self.buffer:
            assert self.process.poll() is None, self.buffer.decode(errors='replace')
            assert time.monotonic() < deadline, self.buffer.decode(errors='replace')

            if select.select([self.serial], [], [], .2)[0]:
                chunk = self.serial.recv(65536)
                self.log.write(chunk)
                self.log.flush()
                self.buffer.extend(chunk)

                if b'\x1b[6n' in chunk:
                    self.serial.sendall(b'\x1b[1;1R')

        end = self.buffer.index(marker)+len(marker)
        result = bytes(self.buffer[:end])
        del self.buffer[:end]

        return result

    def line(self, value):
        self.serial.sendall(value.encode()+b'\r')

    def login(self, password):
        self.until(b'login:')
        self.line('nvyr')
        self.until(b'Password:')
        self.line(password)
        self.until(b':~$')

    def command(self, text, expected=None):
        self.line(text)

        # A prompt also appears in input redraws. Wait for accept-line's terminal
        # handoff before looking for command output or the next actual prompt.
        self.until(b'\x1b[?2004l')

        if expected:
            self.until(expected)

        return self.until(b':~$')

    def cancel(self, text, prompt):
        self.line(text)
        self.until(prompt)
        self.serial.sendall(b'\x03')
        output = self.until(b':~$')

        assert b'Traceback' not in output and b'Operational command [' not in output
        assert b'interrupted' in output or b'cancelled' in output

    def stop(self):
        self.serial.close()
        self.process.terminate()
        self.process.wait(timeout=15)
        self.log.close()
        self.errors.close()

    def poweroff(self):
        self.line('shellcmd poweroff')

        # Continue emulating the serial terminal while prompt_toolkit completes
        # its redraw and the command starts. A bare wait() can deadlock CPR input.
        self.until(b'Power down', timeout=180)
        self.process.wait(timeout=20)


@pytest.mark.parametrize('firmware', ['bios', 'uefi'])
def test_fresh_install_reboot_and_independent_image_upgrade(tmp_path, firmware):
    iso = Path(os.environ['NVYR_INSTALL_ISO']).resolve(strict=True)
    disk = tmp_path/'disk.raw'

    with disk.open('wb') as stream:
        stream.truncate(8*1024**3)

    guest = Guest(tmp_path/'live', iso, disk, firmware=firmware, live=True)

    try:
        guest.login('nvyr')
        guest.cancel('install image', b'Continue? [y/N]')
        guest.line('install image')
        guest.until(b'Continue? [y/N]')
        guest.line('y')
        guest.until(b'Select [1]:')
        guest.line('1')
        guest.until(b'Installation mode:')
        guest.until(b'Select [1]:')
        guest.line('1')
        guest.until(b'Installation name [')
        guest.line('baseline')
        output = guest.until(b'Initial administrator username [nvyr]:')

        assert b'Initial configuration:' not in output  # Factory seed is not a user save.

        guest.line('nvyr')
        guest.until(b'Administrator password:')
        guest.line('install-test-password')
        guest.until(b'Confirm password:')
        guest.line('install-test-password')
        guest.until(b'ERASE ALL DATA ON THE SELECTED DISK:')
        guest.until(b'Proceed with this installation? [y/N]')
        guest.line('y')
        guest.until(b'Installed baseline.', timeout=240)
        guest.until(b':~$')
        guest.poweroff()
    finally:
        guest.stop()

    guest = Guest(tmp_path/'installed', iso, disk, firmware=firmware, live=False)

    try:
        guest.login('install-test-password')

        assert re.search(rb'baseline\s+Yes\s+Yes', guest.command('show system image'))

        guest.cancel('add system image unused.iso', b'Continue? [y/N]')
        guest.cancel('delete system image baseline', b'[y/N]')
        guest.command('shellcmd sh -c "echo invalid >/config/nvyr-images/bad.iso"')
        guest.line('add system image bad.iso')
        guest.until(b'Continue? [y/N]')
        guest.line('y')
        output = guest.until(b':~$')

        assert b'Image operation failed:' in output and b'Traceback' not in output
        assert b'Operational command [\'systemd-run\'' not in output

        # A guest-local HTTP server stalls after a partial response. Exercise the
        # actual configd -> PTY -> systemd worker cancellation path during IO.
        server = ("from http.server import HTTPServer, BaseHTTPRequestHandler as H; import time; "
                  "H.do_GET=lambda s: (s.send_response(200), s.send_header('Content-Length','100000000'), "
                  "s.end_headers(), s.wfile.write(b'partial'), time.sleep(120)); "
                  "HTTPServer(('127.0.0.1',8123),H).serve_forever()")
        guest.command('shellcmd systemd-run --quiet --unit=nvyr-test-download python3 -c "'+server+'"')
        guest.line('add system image http://127.0.0.1:8123/test.iso')
        guest.until(b'Continue? [y/N]')
        guest.line('y')
        guest.until(b'Downloading image...')

        # Give the worker time to enter the blocking HTTP read.
        time.sleep(1)
        guest.serial.sendall(b'\x03')
        output = guest.until(b':~$')

        assert b'interrupted' in output and b'Traceback' not in output and b'Operational command [' not in output

        guest.command('shellcmd systemctl stop nvyr-test-download')
        guest.command('shellcmd python3 -c "from pathlib import Path; assert not list(Path(\'/config/nvyr-images\').glob(\'*.part\')); print(\'no-partial-download\')"', b'no-partial-download')
        guest.command('shellcmd sh -c "echo overlay-persist >/etc/nvyr-test; echo config-persist >/config/user-file"')

        # Copy the actual ISO block device so add system image exercises local
        # source ownership and does not use a test-only installer entry point.
        guest.command('shellcmd dd if=/dev/sr0 of=/config/nvyr-images/test.iso bs=4M status=none')
        guest.line('add system image test.iso')
        guest.until(b'Continue? [y/N]')
        guest.line('y')
        guest.until(b'Installation name [')
        guest.line('upgrade')
        guest.until(b'Select [1]:')
        guest.line('1')
        guest.until(b'Transfer SSH host keys? [y/N]')
        guest.line('y')
        guest.until(b'Make the new image the default boot image? [y/N]')
        guest.line('y')
        guest.until(b'Proceed with this installation? [y/N]')
        guest.line('y')
        guest.until(b'Installed upgrade.', timeout=240)
        guest.until(b':~$')

        assert re.search(rb'upgrade\s+Yes', guest.command('show system image'))

        guest.poweroff()
    finally:
        guest.stop()

    guest = Guest(tmp_path/'upgrade', iso, disk, firmware=firmware, live=False)

    try:
        guest.login('install-test-password')

        assert re.search(rb'upgrade\s+Yes\s+Yes', guest.command('show system image'))

        guest.command('shellcmd cat /config/user-file', b'config-persist')
        guest.command('shellcmd sh -c "test ! -e /etc/nvyr-test && echo clean-root"', b'clean-root')
        guest.command('shellcmd sh -c "echo upgrade-only >/config/user-file"')
        guest.command('set system boot image baseline')
        guest.poweroff()
    finally:
        guest.stop()

    guest = Guest(tmp_path/'rollback', iso, disk, firmware=firmware, live=False)

    try:
        guest.login('install-test-password')
        guest.command('shellcmd cat /etc/nvyr-test /config/user-file', b'config-persist')

        assert re.search(rb'baseline\s+Yes\s+Yes', guest.command('show system image'))

        guest.command('rename system image upgrade to unused')
        guest.command('show system image', b'unused')
        guest.line('delete system image baseline')
        guest.until(b"Delete image 'baseline'")
        guest.until(b'[y/N]')
        guest.line('y')
        guest.until(b'Cannot delete the running or default boot image')
        guest.until(b':~$')
        guest.line('delete system image unused')
        guest.until(b"Delete image 'unused'")
        guest.until(b'[y/N]')
        guest.line('y')
        guest.until(b':~$')
        listing = guest.command('show system image')

        assert re.search(rb'baseline\s+Yes\s+Yes', listing) and b'unused' not in listing

        guest.poweroff()
    finally:
        guest.stop()
