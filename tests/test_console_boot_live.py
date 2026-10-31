"""Opt-in bootloader checks using tiny QEMU ISOs, without booting a router host.

Requires live-build, grub-pc-bin, grub-efi-amd64-bin,
xorriso, mtools, qemu-system-x86 and ovmf in the test environment only.
"""

import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(os.environ.get('NVYR_CONSOLE_BOOT_TEST') != '1',
                                reason='requires QEMU and Debian live-build bootloader tools')


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


@pytest.mark.parametrize('firmware', ['grub-bios', 'grub-uefi'])
def test_bootloader_serial_and_vga_input_output(tmp_path, firmware):
    image = tmp_path/'image'
    iso = tmp_path/'console.iso'
    grub = image/'boot/grub'
    grub.mkdir(parents=True)
    shutil.copy('/usr/share/grub/unicode.pf2', grub/'unicode.pf2')
    shutil.copy(ROOT/'images/bootloaders/grub-pc/config.cfg', grub/'config.cfg')
    (grub/'grub.cfg').write_text('source /boot/grub/config.cfg\nset timeout=-1\n'
                                'menuentry "nVyR console test" {\n echo vgakeyboardworks\n sleep 60\n}\n')
    run('grub-mkrescue', '-o', str(iso), str(image))

    serial_path, qmp_path = tmp_path/'serial.sock', tmp_path/'qmp.sock'
    command = ['qemu-system-x86_64', '-accel', 'tcg', '-m', '128', '-nic', 'none', '-display', 'none',
               '-cdrom', str(iso), '-boot', 'd', '-no-reboot',
               '-serial', f'unix:{serial_path},server=on,wait=on',
               '-qmp', f'unix:{qmp_path},server=on,wait=off']

    if firmware == 'grub-uefi':
        command += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd']

    log = (tmp_path/'qemu.log').open('w')
    process = subprocess.Popen(command, stdout=log, stderr=log)
    serial, qmp, reader = None, None, None

    try:
        deadline = time.monotonic()+15

        while not serial_path.exists():
            assert process.poll() is None, (tmp_path/'qemu.log').read_text()
            assert time.monotonic() < deadline

            time.sleep(.05)

        serial = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        serial.connect(str(serial_path))
        output = bytearray()

        def until(value, timeout=45):
            deadline = time.monotonic()+timeout

            while value not in output:
                assert process.poll() is None, output.decode(errors='replace')
                assert time.monotonic() < deadline, output.decode(errors='replace')

                if select.select([serial], [], [], .1)[0]:
                    output.extend(serial.recv(65536))

        until(b'nVyR console test')
        qmp = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        qmp.settimeout(10)
        qmp.connect(str(qmp_path))
        reader = qmp.makefile('rb')
        json.loads(reader.readline())

        def execute(name, arguments=None):
            qmp.sendall((json.dumps({'execute': name, 'arguments': arguments or {}})+'\n').encode())

            while True:
                response = json.loads(reader.readline())

                assert 'error' not in response, response

                if 'return' in response:
                    return response['return']

        execute('qmp_capabilities')
        snapshot = tmp_path/'vga.ppm'

        # The serial menu can arrive before the next display refresh.
        deadline = time.monotonic()+5

        while True:
            execute('screendump', {'filename': str(snapshot)})
            pixels = snapshot.read_bytes().split(b'\n', 3)[-1]
            if len(set(pixels)) > 2 or time.monotonic() >= deadline:
                break

            time.sleep(.1)

        # VGA has a rendered screen, not just a serial-only terminal. Keyboard
        # injection below also proves the VGA/console input terminal is active.
        assert len(set(pixels)) > 1

        output.clear()
        serial.sendall(b'c')
        until(b'grub>')
        output.clear()
        serial.sendall(b'echo serialworks\r')
        until(b'serialworks')
        serial.sendall(b'\x1b')
        output.clear()
        until(b'nVyR console test')
        output.clear()
        execute('send-key', {'keys': [{'type': 'qcode', 'data': 'ret'}]})
        until(b'vgakeyboardworks')
    finally:
        if reader:
            reader.close()

        if qmp:
            qmp.close()

        if serial:
            serial.close()

        process.terminate()
        process.wait(timeout=10)
        log.close()
