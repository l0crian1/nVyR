# Serial and VGA consoles: implementation and maintenance

For configuration and command usage, see the [user guide](../users/serial-console.md).

## Integration

- `images/assemble.sh` adds `console=tty0 console=ttyS0,115200n8` to live, failsafe
  and installer kernel arguments. Kernel messages go to both consoles; the last
  console is `/dev/console`, so userspace startup status is primarily serial.
- GRUB is used for both BIOS and UEFI. Its menu enables serial input/output and
  retains VGA/keyboard operation. UEFI uses GRUB's graphics output to avoid firmware
  console redirection overlapping its explicit serial terminal. If serial initialization
  fails, the display console remains available.
- systemd's getty generator starts `serial-getty@ttyS0.service` for the active
  kernel console. The packaged template drop-in runs agetty at a fixed 115200 8N1,
  without hardware flow control or requiring modem carrier. There is no forced
  getty dependency on absent serial hardware and no separate serial CLI.
- The image manager writes installed GRUB entries with both kernel console arguments.
  Package configuration never runs `update-grub` over this managed menu. The existing
  `/etc/default/grub.d/20-nvyr-console.cfg` remains available for standalone Debian
  package deployments. See [installation](installation.md) for managed disk boots.

## Automated checks

On Linux, ordinary tests cover build staging, installed GRUB settings, the real
agetty login prompt and line settings, and interactive CLI sessions under both
VT100 and Linux terminal types:

```sh
PYTHONPATH=src python3 -m pytest -q tests/test_build_metadata.py tests/test_serial_console.py
```

agetty's test requires root and the standard Linux agetty executable. The CLI tests
use PTYs and an isolated configd with fake feature backends; they do not change
host networking.

The optional bootloader checks use QEMU, OVMF, live-build, grub-pc-bin,
grub-efi-amd64-bin, xorriso and mtools in the test
environment only:

```sh
NVYR_CONSOLE_BOOT_TEST=1 PYTHONPATH=src python3 -m pytest -q tests/test_console_boot_live.py
```

These boot tiny BIOS GRUB and UEFI GRUB test ISOs, interact over serial,
inspect VGA output and select a menu entry with a VGA keyboard. They do not replace
full ISO/kernel/login qualification on the target hardware.

## Manual full-image test

Build the ISO using the [normal image build](debian.md). In a desktop Linux test
environment with QEMU, keep the VGA window open and attach COM1 to the terminal:

```sh
qemu-system-x86_64 -m 2048 -cdrom dist/nvyr-0.1.0-amd64.iso -boot d -nic none -serial mon:stdio
```

For UEFI repeat with OVMF, using the firmware path supplied by your distribution:

```sh
qemu-system-x86_64 -m 2048 -cdrom dist/nvyr-0.1.0-amd64.iso -boot d -nic none -serial mon:stdio \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
```

1. Confirm the boot menu appears on both serial and VGA. Navigate from each and
   boot the live entry. Run `install image` for the guided disk installation.
2. Confirm kernel boot messages appear on both displays. On serial, log in and run
   `cat /proc/cmdline`, `systemctl status serial-getty@ttyS0`, and `stty -a`.
   Check `115200`, `cs8`, `-parenb`, `-cstopb`, `-crtscts` and `clocal`.
3. Run `nvyr`. Try `sho<Tab>version`, `?`, history arrows, `configure`,
   `set system host-name serial-test`, `compare`, `discard`, and `exit`. Exit the
   CLI and check that the shell still echoes input and accepts ordinary editing.
4. In VGA, verify password authentication and run the same CLI checks. Keep
   both sessions open to confirm one console does not disable the other.
5. Log out on serial and verify the login prompt returns. Reboot and repeat. Boot
   once without a connected serial terminal and verify VGA management still works.
6. On a GRUB-installed test system, check the generated menu contains both console
   arguments, then reboot and repeat the serial/VGA checks. On physical hardware,
   repeat with its serial port or matching BMC serial-over-LAN connection.

QEMU's `Ctrl-A X` exits the emulator; `Ctrl-A C` switches its terminal to the
monitor. These are emulator shortcuts, not nVyR CLI shortcuts.
