# Installation and image management: implementation and maintenance

For configuration and command usage, see the [user guide](../users/installation.md).

## Reliability and implementation

The ISO carries `/nvyr/image.json`, containing build identity, supported layout and
configuration-format versions, architecture, payload sizes and SHA-256 hashes.
Installation validates it before making installation changes and verifies copied
payloads again. These hashes detect corruption, **not publisher authenticity**;
install only trusted images.

Schema declarations and callbacks are checked at build time using the matching
source code. The installer checks saved-file metadata and that retained recovery
records are readable JSON objects; it does not load the incoming schema or validate
configuration features using the running image's code. New validators, suggestors
and schema declarations therefore do not require a package update before installing
a newer image. Python from the incoming ISO is not executed by the installer.

The new image validates and applies the retained configuration with its own runtime
when it boots. Successful installation confirms image integrity and transfer, not
that every retained command is supported by the new image.

Images are staged privately and flushed before publication. The installed filesystem
contains `/boot/nvyr/generation-*/{catalog.json,grub.cfg}` and a `current` symlink.
One atomic, durable pointer replacement publishes the metadata and boot menu together.
The stable `/boot/grub/grub.cfg` sources that menu. Upgrades never reinstall shared
GRUB binaries or rewrite EFI variables. Interrupted publication can leave an unused
staging/generation directory or complete unreferenced image; it cannot expose an
incomplete image in the active menu. Such remnants may be inspected and removed by
an administrator while offline; do not remove catalog-referenced image directories.

The EFI fallback loader allows boot without depending on NVRAM registration. Keep
the disk's EFI fallback entry available in firmware. Physical firmware and storage
hardware still require qualification in addition to the VM regression tests.

Image operations use an exclusive filesystem lock. Configuration copying holds
configd's snapshot lock at a durable journal boundary; its existing recovery logic
handles a copied interrupted transaction. User applications modifying their own
files are not quiesced automatically. Stop such workloads for a consistent copy.
Migration providers in `helpers/image_migration.py` are the extension point for
future services needing additional data transfer or application-aware snapshots.

The operational script starts a root transient systemd service with an attached
PTY. This allows mounting/partitioning without weakening configd's sandbox. Ctrl+C
unwinds mounts and staging; do not kill power during an explicitly approved fresh
disk erase. Normal upgrades preserve all older image directories and boot paths.

General Debian APT sources are excluded from the SquashFS and automatic APT timers
are masked. Use image upgrades for the operating system; unmanaged package upgrades
are not supported.

## Verification

Unit tests: `pytest tests/test_images.py tests/test_build_metadata.py`.
GRUB BIOS/UEFI serial and VGA tests: `NVYR_CONSOLE_BOOT_TEST=1 pytest tests/test_console_boot_live.py`.
Full disposable VM installation/upgrade/rollback test:

```
NVYR_INSTALL_BOOT_TEST=1 NVYR_INSTALL_ISO=/path/to/nvyr.iso \
    pytest -s tests/test_installation_boot_live.py
```

Manual qualification: install onto a disposable disk using both BIOS and UEFI;
verify authenticated VGA/serial login, save and reboot a configuration, change an
OS file and a `/config` file, then add a new image. Verify transferred config/user
files and selected SSH-key behavior, clean new OS overlay, and unchanged old-image
files after rolling back. Exercise cancelling both confirmations, a corrupt ISO,
an out-of-space destination, interrupted addition, rename, default selection and
protected deletion. Check `show system image` against GRUB's menu each time.

Qualification on 2026-10-16 UTC used Debian 13 build containers and disposable QEMU
BIOS/OVMF guests. Both guests completed a real CLI installation, disk boot with the
chosen password, image addition, a boot into the new image, default selection and
rollback. `/config` files and credentials transferred; OS overlay changes remained
specific to their image, and rollback recovered the older image's original files.
An additional guest run verified rename, protected deletion and inactive-image deletion.
Separate GRUB tests verified serial input/output and VGA display/keyboard handling.

The installation refinements were additionally tested through both firmware paths:
factory seeds skip the retention prompt, image listings have independent running
and default columns, `rename ... to ...` updates the catalog, invalid ISOs return
readable errors, and Ctrl+C cancels prompts and a stalled HTTP download without a
traceback or subprocess diagnostic. Partial downloads are removed. Permission tests
use an unprivileged process to verify copying is allowed while writes, replacement,
and deletion of the saved file fail. The built ISO contains all requested diagnostic
tools (`dnsutils` is provided by Debian's `bind9-dnsutils` package).

Use a current QEMU/OVMF environment for VM qualification. The host's QEMU 6.2
encountered an early UEFI kernel panic; repeating the complete UEFI workflow with
Debian 13's QEMU 10.0.13 passed. This did not require changing the installed OS.

The loop-backed root currently produces busy-loop teardown messages during poweroff;
systemd remounts its ext4 storage read-only and synchronizes filesystems, and the reboot/persistence checks passed. Physical
hardware, abrupt power loss and Secure Boot have not been qualified.

## Saved configuration metadata

Saved JSON reserves `_nvyr` for file metadata. Its `factory` flag is `true` for
the factory seed and `false` after an explicit save or installer-selected
administrator credentials. Saved dependency metadata also lives in this object.
Configd and `load` remove it before using the configuration tree; it is not part of running configuration, scripts, or history.
Saved files require this metadata; `load` also accepts a raw JSON configuration tree.
Image upgrades preserve metadata, and all install/upgrade paths offer retention only for non-factory
saved files. Future file directives can live under `_nvyr` without adding CLI nodes.

## Persistent state binding

`/config/.nvyr` is private, root-owned 0700. At early boot it is bound to
`/var/lib/nvyr`, preserving configd history, recovery journals, durable login state,
account UID reservations, physical port naming and SSH keys before services start.
Custom development `--state` directories use `boot.json` unless `--saved` is supplied.
Only the selected saved path is read; files at other locations are not imported.
