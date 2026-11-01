"""Guided disk/image installation. Run as root outside configd's service sandbox."""

from contextlib import contextmanager
from functools import partial
import fcntl
import getpass
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import uuid

from nvyr.errors import RouterError
from nvyr.helpers import image_migration
from nvyr.helpers.images import Images, STORAGE, SAVED, image_name, verify_media
from nvyr.helpers.passwords import hash_password
from nvyr.helpers.process import cmd, run, rc_cmd
from nvyr.helpers.template import write
from nvyr.storage import has_saved_configuration

ARCHIVE = Path('/config/nvyr-images')


@contextmanager
def installation_lock():
    with os.fdopen(os.open('/run/lock/nvyr-install.lock', os.O_CREAT | os.O_RDWR, 0o600), 'a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RouterError('Another image installation is already in progress') from None

        yield


def confirm(message):
    return input(message+' [y/N] ').strip().lower() == 'y'


def confirm_vanished(issues, destination):
    """Offer an explicit override only for rsync's vanished-source warning."""
    print('\nFiles disappeared while copying persistent data.')
    for source, _, output in issues:
        print(f'\nSource: {source}')
        print(output.strip() or 'rsync reported vanished source files (exit 24).')

    affected = image_migration.affected_containers(issues, destination)
    for name, volume, source in affected:
        print(f'Affected container: {name}; volume: {volume}; source: {source}')

    print('\nThe copied application data may be incomplete or inconsistent.')
    print('Recommended: decline, disable the affected containers in configuration, commit, and retry installation.')
    for name in sorted({name for name, _, _ in affected}):
        print(f'  set container name {name} disable')
    if affected:
        print('  commit')
    print('Do not save the disabled state unless you also want it disabled after reboot.')
    return confirm('Continue with this copy anyway?')


def choose(message, choices, default=0):
    print(message)

    for number, label in enumerate(choices, 1):
        print(f'  {number}. {label}')

    while True:
        value = input(f'Select [{default+1}]: ').strip() or str(default+1)
        if value.isdecimal() and 1 <= int(value) <= len(choices):
            return int(value)-1

        print('Enter one of the listed numbers.')


@contextmanager
def mounted(device, *, options='ro,noload', filesystem=None):
    with tempfile.TemporaryDirectory(prefix='nvyr-mount-', dir='/run') as directory:
        argv = ['mount', '-o', options]

        if filesystem:
            argv += ['-t', filesystem]

        if run([*argv, '--', str(device), directory], timeout=60):
            raise RouterError(f'Could not mount {device}')

        try:
            yield Path(directory)
        finally:
            # Never lazily unmount: an installation must finish its filesystem IO.
            if run(['umount', '--', directory], timeout=None):
                raise RouterError(f'Could not unmount {device}; installation is incomplete')


def inventory():
    return json.loads(cmd(['lsblk', '--json', '--bytes', '--paths', '-o',
                          'NAME,TYPE,SIZE,VENDOR,MODEL,TRAN,SERIAL,RM,RO,MOUNTPOINTS,FSTYPE,UUID,MAJ:MIN']))['blockdevices']


def descendants(device):
    yield device

    for child in device.get('children', []):
        yield from descendants(child)


def eligible_disks(devices):
    result = []

    for disk in devices:
        # Excludes the boot medium, mounted partitions, swap, LVM/RAID consumers,
        # readonly devices and identifiable removable USB sticks.
        if (disk['type'] != 'disk' or disk['ro'] or disk['size'] < 4*1024**3
                or (disk['rm'] and disk.get('tran') == 'usb')):
            continue

        if any(any(node.get('mountpoints') or []) or node['type'] not in ('disk', 'part')
               for node in descendants(disk)):
            continue

        result.append(disk)

    return result


def disk_label(disk):
    details = ' | '.join(str(disk.get(key) or 'unknown').strip() for key in ('vendor', 'model', 'tran', 'serial'))
    return f"{disk['name']} | {disk['size']/1024**3:.1f} GiB | {details}"


def recheck_disk(original):
    disk = next((disk for disk in eligible_disks(inventory()) if disk['name'] == original['name']), None)
    if disk is None or any(disk.get(key) != original.get(key) for key in ('size', 'serial', 'maj:min')):
        raise RouterError('The selected disk changed or became mounted; installation cancelled')

    return disk


def existing_installation(disk):
    found = []

    for node in descendants(disk):
        if node.get('fstype') != 'ext4':
            continue

        status, header = rc_cmd(['dumpe2fs', '-h', node['name']], env=os.environ | {'LC_ALL': 'C'})
        if status:
            raise RouterError(f"Could not inspect filesystem {node['name']}")

        if 'needs_recovery' in header:
            raise RouterError(f"{node['name']} needs filesystem journal recovery. Boot and cleanly shut down its installed system, or repair it offline, before retrying")

        with mounted(node['name']) as root:
            pointer = root/'boot/nvyr/current'
            if pointer.exists() or pointer.is_symlink():
                catalog = Images(root).catalog()  # Corrupt installs must not be mistaken for empty disks.
                found.append((node['name'], catalog))

    if len(found) > 1:
        raise RouterError('Multiple nVyR installations found on this disk; select an unambiguous target')

    return found[0] if found else None


def live_media():
    for path in (Path('/run/live/medium'), Path('/lib/live/mount/medium')):
        if (path/'nvyr/image.json').is_file():
            return path

    raise RouterError('install image requires a booted nVyR live ISO; use add system image on an installed system')


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        newurl = urllib.parse.urljoin(request.full_url, newurl)
        scheme = urllib.parse.urlsplit(newurl).scheme
        if scheme not in ('http', 'https') or (request.type == 'https' and scheme != 'https'):
            raise RouterError('Refusing an unsafe image download redirect')

        return super().redirect_request(request, fp, code, message, headers, newurl)


def acquire(source):
    """Called only after initial approval. Return (ISO path, automatically downloaded)."""
    parsed = urllib.parse.urlsplit(source)
    if parsed.scheme in ('http', 'https'):
        if parsed.username or parsed.password or not parsed.hostname:
            raise RouterError('Image URL must have a host and no embedded credentials')

        ARCHIVE.mkdir(parents=True, exist_ok=True)
        target = ARCHIVE/('download-'+uuid.uuid4().hex+'.iso')
        temporary = target.with_suffix('.part')
        print('Downloading image...')

        try:
            with urllib.request.build_opener(SafeRedirect()).open(source, timeout=30) as response, temporary.open('xb') as output:
                os.chmod(temporary, 0o600)
                received = 0

                while block := response.read(1024*1024):
                    if shutil.disk_usage(ARCHIVE).free < len(block)+64*1024**2:
                        raise RouterError('Insufficient free space for the ISO download')

                    output.write(block)
                    received += len(block)

                expected = response.headers.get('Content-Length')
                if expected is not None and received != int(expected):
                    raise RouterError('ISO download was incomplete; please retry')

                output.flush()
                os.fsync(output.fileno())

            os.replace(temporary, target)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise

        return target, True

    path = Path(source)
    if not path.is_absolute() and len(path.parts) == 1:
        path = ARCHIVE/path

    path = path.resolve(strict=True)
    if not path.is_file():
        raise RouterError('The ISO source must be a regular file')

    return path, False


def ask_name(document, catalog=None):
    default = document['build']['version']

    while True:
        name = input(f'Installation name [{default}]: ').strip() or default

        try:
            image_name(name)

            if catalog:
                Images.unique(catalog, name)

            return name
        except RouterError as error:
            print(error)


def ask_administrator():
    while True:
        username = input('Initial administrator username [nvyr]: ').strip() or 'nvyr'
        if re.fullmatch(r'(?!(?:root|nvyr-dev)$)[a-z_][a-z0-9_-]{0,30}', username):
            break

        print('Use a non-root Linux username: lowercase letters, digits, underscores or hyphens.')

    while True:
        password = getpass.getpass('Administrator password: ')
        if password != getpass.getpass('Confirm password: '):
            print('Passwords do not match.')
            continue

        try:
            encrypted = hash_password(password)
            del password

            return username, encrypted
        except RouterError as error:
            print(error)


def space_required(document, source=None):
    payload = sum(item['bytes'] for item in document['files'].values())
    copied = int(cmd(['du', '-sx', '--block-size=1', str(source)]).split()[0]) if source else 0

    return payload+copied+512*1024**2


def bootloader(root, esp, disk):
    # Stable bootstrap. Upgrades only switch boot/nvyr/current; they do not
    # reinstall shared GRUB code or write EFI variables.
    (root/'boot/grub').mkdir(parents=True, exist_ok=True)
    write(root/'boot/grub/grub.cfg', 'source /boot/nvyr/current/grub.cfg\n')

    if run(['grub-install', '--target=i386-pc', '--boot-directory='+str(root/'boot'), '--recheck', disk], timeout=None):
        raise RouterError('Could not install the BIOS bootloader')

    if run(['grub-install', '--target=x86_64-efi', '--efi-directory='+str(esp),
                '--boot-directory='+str(root/'boot'), '--removable', '--no-nvram'], timeout=None):
        raise RouterError('Could not install the EFI bootloader')


def partition(disk):
    table = ('label: gpt\n'
             'size=1MiB, type=21686148-6449-6E6F-744E-656564454649\n'
             'size=512MiB, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B\n'
             'type=0FC63DAF-8483-4772-8E79-3D69D8477DE4\n')
    subprocess.run(['sfdisk', '--wipe', 'always', '--wipe-partitions', 'always', disk],
                   input=table, text=True, check=True)

    if run(['udevadm', 'settle'], timeout=60):
        raise RouterError('Device discovery did not settle after partitioning')

    # Ask the kernel for partition paths; don't assume sdX-style names (NVMe etc.).
    device = next(item for item in inventory() if item['name'] == disk)
    parts = [item['name'] for item in device.get('children', []) if item['type'] == 'part']
    if len(parts) != 3:
        raise RouterError('Kernel did not expose the expected GPT partitions')

    if run(['mkfs.vfat', '-F', '32', '-n', 'NVYR-EFI', parts[1]], timeout=None):
        raise RouterError('Could not create the EFI filesystem')

    if run(['mkfs.ext4', '-F', '-L', 'NVYR-SYSTEM', parts[2]], timeout=None):
        raise RouterError('Could not create the nVyR filesystem')

    return parts[1], parts[2]


def summary(document, name, *, target, copy_from, retain, ssh_keys, make_default, fresh=False, administrator=None, developer=None):
    from tabulate import tabulate

    rows = [
        ('Target', target),
        ('Disk action', 'ERASE ALL DATA' if fresh else 'Preserve existing images'),
        ('Image', name),
        ('Version', document['build']['version']),
        ('Built', document['build']['build_timestamp']),
        ('Persistent files copied from', copy_from or 'none'),
        ('Saved configuration', 'retain' if retain else 'factory defaults'),
        ('SSH host keys', 'transfer if present' if ssh_keys else 'generate new keys on first use'),
        ('Default boot image', 'new image' if make_default else 'unchanged'),
    ]

    if administrator:
        rows.append(('Initial administrator', administrator[0]))
        rows.append(('Initial role', 'dev-admin' if developer else 'sys-admin'))
    elif not retain:
        rows.append(('Factory credentials', 'nvyr / nvyr; replace them after boot.'))

    print('\nInstallation plan:')
    print(tabulate(rows, tablefmt='presto'))
    print()

    return confirm('Proceed with this installation?')


def add(source):
    print('Install an additional nVyR image. Use only trusted ISO sources; hashes verify integrity, not publisher identity.')

    if not confirm('Continue?'):
        return

    with installation_lock():
        _add(source)


def _add(source):
    images = Images()
    catalog = images.catalog()
    if images.running not in catalog['images']:
        raise RouterError('add system image requires an installed system; use install image from live media')

    iso, automatic = acquire(source)

    with mounted(iso, options='loop,ro,nodev,nosuid,noexec') as media:
        print('Verifying ISO compatibility and payload hashes...')
        document = verify_media(media)
        name = ask_name(document, catalog)
        retain = has_saved_configuration(Path('/config')/SAVED) and choose(
            'Configuration for the new image:', ['Retain saved configuration and durable accounts', 'Factory defaults']) == 0
        ssh_keys = confirm('Transfer SSH host keys?')
        make_default = confirm('Make the new image the default boot image?')
        running = catalog['images'][images.running]['name']
        if not summary(document, name, target=str(STORAGE), copy_from=running+' /config',
                       retain=retain, ssh_keys=ssh_keys, make_default=make_default):
            return

        with images.locked():
            if shutil.disk_usage(STORAGE).free < space_required(document, Path('/config')):
                raise RouterError('Insufficient disk space for this image and an independent configuration copy')

            images.add(media, document, name, partial(image_migration.prepare, source=Path('/config'),
                       retain=retain, ssh_keys=ssh_keys, lock_state=Path('/var/lib/nvyr'),
                       confirm_vanished=confirm_vanished,
                       exclude=('nvyr-images/'+iso.name,) if automatic else ()), make_default=make_default)

    if automatic:
        iso.unlink()

    print(f'Installed {name}. Reboot when ready; the running image has not changed.')


def install():
    print('Install nVyR from the live ISO. A fresh installation erases the entire selected disk.')

    if not confirm('Continue?'):
        return

    with installation_lock():
        _install()


def _install():
    """Collect and confirm an installation plan, then recheck and modify the disk.

    Fresh installs partition and install a bootloader. Existing installations
    add an image under the catalog lock while preserving other images. Rechecks
    after the prompts prevent acting on stale disk or image-catalog selections.
    """
    media = live_media()
    print('Verifying ISO compatibility and payload hashes...')
    document = verify_media(media)
    disks = eligible_disks(inventory())
    if not disks:
        raise RouterError('No eligible unmounted disks (at least 4 GiB) found')

    default = max(range(len(disks)), key=lambda i: disks[i]['size'])
    disk = disks[choose('Select the installation disk (device | capacity | vendor | model | transport | serial):',
                        [disk_label(item) for item in disks], default)]
    fresh = choose('Installation mode:', ['ERASE disk for a fresh installation',
                                        'Add an image, preserving an existing nVyR installation']) == 0

    # Inspect old filesystems only when preserving them. A confirmed fresh
    # installation replaces them, regardless of their journal or catalog state.
    existing = None if fresh else existing_installation(disk)
    if not fresh and existing is None:
        raise RouterError('No existing nVyR installation found on the selected disk; use a fresh installation')

    catalog = None if fresh else existing[1]
    name = ask_name(document, catalog)
    administrator = None
    developer = None

    if fresh:
        saved_available = has_saved_configuration(Path('/config')/SAVED)
        retain = saved_available and choose('Initial configuration:', ['Live ISO saved configuration', 'Factory defaults']) == 0
        ssh_keys, make_default = False, True
        administrator = ask_administrator()
        developer = confirm('Enable developer administration?')
        source_description = 'live ISO /config' if retain else None
    else:
        with mounted(existing[0]) as root:
            saved_available = has_saved_configuration(Images(root).path(catalog['default'])/'config'/SAVED)

        retain = saved_available and choose('Configuration for the new image:', ['Retain default image configuration', 'Factory defaults']) == 0
        ssh_keys = confirm('Transfer SSH host keys?')
        make_default = confirm('Make the new image the default boot image?')
        source_description = catalog['images'][catalog['default']]['name']+' /config'

    if not summary(document, name, target=disk_label(disk), copy_from=source_description, retain=retain,
                   ssh_keys=ssh_keys, make_default=make_default, fresh=fresh, administrator=administrator, developer=developer):
        return

    # User confirmation may take arbitrarily long; refresh eligibility immediately
    # before any destructive operation rather than trusting the initial inventory.
    recheck_disk(disk)

    if fresh:
        if disk['size'] < space_required(document, Path('/config') if retain else None)+600*1024**2:
            raise RouterError('The selected disk is too small for this image and configuration')

        esp_device, root_device = partition(disk['name'])

        with mounted(root_device, options='rw', filesystem='ext4') as root, mounted(esp_device, options='rw', filesystem='vfat') as esp:
            images = Images(root)

            with images.locked():
                status, filesystem_uuid = rc_cmd(['blkid', '-s', 'UUID', '-o', 'value', root_device])
                if status or not filesystem_uuid.strip():
                    raise RouterError('Could not read the nVyR filesystem UUID')

                filesystem_uuid = filesystem_uuid.strip()
                images.add(media, document, name, partial(image_migration.prepare,
                           source=Path('/config') if retain else None, retain=retain, ssh_keys=False,
                           live_state=Path('/var/lib/nvyr') if retain else None,
                           lock_state=Path('/var/lib/nvyr') if retain else None,
                           confirm_vanished=confirm_vanished,
                           administrator=administrator, developer=developer), make_default=True, filesystem_uuid=filesystem_uuid)
                bootloader(root, esp, disk['name'])
    else:
        with mounted(existing[0], options='rw', filesystem='ext4') as root:
            images = Images(root)

            with images.locked():
                if images.catalog() != catalog:
                    raise RouterError('The installation changed during confirmation; run install image again')

                source = images.path(catalog['default'])/'config'
                if shutil.disk_usage(root).free < space_required(document, source):
                    raise RouterError('Insufficient free space for the new image')

                images.add(media, document, name, partial(image_migration.prepare, source=source,
                           retain=retain, ssh_keys=ssh_keys, confirm_vanished=confirm_vanished), make_default=make_default)

    print(f'Installed {name}. Remove the live ISO before booting from disk.')


def main():
    if os.geteuid() != 0:
        raise SystemExit('Image management requires root through the nVyR CLI')

    def interrupted(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)

    try:
        operation, *arguments = sys.argv[1:]
        if operation == 'install' and not arguments:
            install()
        elif operation == 'add' and len(arguments) == 1:
            add(arguments[0])
        elif operation == 'select' and len(arguments) == 1:
            Images().select(arguments[0])
        elif operation == 'rename' and len(arguments) == 2:
            Images().rename(*arguments)
        elif operation == 'delete' and len(arguments) == 1:
            if confirm(f'Delete image {arguments[0]!r} and all of its persistent files?'):
                Images().delete(arguments[0])
        else:
            raise RouterError('Invalid image management operation or arguments')
    except (KeyboardInterrupt, EOFError):
        print('\nImage operation interrupted; previously installed images remain available.', file=sys.stderr)
        raise SystemExit(130) from None
    except (RouterError, OSError, ValueError, http.client.HTTPException, subprocess.SubprocessError) as error:
        print(f'Image operation failed: {error}', file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == '__main__':
    main()
