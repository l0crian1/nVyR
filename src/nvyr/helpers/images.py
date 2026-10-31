"""Installed-image catalog and atomic GRUB publication; independent of configd."""

from contextlib import contextmanager
from copy import deepcopy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import uuid

from nvyr.errors import RouterError
from nvyr.storage import atomic_json, sync_directory

STORAGE = Path('/run/nvyr-storage')
BOOT_ID = Path('/run/nvyr-image-id')
SAVED = 'nvyr-saved-config'
PAYLOAD = {'rootfs': 'filesystem.squashfs', 'kernel': 'vmlinuz', 'initrd': 'initrd.img'}
FORMAT = 1


def image_name(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', value):
        raise RouterError('Image names need 1–64 letters, digits, dots, underscores or hyphens, starting with a letter or digit')

    return value


def identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{32}', value):
        raise RouterError('Invalid installed-image identifier')

    return value


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def manifest(media, metadata):
    """Build-time manifest; hashes detect corruption, not publisher authenticity."""
    media = Path(media).resolve()
    files = {}

    for role, name in PAYLOAD.items():
        path = media/'live'/name
        if not path.exists():
            candidates = list((media/'live').glob(name+'-*'))
            if len(candidates) != 1:
                raise RouterError(f'Expected exactly one {role} payload in live/')

            path = candidates[0]

        path = path.resolve(strict=True)
        relative = path.relative_to(media).as_posix()
        files[role] = {'path': relative, 'bytes': path.stat().st_size, 'sha256': digest(path)}

    return {'format': FORMAT, 'product': 'nvyr', 'architecture': 'amd64',
            'layout': 1, 'configuration_format': 1, 'build': metadata, 'files': files}


def verify_media(media):
    """Return a compatible manifest after checking every declared boot payload.

    Paths must resolve within the supplied media. Size/hash checks establish
    payload integrity, not publisher authenticity; failures become RouterError.
    """
    media = Path(media).resolve()

    try:
        document = json.loads((media/'nvyr/image.json').read_text())
        # Only an object can carry the versioned image manifest contract.
        if not isinstance(document, dict):
            raise ValueError('manifest must be an object')

        # Reject images whose product, architecture or storage format cannot boot here.
        if any(document.get(key) != value for key, value in
               {'format': FORMAT, 'product': 'nvyr', 'architecture': 'amd64',
                'layout': 1, 'configuration_format': 1}.items()):
            raise ValueError('unsupported product, architecture or image format')

        # Require exactly the payload roles the installer knows how to stage.
        if not isinstance(document['files'], dict) or set(document['files']) != set(PAYLOAD):
            raise ValueError('missing or unexpected boot payload')

        # Installed image identity needs a nonempty version and build timestamp.
        if (not isinstance(document['build'], dict)
                or not isinstance(document['build']['version'], str)
                or not document['build']['version']
                or not isinstance(document['build']['build_timestamp'], str)
                or not document['build']['build_timestamp']):
            raise ValueError('missing build identity')

        for entry in document['files'].values():
            # Each payload must supply structured path, size and digest metadata.
            if not isinstance(entry, dict):
                raise ValueError('payload entries must be objects')

            relative = Path(entry['path'])
            # Manifest paths may only name payloads beneath the media's live directory.
            if relative.is_absolute() or '..' in relative.parts or relative.parts[:1] != ('live',):
                raise ValueError('unsafe payload path')

            path = (media/relative).resolve(strict=True)
            # Resolving symlinks must not escape the mounted media either.
            path.relative_to(media)

            # Verify a regular file with the declared positive size and SHA-256 digest.
            if (not stat.S_ISREG(path.stat().st_mode) or type(entry['bytes']) is not int
                    or entry['bytes'] <= 0 or path.stat().st_size != entry['bytes']
                    or not re.fullmatch('[0-9a-f]{64}', entry['sha256']) or digest(path) != entry['sha256']):
                raise ValueError(f'payload integrity check failed: {relative}')

        return document
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise RouterError(f'Not a compatible, intact nVyR image: {error}') from error


def running_id():
    return identifier(BOOT_ID.read_text().strip()) if BOOT_ID.exists() else None


def sync_tree(root):
    """Finish payload/config writes before a catalog can reference them."""
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in files:
            path = Path(parent)/name
            if path.is_symlink() or not path.is_file():
                continue

            with path.open('rb') as stream:
                os.fsync(stream.fileno())

        sync_directory(parent)


class Images:
    def __init__(self, root=STORAGE, *, running=None):
        self.root = Path(root)
        self.running = running if running is not None else running_id()
        self.boot = self.root/'boot/nvyr'

    @contextmanager
    def locked(self):
        self.boot.mkdir(parents=True, exist_ok=True)

        with os.fdopen(os.open(self.boot/'lock', os.O_CREAT | os.O_RDWR, 0o600), 'a') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def catalog(self):
        current = self.boot/'current'
        if not current.is_symlink():
            raise RouterError('No complete nVyR installation found on this filesystem')

        try:
            generation = current.resolve(strict=True)
            if generation.parent != self.boot.resolve() or not generation.name.startswith('generation-'):
                raise ValueError('unsafe catalog pointer')

            value = json.loads((generation/'catalog.json').read_text())
            if value['format'] != FORMAT or not re.fullmatch(r'[0-9a-fA-F-]{36}', value['uuid']):
                raise ValueError('unsupported catalog')

            if value['default'] not in value['images'] or not value['images']:
                raise ValueError('missing default image')

            names = set()

            for key, entry in value['images'].items():
                identifier(key)
                name = image_name(entry['name'])
                if name in names:
                    raise ValueError('duplicate image name')

                names.add(name)
                path = self.path(key)
                if not (path/'image.json').is_file():
                    raise ValueError(f'incomplete image: {name}')

            return value
        except (OSError, KeyError, TypeError, ValueError) as error:
            raise RouterError(f'Cannot read installed-image catalog: {error}') from error

    def path(self, key):
        path = self.root/'images'/identifier(key)
        if path.is_symlink() or path.resolve().parent != (self.root/'images').resolve():
            raise RouterError('Unsafe installed-image directory')

        return path

    @staticmethod
    def find(catalog, name):
        image_name(name)

        for key, entry in catalog['images'].items():
            if entry['name'] == name:
                return key

        raise RouterError(f'Image {name!r} is not installed')

    @staticmethod
    def unique(catalog, name):
        image_name(name)

        if any(entry['name'] == name for entry in catalog['images'].values()):
            raise RouterError(f'Image {name!r} already exists')

    def menu(self, catalog):
        if not re.fullmatch(r'[0-9a-fA-F-]{36}', catalog['uuid']):
            raise RouterError('Invalid boot filesystem UUID')

        lines = ['# Generated by nVyR image management; do not use update-grub.',
                 'terminal_input console', 'terminal_output console',
                 'if [ "$grub_platform" = efi ]; then',
                 '  insmod all_video', '  insmod gfxterm',
                 '  if loadfont $prefix/fonts/unicode.pf2; then terminal_output gfxterm; fi', 'fi',
                 'if serial --unit=0 --speed=115200 --word=8 --parity=no --stop=1; then',
                 '  terminal_input --append serial', '  terminal_output --append serial', 'fi',
                 'set timeout=5', f"set default='nvyr-{identifier(catalog['default'])}'",
                 f"search --no-floppy --fs-uuid --set=root {catalog['uuid']}"]

        for key, entry in catalog['images'].items():
            identifier(key)
            name = image_name(entry['name'])
            lines += [f"menuentry 'nVyR {name}' --id 'nvyr-{key}' {{",
                      f"  linux /images/{key}/vmlinuz boot=nvyr root=UUID={catalog['uuid']} nvyr.image={key} ro console=tty0 console=ttyS0,115200n8",
                      f'  initrd /images/{key}/initrd.img', '}']
            lines += [f"menuentry 'nVyR {name} - one-boot developer recovery' --id 'nvyr-recovery-{key}' {{",
                      f"  linux /images/{key}/vmlinuz boot=nvyr root=UUID={catalog['uuid']} nvyr.image={key} nvyr.developer-recovery=1 ro console=tty0 console=ttyS0,115200n8",
                      f'  initrd /images/{key}/initrd.img', '}']

        return '\n'.join(lines)+'\n'

    def publish(self, catalog):
        """One durable symlink switch publishes both metadata and the boot menu."""
        from nvyr.helpers.template import write

        generation = self.boot/('generation-'+uuid.uuid4().hex)
        generation.mkdir(parents=True)
        atomic_json(generation/'catalog.json', catalog)
        write(generation/'grub.cfg', self.menu(catalog), mode=0o600)
        sync_directory(generation)
        sync_directory(self.boot)

        temporary = self.boot/('.current-'+uuid.uuid4().hex)

        try:
            temporary.symlink_to(generation.name)
            os.replace(temporary, self.boot/'current')
            sync_directory(self.boot)
        finally:
            temporary.unlink(missing_ok=True)

    def add(self, media, document, name, prepare, *, make_default, filesystem_uuid=None):
        """Caller holds the disk lock. prepare populates only the private staging tree."""
        catalog = self.catalog() if filesystem_uuid is None else {
            'format': FORMAT, 'uuid': filesystem_uuid, 'default': None, 'images': {}}
        self.unique(catalog, name)
        key = uuid.uuid4().hex
        staging = self.root/('.install-'+key)
        staging.mkdir(mode=0o700)

        try:
            for role, destination in PAYLOAD.items():
                source = Path(media)/document['files'][role]['path']
                shutil.copyfile(source, staging/destination)

                if digest(staging/destination) != document['files'][role]['sha256']:
                    raise RouterError(f'Copied {role} failed its integrity check')

            for directory in ('overlay/upper', 'overlay/work', 'config'):
                (staging/directory).mkdir(parents=True, mode=0o700)

            # OverlayFS takes / permissions from its upper root. The containing
            # image directory remains private, but the booted / must be traversable.
            (staging/'overlay/upper').chmod(0o755)
            prepare(staging)
            atomic_json(staging/'image.json', document)
            sync_tree(staging)

            (self.root/'images').mkdir(exist_ok=True)
            os.rename(staging, self.path(key))
            sync_directory(self.root/'images')

            catalog = deepcopy(catalog)
            catalog['images'][key] = {'name': name, 'build': document['build']}

            if make_default or catalog['default'] is None:
                catalog['default'] = key

            self.publish(catalog)

            return key
        finally:
            # An interruption after rename leaves a complete, unreferenced image,
            # never a broken menu. Do not delete a potentially published image.
            if staging.exists():
                shutil.rmtree(staging)

    def select(self, name):
        with self.locked():
            catalog = self.catalog()
            catalog['default'] = self.find(catalog, name)
            self.publish(catalog)

    def rename(self, old, new):
        with self.locked():
            catalog = self.catalog()
            key = self.find(catalog, old)
            self.unique(catalog, new)
            catalog['images'][key]['name'] = new
            self.publish(catalog)

    def delete(self, name):
        with self.locked():
            catalog = self.catalog()
            key = self.find(catalog, name)
            if key in (self.running, catalog['default']):
                raise RouterError('Cannot delete the running or default boot image')

            path = self.path(key)

            # Inactive images can still have administrator-mounted volumes.
            # Never recurse into one during deletion.
            device = self.root.stat().st_dev
            device_number = f'{os.major(device)}:{os.minor(device)}'

            for line in Path('/proc/self/mountinfo').read_text().splitlines():
                fields = line.split()
                origin, target = [re.sub(r'\\([0-7]{3})', lambda match: chr(int(match[1], 8)), field)
                                  for field in fields[3:5]]
                if (Path(target).is_relative_to(path) or
                        (fields[2] == device_number and Path(origin).is_relative_to('/images/'+key))):
                    raise RouterError('Cannot delete an image containing mounted filesystems')

            del catalog['images'][key]
            self.publish(catalog)  # A crash during removal cannot break the menu.
            shutil.rmtree(path)
            sync_directory(path.parent)

    def listing(self):
        from tabulate import tabulate

        catalog = self.catalog()
        rows = [(entry['name'], 'Yes' if key == self.running else '',
                 'Yes' if key == catalog['default'] else '')
                for key, entry in catalog['images'].items()]

        return tabulate(rows, headers=('Image', 'Running', 'Default'), tablefmt='simple')+'\n'
