"""Copy persistent image data without modifying the source installation."""

from contextlib import contextmanager, nullcontext
from copy import deepcopy
import fcntl
import json
import os
from pathlib import Path
import re
import shutil

from nvyr.errors import RouterError
from nvyr.helpers.accounts import factory_configuration
from nvyr.helpers.container_config import VOLUME_ROOT
from nvyr.helpers.process import cmd, rc_cmd
from nvyr.storage import atomic_json, read_saved, saved_document
from nvyr.helpers.images import SAVED


@contextmanager
def configuration_snapshot(state):
    # Store writes take the same lock. A copied in-progress transaction remains
    # recoverable through its existing journal; no service freezing is necessary.
    with (Path(state)/'snapshot.lock').open('a') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


def copy_directory(source, destination, *, exclude=(), vanished=None):
    destination.mkdir(parents=True, exist_ok=True)

    status, output = rc_cmd(
        ['rsync', '-aHAX', '--numeric-ids', *[f'--exclude=/{name}' for name in exclude],
         '--', str(source)+'/', str(destination)+'/'], timeout=None, env=os.environ | {'LC_ALL': 'C'},
    )
    if status == 24 and vanished is not None:
        vanished.append((Path(source), Path(destination), output))
        return

    if status:
        message = f'Could not copy persistent files from {source} to {destination} (rsync exit {status})'
        if output.strip():
            message += ':\n' + output.strip()
        raise RouterError(message)


def persistent_files(destination, *, source, **options):
    if source is not None:
        copy_directory(source, destination, exclude=options.get('exclude', ()),
                       vanished=options.get('vanished'))


def daemon_state(destination, *, source, live_state=None, **options):
    if live_state is not None:
        copy_directory(Path(live_state), destination/'.nvyr', vanished=options.get('vanished'))


# Migration steps own separate parts of the target. Future persistent services
# can add a provider here without changing image publication or boot selection.
PROVIDERS = (persistent_files, daemon_state)


def affected_containers(issues, destination):
    """Attribute vanished paths to configured bind volumes without querying Podman."""
    state = destination / '.nvyr/state.json'
    saved = destination / SAVED
    configuration = None
    if state.is_file():
        configuration = json.loads(state.read_text()).get('configuration')
    if configuration is None and saved.is_file():
        configuration, _ = read_saved(saved)
    if configuration is None:
        return []

    paths = []
    for source, target, output in issues:
        for name in re.findall(r'^file has vanished: "(.*)"$', output, flags=re.MULTILINE):
            path = Path(name)
            if path.is_relative_to(source):
                paths.append(Path('/config') / target.relative_to(destination) / path.relative_to(source))

    affected = set()
    for name, container in configuration.get('container', {}).get('name', {}).items():
        for volume, settings in container.get('volume', {}).items():
            location = settings.get('source')
            if not location:
                continue
            location = Path(location)
            if not location.is_absolute():
                location = Path(VOLUME_ROOT) / location
            if any(path == location or path.is_relative_to(location) for path in paths):
                affected.add((name, volume, str(location)))
    return sorted(affected)


def validate_records(private):
    """Check copied journal structure without interpreting configuration features."""
    for name in ('state.json', 'transaction.json', 'confirmed.json'):
        path = private/name
        if not path.exists():
            continue

        try:
            value = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as error:
            raise RouterError(f'Cannot read retained configuration record {name}: {error}') from error

        # Recovery records must be JSON objects, regardless of schema version.
        if not isinstance(value, dict):
            raise RouterError(f'Retained configuration record {name} must be a JSON object')

        for key in ('configuration', 'before', 'after'):
            # Configuration bodies are objects; their contents belong to the new runtime.
            if key in value and not isinstance(value[key], dict):
                raise RouterError(f'Retained configuration record {name}: {key} must be a JSON object')


def prepare(staging, *, source=None, retain=True, ssh_keys=True, administrator=None,
            live_state=None, lock_state=None, exclude=(), developer=None, confirm_vanished=None):
    """Populate a staged image's persistent configuration before publication.

    Providers copy durable files under the optional source snapshot lock. Retain,
    factory and fresh-install credential choices then determine which config and
    journals survive. Check file structure without loading the incoming schema:
    its callbacks and declarations may be newer than this installer. The new
    runtime validates configuration on boot. This routine neither switches the
    running image nor executes incoming code.
    """
    destination = staging/'config'

    if source is not None:
        for path in (Path(source)/'.nvyr', Path(source)/SAVED):
            if path.is_symlink() or (path.exists() and (path.stat().st_uid != 0 or path.stat().st_mode & 0o022)):
                raise RouterError(f'Reserved source path is not protected: {path}')

    guard = configuration_snapshot(lock_state) if lock_state else nullcontext()
    vanished = [] if confirm_vanished is not None else None

    with guard:
        for provider in PROVIDERS:
            provider(destination, source=source, live_state=live_state, exclude=exclude, vanished=vanished)

    # Never hold configd's snapshot lock while waiting for a human decision.
    if vanished:
        validate_records(destination / '.nvyr')
        if not confirm_vanished(vanished, destination):
            raise RouterError('Installation cancelled because persistent files vanished during copying')

    private = destination/'.nvyr'
    policy = private/'login/developer.json'
    # Image additions preserve installation policy, even when choosing factory configuration.
    # Only a fresh install supplies developer explicitly; upgrades never ask this question.
    developer_policy = (json.loads(policy.read_text()) if policy.exists() else {'enabled': False})
    if developer is not None:
        developer_policy = {'enabled': developer}

    # Reserved paths cannot be links supplied by a user through writable /config.
    for path in (private, destination/SAVED, destination/'nvyr-images'):
        if path.is_symlink():
            raise RouterError(f'Reserved configuration path cannot be a symlink: {path.name}')

    saved = destination/SAVED
    if retain and source is not None and not saved.is_file():
        raise RouterError('The source image has no saved configuration; save it first or choose factory defaults')

    if retain and saved.is_file():
        configuration, metadata = read_saved(saved)
    else:
        configuration = factory_configuration(developer=developer_policy['enabled'])
        metadata = {'factory': True}

    if not retain:
        # A factory choice must not resurrect committed accounts or a rollback
        # journal on the next boot. User-owned files outside .nvyr remain copied.
        keys = private/'ssh'
        if ssh_keys and keys.is_dir():
            shutil.move(keys, staging/'ssh-transfer')

        if private.exists():
            shutil.rmtree(private)

        if (staging/'ssh-transfer').exists():
            private.mkdir(mode=0o700)
            shutil.move(staging/'ssh-transfer', private/'ssh')

    if administrator:
        metadata = dict(metadata, factory=False)
        username, encrypted = administrator
        configuration = deepcopy(configuration)

        # The installer-selected account replaces factory credentials on a fresh
        # install. Other users from an explicitly selected saved config survive.
        if not retain:
            configuration['system']['login']['user'] = {}

        configuration.setdefault('system', {}).setdefault('login', {}).setdefault('user', {})[username] = {
            'role': 'dev-admin' if developer_policy['enabled'] else 'sys-admin',
            'authentication': {'encrypted-password': encrypted}}

        # A fresh install uses the selected saved configuration and credentials,
        # not the live session's unsaved state or its pending rollback journal.
        for name in ('state.json', 'transaction.json', 'confirmed.json'):
            (private/name).unlink(missing_ok=True)

        if (private/'history').exists():
            shutil.rmtree(private/'history')

    if not ssh_keys and (private/'ssh').exists():
        shutil.rmtree(private/'ssh')

    private.mkdir(mode=0o700, exist_ok=True)
    os.chown(private, 0, 0)
    private.chmod(0o700)
    atomic_json(policy, developer_policy)

    # Do not couple image upgrades to this installer's schema or callback registry.
    validate_records(private)

    group_text = cmd(['unsquashfs', '-cat', str(staging/'filesystem.squashfs'), 'etc/group'], timeout=None)
    group = next((int(line.split(':')[2]) for line in group_text.splitlines()
                  if line.startswith('nvyr-access:')), None)
    if group is None:
        raise RouterError('Incoming image lacks the nVyR access group')

    os.chown(destination, 0, group)
    destination.chmod(0o1775)  # Users can create files, but cannot replace root-owned entries.

    archive = destination/'nvyr-images'
    archive.mkdir(exist_ok=True)
    os.chown(archive, 0, group)
    archive.chmod(0o2775)

    atomic_json(saved, saved_document(configuration, metadata=metadata), mode=0o644)
