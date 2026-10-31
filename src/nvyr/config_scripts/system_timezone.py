"""Select the host's local time zone without changing its clock or NTP service."""

import os
from pathlib import Path
import stat
import tempfile
import time

from nvyr.errors import RecoveryError, RouterError
from nvyr.helpers import timezones
from nvyr.storage import sync_directory
from nvyr.tree import lookup


LOCALTIME = Path('/etc/localtime')
TIMEZONE = Path('/etc/timezone')


def file_state(path):
    """Retain a symlink itself, including broken links, rather than its target."""
    if path.is_symlink():
        return {'link': os.readlink(path)}
    if path.exists():
        return {'data': path.read_bytes(), 'mode': stat.S_IMODE(path.stat().st_mode)}
    return None


def get_config(context):
    return {
        # Whole-system deletion has no active branch for schema defaults to fill.
        'zone': lookup(context.effective, ('system', 'time-zone'), 'UTC'),
        'previous': {path: file_state(path) for path in (LOCALTIME, TIMEZONE)},
    }


def verify(configuration, context):
    # The schema validates the installed zone name; there are no cross-field constraints.
    pass


def generate(configuration, context):
    zone = configuration['zone']
    target = timezones.ZONEINFO / zone
    # A removed tzdata file must fail preparation, not leave a dangling system link.
    target.resolve(strict=True)
    desired = {
        LOCALTIME: {'link': str(target)},
        TIMEZONE: {'data': (zone + '\n').encode('utf-8'), 'mode': 0o644},
    }
    return [
        {'path': path, 'before': configuration['previous'][path], 'after': value}
        for path, value in desired.items() if configuration['previous'][path] != value
    ]


def install_file(path, value):
    """Replace the directory entry atomically; never write through localtime's link."""
    if value is None:
        path.unlink(missing_ok=True)
    else:
        with tempfile.TemporaryDirectory(prefix='.nvyr-timezone-', dir=path.parent) as directory:
            temporary = Path(directory) / 'value'
            if 'link' in value:
                temporary.symlink_to(value['link'])
            else:
                with temporary.open('wb') as stream:
                    stream.write(value['data'])
                    stream.flush()
                    os.chmod(temporary, value['mode'])
                    os.fsync(stream.fileno())
            os.replace(temporary, path)
    sync_directory(path.parent)


def apply(files, context):
    try:
        for entry in files:
            install_file(entry['path'], entry['after'])
        # Python caches the process timezone; refresh it without restarting configd.
        time.tzset()
    except OSError as error:
        try:
            for entry in reversed(files):
                install_file(entry['path'], entry['before'])
            time.tzset()
        except OSError as rollback_error:
            raise RecoveryError(f'Cannot restore time zone: {rollback_error}') from error
        raise RouterError(f'Cannot apply time zone: {error}') from error
