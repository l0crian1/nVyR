"""Host system settings used by configuration scripts."""

from pathlib import Path
import socket

from nvyr.errors import RecoveryError, RouterError
from nvyr.helpers import hosts
from nvyr.helpers.template import write
from nvyr.storage import sync_directory


def hostname_hosts(text, hostname):
    """Keep Debian's local-hostname address separate from localhost and static hosts."""
    names = hostname
    if '.' in hostname:
        names += ' ' + hostname.split('.', 1)[0]

    entry = f'127.0.1.1\t{names}\n'
    lines = []
    replaced = False

    for line in text.splitlines(keepends=True):
        fields = line.split('#', 1)[0].split()
        if fields and fields[0] == '127.0.1.1':
            if not replaced:
                lines.append(entry)
                replaced = True
        else:
            lines.append(line)

    if not replaced:
        if lines and not lines[-1].endswith('\n'):
            lines[-1] += '\n'
        lines.append(entry)

    result = ''.join(lines)
    _, managed = hosts.split_dhcp(result)
    return hosts.with_dhcp(result, hosts.entries(managed))


def apply_hostname(hostname, *, path='/etc/hostname', hosts_path='/etc/hosts'):
    """Set the kernel name, boot file and local resolution, compensating failures."""
    with hosts.locked(hosts_path):
        _apply_hostname(hostname, path=path, hosts_path=hosts_path)


def _apply_hostname(hostname, *, path, hosts_path):
    """Keep the read, write and any compensation inside the shared hosts lock."""
    path = Path(path)
    hosts_path = Path(hosts_path)
    snapshots = {}

    try:
        previous = socket.gethostname()
        for target in (path, hosts_path):
            text = target.read_text(encoding='utf-8') if target.exists() else None
            mode = target.stat().st_mode & 0o777 if text is not None else 0o644
            snapshots[target] = (text, mode)
    except OSError as error:
        raise RouterError(f'Cannot read existing hostname: {error}') from error

    desired_files = {
        path: hostname + '\n',
        hosts_path: hostname_hosts(snapshots[hosts_path][0] or '', hostname),
    }

    try:
        if previous != hostname:
            socket.sethostname(hostname.encode('utf-8'))

        for target, desired in desired_files.items():
            if snapshots[target][0] != desired:
                write(target, desired, mode=0o644)
    except (OSError, RouterError) as error:
        try:
            if socket.gethostname() != previous:
                socket.sethostname(previous.encode('utf-8'))

            # A durable write can fail after rename, so inspect the file too.
            for target, (text, mode) in snapshots.items():
                current = target.read_text(encoding='utf-8') if target.exists() else None
                if current != text:
                    if text is None:
                        target.unlink()
                        sync_directory(target.parent)
                    else:
                        write(target, text, mode=mode)
        except (OSError, RouterError) as rollback_error:
            raise RecoveryError(f'Cannot restore hostname after failed application: {rollback_error}') from error

        raise RouterError(f'Cannot apply hostname {hostname!r}: {error}') from error
