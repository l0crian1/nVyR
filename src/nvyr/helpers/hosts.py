"""Serialize writers of the shared hosts file across atomic replacements."""

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path

from nvyr.errors import RouterError

DHCP_BEGIN = '# BEGIN nVyR DHCP hosts\n'
DHCP_END = '# END nVyR DHCP hosts\n'


@contextmanager
def locked(path):
    """Lock a stable sibling inode, not the hosts inode replaced by each writer."""
    path = Path(path)
    lock_path = path.with_name(f'.nvyr-{path.name}.lock')
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def split_dhcp(text):
    """Remove only our marked section, preserving all other lines verbatim."""
    before, separator, remainder = text.partition(DHCP_BEGIN)
    if not separator:
        if DHCP_END in text:
            raise RouterError('Malformed nVyR DHCP hosts section: missing beginning marker')
        return text, ''

    managed, separator, after = remainder.partition(DHCP_END)
    if not separator or DHCP_BEGIN in remainder or DHCP_END in after:
        raise RouterError('Malformed nVyR DHCP hosts section: invalid boundary markers')
    return before + after, managed


def entries(text):
    """Read address/name fields, ignoring comments and blank lines."""
    result = []
    for line in text.splitlines():
        fields = line.split('#', 1)[0].split()
        if len(fields) >= 2:
            result.append((fields[0], fields[1:]))
    return result


def with_dhcp(text, records):
    """Static names always win; DHCP never replaces localhost or the router name."""
    unmanaged, _ = split_dhcp(text)
    reserved = {name.lower().rstrip('.') for _, names in entries(unmanaged) for name in names}
    lines = []
    for address, names in records:
        available = [name for name in names if name.lower().rstrip('.') not in reserved]
        if available:
            lines.append(f'{address}\t{" ".join(available)}\n')

    if not lines:
        return unmanaged
    if unmanaged and not unmanaged.endswith('\n'):
        unmanaged += '\n'
    return unmanaged + DHCP_BEGIN + ''.join(lines) + DHCP_END
