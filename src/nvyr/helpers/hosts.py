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


def split_section(text, name):
    """Remove only our marked section, preserving all other lines verbatim."""
    begin = f'# BEGIN nVyR {name} hosts\n'
    end = f'# END nVyR {name} hosts\n'
    lines = text.splitlines(keepends=True)
    if begin not in lines and end not in lines:
        return text, ''

    if lines.count(begin) != 1 or lines.count(end) != 1:
        raise RouterError(f'Malformed nVyR {name} hosts section: invalid boundary markers')
    start, stop = lines.index(begin), lines.index(end)
    if stop < start:
        raise RouterError(f'Malformed nVyR {name} hosts section: end precedes beginning')
    return ''.join(lines[:start] + lines[stop + 1:]), ''.join(lines[start + 1:stop])


def split_dhcp(text):
    return split_section(text, 'DHCP')


def append_section(text, name, content):
    if not content:
        return text
    if text and not text.endswith('\n'):
        text += '\n'
    return text + f'# BEGIN nVyR {name} hosts\n' + content + f'# END nVyR {name} hosts\n'


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

    return append_section(unmanaged, 'DHCP', ''.join(lines))
