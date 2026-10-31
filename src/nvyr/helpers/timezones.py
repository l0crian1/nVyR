"""Installed IANA zone names shared by configuration validation and completion."""

from pathlib import Path, PurePosixPath
from zoneinfo import available_timezones


ZONEINFO = Path('/usr/share/zoneinfo')


def available():
    """Exclude Python-only data and internal zones that cannot select host localtime."""
    return sorted(name for name in available_timezones() if valid_name(name))


def valid_name(value):
    name = PurePosixPath(value)
    if (not name.parts or name.is_absolute() or name.as_posix() != value
            or '..' in name.parts or name.parts[0] in {'posix', 'right', 'localtime', 'posixrules'}):
        return False
    try:
        target = (ZONEINFO / value).resolve(strict=True)
        if not target.is_relative_to(ZONEINFO.resolve()):
            return False
        with target.open('rb') as stream:
            return stream.read(4) == b'TZif'
    except (OSError, ValueError):
        return False
