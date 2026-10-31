#!/usr/bin/env python3
"""Display active terminal logins from the system's login accounting."""

import json
import os
from pathlib import Path
import re
import time

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers.output import elapsed_time
from nvyr.helpers.process import cmd


LOGIN = re.compile(
    r'^(\S+)\s+(\S+)\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2})\s+'
    r'(\S+)\s+(\d+)(?:\s+\((.*)\))?\s*$'
)
ACCOUNTING = Path('/run/utmp')


def session_alive(pid):
    """Ignore stale accounting after an unclean session exit without sending a signal."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # An existing process owned by another user is still a live session.
        pass
    return True


def idle_seconds(terminal, now):
    """TTY access time measures idle time; unavailable devices remain unknown."""
    if not re.fullmatch(r'(?:pts/[0-9]+|tty[A-Za-z0-9]*|console)', terminal):
        return None

    try:
        accessed = (Path('/dev') / terminal).stat().st_atime
    except (FileNotFoundError, PermissionError):
        # Sessions may disconnect between the accounting read and device lookup.
        return None

    return max(0, int(now - accessed))


def login_records(output, now):
    """Keep one row per login, even when accounts or source addresses repeat."""
    records = []
    for line in output.splitlines():
        if not line.strip():
            continue

        match = LOGIN.fullmatch(line)
        if match is None:
            raise OperationalError('Cannot interpret the system login accounting output.')

        user, terminal, started, _, pid, source = match.groups()
        if not session_alive(int(pid)):
            continue
        if not source:
            source = 'Console' if terminal.startswith('tty') or terminal == 'console' else 'Local'

        records.append({
            'user': user,
            'terminal': terminal,
            'source': source,
            'login_time': started,
            'idle_seconds': idle_seconds(terminal, now),
            'pid': int(pid),
        })

    return records


@opmode.command
def show(raw: bool = False):
    """Show current SSH/console terminal logins, not configuration sessions."""
    if not ACCOUNTING.exists():
        raise OperationalError('Login accounting is unavailable: /run/utmp is missing.')

    # C.UTF-8 selects ISO dates; omit --lookup to keep SSH's recorded source address.
    # Read terminal accounting explicitly; this image does not register logind sessions.
    output = cmd(['who', '--users', str(ACCOUNTING)], env=dict(os.environ, LC_ALL='C.UTF-8'), timeout=5)
    records = login_records(output, time.time())

    current_terminal = os.environ.get('NVYR_SESSION_TTY', '').removeprefix('/dev/')
    for record in records:
        record['current_session'] = record['terminal'] == current_terminal

    if raw:
        return json.dumps(records)
    if not records:
        return 'No users logged in.\n'

    rows = []
    for record in records:
        user = record['user'] + (' (this session)' if record['current_session'] else '')
        rows.append([user, record['terminal'], record['source'],
                     record['login_time'], elapsed_time(record['idle_seconds'])])

    return tabulate(rows, headers=['User', 'Terminal', 'Source', 'Login time', 'Idle'],
                    disable_numparse=True) + '\n'


if __name__ == '__main__':
    opmode.run()
