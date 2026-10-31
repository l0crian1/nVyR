#!/usr/bin/env python3
"""Image operations; authorization is enforced by configd before terminal handoff."""

import uuid

from nvyr import opmode
from nvyr.helpers.images import Images
from nvyr.helpers.process import call


def _worker(operation, *arguments):
    # PID 1 starts the installer outside configd's read-only mount namespace.
    # Keep configd's sandbox intact, and attach a PTY for prompts/getpass/Ctrl+C.
    status = call(['systemd-run', '--quiet', '--wait', '--collect', '--pty', '--service-type=exec',
             '--unit=nvyr-image-'+uuid.uuid4().hex, '/usr/bin/python3', '-I',
             '-m', 'nvyr.helpers.installation', operation, *arguments],
                 new_process_group=False)

    # The worker already displays a useful error or cancellation message.
    # Propagate status without logging the entire systemd-run invocation.
    if status:
        raise SystemExit(status)


@opmode.command
def install():
    _worker('install')


@opmode.command
def add(source: str):
    _worker('add', source)


@opmode.command
def show():
    return Images().listing()


@opmode.command
def select(name: str):
    _worker('select', name)


@opmode.command
def rename(old: str, new: str):
    _worker('rename', old, new)


@opmode.command
def delete(name: str):
    _worker('delete', name)


if __name__ == '__main__':
    opmode.run()
