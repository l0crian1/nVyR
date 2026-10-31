#!/usr/bin/env python3
"""Generate a bounded snapshot in the host namespace, outside configd's sandbox."""

import uuid

from nvyr import opmode
from nvyr.helpers.process import call


@opmode.command
def generate():
    """The service deadline also terminates any remaining collector descendants."""
    arguments = ['systemd-run', '--quiet', '--wait', '--pipe', '--collect', '--service-type=exec',
                 '--unit=nvyr-diagnostics-' + uuid.uuid4().hex,
                 '--property=UMask=0077', '--property=RuntimeMaxSec=75',
                 '--property=TimeoutStopSec=2', '--property=KillMode=control-group',
                 '/usr/bin/python3', '-I', '-m', 'nvyr.helpers.diagnostics']
    status = call(arguments, timeout=80, new_process_group=False)
    if status:
        raise SystemExit(status)


if __name__ == '__main__':
    opmode.run()
