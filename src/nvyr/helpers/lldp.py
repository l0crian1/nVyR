"""Native LLDP service installation and control socket access."""

import json
import shlex
from pathlib import Path

from nvyr.errors import RouterError
from nvyr.helpers.process import cmd, run
from nvyr.helpers.template import write

ROOT = Path('/run/nvyr-lldp')
SOCKET = ROOT / 'control.sock'
UNIT = 'nvyr-lldp.service'


def control(*arguments, raw=False):
    if not SOCKET.exists():
        raise RouterError('LLDP is not running.')

    command = ['lldpcli', '-u', str(SOCKET)]
    if raw:
        command.extend(['-f', 'json0'])
    output = cmd([*command, *arguments], timeout=10)
    return json.loads(output) if raw else output


def install(plan):
    configuration = ROOT / 'lldpd.conf'
    environment = ROOT / 'daemon.env'
    if plan is None:
        cmd(['systemctl', 'stop', UNIT], timeout=20)
        configuration.unlink(missing_ok=True)
        environment.unlink(missing_ok=True)
        return

    unchanged = (configuration.exists() and configuration.read_text() == plan['configuration']
                 and environment.exists() and environment.read_text() == plan['environment'])
    if unchanged and run(['systemctl', 'is-active', '--quiet', UNIT]) == 0:
        control('show', 'configuration')
        return

    ROOT.mkdir(parents=True, exist_ok=True, mode=0o755)
    # lldpd's unprivileged startup client reads these public advertisement settings.
    write(configuration, plan['configuration'], mode=0o644)
    write(environment, plan['environment'], mode=0o600)

    # Restart restores native defaults, including removed port overrides.
    # Configd owns compensation if installation or native configuration fails.
    cmd(['systemctl', 'restart', UNIT], timeout=45)

    # The native file loader returns success even for invalid commands. Individual
    # commands propagate errors, so check the rendered settings before committing.
    for line in plan['configuration'].splitlines():
        if line.strip():
            control(*shlex.split(line))

    # lldpcli silently ignores settings for unknown ports; do not report those as applied.
    document = control('show', 'interfaces', 'details', raw=True)
    present = {port['name'] for group in document.get('lldp', ()) for port in group.get('interface', ())}
    missing = set(plan['overrides']) - present
    if missing:
        raise RouterError('LLDP overrides require available, eligible interfaces: ' + ', '.join(sorted(missing)))
