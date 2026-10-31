"""Host-worker transport and locking for container lifecycle and operations."""

import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid

from nvyr.errors import RecoveryError, RouterError
from nvyr.helpers import container_config as config, filesystem
from nvyr.helpers.process import cmd, rc_cmd
from nvyr.helpers.template import write
from nvyr.render import json_text


def worker_command(*arguments, terminal=False):
    return ['systemd-run', '--quiet', '--wait', '--pty' if terminal else '--pipe', '--collect', '--service-type=exec',
            '--unit=nvyr-container-worker-' + uuid.uuid4().hex,
            '--property=UMask=0077', '/usr/bin/python3', '-I', '-m', 'nvyr.helpers.containers', *arguments]


def run_apply(payload, *, recovery=False, report=print):
    """Send prepared application data; worker diagnostics alone reach the terminal."""
    try:
        filesystem.protected_directory(config.RUNTIME)
        with tempfile.TemporaryDirectory(dir=config.RUNTIME, prefix='request-') as folder:
            request = Path(folder) / 'request.json'
            write(request, json_text(payload))

            try:
                status, output = rc_cmd(worker_command('apply', str(request)), timeout=None)
            except RouterError as error:
                raise RecoveryError(f'Cannot confirm container worker completion: {error}') from error

            if output.strip():
                report(output.strip())
            if status:
                if status != 1:
                    raise RecoveryError(output.strip() or 'Container rollback failed')
                raise RouterError(output.strip() or 'Container apply failed')
    except (RouterError, OSError, ValueError) as error:
        if not recovery:
            raise
        report(f'Container recovery failed; configd remains available: {error}')
    return None


def main():
    from nvyr.config_scripts import container
    from nvyr.helpers import container_operations
    from nvyr.op_scripts import containers as operations

    os.umask(0o077)
    try:
        filesystem.protected_directory(config.RUNTIME)
        if sys.argv[1:] == ['images']:
            print(cmd(['podman', 'images', '--format=json']), end='')
            return
        if len(sys.argv) == 3 and sys.argv[1] == 'connect':
            # Resolve an immutable ID; an interactive shell must not hold the apply lock.
            arguments = container_operations.connect_command(container_operations.observations(), **json.loads(sys.argv[2]))
            os.execvp(arguments[0], arguments)

        with (config.RUNTIME / 'lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            operation, value = sys.argv[1:3]
            if operation == 'apply':
                filesystem.protected_directory(container.STATE.parent)
                filesystem.protected_directory(config.VOLUME_ROOT)
                container.apply(json.loads(Path(value).read_text()))
            elif operation in ('add', 'update'):
                operations._pull(value)
            elif operation == 'update-container':
                section = container_operations.configured_state()['configuration'].get('name', {}).get(value)
                if section is None:
                    raise RouterError(f'Container {value} is not configured')
                operations._pull(section['image'])
            elif operation == 'restart':
                operations._restart(value)
            elif operation == 'restart-pod':
                operations._restart_pod(value)
            else:
                raise RouterError('Unknown container operation')
    except RecoveryError as error:
        print(error, file=sys.stderr)
        raise SystemExit(2)
    except (RouterError, OSError, ValueError) as error:
        print(error, file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
