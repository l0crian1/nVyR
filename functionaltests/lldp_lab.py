"""A native LLDP peer for existing test links; owns no nVyR configuration."""

from contextlib import contextmanager
import json
import shlex
import subprocess
import time

from nvyr.config_scripts.service_lldp import generate


def control(directory, *arguments, raw=False):
    command = ['lldpcli', '-u', str(directory / 'socket')]
    if raw:
        command.extend(['-f', 'json0'])
    output = subprocess.check_output([*command, *arguments], text=True, stderr=subprocess.STDOUT)
    return json.loads(output) if raw else output


@contextmanager
def daemon(directory, namespace, configuration):
    directory.mkdir(parents=True, exist_ok=True)
    plan = generate(configuration, None)
    path = directory / 'lldpd.conf'
    path.write_text(plan['configuration'])
    path.chmod(0o644)
    environment = shlex.split(plan['environment'])[0].split('=', 1)[1]
    arguments = ['ip', 'netns', 'exec', namespace, 'lldpd', '-dd',
                 '-u', str(directory / 'socket'), '-p', str(directory / 'pid'),
                 '-O', str(path), *shlex.split(environment)]
    with (directory / 'log').open('w+') as log:
        process = subprocess.Popen(arguments, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None or time.monotonic() >= deadline:
                    log.seek(0)
                    raise AssertionError('LLDP peer did not start: ' + log.read())
                if (directory / 'socket').exists():
                    try:
                        state = control(directory, 'show', 'configuration', raw=True)
                    except subprocess.CalledProcessError:
                        # The socket is bound before the daemon begins accepting requests.
                        pass
                    else:
                        fields = state['configuration'][0]['config'][0]
                        if fields['hostname'][0]['value'] == configuration['system-name']:
                            break
                time.sleep(.05)
            # Match apply's checked commands; native file loading hides failures.
            for line in plan['configuration'].splitlines():
                if line.strip():
                    control(directory, *shlex.split(line))
            yield directory
        finally:
            process.terminate()
            process.wait(timeout=10)
