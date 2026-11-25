#!/usr/bin/env python3
"""Read Podman directly; delegate workload changes to the host apply worker."""

import json
import sys
import time

from nvyr import opmode
from nvyr.errors import RecoveryError, RouterError
from nvyr.config_scripts import container as container_script
from nvyr.helpers import container_config as config
from nvyr.helpers.validators import container_image as image_reference
from nvyr.helpers.container_operations import configured_state, display
from nvyr.helpers.containers import worker_command
from nvyr.helpers.process import call, cmd, rc_cmd


def _pull(reference, *, name=None, report=print):
    if not image_reference(reference):
        raise RouterError('Use a container image name with an optional registry, tag or digest')

    current = configured_state()
    container_script.configure_registry(container_script.registry_text(current['configuration']))
    status, output = rc_cmd(['podman', 'image', 'exists', '--', reference])
    if status not in (0, 1):
        raise RouterError(output.strip() or 'Could not read the local image store')

    previous = ''
    if status == 0:
        previous = cmd(['podman', 'image', 'inspect', '--format', '{{.Id}}', '--', reference]).strip()
    cmd(['podman', 'pull', '--quiet', '--', reference], timeout=1800)
    image = cmd(['podman', 'image', 'inspect', '--format', '{{.Id}}', '--', reference]).strip()
    if previous == image:
        report(f'Already up to date: {reference} ({image[:12]})')
    elif previous:
        report(f'Updated {reference}: {previous[:12]} -> {image[:12]}')
    else:
        report(f'Downloaded {reference} ({image[:12]})')

    if name:
        report(f'Use "restart container {name}" to start it with the local image.')
    else:
        report('Running containers keep their current image until restarted.')


def _remove(reference):
    if not image_reference(reference):
        raise RouterError('Use a local image name or image ID')
    print(cmd(['podman', 'rmi', '--', reference]).strip())


def _restart(name, *, report=print):
    """Restart only an enabled managed service, under the same lock as apply."""
    if container_script.STATE.with_suffix('.pending.json').exists():
        raise RecoveryError('An interrupted container operation needs recovery before restarting containers.')

    configuration = configured_state()['configuration']
    section = configuration.get('name', {}).get(name)
    if section is None:
        raise RouterError(f'Container {name} is not configured')
    if not config.enabled(section, configuration):
        raise RouterError(f'Container {name} or its pod is configured disabled')

    # Never restart a foreign container that has reused a configured name.
    container_script.owned('container', name)
    unit = config.unit_name(name) + '.service'
    if not (container_script.QUADLETS / (config.unit_name(name) + '.container')).is_file():
        raise RouterError(f'Container {name} has no generated service; reapply its configuration first')

    cmd(['systemctl', 'reset-failed', unit])
    # Allow the Quadlet's 30-second stop and 60-second start timeouts to finish.
    cmd(['systemctl', 'restart', unit], timeout=105)
    report(f'Container {name} service restarted.')


def _restart_pod(name, *, report=print):
    """Restart the pod and its enabled members through Quadlet's dependencies."""
    if container_script.STATE.with_suffix('.pending.json').exists():
        raise RecoveryError('An interrupted container operation needs recovery before restarting pods.')
    configuration = configured_state()['configuration']
    section = configuration.get('pod', {}).get(name)
    if section is None:
        raise RouterError(f'Pod {name} is not configured')
    if 'disable' in section:
        raise RouterError(f'Pod {name} is configured disabled')
    if container_script.owned('pod', name):
        container_script.validate_pod_members(name, configuration.get('name', {}))
    unit = config.pod_unit_name(name)
    if not (container_script.QUADLETS / (unit + '.pod')).is_file():
        raise RouterError(f'Pod {name} has no generated service; reapply its configuration first')
    members = [config.unit_name(member) + '.service'
               for member, settings in configuration.get('name', {}).items()
               if settings.get('pod') == name and config.enabled(settings, configuration)]
    cmd(['systemctl', 'reset-failed', unit + '.service', *members])
    cmd(['systemctl', 'restart', unit + '.service'], timeout=105)
    # A pod's start job completes before its WantedBy members finish starting.
    if members:
        cmd(['systemctl', 'start', *members], timeout=75)
    report(f'Pod {name} and its enabled containers restarted.')


def _worker(operation, *arguments):
    status = call(worker_command(operation, *arguments), new_process_group=False)
    if status:
        raise SystemExit(status)


@opmode.command
def show(name: str | None = None, detail: bool = False, raw: bool = False):
    return display('containers', name=name, detail=detail, raw=raw)


@opmode.command
def pods(name: str | None = None, raw: bool = False):
    return display('pods', name=name, raw=raw)


@opmode.command
def restart_pod(name: str):
    _worker('restart-pod', name)


@opmode.command
def networks(name: str | None = None, raw: bool = False):
    return display('networks', name=name, raw=raw)


@opmode.command
def images(raw: bool = False):
    return display('images', raw=raw)


@opmode.command
def statistics(name: str | None = None, follow: bool = False, raw: bool = False):
    if not follow:
        return display('statistics', name=name, raw=raw)

    try:
        while True:
            output = display('statistics', name=name, raw=raw)
            if sys.stdout.isatty() and not raw:
                print('\033[H\033[2J', end='')
            print(output, end='' if output.endswith('\n') else '\n', flush=True)
            time.sleep(2)
    except (KeyboardInterrupt, EOFError):
        return None


@opmode.command
def restart(name: str):
    _worker('restart', name)


@opmode.command
def connect(name: str, send_command: str | None = None):
    """Enter a container shell or execute a command without host shell evaluation."""
    options = json.dumps({'name': name, 'command': send_command})
    status = call(worker_command('connect', options, terminal=send_command is None), new_process_group=False)
    if status:
        raise SystemExit(status)


@opmode.command
def add(image: str):
    _worker('add', image)


@opmode.command
def remove(image: str):
    _worker('remove', image)


@opmode.command
def update(image: str):
    _worker('update', image)


@opmode.command
def update_container(name: str):
    _worker('update-container', name)


if __name__ == '__main__':
    opmode.run()
