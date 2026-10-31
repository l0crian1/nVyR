"""Shared lifecycle for live Podman feature and validation smoketests."""

import json
from pathlib import Path
import shutil
import shlex
import tempfile

import pytest

from nvyr.helpers.process import cmd
from nvyr.tree import lookup
from smoketests.assertions import assert_false, assert_not_in
from smoketests.support import prepared_test


def idle_container(config, *, entrypoint=False):
    """Run an idle PID 1 that handles TERM, avoiding Podman's forced-stop timeout."""
    executable = 'entrypoint' if entrypoint else 'command'
    config.set('set container name NVYRSMOKE ' + executable + ' sh')
    script = "trap 'exit 0' TERM INT; while :; do sleep 3600 & wait \"$!\"; done"
    arguments = shlex.join(['-c', script])
    config.set('set container name NVYRSMOKE argument ' + shlex.quote(arguments))


@pytest.fixture(scope='module')
def container_suite(config, request):
    """Reserve native names once per module; cases still inspect their own settings."""
    prepared = False
    original_registries = {}

    def standup(session):
        nonlocal prepared, original_registries
        running = session.get_config()
        original_registries = lookup(running, ('container', 'registry'), {})
        assert_not_in('NVYRSMOKE', lookup(running, ('container', 'name'), {}))
        assert_not_in('NVYRSMOK2', lookup(running, ('container', 'name'), {}))
        assert_not_in('NVYRPOD', lookup(running, ('container', 'name'), {}))
        assert_not_in('NVYRPOD', lookup(running, ('container', 'pod'), {}))
        assert_not_in('NVYRSMOKE', lookup(running, ('container', 'pod'), {}))
        assert_not_in('NVYRSMOK2', lookup(running, ('container', 'pod'), {}))
        assert_not_in('NVYRSMOKE', lookup(running, ('container', 'network'), {}))
        assert_not_in('NVYRSMOKE2', lookup(running, ('container', 'network'), {}))
        assert_not_in('NVYRSMOKE-0', lookup(running, ('container', 'network'), {}))
        assert_not_in('NVYRBASE', lookup(running, ('container', 'network'), {}))
        assert_not_in('NVYRSMOKE', lookup(running, ('vrf', 'name'), {}))
        for link in json.loads(cmd(['ip', '-j', '-d', 'link', 'show'])):
            assert_not_in(link['ifname'], ('NVYRSMOKE', 'pd-NVYRBASE', 'pd-NVYRSMOKE', 'pd-NVYRSMOKE2',
                                           'pd-NVYRSMOKE-0', 'pd-NVYRSMOKE-9', 'pd-NVYRSMOK2-0',
                                           'pd-NVYRPOD-0', 'pd-NVYRPOD-9'))
            assert_false(link.get('linkinfo', {}).get('info_data', {}).get('table') == 28405,
                         msg='Container smoketest VRF table is already in use')
        for vrf in lookup(running, ('vrf', 'name'), {}).values():
            assert_false(str(vrf.get('table')) == '28405', msg='Container smoketest VRF table is configured')
        names = json.loads(cmd(['podman', 'ps', '-a', '--format=json']))
        assert_not_in('NVYRSMOKE', [name for entry in names for name in entry['Names']])
        assert_not_in('NVYRSMOK2', [name for entry in names for name in entry['Names']])
        assert_not_in('NVYRPOD', [name for entry in names for name in entry['Names']])
        pods = json.loads(cmd(['podman', 'pod', 'ps', '--format=json']))
        assert_not_in('NVYRPOD', [entry['Name'] for entry in pods])
        networks = json.loads(cmd(['podman', 'network', 'ls', '--format=json']))
        assert_not_in('NVYRSMOKE', [entry['name'] for entry in networks])
        assert_not_in('NVYRSMOKE2', [entry['name'] for entry in networks])
        assert_not_in('NVYRSMOKE-0', [entry['name'] for entry in networks])
        assert_not_in('NVYRBASE', [entry['name'] for entry in networks])
        prepared = True

    def cleanup(session):
        if not prepared:
            return
        session.discard()
        running = session.get_config()
        changed = False
        for name in ('NVYRSMOKE', 'NVYRSMOK2'):
            if lookup(running, ('container', 'name', name), None) is not None:
                session.delete('delete container name ' + name)
                changed = True
        if lookup(running, ('container', 'pod', 'NVYRPOD'), None) is not None:
            session.delete('delete container pod NVYRPOD')
            changed = True
        for name in ('NVYRSMOKE', 'NVYRSMOKE2', 'NVYRSMOKE-0'):
            if lookup(running, ('container', 'network', name), None) is not None:
                session.delete('delete container network ' + name)
                changed = True
        if lookup(running, ('container', 'registry'), {}) != original_registries:
            changed = True
            if lookup(running, ('container', 'registry'), {}):
                session.delete('delete container registry')
            for registry, settings in original_registries.items():
                session.set(f'set container registry {registry} priority {settings["priority"]}')
        if changed:
            session.commit()
        if lookup(running, ('vrf', 'name', 'NVYRSMOKE'), None) is not None:
            session.delete('delete vrf name NVYRSMOKE')
            session.commit()

    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, standup, cleanup, stop=stop):
        yield cleanup


@pytest.fixture(autouse=True)
def container_environment(config, request, container_suite):
    """Discard rejected edits without committing; remove successfully installed objects."""
    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, lambda session: None, container_suite, stop=stop):
        yield


@pytest.fixture(scope='module')
def ipv4_network(config, request, container_suite):
    """Keep a common bridge definition for tests that change only container options."""
    def standup(session):
        session.set('set container network NVYRBASE subnet 198.18.232.0/24')
        session.commit()

    def cleanup(session):
        # Release consumers first, including after a failed test setup.
        container_suite(session)
        if lookup(session.get_config(), ('container', 'network', 'NVYRBASE'), None) is not None:
            session.delete('delete container network NVYRBASE')
            session.commit()

    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, standup, cleanup, stop=stop):
        yield


@pytest.fixture(scope='module')
def image(request):
    """Workload tests use an explicitly preloaded image, never download during a suite."""
    value = request.config.getoption('--container-image')
    if not value:
        pytest.skip('Pass --container-image with a preloaded BusyBox-compatible image')
    cmd(['podman', 'image', 'inspect', value])
    return value


@pytest.fixture
def volume_directory(config, container_environment):
    """Release the test workload's mounts before deleting its temporary persistent files."""
    root = Path('/config/containers')
    root.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='nvyr-smoke-', dir=root))
    try:
        yield directory
    finally:
        config.discard()
        if lookup(config.get_config(), ('container', 'name', 'NVYRSMOKE'), None) is not None:
            config.delete('delete container name NVYRSMOKE')
            config.commit()
        # Retain the directory if releasing its consumer failed above.
        shutil.rmtree(directory)

