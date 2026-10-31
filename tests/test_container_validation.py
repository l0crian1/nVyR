"""Individual values fail at schema entry; complete objects use lifecycle verification."""

from copy import deepcopy

import pytest

from nvyr.errors import RouterError
from nvyr.schema import Schema
from tests.container_harness import verify_container


@pytest.mark.parametrize('command', [
    'set container registry https://docker.io',
    'set container registry docker.io priority 0',
    'set container registry docker.io priority 65536',
    'set container network host',
    'set container pod POD network none',
    'set container name APP network bridge',
    'set container network LAN subnet 192.0.2.0/31',
    'set container network LAN subnet 192.0.2.1/32',
    'set container network LAN subnet 192.0.2.1/24',
    'set container network LAN subnet fd00::/127',
    'set container network LAN subnet fd00::1/128',
    'set container network LAN subnet fd00::1/64',
    'set container network LAN subnet invalid',
    'set container network LAN subnet fe80::%eth0/64',
    'set container network LAN vrf 1invalid',
    'set container network LAN mtu 67',
    'set container network LAN mtu 65536',
    'set container name pod',
    'set container pod ABCDEFGHIJK',
    'set container name APP network LAN id 00',
    'set container pod POD network LAN id 01',
    'set container name APP name-server example.com',
    'set container pod POD name-server example.com',
    'set container name APP host-name bad/name',
    'set container name APP capability net-admn',
    'set container name APP environment-file ../secret',
    'set container name APP entrypoint "unbalanced\'"',
    'set container name APP argument "unbalanced\'"',
    'set container name APP image dir:/etc',
    'set container name APP device /etc/passwd',
    'set container name APP device /dev/net/tun destination /etc/passwd',
    'set container name APP device /dev/net/tun permissions rwx',
    'set container name APP tmpfs relative',
    'set container name APP tmpfs /tmp size 0',
    'set container name APP tmpfs /tmp mode 888',
    'set container name APP volume DATA source ../secret',
    'set container name APP volume DATA destination relative',
])
def test_invalid_value_never_enters_candidate(controller, engine, session, command):
    before = deepcopy(engine.view(session))

    with pytest.raises(RouterError):
        controller.execute(command, session)

    assert engine.view(session) == before


@pytest.mark.parametrize('configuration', [
    {'network': {'host': {'subnet': {'192.0.2.0/24': {}}}}},
    {'name': {'pod': {'image': 'alpine'}}},
    {'network': {'LAN': {'subnet': {'192.0.2.0/31': {}}}}},
    {'network': {'LAN': {'subnet': {'fd00::1/64': {}}}}},
    {'name': {'APP': {'image': 'alpine', 'network': {'LAN': {'id': '00'}}}}},
    {'name': {'APP': {'image': 'alpine', 'capability': ['unknown']}}},
])
def test_loaded_configuration_uses_the_same_value_validators(configuration):
    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration({'container': configuration})


def test_valid_boundaries_and_incomplete_cli_objects(controller, engine, session):
    controller.execute('set container network ABCDEFGHIJKL subnet 192.0.2.0/30 mtu 68', session)
    controller.execute('set container network V6 subnet fd00::/126 mtu 1280', session)
    controller.execute('set container name ABCDEFGHIJ image alpine network ABCDEFGHIJKL id 9', session)
    controller.execute('set container name ABCDEFGHIJ volume DATA source APP/data', session)
    controller.execute('set container name ABCDEFGHIJ volume DATA destination /data', session)
    controller.execute('set container pod pod network V6 id 0', session)

    verify_container(engine.view(session)['container'])
