"""Container options, safe file inputs, search order and generated native arguments."""

from tests.container_harness import verify_container

import json
import os
from pathlib import Path
import stat
import tomllib

import pytest

from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import container_config, suggestors
from nvyr.config_scripts import container as containers
from tests.container_rendering import container_unit
from tests.container_rendering import network_unit
from tests.test_containers import FakeRuntime, IMAGE_ID, configuration


def test_extended_cli_options(controller, engine, session):
    controller.execute('set container name APP image alpine capability net-admin capability net-raw', session)
    controller.execute('set container name APP allow-host-networking', session)
    controller.execute('set container name APP host-name app01 entrypoint "sh -c" argument "sleep infinity"', session)
    controller.execute('set container name APP disable-dns environment-file APP/app.env', session)
    controller.execute('set container name APP device /dev/net/tun destination /dev/net/tun', session)
    controller.execute('set container name APP device /dev/net/tun permissions rw', session)
    controller.execute('set container name APP tmpfs /tmp size 64m', session)
    controller.execute('set container name APP tmpfs /tmp mode 1777', session)
    section = engine.view(session)['container']
    verify_container(section)
    output = container_unit('APP', section['name']['APP'], IMAGE_ID)
    assert 'AddCapability=NET_ADMIN' in output
    assert 'AddCapability=NET_RAW' in output
    assert 'HostName=app01' in output
    assert 'DNS=none' in output
    assert 'AddDevice=/dev/net/tun:/dev/net/tun:rw' in output
    assert 'Tmpfs=/tmp:rw,noexec,nosuid,nodev,size=67108864,mode=1777' in output
    assert 'EnvironmentFile=/run/nvyr-containers/environment/415050.env' in output


def test_capability_suggestions_and_invalid_values(controller, session):
    choices = dict(controller.completion('set container name APP capability ', session)['candidates'])
    assert 'net-admin' in choices
    assert 'net-raw' in choices
    assert choices['none'] == 'Drop all default capabilities; retain only explicitly named capabilities'
    with pytest.raises(RouterError):
        controller.execute('set container name APP capability net-admn', session)


def test_capability_none_drops_default_and_all_other_capabilities(controller, engine, session):
    controller.execute('set container name APP image alpine capability none', session)
    configuration = engine.view(session)['container']
    verify_container(configuration)
    unit = container_unit('APP', configuration['name']['APP'], IMAGE_ID)
    assert 'DropCapability=all' in unit
    assert 'AddCapability=' not in unit
    assert 'NoNewPrivileges=true' in unit


def test_capability_none_allows_only_explicit_additions(controller, engine, session):
    controller.execute('set container name APP image alpine capability none capability net-admin', session)
    configuration = engine.view(session)['container']
    verify_container(configuration)
    unit = container_unit('APP', configuration['name']['APP'], IMAGE_ID)
    assert 'DropCapability=all' in unit
    assert [line for line in unit.splitlines() if line.startswith('AddCapability=')] == ['AddCapability=NET_ADMIN']

    controller.execute('delete container name APP capability none', session)
    unit = container_unit('APP', engine.view(session)['container']['name']['APP'], IMAGE_ID)
    assert 'AddCapability=NET_BIND_SERVICE' in unit
    assert 'AddCapability=NET_ADMIN' in unit


def test_privileged_removes_contradictory_security_defaults():
    unit = container_unit('APP', {'privileged': True}, IMAGE_ID)
    assert 'PodmanArgs=--privileged' in unit
    assert 'DropCapability=' not in unit
    assert 'NoNewPrivileges=' not in unit


def test_registry_order_missing_and_duplicate_priorities():
    section = {'registry': {'docker.io': {'priority': '20'}, 'quay.io': {'priority': '5'}}}
    assert tomllib.loads(containers.registry_text(section))['unqualified-search-registries'] == ['quay.io', 'docker.io']
    section['registry']['quay.io']['priority'] = '20'
    with pytest.raises(ValidationError, match='unique'):
        verify_container(section)
    del section['registry']['quay.io']['priority']
    with pytest.raises(ValidationError, match='requires priority'):
        verify_container(section)


def test_network_vrf_dependency_and_mtu(controller, engine, session):
    controller.execute('set vrf name BLUE table 210', session)
    controller.execute('set container network LAN subnet 172.29.210.0/24', session)
    controller.execute('set container network LAN vrf BLUE mtu 1400', session)
    controller.execute('set container network LAN disable-dns', session)
    network = engine.view(session)['container']['network']['LAN']
    assert 'Options=vrf=BLUE' in network_unit('LAN', network)
    assert 'Options=mtu=1400' in network_unit('LAN', network)
    with pytest.raises(RouterError, match='referenc'):
        controller.execute('delete vrf name BLUE', session)
    assert engine.commit(session)['results']['container']['success']


def test_vrf_dns_rejected_and_missing_reference(controller, engine, session):
    controller.execute('set container network LAN subnet 172.29.210.0/24 vrf BLUE', session)
    with pytest.raises(ValidationError, match='require disable-dns'):
        verify_container(engine.view(session)['container'], vrfs=['BLUE'])
    controller.execute('set container network LAN disable-dns', session)
    result = engine.commit(session)
    assert not result['results']['container']['success']
    assert 'VRF BLUE is not configured' in result['results']['container']['error']


def test_cli_entrypoint_can_be_cleared(controller, engine, session):
    controller.execute('set container name APP image alpine entrypoint ""', session)
    assert engine.view(session)['container']['name']['APP']['entrypoint'] == ''


def test_ipv6_network_mtu_minimum():
    with pytest.raises(ValidationError, match='1280'):
        verify_container({'network': {'LAN': {'subnet': {'fd00::/64': {}}, 'mtu': '1200'}}})


def test_dns_conflicts_and_network_requirement():
    desired = configuration()
    section = desired['name']['APP']
    section['name-server'] = ['1.1.1.1', '2001:4860:4860::8888']
    verify_container(desired)
    assert 'DNS=1.1.1.1' in container_unit('APP', section, IMAGE_ID)
    section['disable-dns'] = True
    with pytest.raises(ValidationError, match='conflicts'):
        verify_container(desired)
    del section['disable-dns']
    del section['network']
    with pytest.raises(ValidationError, match='network attachment'):
        verify_container(desired)


def test_tmpfs_mount_overlap():
    desired = configuration()
    desired['name']['APP']['volume'] = {'DATA': {'source': 'APP/data', 'destination': '/data'}}
    desired['name']['APP']['tmpfs'] = {'/data/cache': {'size': '1m'}}
    with pytest.raises(ValidationError, match='overlap'):
        verify_container(desired)


def test_entrypoint_omission_clear_and_literal_arguments():
    assert 'Entrypoint=' not in container_unit('APP', {}, IMAGE_ID)
    assert 'Entrypoint=[]' in container_unit('APP', {'entrypoint': ''}, IMAGE_ID)
    rendered = container_unit('APP', {'entrypoint': 'sh -c "echo $HOME %n"'}, IMAGE_ID)
    assert '$$HOME %%n' in rendered


def test_environment_source_confinement(tmp_path):
    root = tmp_path / 'root'
    root.mkdir()
    (root / 'app.env').write_text('VALUE=hello\n')
    assert containers.filesystem.read_text(root, 'app.env') == 'VALUE=hello\n'
    (root / 'link.env').symlink_to(root / 'app.env')
    with pytest.raises(OSError):
        containers.filesystem.read_text(root, 'link.env')
    (root / 'linked').symlink_to(root, target_is_directory=True)
    with pytest.raises(OSError):
        containers.filesystem.read_text(root, 'linked/app.env')
    with pytest.raises(ValueError):
        containers.filesystem.read_text(root, '../app.env')
    (root / 'directory').mkdir()
    with pytest.raises(RouterError, match='regular file'):
        containers.filesystem.read_text(root, 'directory')


def test_environment_change_restarts_and_failure_restores_snapshot(tmp_path, monkeypatch):
    original = Path.lstat

    def metadata(path):
        """Model the reserved environment directory's ownership, retaining real I/O."""
        result = original(path)
        if path == tmp_path / 'environment':
            fields = list(result)
            fields[stat.ST_UID] = 0
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(Path, 'lstat', metadata)
    environment = 'VALUE=old\n'
    monkeypatch.setattr(containers.filesystem, 'read_text', lambda root, source: environment)
    monkeypatch.setattr(container_config, 'environment_path', lambda name: str(tmp_path / 'environment' / name))
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    desired['name']['APP']['environment-file'] = 'app.env'
    runtime.apply(runtime.generate(desired))
    runtime.events.clear()
    runtime.apply(runtime.generate(desired))
    assert not any(event[:2] == ('systemctl', 'stop') for event in runtime.events)

    environment = 'VALUE=new\n'
    runtime.fail_start = 1
    with pytest.raises(RouterError, match='previous configuration restored'):
        runtime.apply(runtime.generate(desired))
    assert (tmp_path / 'environment' / 'APP').read_text() == 'VALUE=old\n'
    assert json.loads(runtime.state.read_text())['inputs']['APP']['environment'] == containers.fingerprint('VALUE=old\n')


def test_image_suggestions_use_rootful_store(monkeypatch):
    from nvyr.helpers import process

    calls = []

    def images(argv, **kwargs):
        calls.append(argv)
        return json.dumps([{'Names': ['docker.io/library/alpine:latest']}, {'Names': None}])

    monkeypatch.setattr(process, 'cmd', images)
    result = suggestors.container_images(suggestors.Context())
    assert [item.value for item in result] == ['docker.io/library/alpine:latest']
    assert calls[0][-1] == 'images'
    assert calls[0][0] == 'systemd-run'
