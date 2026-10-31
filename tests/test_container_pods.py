"""Pod grammar, shared ownership, service ordering and operational contracts."""

from tests.container_harness import ContainerHarness
from tests.container_harness import verify_container

from copy import deepcopy
from email.parser import Parser
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nvyr.errors import OperationalError, RouterError, ValidationError
from nvyr.config_scripts import container
from nvyr.helpers import container_config as config, container_operations as views
from tests.container_rendering import container_unit, pod_unit
from nvyr.op_scripts import services
from tests.test_containers import FakeRuntime, IMAGE, IMAGE_ID
from tests.test_login import as_role


def configuration():
    return {'network': {'LAN': {'subnet': {'172.29.210.0/24': {}}}},
            'pod': {'WEB': {'network': {'LAN': {'address': ['172.29.210.10']}}}},
            'name': {'APP': {'image': IMAGE, 'pod': 'WEB'}, 'CACHE': {'image': IMAGE, 'pod': 'WEB'}}}


def test_anchored_pod_schema_and_dependency(controller, engine, session):
    controller.execute('set container network LAN subnet 172.29.210.0/24', session)
    controller.execute('set container pod WEB description service host-name web network LAN address 172.29.210.10', session)
    controller.execute('set container name APP image alpine pod WEB', session)
    effective = engine.schema.defaults(engine.view(session))['container']
    verify_container(effective)
    assert effective['pod']['WEB']['network']['LAN']['id'] == '0'
    assert 'WEB' in dict(controller.completion('set container name APP pod ', session)['candidates'])
    instances = dict(controller.completion('run show system services container name ', session)['candidates'])
    assert instances['WEB'] == 'Pod' and instances['APP'] == 'Container'
    engine.commit(session)

    with pytest.raises(RouterError, match='WEB'):
        controller.execute('delete container pod WEB', session)
    with pytest.raises(RouterError, match='referenced by'):
        controller.execute('delete container network LAN', session)


@pytest.mark.parametrize('setting', ['network', 'port', 'allow-host-networking', 'host-name', 'name-server', 'disable-dns'])
def test_members_cannot_override_shared_settings(setting):
    desired = configuration()
    desired['name']['APP'][setting] = {}
    with pytest.raises(ValidationError, match='pod membership conflicts'):
        verify_container(desired)


def test_pods_share_container_name_and_address_namespaces():
    desired = configuration()
    desired['name']['WEB'] = {'image': IMAGE}
    with pytest.raises(ValidationError, match='names must be distinct'):
        verify_container(desired)
    del desired['name']['WEB']
    desired['name']['OTHER'] = {'image': IMAGE, 'network': {'LAN': {'address': ['172.29.210.10']}}}
    with pytest.raises(ValidationError, match='already assigned'):
        verify_container(desired)


def test_native_infrastructure_name_is_reserved(controller, session):
    desired = configuration()
    desired['name']['WEB-infra'] = {'image': IMAGE}
    with pytest.raises(ValidationError, match='pod infrastructure'):
        verify_container(desired)
    with pytest.raises(RouterError, match='pod is reserved'):
        controller.execute('set container name pod', session)


def test_pod_infrastructure_init_is_packaged():
    root = Path(__file__).resolve().parents[1]
    dependencies = Parser().parsestr((root / 'packaging/debian/control').read_text())['Depends']
    assert 'catatonit' in [value.strip() for value in dependencies.split(',')]
    assert 'catatonit' in (root / 'images/router.list.chroot').read_text().splitlines()


def test_pod_attachment_limits_and_bridge_collisions():
    desired = configuration()
    desired['network']['WAN'] = {'subnet': {'172.29.211.0/24': {}}}
    desired['pod']['WEB']['network']['WAN'] = {}
    with pytest.raises(ValidationError, match='duplicate id 0'):
        verify_container(desired)
    desired['pod']['WEB']['network']['WAN']['id'] = '9'
    verify_container(desired)
    assert config.interface_owners(desired)['pd-WEB-9'] == ('pod', 'WEB')
    assert 'pd-APP-0' not in config.interface_owners(desired)
    desired['network']['WEB-9'] = {'subnet': {'172.29.212.0/24': {}}}
    with pytest.raises(ValidationError, match='pd-WEB-9 conflicts'):
        verify_container(desired)


def test_missing_pod_and_host_network_conflicts():
    desired = configuration()
    desired['name']['APP']['pod'] = 'MISSING'
    with pytest.raises(ValidationError, match='pod MISSING is not configured'):
        verify_container(desired)
    desired['name']['APP']['pod'] = 'WEB'
    desired['pod']['WEB']['allow-host-networking'] = True
    with pytest.raises(ValidationError, match='conflicts with network'):
        verify_container(desired)


def test_pod_published_ports_conflict_with_standalone_containers():
    desired = configuration()
    port = {'HTTP': {'protocol': 'tcp', 'source-port': '8080', 'destination-port': '80'}}
    desired['pod']['WEB']['port'] = port
    desired['name']['OTHER'] = {'image': IMAGE, 'network': {'LAN': {}}, 'port': port}
    with pytest.raises(ValidationError, match='published host port conflicts'):
        verify_container(desired)


def test_quadlets_share_namespace_without_redundant_member_network():
    desired = configuration()
    pod = desired['pod']['WEB']
    pod.update({'host-name': 'web', 'name-server': ['1.1.1.1'],
                'port': {'HTTP': {'protocol': 'tcp', 'source-port': '8080', 'destination-port': '80'}}})
    text = pod_unit('WEB', pod)
    assert 'Network=nvyr-network-4c414e.network:host_interface_name=pd-WEB-0,ip=172.29.210.10' in text
    assert 'PodName=WEB' in text and 'ExitPolicy=continue' in text
    assert 'DNS=1.1.1.1' in text and 'HostName=web' in text
    assert 'PublishPort=0.0.0.0:8080:80/tcp' in text

    member = container_unit('APP', desired['name']['APP'], IMAGE_ID)
    assert 'Pod=nvyr-pod-574542.pod' in member
    assert 'Network=' not in member and 'HostName=' not in member and 'DNS=' not in member
    assert '--memory=536870912' in member


def test_pod_network_change_restarts_members_before_replacing_network(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    runtime.events.clear()
    desired['network']['LAN']['internal'] = True
    runtime.apply(runtime.generate(desired))

    remove = runtime.events.index(('podman', 'network', 'rm', 'LAN'))
    for name in ('APP', 'CACHE'):
        assert any(event[:2] == ('systemctl', 'stop') and config.unit_name(name) + '.service' in event
                   for event in runtime.events[:remove])
    assert any(event[:2] == ('systemctl', 'stop') and config.pod_unit_name('WEB') + '.service' in event
               for event in runtime.events[:remove])


def test_member_change_preserves_pod_and_siblings(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    runtime.events.clear()
    desired['name']['APP']['memory'] = '64m'
    runtime.apply(runtime.generate(desired))
    stopped = [event[2:] for event in runtime.events if event[:2] == ('systemctl', 'stop')]
    assert stopped == [(config.unit_name('APP') + '.service',)]


def test_pod_disable_enable_and_rollback(tmp_path):
    runtime = FakeRuntime(tmp_path)
    original = configuration()
    runtime.apply(runtime.generate(original))
    desired = deepcopy(original)
    desired['pod']['WEB']['disable'] = True
    runtime.apply(runtime.generate(desired))
    assert list(runtime.quadlets.iterdir()) == [runtime.quadlets / (config.network_unit_name('LAN') + '.network')]

    runtime.apply(runtime.generate(original))
    desired = deepcopy(original)
    desired['pod']['WEB']['host-name'] = 'changed'
    runtime.fail_start = 1
    with pytest.raises(RouterError, match='previous configuration restored'):
        runtime.apply(runtime.generate(desired))
    assert runtime.read()['configuration'] == original
    assert 'HostName=changed' not in (runtime.quadlets / (config.pod_unit_name('WEB') + '.pod')).read_text()


def test_interrupted_pod_is_included_in_cleanup(tmp_path):
    runtime = FakeRuntime(tmp_path)
    runtime.apply(runtime.generate(configuration()))
    runtime.pending.write_text(json.dumps(container.inventory(configuration())))
    runtime.apply(runtime.generate({}, recovery=True))
    assert not list(runtime.quadlets.iterdir())
    assert not runtime.pending.exists()


def test_foreign_pod_member_blocks_removal(tmp_path):
    pod = {'Labels': {'nvyr.managed': 'true'}, 'InfraContainerID': 'infra',
           'Containers': [{'Id': 'infra', 'Name': 'pause'}, {'Id': 'foreign', 'Name': 'MANUAL'}]}
    runtime = ContainerHarness(state=tmp_path / 'state', execute=lambda *args: json.dumps(pod))
    with pytest.raises(RouterError, match='unmanaged member MANUAL'):
        runtime.validate_pod_members('WEB', configuration()['name'])


def test_unlabelled_native_pod_is_not_adopted(tmp_path):
    runtime = ContainerHarness(state=tmp_path / 'state', execute=lambda *args: '[{"Labels": null}]',
                                 status=lambda *args: (0, ''))
    with pytest.raises(RouterError, match='outside nVyR management'):
        runtime.owned('pod', 'WEB')


def test_interrupted_member_move_remains_owned(tmp_path):
    pod = {'Labels': {'nvyr.managed': 'true'}, 'Containers': [{'Id': 'app', 'Name': 'APP'}]}
    runtime = ContainerHarness(state=tmp_path / 'state', execute=lambda *args: json.dumps([pod]))
    runtime.owned = lambda kind, name: kind == 'container' and name == 'APP'
    desired = {'name': {'APP': {'image': IMAGE, 'pod': 'NEW'}}}
    runtime.validate_pod_members('OLD', desired['name'])


def test_pod_restart_dispatch_and_permissions(controller, monkeypatch):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'output\n')
    with as_role('read-only'):
        controller.execute('show containers pods')
        controller.execute('show containers pod WEB')
        with pytest.raises(RouterError, match='net-admin'):
            controller.execute('restart container pod WEB')
    assert calls == [['containers.nvyr.op', 'pods'], ['containers.nvyr.op', 'pods', '--name', 'WEB']]
    with as_role('net-admin'):
        result = controller.execute('restart container pod WEB')
        assert result['argv'] == ['containers.nvyr.op', 'restart_pod', 'WEB']
        controller.authorize_terminal('restart container pod WEB', None)


def test_pod_service_inventory_inherits_vrf_and_disabled_state():
    desired = configuration()
    desired['network']['LAN']['vrf'] = 'BLUE'
    desired['pod']['WEB']['disable'] = True
    records = {item['instance']: item for item in services.inventory({'container': desired}) if item['service'] == 'container'}
    assert records['APP']['vrfs'] == ['BLUE']
    assert records['WEB']['vrfs'] == ['BLUE']
    assert records['APP']['disabled'] and records['WEB']['disabled']


def test_pod_restart_waits_for_enabled_members(tmp_path):
    runtime = FakeRuntime(tmp_path)
    desired = configuration()
    desired['name']['CACHE']['disable'] = True
    runtime.apply(runtime.generate(desired))
    runtime.events.clear()
    runtime.restart_pod('WEB')
    assert runtime.events[-1] == ('systemctl', 'start', config.unit_name('APP') + '.service')


def test_precreation_pod_failure_and_empty_display(tmp_path, monkeypatch):
    runtime = SimpleNamespace(read=lambda: {'configuration': {'pod': {'WEB': {}}}},
                              execute=lambda *args: '[]', pending=tmp_path / 'pending')
    monkeypatch.setattr(views.services, 'unit_properties', lambda units: {
        unit: {'LoadState': 'loaded', 'ActiveState': 'failed', 'SubState': 'failed',
               'ExecMainCode': '1', 'ExecMainStatus': '125'} for unit in units})
    record = json.loads(views.show(runtime, 'pods', name='WEB', raw=True))[0]
    assert record['state'] == 'Failed'
    assert record['reason'] == 'Exited with status 125'
    assert 'Failed' in views.show(runtime, 'pods', name='WEB')
    with pytest.raises(OperationalError, match='does not exist'):
        views.show(runtime, 'pods', name='MISSING')
    runtime.read = lambda: {'configuration': {}}
    assert views.show(runtime, 'pods') == 'No pods configured or present.\n'
