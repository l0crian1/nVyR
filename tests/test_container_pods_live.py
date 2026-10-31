"""Podman pod lifecycle and networking in an opt-in disposable systemd host."""

from copy import deepcopy
import json
from urllib.request import urlopen

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import container_operations
from nvyr.helpers.process import cmd, rc_cmd
from tests.test_containers_live import application, host_link, inspect, pytestmark, runtime


def configuration():
    return {'network': {'PODLAN': {'subnet': {'172.29.238.0/24': {}}}},
            'pod': {'LIVEPOD': {'network': {'PODLAN': {'address': ['172.29.238.10']}}}},
            'name': {'LIVE': {**application(), 'pod': 'LIVEPOD'},
                     'LIVE2': {**application(), 'pod': 'LIVEPOD'}}}


def pod():
    return json.loads(cmd(['podman', 'pod', 'inspect', 'LIVEPOD']))[0]


def test_shared_network_localhost_and_pod_display(runtime):
    """Both members share one attachment and can reach a service over localhost."""
    runtime.apply(runtime.generate(configuration()))
    assert inspect('LIVE')['Pod'] == inspect('LIVE2')['Pod'] == pod()['Id']
    assert host_link('pd-LIVEPOD-0')['master'] == 'pd-PODLAN'
    assert rc_cmd(['ip', 'link', 'show', 'pd-LIVE-0'])[0] != 0
    cmd(['podman', 'exec', 'LIVE2', 'sh', '-c', 'echo shared >/tmp/index.html; httpd -p 8080 -h /tmp'])
    assert cmd(['podman', 'exec', 'LIVE', 'wget', '-qO-', 'http://127.0.0.1:8080']).strip() == 'shared'

    records = json.loads(container_operations.show(runtime, 'pods', name='LIVEPOD', raw=True))
    assert records[0]['networks'][0]['addresses'] == ['172.29.238.10/24']
    assert {member['name'] for member in records[0]['members']} == {'LIVE', 'LIVE2'}
    assert '172.29.238.10/24' in container_operations.show(runtime, 'pods', name='LIVEPOD')


def test_member_change_and_disable_preserve_pod(runtime):
    """A member's settings or disable flag do not interrupt its sibling or shared namespace."""
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    original_pod = pod()['Id']
    sibling = inspect('LIVE2')['Id']
    desired['name']['LIVE']['memory'] = '64m'
    runtime.apply(runtime.generate(desired))
    assert pod()['Id'] == original_pod
    assert inspect('LIVE2')['Id'] == sibling
    assert inspect('LIVE')['HostConfig']['Memory'] == 64 * 1024**2

    desired['name']['LIVE']['disable'] = True
    runtime.apply(runtime.generate(desired))
    assert pod()['Id'] == original_pod
    assert inspect('LIVE2')['Id'] == sibling
    assert rc_cmd(['podman', 'container', 'exists', 'LIVE'])[0] == 1


def test_pod_change_restart_disable_and_reenable(runtime):
    """Changes to the shared namespace recreate members; disabling the pod suppresses both."""
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    before = inspect('LIVE')['Id']
    desired['pod']['LIVEPOD']['host-name'] = 'pod-host'
    runtime.apply(runtime.generate(desired))
    assert inspect('LIVE')['Id'] != before
    assert cmd(['podman', 'exec', 'LIVE2', 'hostname']).strip() == 'pod-host'
    before = inspect('LIVE')['Id']
    runtime.restart_pod('LIVEPOD')
    assert inspect('LIVE')['Id'] != before
    assert inspect('LIVE2')['State']['Running']

    desired['pod']['LIVEPOD']['disable'] = True
    runtime.apply(runtime.generate(desired))
    assert rc_cmd(['podman', 'pod', 'exists', 'LIVEPOD'])[0] == 1
    assert rc_cmd(['podman', 'container', 'exists', 'LIVE2'])[0] == 1
    del desired['pod']['LIVEPOD']['disable']
    runtime.apply(runtime.generate(desired))
    assert inspect('LIVE2')['State']['Running']


def test_pod_multiple_networks_ipv6_dns_and_publishing(runtime):
    """Pods reuse attachment IDs, dual-stack allocation, DNS and published ports."""
    desired = configuration()
    desired['network']['SECOND'] = {'subnet': {'fd00:29:238::/64': {}}, 'disable-dns': True}
    settings = desired['pod']['LIVEPOD']
    settings['network']['SECOND'] = {'id': '9', 'address': ['fd00:29:238::10']}
    settings['name-server'] = ['1.1.1.1']
    settings['port'] = {'HTTP': {'protocol': 'tcp', 'source-address': '127.0.0.1',
                                'source-port': '28389', 'destination-port': '8080'}}
    runtime.apply(runtime.generate(desired))
    assert host_link('pd-LIVEPOD-9')['master'] == 'pd-SECOND'
    infra = inspect(pod()['InfraContainerID'])
    assert infra['HostConfig']['Dns'] == ['1.1.1.1']
    cmd(['podman', 'exec', 'LIVE', 'sh', '-c', 'echo published >/tmp/index.html; httpd -p 8080 -h /tmp'])
    with urlopen('http://127.0.0.1:28389', timeout=5) as response:
        assert response.read().strip() == b'published'
    output = container_operations.show(runtime, 'pods', name='LIVEPOD')
    assert 'fd00:29:238::10/64' in output and '28389' in output


def test_failed_member_start_restores_pod_configuration(runtime):
    """Rollback rebuilds the previous shared namespace and both working members."""
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    changed = deepcopy(desired)
    changed['pod']['LIVEPOD']['host-name'] = 'failed-change'
    changed['name']['LIVE']['command'] = '/does-not-exist'
    with pytest.raises(RouterError, match='previous configuration restored'):
        runtime.apply(runtime.generate(changed))
    assert runtime.read()['configuration'] == desired
    assert inspect('LIVE')['State']['Running'] and inspect('LIVE2')['State']['Running']


def test_pod_host_and_isolated_networking(runtime):
    """Host networking is explicit; an unattached pod is otherwise isolated."""
    runtime.apply(runtime.generate({'pod': {'LIVEPOD': {}}}))
    assert pod()['State'] == 'Running'
    desired = {'pod': {'LIVEPOD': {}}, 'name': {'LIVE': {**application(), 'pod': 'LIVEPOD'}}}
    runtime.apply(runtime.generate(desired))
    assert inspect(pod()['InfraContainerID'])['HostConfig']['NetworkMode'] == 'none'
    desired['pod']['LIVEPOD']['allow-host-networking'] = True
    runtime.apply(runtime.generate(desired))
    assert inspect(pod()['InfraContainerID'])['HostConfig']['NetworkMode'] == 'host'


def test_member_move_preserves_both_pods_and_other_members(runtime):
    """Moving a member recreates only that workload, retaining the old pod's sibling."""
    desired = configuration()
    runtime.apply(runtime.generate(desired))
    original_pod = pod()['Id']
    sibling = inspect('LIVE2')['Id']
    desired['pod']['NEWPOD'] = {'network': {'PODLAN': {'address': ['172.29.238.20']}}}
    desired['name']['LIVE']['pod'] = 'NEWPOD'
    runtime.apply(runtime.generate(desired))
    assert pod()['Id'] == original_pod
    assert inspect('LIVE2')['Id'] == sibling
    assert inspect('LIVE')['Pod'] != original_pod
    member = inspect('LIVE')['Id']

    del desired['name']['LIVE2']
    del desired['pod']['LIVEPOD']
    runtime.apply(runtime.generate(desired))
    assert inspect('LIVE')['Id'] == member
    assert rc_cmd(['podman', 'pod', 'exists', 'LIVEPOD'])[0] == 1
