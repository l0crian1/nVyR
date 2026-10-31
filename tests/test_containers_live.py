"""Opt-in Podman/Netavark tests in a disposable privileged systemd container only."""

from tests.container_harness import ContainerHarness

from copy import deepcopy
import json
import os
from pathlib import Path
import time

import pytest

from nvyr.errors import RouterError
from nvyr.config_scripts import container as containers
from nvyr.helpers.container_operations import show
from nvyr.helpers.container_config import unit_name
from nvyr.helpers.process import cmd, rc_cmd


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_PODMAN_TEST') != '1', reason='isolated native Podman test only')
IMAGE = 'docker.io/library/busybox:1.37'


@pytest.fixture
def runtime(tmp_path):
    containers.RUNTIME.mkdir(parents=True, exist_ok=True)
    instance = ContainerHarness(state=tmp_path / 'managed.json')
    yield instance
    instance.apply(instance.generate({}))


def application():
    return {'image': IMAGE, 'command': 'sleep', 'argument': 'infinity'}


def inspect(name='LIVE'):
    return json.loads(cmd(['podman', 'inspect', name]))[0]


def host_link(name):
    return json.loads(cmd(['ip', '-j', '-d', 'link', 'show', 'dev', name]))[0]


def test_native_network_and_attachment_names(runtime):
    """Netavark creates exact 15-byte names and keeps remaining attachment IDs stable."""
    desired = {
        'network': {
            'ABCDEFGHIJKL': {'subnet': {'172.29.233.0/24': {}}},
            'SECOND': {'subnet': {'172.29.234.0/24': {}}},
        },
        'name': {'ABCDEFGHIJ': {
            **application(),
            'network': {'ABCDEFGHIJKL': {}, 'SECOND': {'id': '9'}},
        }},
    }
    runtime.apply(runtime.generate(desired))
    bridge = json.loads(cmd(['podman', 'network', 'inspect', 'ABCDEFGHIJKL']))[0]
    assert bridge['network_interface'] == 'pd-ABCDEFGHIJKL'
    assert host_link('pd-ABCDEFGHIJKL')['linkinfo']['info_kind'] == 'bridge'
    assert host_link('pd-ABCDEFGHIJ-0')['master'] == 'pd-ABCDEFGHIJKL'
    assert host_link('pd-ABCDEFGHIJ-9')['master'] == 'pd-SECOND'
    before = inspect('ABCDEFGHIJ')['Id']
    runtime.apply(runtime.generate(desired))
    assert inspect('ABCDEFGHIJ')['Id'] == before

    del desired['name']['ABCDEFGHIJ']['network']['ABCDEFGHIJKL']
    runtime.apply(runtime.generate(desired))
    assert host_link('pd-ABCDEFGHIJ-9')['master'] == 'pd-SECOND'
    assert rc_cmd(['ip', 'link', 'show', 'dev', 'pd-ABCDEFGHIJ-0'])[0] != 0


def test_native_foreign_link_collision_preserves_running_container(runtime):
    """An unrelated interface blocks a changed suffix before the working container is stopped."""
    desired = configuration_with_network()
    runtime.apply(runtime.generate(desired))
    before = inspect()['Id']
    cmd(['ip', 'link', 'add', 'pd-LIVE-1', 'type', 'dummy'])
    try:
        desired['name']['LIVE']['network']['LIVE']['id'] = '1'
        with pytest.raises(RouterError, match='pd-LIVE-1 already exists'):
            runtime.apply(runtime.generate(desired))
        assert inspect()['Id'] == before
        assert inspect()['State']['Running']
        assert host_link('pd-LIVE-1')['linkinfo']['info_kind'] == 'dummy'
    finally:
        cmd(['ip', 'link', 'delete', 'pd-LIVE-1'])


def configuration_with_network():
    return {'network': {'LIVE': {'subnet': {'172.29.210.0/24': {}}}},
            'name': {'LIVE': {**application(), 'network': {'LIVE': {}}}}}


def test_native_limits_namespace_and_noop(runtime):
    """The generated systemd service enforces limits and isolates the default network."""
    desired = {'name': {'LIVE': application()}}
    runtime.apply(runtime.generate(desired))
    before = inspect()
    assert before['HostConfig']['PidsLimit'] == 256
    assert before['HostConfig']['Memory'] == 512 * 1024**2
    assert before['HostConfig']['CpuQuota'] == before['HostConfig']['CpuPeriod']
    assert before['HostConfig']['NetworkMode'] == 'none'
    status = cmd(['podman', 'exec', 'LIVE', 'cat', '/proc/1/status'])
    baseline = cmd(['podman', 'run', '--rm', '--network=none', IMAGE, 'cat', '/proc/self/status'])
    effective = next(line for line in status.splitlines() if line.startswith('CapEff:'))
    expected = next(line for line in baseline.splitlines() if line.startswith('CapEff:'))
    assert effective == expected
    runtime.apply(runtime.generate(desired))
    assert inspect()['Id'] == before['Id']


def test_native_persistent_volume_and_readonly(runtime):
    """Recreation retains volume data, and the kernel enforces read-only mounts."""
    desired = {'name': {'LIVE': application()}}
    desired['name']['LIVE']['volume'] = {'DATA': {'source': 'LIVE-test/data', 'destination': '/data'}}
    runtime.apply(runtime.generate(desired))
    cmd(['podman', 'exec', 'LIVE', 'sh', '-c', 'echo retained > /data/value'])
    desired['name']['LIVE']['volume']['DATA']['read-only'] = True
    runtime.apply(runtime.generate(desired))
    assert cmd(['podman', 'exec', 'LIVE', 'cat', '/data/value']).strip() == 'retained'
    status, _ = rc_cmd(['podman', 'exec', 'LIVE', 'touch', '/data/new'])
    assert status != 0
    runtime.apply(runtime.generate({}))
    assert Path('/config/containers/LIVE-test/data/value').read_text().strip() == 'retained'


def test_native_symlink_escape_cannot_replace_running_container(runtime, tmp_path):
    """A malicious source symlink fails and compensation restores the earlier service."""
    desired = {'name': {'LIVE': application()}}
    runtime.apply(runtime.generate(desired))
    directory = Path('/config/containers/LIVE-escape')
    directory.parent.mkdir(parents=True, exist_ok=True)
    directory.symlink_to(tmp_path, target_is_directory=True)
    changed = deepcopy(desired)
    changed['name']['LIVE']['volume'] = {'DATA': {'source': 'LIVE-escape', 'destination': '/data'}}
    try:
        with pytest.raises(RouterError, match='previous configuration restored'):
            runtime.apply(runtime.generate(changed))
        assert inspect()['State']['Running']
        assert not inspect()['Mounts']
    finally:
        directory.unlink()


def test_native_host_network_and_literal_environment(runtime):
    """Host networking is explicit; systemd must not expand configured environment values."""
    desired = {'name': {'LIVE': application()}}
    desired['name']['LIVE']['allow-host-networking'] = True
    desired['name']['LIVE']['environment'] = {'LITERAL': {'value': '${HOSTNAME} %n two words'}}
    runtime.apply(runtime.generate(desired))
    assert inspect()['HostConfig']['NetworkMode'] == 'host'
    assert cmd(['podman', 'exec', 'LIVE', 'printenv', 'LITERAL']).strip() == '${HOSTNAME} %n two words'


def test_native_ipv4_ipv6_dns_and_network_replacement(runtime):
    """Netavark assigns both families and DNS aliases, then reattaches clients after a change."""
    desired = {'network': {'LIVE': {'subnet': {'172.29.210.0/24': {}, 'fd00:210::/64': {}}}},
               'name': {'LIVE': application()}}
    desired['name']['LIVE']['network'] = {'LIVE': {'address': ['172.29.210.10', 'fd00:210::10'], 'alias': ['service-test']}}
    runtime.apply(runtime.generate(desired))
    before = inspect()
    addresses = before['NetworkSettings']['Networks']['LIVE']
    assert addresses['IPAddress'] == '172.29.210.10'
    assert addresses['GlobalIPv6Address'] == 'fd00:210::10'
    assert '172.29.210.10' in cmd(['podman', 'exec', 'LIVE', 'nslookup', 'service-test'])
    desired['network']['LIVE']['disable-dns'] = True
    runtime.apply(runtime.generate(desired))
    assert inspect()['Id'] != before['Id']
    assert not json.loads(cmd(['podman', 'network', 'inspect', 'LIVE']))[0]['dns_enabled']


def test_native_network_isolation_disable_and_restore(runtime):
    """Both bridges must opt out; replacement applies and removes the override for live clients."""
    desired = {
        'network': {
            'LEFT': {'subnet': {'172.29.235.0/24': {}}, 'disable-dns': True},
            'RIGHT': {'subnet': {'172.29.236.0/24': {}}, 'disable-dns': True},
        },
        'name': {
            'CLIENT': {**application(), 'network': {'LEFT': {}}},
            'SERVER': {'image': IMAGE, 'command': 'httpd', 'argument': '-f -p 80',
                       'network': {'RIGHT': {'address': ['172.29.236.10']}}},
        },
    }
    request = ['podman', 'exec', 'CLIENT', 'wget', '-S', '-T', '1', '-t', '1', '-O', '-', 'http://172.29.236.10/']
    runtime.apply(runtime.generate(desired))
    status, output = rc_cmd(request)
    assert status != 0 and '404' not in output

    desired['network']['LEFT']['isolation'] = {'disable': True}
    runtime.apply(runtime.generate(desired))
    status, output = rc_cmd(request)
    assert status != 0 and '404' not in output

    desired['network']['RIGHT']['isolation'] = {'disable': True}
    runtime.apply(runtime.generate(desired))
    status, output = rc_cmd(request)
    assert status == 0 or '404' in output

    del desired['network']['LEFT']['isolation']
    runtime.apply(runtime.generate(desired))
    status, output = rc_cmd(request)
    assert status != 0 and '404' not in output


def test_native_firewall_coexistence_and_published_port(runtime):
    """Netavark owns its table; an nVyR forwarding drop still overrides its forwarding accept."""
    desired = {'network': {'LIVE': {'subnet': {'172.29.210.0/24': {}}, 'disable-dns': True}},
               'name': {'LIVE': {'image': IMAGE, 'command': 'httpd', 'argument': '-f -p 80',
                                'network': {'LIVE': {'address': ['172.29.210.10']}},
                                'port': {'HTTP': {'protocol': 'tcp', 'source-port': '18980', 'destination-port': '80'}}},
                        'CLIENT': application()}}
    desired['name']['CLIENT']['network'] = {'LIVE': {}}
    runtime.apply(runtime.generate(desired))
    status, output = rc_cmd(['podman', 'exec', 'CLIENT', 'wget', '-S', '-O', '-', 'http://172.29.210.10/'])
    assert '404' in output or status == 0
    status, output = rc_cmd(['wget', '-S', '-O', '-', 'http://127.0.0.1:18980/'])
    assert '404' in output or status == 0
    rules = cmd(['nft', 'list', 'tables'])
    assert 'netavark' in rules
    cmd(['ip', 'netns', 'add', 'nvyr-podman-client'])
    cmd(['ip', 'link', 'add', 'podtest0', 'type', 'veth', 'peer', 'name', 'podtest1'])
    cmd(['nft', 'add', 'table', 'inet', 'nvyr_filter'])
    try:
        cmd(['ip', 'link', 'set', 'podtest1', 'netns', 'nvyr-podman-client'])
        cmd(['ip', 'address', 'add', '198.18.250.1/24', 'dev', 'podtest0'])
        cmd(['ip', 'link', 'set', 'podtest0', 'up'])
        cmd(['ip', '-n', 'nvyr-podman-client', 'address', 'add', '198.18.250.2/24', 'dev', 'podtest1'])
        cmd(['ip', '-n', 'nvyr-podman-client', 'link', 'set', 'podtest1', 'up'])
        request = ['ip', 'netns', 'exec', 'nvyr-podman-client', 'wget', '-T', '1', '-t', '1',
                   '-S', '-O', '-', 'http://198.18.250.1:18980/']
        status, output = rc_cmd(request)
        assert '404' in output or status == 0
        cmd(['nft', 'add', 'chain', 'inet', 'nvyr_filter', 'forward', '{ type filter hook forward priority filter; policy drop; }'])
        status, output = rc_cmd(request)
        assert status != 0 and '404' not in output
        # nVyR's own table replacement must leave Netavark's networks and mappings intact.
        cmd(['nft', 'delete', 'table', 'inet', 'nvyr_filter'])
        cmd(['nft', 'add', 'table', 'inet', 'nvyr_filter'])
        assert 'netavark' in cmd(['nft', 'list', 'tables'])
        assert inspect()['State']['Running']
        status, output = rc_cmd(request)
        assert '404' in output or status == 0
    finally:
        cmd(['nft', 'delete', 'table', 'inet', 'nvyr_filter'])
        cmd(['ip', 'link', 'delete', 'podtest0'])
        cmd(['ip', 'netns', 'delete', 'nvyr-podman-client'])


def test_native_failed_start_restores_previous_image_and_unit(runtime):
    """A nonexistent executable fails commit and restores the working container definition."""
    desired = {'name': {'LIVE': application()}}
    runtime.apply(runtime.generate(desired))
    changed = deepcopy(desired)
    changed['name']['LIVE']['command'] = '/does-not-exist'
    with pytest.raises(RouterError, match='previous configuration restored'):
        runtime.apply(runtime.generate(changed))
    assert inspect()['State']['Running']
    assert cmd(['systemctl', 'is-active', unit_name('LIVE') + '.service']).strip() == 'active'


def test_native_recovery_removes_interrupted_objects_without_quadlets(runtime):
    """Boot cleanup finds interrupted objects even when runtime definitions were lost."""
    desired = configuration_with_network()
    cmd(['podman', 'network', 'create', '--label=nvyr.managed=true', '--subnet=172.29.210.0/24', 'LIVE'])
    cmd(['podman', 'run', '-d', '--name=LIVE', '--label=nvyr.managed=true', '--network=LIVE',
         IMAGE, 'sleep', 'infinity'])
    runtime.pending.write_text(json.dumps(containers.inventory(desired)))

    runtime.apply(runtime.generate({}, recovery=True))

    assert rc_cmd(['podman', 'container', 'exists', 'LIVE'])[0] == 1
    assert rc_cmd(['podman', 'network', 'exists', 'LIVE'])[0] == 1
    assert not runtime.pending.exists()


def test_native_alpine_default_shell_stays_running(runtime):
    """Default stdin/TTY keeps the image shell alive on both automatically addressed networks."""
    image = 'docker.io/library/alpine:latest'
    image_config = json.loads(cmd(['podman', 'image', 'inspect', image]))[0]
    assert image_config['Config']['Cmd'] == ['/bin/sh']
    desired = {
        'network': {
            'ALPINE1': {'subnet': {'172.29.231.0/24': {}}},
            'ALPINE2': {'subnet': {'172.29.232.0/24': {}}},
        },
        'name': {'LIVE': {'image': image, 'network': {'ALPINE1': {}, 'ALPINE2': {'id': '1'}}}},
    }
    runtime.apply(runtime.generate(desired))
    container = inspect()
    assert container['State']['Running']
    assert container['Config']['OpenStdin']
    assert container['Config']['Tty']
    assert container['Config']['Cmd'] == ['/bin/sh']
    assert set(container['NetworkSettings']['Networks']) == {'ALPINE1', 'ALPINE2'}
    output = show(runtime, 'containers')
    assert 'LIVE' in output and 'Running' in output

    # Opting out of both restores noninteractive shell exit and normal Quadlet cleanup.
    desired['name']['LIVE'].update({'interactive': {'disable': True}, 'tty': {'disable': True}})
    runtime.apply(runtime.generate(desired))
    unit = unit_name('LIVE') + '.service'
    deadline = time.monotonic() + 5
    while cmd(['systemctl', 'show', unit, '--property=ActiveState', '--value']).strip() != 'inactive':
        assert time.monotonic() < deadline, 'Alpine shell did not finish'
        time.sleep(0.05)

    assert cmd(['systemctl', 'show', unit, '--property=Result', '--value']).strip() == 'success'
    assert cmd(['systemctl', 'show', unit, '--property=ExecMainStatus', '--value']).strip() == '0'
    assert json.loads(cmd(['podman', 'ps', '-a', '--filter=name=LIVE', '--format=json'])) == []

    desired['name']['LIVE'].update({'command': 'sleep', 'argument': 'infinity'})
    runtime.apply(runtime.generate(desired))
    assert inspect()['State']['Running']
    assert set(inspect()['NetworkSettings']['Networks']) == {'ALPINE1', 'ALPINE2'}
    output = show(runtime, 'containers')
    assert 'LIVE' in output and 'Running' in output


def test_native_interactive_and_tty_independent_overrides(runtime):
    """Podman receives each independent override and restores defaults when it is removed."""
    desired = {'name': {'LIVE': application()}}
    desired['name']['LIVE']['interactive'] = {'disable': True}
    runtime.apply(runtime.generate(desired))
    assert not inspect()['Config']['OpenStdin']
    assert inspect()['Config']['Tty']

    del desired['name']['LIVE']['interactive']
    desired['name']['LIVE']['tty'] = {'disable': True}
    runtime.apply(runtime.generate(desired))
    assert inspect()['Config']['OpenStdin']
    assert not inspect()['Config']['Tty']

    del desired['name']['LIVE']['tty']
    runtime.apply(runtime.generate(desired))
    assert inspect()['Config']['OpenStdin']
    assert inspect()['Config']['Tty']
