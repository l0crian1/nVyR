"""Native option behavior in an explicitly enabled disposable Podman host."""

from pathlib import Path

from nvyr.helpers.process import cmd
from tests.test_containers_live import application, configuration_with_network, host_link, inspect, pytestmark, runtime


def test_native_capability_device_hostname_tmpfs(runtime):
    """Requested capabilities, mapped devices and volatile mounts reach the running process."""
    desired = {'name': {'LIVE': {
        **application(), 'capability': ['net-admin', 'net-raw'], 'host-name': 'nvyr-options',
        'device': {'/dev/null': {'destination': '/dev/test-null', 'permissions': 'rw'}},
        'tmpfs': {'/scratch': {'size': '8m', 'mode': '1777'}},
    }}}
    runtime.apply(runtime.generate(desired))
    assert cmd(['podman', 'exec', 'LIVE', 'hostname']).strip() == 'nvyr-options'
    cmd(['podman', 'exec', 'LIVE', 'sh', '-c', 'test -c /dev/test-null && echo test >/dev/test-null'])
    cmd(['podman', 'exec', 'LIVE', 'ip', 'link', 'add', 'test0', 'type', 'dummy'])
    mounts = cmd(['podman', 'exec', 'LIVE', 'cat', '/proc/mounts'])
    assert ' /scratch tmpfs ' in mounts
    assert 'size=8192k' in mounts


def test_native_environment_file_override_and_refresh(runtime):
    """Files stay confined, explicit variables win, and changed file contents trigger recreation."""
    source = Path('/config/containers/options-test.env')
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text('FROM_FILE=hello\nOVERRIDE=file\nLITERAL=$HOME %n\n')
    desired = {'name': {'LIVE': {**application(), 'environment-file': source.name,
                               'environment': {'OVERRIDE': {'value': 'config'}}}}}
    try:
        runtime.apply(runtime.generate(desired))
        before = inspect()['Id']
        environment = cmd(['podman', 'exec', 'LIVE', 'env']).splitlines()
        assert 'FROM_FILE=hello' in environment
        assert 'OVERRIDE=config' in environment
        assert 'LITERAL=$HOME %n' in environment
        source.write_text('FROM_FILE=changed\n')
        runtime.apply(runtime.generate(desired))
        assert inspect()['Id'] != before
        assert 'FROM_FILE=changed' in cmd(['podman', 'exec', 'LIVE', 'env']).splitlines()
    finally:
        source.unlink()


def test_native_entrypoint_override_and_clear(runtime):
    """Entrypoint is argv rather than shell interpolation and an empty override is honored."""
    desired = {'name': {'LIVE': {'image': application()['image'], 'entrypoint': 'sleep', 'argument': 'infinity'}}}
    runtime.apply(runtime.generate(desired))
    assert inspect()['State']['Running']
    assert inspect()['Config']['Entrypoint'] == ['sleep']
    desired['name']['LIVE']['entrypoint'] = ''
    desired['name']['LIVE']['command'] = 'sleep'
    runtime.apply(runtime.generate(desired))
    assert not inspect()['Config']['Entrypoint']
    assert inspect()['State']['Running']
    desired['name']['LIVE']['entrypoint'] = 'sh -c "exec sleep infinity" "$HOME %n"'
    del desired['name']['LIVE']['command']
    del desired['name']['LIVE']['argument']
    runtime.apply(runtime.generate(desired))
    assert inspect()['Config']['Entrypoint'] == ['sh', '-c', 'exec sleep infinity', '$HOME %n']
    assert inspect()['State']['Running']


def test_native_tun_device(runtime):
    """TUN is available through an explicit device mapping without privileged mode."""
    desired = {'name': {'LIVE': {**application(), 'capability': ['net-admin'],
                               'device': {'/dev/net/tun': {'permissions': 'rw'}}}}}
    runtime.apply(runtime.generate(desired))
    cmd(['podman', 'exec', 'LIVE', 'test', '-c', '/dev/net/tun'])
    assert not inspect()['HostConfig']['Privileged']


def test_native_container_dns(runtime):
    """Explicit DNS servers are forwarded by Aardvark; disable-dns preserves the image file."""
    desired = configuration_with_network()
    desired['name']['LIVE']['name-server'] = ['1.1.1.1', '9.9.9.9']
    runtime.apply(runtime.generate(desired))
    assert inspect()['HostConfig']['Dns'] == ['1.1.1.1', '9.9.9.9']
    del desired['name']['LIVE']['name-server']
    desired['name']['LIVE']['disable-dns'] = True
    runtime.apply(runtime.generate(desired))
    assert inspect()['ResolvConfPath'] == ''
    assert inspect()['State']['Running']


def test_native_privileged(runtime):
    """Privileged mode is explicit and does not retain contradictory capability drops."""
    desired = {'name': {'LIVE': {**application(), 'privileged': True}}}
    runtime.apply(runtime.generate(desired))
    assert inspect()['HostConfig']['Privileged']
    status = cmd(['podman', 'exec', 'LIVE', 'cat', '/proc/1/status'])
    assert 'NoNewPrivs:\t0' in status


def test_native_network_vrf_and_mtu(runtime):
    """Netavark attaches its own bridge to a VRF and sets bridge/veth MTUs."""
    cmd(['ip', 'link', 'add', 'OPTBLUE', 'type', 'vrf', 'table', '2011'])
    cmd(['ip', 'link', 'set', 'OPTBLUE', 'up'])
    desired = configuration_with_network()
    desired['network']['LIVE'].update({'vrf': 'OPTBLUE', 'mtu': '1400', 'disable-dns': True})
    desired['name']['LIVE']['capability'] = ['net-raw']
    try:
        runtime.apply(runtime.generate(desired, vrfs=['OPTBLUE']))
        assert host_link('pd-LIVE')['master'] == 'OPTBLUE'
        assert host_link('pd-LIVE')['mtu'] == 1400
        assert host_link('pd-LIVE-0')['mtu'] == 1400
        cmd(['podman', 'exec', 'LIVE', 'ping', '-c', '1', '-W', '2', '172.29.210.1'])
    finally:
        runtime.apply(runtime.generate({}))
        cmd(['ip', 'link', 'delete', 'OPTBLUE'])


def test_native_ipv6_network_vrf(runtime):
    """IPv6 gateway reachability survives Netavark's VRF bridge attachment."""
    cmd(['ip', 'link', 'add', 'OPTBLUE6', 'type', 'vrf', 'table', '2012'])
    cmd(['ip', 'link', 'set', 'OPTBLUE6', 'up'])
    desired = {
        'network': {'LIVE': {'subnet': {'fd00:29:210::/64': {}}, 'vrf': 'OPTBLUE6', 'disable-dns': True}},
        'name': {'LIVE': {**application(), 'network': {'LIVE': {}}, 'capability': ['net-raw']}},
    }
    try:
        runtime.apply(runtime.generate(desired, vrfs=['OPTBLUE6']))
        assert host_link('pd-LIVE')['master'] == 'OPTBLUE6'
        cmd(['podman', 'exec', 'LIVE', 'ping6', '-c', '1', '-W', '2', 'fd00:29:210::1'])
    finally:
        runtime.apply(runtime.generate({}))
        cmd(['ip', 'link', 'delete', 'OPTBLUE6'])
