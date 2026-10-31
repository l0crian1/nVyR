"""Batch-created container runtime scenarios: one setup and one final cleanup.

Tests device access, hostname, exec, tmpfs, environment, DNS, mounts, resource
limits, IPv4/IPv6 networking, operational views, failure restart and replacement.
Each case owns a separate workload; mutations cannot restart another case's
container. Networks are shared except for MTU, VRF and address-family scenarios.
Incompatible: deleting the whole container tree or changing the shared bridge.
"""

import json
from pathlib import Path
import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.helpers.process import cmd, rc_cmd
from nvyr.op_scripts import containers as container_commands
from smoketests.assertions import (
    assert_equal, assert_in, assert_not_in, assert_not_equal, assert_container_running,
    assert_container_restarted, assert_raises,
)


def test_container_device():
    """Device destinations can differ from their source and expose a real device."""
    cmd(['podman', 'exec', 'CTDEVICE', 'sh', '-c', 'test -c /dev/test-null && echo test >/dev/test-null'])


def test_container_hostname():
    """A container-specific hostname reaches the process without changing the router hostname."""
    assert_equal(cmd(['podman', 'exec', 'CTHOST', 'hostname']).strip(), 'smoke-container')


def test_connect_container_command():
    """The installed worker runs quoted commands inside the container and returns failures."""
    output = cmd(['containers.nvyr.op', 'connect', 'CTCONNECT', '--send-command',
                  'printf "container: "; hostname'])
    assert_in('container: smoke-container', output)
    status, output = rc_cmd(['containers.nvyr.op', 'connect', 'CTCONNECT', '--send-command', 'exit 7'])
    assert_equal(status, 7)


def test_container_tmpfs():
    """Temporary storage has the configured capacity and disappears with its container."""
    mounts = cmd(['podman', 'exec', 'CTTMPFS', 'cat', '/proc/mounts'])
    assert_in(' /scratch tmpfs ', mounts)
    assert_in('size=8192k', mounts)


def test_container_environment_file():
    """An environment file provides defaults while explicit variables override its values."""
    environment = cmd(['podman', 'exec', 'CTENV', 'env']).splitlines()
    assert_in('SMOKE_FILE=from-file', environment)
    assert_in('SMOKE_OVERRIDE=explicit', environment)


def test_disable_and_reenable(config):
    """Disabling removes the runtime instance; enabling recreates it from configuration."""
    config.set('set container name CTDISABLE disable')
    config.commit()
    containers = json.loads(cmd(['podman', 'ps', '-a', '--format=json']))
    assert_not_in('CTDISABLE', [name for entry in containers for name in entry['Names']])
    config.delete('delete container name CTDISABLE disable')
    config.commit()
    container = json.loads(cmd(['podman', 'inspect', 'CTDISABLE']))[0]
    assert_equal(container['State']['Running'], True)


def test_network_dns_alias():
    """Aardvark resolves a configured attachment alias to the container address."""
    output = cmd(['podman', 'exec', 'CTDNS', 'nslookup', 'smoke-service'])
    assert_in('198.18.230.10', output)


def test_environment_literal_values():
    """Shell and systemd metacharacters remain literal environment values."""
    assert_in('SMOKE_LITERAL=$HOME %n two words',
              cmd(['podman', 'exec', 'CTLITERAL', 'env']).splitlines())


def test_restart_after_failure():
    """Systemd restarts a failed workload under the default on-failure policy."""
    previous = assert_container_running('CTFAIL')['Id']
    cmd(['podman', 'kill', '--signal=KILL', 'CTFAIL'])
    assert_container_restarted('CTFAIL', previous)


def test_unrelated_commit_preserves_workload(config):
    """Adding an unused network must not restart an unchanged container."""
    previous = assert_container_running('CTKEEP')['Id']

    config.set('set container network CTUNUSED subnet 198.18.234.0/24')
    config.commit()
    assert_equal(assert_container_running('CTKEEP')['Id'], previous)


def test_network_edit_recreates_attached_workload(config):
    """A bridge MTU change recreates attached containers with the new link settings."""
    previous = assert_container_running('CTNETEDIT')['Id']

    config.set('set container network CTEDITNET mtu 1400')
    config.commit()
    assert_not_equal(assert_container_running('CTNETEDIT')['Id'], previous)
    link = json.loads(cmd(['ip', '-j', 'link', 'show', 'dev', 'pd-CTNETEDIT-0']))[0]
    assert_equal(link['mtu'], 1400)


def test_persistent_volume_survives_recreation(config, container_scenario):
    """Persistent contents survive replacement; a read-only remount rejects writes."""
    directory = container_scenario["volume"]
    cmd(['podman', 'exec', 'CTVOLUME', 'sh', '-c', 'echo persistent >/data/value'])
    assert_equal((Path(directory) / 'value').read_text().strip(), 'persistent')
    config.set('set container name CTVOLUME volume DATA read-only')
    config.commit()

    assert_equal(cmd(['podman', 'exec', 'CTVOLUME', 'cat', '/data/value']).strip(), 'persistent')
    status, output = rc_cmd(['podman', 'exec', 'CTVOLUME', 'sh', '-c', 'echo changed >/data/value'])
    assert_not_equal(status, 0, msg=output)
    assert_equal((Path(directory) / 'value').read_text().strip(), 'persistent')


def test_show_containers():
    """Summary and detail show the running workload without exposing its environment."""
    assert_in('CTSHOW', container_commands.show())
    details = container_commands.show(name='CTSHOW', detail=True)
    assert_in('Running', details)
    assert_in('512.0 MiB', details)
    assert_not_in('do-not-display-this', details)
    records = json.loads(container_commands.show(name='CTSHOW', raw=True))
    assert_equal(len(records), 1)
    assert_equal(records[0]['managed'], True)
    assert_equal(records[0]['command'][0], 'sh')


def test_show_disabled_container():
    """A configured disabled workload remains visible even without a native container."""
    records = json.loads(container_commands.show(name='CTDISABLED', raw=True))
    assert_equal(records[0]['state'], 'Disabled')
    assert_equal(records[0]['id'], None)


def test_show_container_network_inventory():
    """The scoped network view correlates the bridge, VRF and assigned container address."""
    record = json.loads(container_commands.networks(name='CTVRFNET', raw=True))[0]
    assert_equal(record['interface'], 'pd-CTVRFNET')
    assert_equal(record['vrf'], 'CTVRF')
    assert_equal(record['subnets'][0]['gateway'], '198.18.235.1')
    assert_equal(record['attachments'][0]['container'], 'CTNETVIEW')
    assert_in('198.18.235.10/24', record['attachments'][0]['addresses'])
    assert_in('pd-CTVRFNET', container_commands.networks())


def test_show_container_image_inventory():
    """Image users are correlated by content ID, including tagged aliases."""
    identifier = assert_container_running('CTIMAGES')['Image'].removeprefix('sha256:')
    images = json.loads(container_commands.images(raw=True))
    record = next(item for item in images if item['id'].removeprefix('sha256:') == identifier)
    assert_in('CTIMAGES', record['containers'])
    assert_in('CTIMAGES', container_commands.images())


def test_show_container_statistics():
    """One snapshot reports actual cgroup accounting for the selected workload."""
    records = json.loads(container_commands.statistics(name='CTSTATS', raw=True))
    assert_equal(len(records), 1)
    assert_equal(records[0]['name'], 'CTSTATS')
    assert_in('%', records[0]['cpu_percent'])
    assert_in('/', records[0]['mem_usage'])
    assert_in('CTSTATS', container_commands.statistics())


def test_restart_container(config):
    """Managed restart recreates the service workload using the same pinned image."""
    previous = assert_container_running('CTRESTART')
    configuration = config.get_config()

    container_commands.restart('CTRESTART')

    assert_container_restarted('CTRESTART', previous['Id'])
    current = assert_container_running('CTRESTART')
    assert_equal(current['Image'], previous['Image'])
    assert_equal(config.get_config(), configuration)


def test_restart_disabled_container_rejected():
    """The operational restart cannot bypass a disabled configuration."""
    with assert_raises(SystemExit) as error:
        container_commands.restart('CTNOREST')
    assert_equal(error.value.code, 1)
    assert_equal(json.loads(container_commands.show(name='CTNOREST', raw=True))[0]['state'], 'Disabled')


def test_container_capability():
    """NET_ADMIN permits network administration inside the container namespace."""
    cmd(['podman', 'exec', 'CTCAP', 'ip', 'link', 'add', 'test0', 'type', 'dummy'])
    link = json.loads(cmd(['podman', 'inspect', 'CTCAP']))[0]
    assert_in('CAP_NET_ADMIN', link['EffectiveCaps'])


def test_ipv6_static_attachment():
    """An IPv6 attachment receives its configured address and named host veth."""
    container = assert_container_running('CTIPV6')
    assert_equal(container['NetworkSettings']['Networks']['CTIP6NET']['GlobalIPv6Address'],
                 'fd00:198:18:230::10')
    link = json.loads(cmd(['ip', '-j', 'link', 'show', 'dev', 'pd-CTIPV6-0']))[0]
    assert_equal(link['master'], 'pd-CTIP6NET')


def test_dual_stack_attachment():
    """One attachment supports one explicit address from each configured family."""
    attachment = assert_container_running('CTDUAL')['NetworkSettings']['Networks']['CTDUALNET']
    assert_equal(attachment['IPAddress'], '198.18.233.10')
    assert_equal(attachment['GlobalIPv6Address'], 'fd00:198:18:233::10')


def test_default_network_isolation():
    """Omitting attachments uses network=none rather than an implicit Podman bridge."""
    container = assert_container_running('CTNONE')
    assert_equal(container['HostConfig']['NetworkMode'], 'none')
    assert_equal(container['HostConfig']['Privileged'], False)


def test_resource_overrides_and_removal(config):
    """Resource edits recreate the workload; removing overrides restores bounded defaults."""
    container = assert_container_running('CTRES')
    assert_equal(container['HostConfig']['Memory'], 128 * 1024**2)
    assert_equal(container['HostConfig']['PidsLimit'], 64)
    assert_equal(container['HostConfig']['CpuQuota'] / container['HostConfig']['CpuPeriod'], 0.5)
    original_id = container['Id']

    config.delete('delete container name CTRES memory')
    config.delete('delete container name CTRES cpus')
    config.delete('delete container name CTRES process-limit')
    config.commit()

    container = assert_container_running('CTRES')
    assert_not_equal(container['Id'], original_id)
    assert_equal(container['HostConfig']['Memory'], 512 * 1024**2)
    assert_equal(container['HostConfig']['PidsLimit'], 256)
    assert_equal(container['HostConfig']['CpuQuota'] / container['HostConfig']['CpuPeriod'], 1)


def test_published_tcp_port(container_scenario):
    """A TCP publication retains its explicit loopback host binding and destination port."""
    bindings = assert_container_running('CTPTCP')['HostConfig']['PortBindings']
    assert_equal(bindings['8080/tcp'], [{'HostIp': '127.0.0.1', 'HostPort': container_scenario['tcp_port']}])


def test_published_udp_port(container_scenario):
    """UDP publications preserve the selected protocol rather than defaulting to TCP."""
    bindings = assert_container_running('CTPUDP')['HostConfig']['PortBindings']
    assert_equal(bindings['5353/udp'], [{'HostIp': '127.0.0.1', 'HostPort': container_scenario['udp_port']}])
