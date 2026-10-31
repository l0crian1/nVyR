"""CLI translation into native Podman networking and container configuration.

Common container-option cases share a bridge definition; network/VRF mutation cases
use separate objects. Idle workloads handle TERM so cleanup tests no stop timeout.
Traffic forwarding, DNS resolution, and application behavior live in functionaltests.
"""

import json
from pathlib import Path
import socket
import tomllib

import pytest

if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.helpers.process import cmd
from smoketests.assertions import (
    assert_config_commit_rejected, assert_equal, assert_in, assert_not_in, assert_not_equal,
)
from smoketests.container_support import container_environment, container_suite, idle_container, image, ipv4_network, volume_directory


def test_ipv4_network(config):
    """Netavark receives the configured subnet, gateway, and DNS setting."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24 gateway 198.18.230.1')
    config.set('set container network NVYRSMOKE disable-dns')
    config.commit()
    network = json.loads(cmd(['podman', 'network', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(network['subnets'][0]['subnet'], '198.18.230.0/24')
    assert_equal(network['dns_enabled'], False)
    assert_equal(network['network_interface'], 'pd-NVYRSMOKE')


def test_network_vrf_and_mtu(config, image):
    """Netavark creates a bridge inside the configured VRF with the requested MTU."""
    config.set('set vrf name NVYRSMOKE table 28405')
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container network NVYRSMOKE vrf NVYRSMOKE mtu 1400')
    config.set('set container network NVYRSMOKE disable-dns')
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE network NVYRSMOKE')
    config.commit()

    link = json.loads(cmd(['ip', '-j', 'link', 'show', 'dev', 'pd-NVYRSMOKE']))[0]
    assert_equal(link['master'], 'NVYRSMOKE')
    assert_equal(link['mtu'], 1400)


def test_container_capability(config, image):
    """The requested capability reaches the native Podman configuration."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE capability net-admin')
    config.commit()
    link = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_in('CAP_NET_ADMIN', link['EffectiveCaps'])


def test_container_capability_none(config, image):
    """Dropping defaults leaves no capabilities in the native Podman configuration."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE capability none')
    config.commit()

    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['EffectiveCaps'] or [], [])
    assert_equal(container['BoundingCaps'] or [], [])


def test_container_capability_none_with_explicit_addition(config, image):
    """Named capabilities are added after defaults are dropped; deleting none restores defaults."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE capability none capability net-admin')
    config.commit()

    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['EffectiveCaps'], ['CAP_NET_ADMIN'])
    assert_equal(container['BoundingCaps'], ['CAP_NET_ADMIN'])

    config.delete('delete container name NVYRSMOKE capability none')
    config.commit()

    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(set(container['EffectiveCaps']), {'CAP_NET_ADMIN', 'CAP_NET_BIND_SERVICE'})


def test_container_uid_gid_and_restore_image_identity(config, image):
    """Explicit IDs reach Podman; auto restores the image's configured user."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE uid 1234 gid 5678')
    config.commit()

    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['Config']['User'], '1234:5678')

    config.set('set container name NVYRSMOKE uid auto gid auto')
    config.commit()

    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    native_image = json.loads(cmd(['podman', 'image', 'inspect', image]))[0]
    assert_equal(container['Config']['User'], native_image['Config'].get('User', ''))


def test_container_gid_preserves_image_user(config, image):
    """A group-only override retains the user selected by the image."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE gid 5678')
    config.commit()

    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    native_image = json.loads(cmd(['podman', 'image', 'inspect', image]))[0]
    image_user = native_image['Config'].get('User', '').split(':', 1)[0] or '0'
    assert_equal(container['Config']['User'], image_user + ':5678')


def test_container_name_servers(config, image, ipv4_network):
    """Explicit container DNS servers reach Podman independently of network DNS defaults."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE network NVYRBASE')
    config.set('set container name NVYRSMOKE name-server 1.1.1.1')
    config.set('set container name NVYRSMOKE name-server 9.9.9.9')
    config.commit()
    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['HostConfig']['Dns'], ['1.1.1.1', '9.9.9.9'])


def test_container_disable_dns(config, image, ipv4_network):
    """The container option leaves image resolver configuration untouched."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE disable-dns network NVYRBASE')
    config.commit()
    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['ResolvConfPath'], '')


def test_container_dns_conflict(config):
    """Keeping image resolv.conf and assigning servers are mutually exclusive."""
    config.set('set container name NVYRSMOKE image alpine disable-dns name-server 1.1.1.1')
    assert_config_commit_rejected(config, 'disable-dns conflicts with name-server')


def test_container_privileged(config, image):
    """Privileged mode is an explicit option rather than a default."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE privileged')
    config.commit()
    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['HostConfig']['Privileged'], True)


def test_container_entrypoint(config, image):
    """Entrypoint selects the executable independently of its arguments."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config, entrypoint=True)
    config.commit()
    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['Config']['Entrypoint'], ['sh'])
    assert_equal(container['State']['Running'], True)


def test_network_unknown_vrf_rejected(config):
    """A dependency reference must resolve before Netavark receives it."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container network NVYRSMOKE vrf NVYRSMOKE')
    config.set('set container network NVYRSMOKE disable-dns')
    assert_config_commit_rejected(config, 'VRF NVYRSMOKE is not configured')


def test_network_vrf_dns_rejected(config):
    """VRF bridges must explicitly disable Aardvark until its VRF binding is supported."""
    config.set('set vrf name NVYRSMOKE table 28405')
    config.commit()

    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container network NVYRSMOKE vrf NVYRSMOKE')
    assert_config_commit_rejected(config, 'VRF networks require disable-dns')


def test_network_ipv6_mtu_rejected(config):
    """IPv6 networks cannot use an MTU below the protocol minimum."""
    config.set('set container network NVYRSMOKE subnet fd00:198:18:230::/64')
    config.set('set container network NVYRSMOKE mtu 1200')
    assert_config_commit_rejected(config, 'IPv6 networks require an mtu of at least 1280')


def test_container_mount_overlap_rejected(config):
    """A tmpfs must not hide a persistent mount or one of its subdirectories."""
    config.set('set container name NVYRSMOKE image alpine')
    config.set('set container name NVYRSMOKE volume DATA source NVYRSMOKE/data')
    config.set('set container name NVYRSMOKE volume DATA destination /data')
    config.set('set container name NVYRSMOKE tmpfs /data/cache size 1m')
    assert_config_commit_rejected(config, 'destinations must not overlap')


def test_ipv6_network(config):
    """An IPv6-only internal network retains its explicitly selected gateway."""
    config.set('set container network NVYRSMOKE subnet fd00:198:18:230::/64 gateway fd00:198:18:230::1')
    config.set('set container network NVYRSMOKE internal')
    config.commit()
    network = json.loads(cmd(['podman', 'network', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(network['ipv6_enabled'], True)
    assert_equal(network['internal'], True)
    assert_equal(network['subnets'][0]['gateway'], 'fd00:198:18:230::1')


def test_network_isolation_disable_and_restore(config):
    """Commit replaces the bridge policy when isolation is disabled or restored."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.commit()
    network = json.loads(cmd(['podman', 'network', 'inspect', 'NVYRSMOKE']))[0]
    assert_not_in('isolate', network.get('options', {}))

    config.set('set container network NVYRSMOKE isolation disable')
    config.commit()
    network = json.loads(cmd(['podman', 'network', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(network['options']['isolate'], 'false')

    config.delete('delete container network NVYRSMOKE isolation disable')
    config.commit()
    network = json.loads(cmd(['podman', 'network', 'inspect', 'NVYRSMOKE']))[0]
    assert_not_in('isolate', network.get('options', {}))


def test_network_attachment_and_defaults(config, image):
    """A running container gets its static address and bounded memory/process defaults."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE network NVYRSMOKE address 198.18.230.10')
    config.commit()
    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['State']['Running'], True)
    assert_equal(container['HostConfig']['Memory'], 512 * 1024**2)
    assert_equal(container['HostConfig']['PidsLimit'], 256)
    assert_equal(container['Config']['OpenStdin'], True)
    assert_equal(container['Config']['Tty'], True)
    assert_equal(container['NetworkSettings']['Networks']['NVYRSMOKE']['IPAddress'], '198.18.230.10')
    link = json.loads(cmd(['ip', '-j', 'link', 'show', 'dev', 'pd-NVYRSMOKE-0']))[0]
    assert_equal(link['master'], 'pd-NVYRSMOKE')


def test_network_attachment_ids(config, image):
    """Explicit IDs select host veth names and survive removal of another attachment."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container network NVYRSMOKE2 subnet 198.18.231.0/24')
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE network NVYRSMOKE')
    config.set('set container name NVYRSMOKE network NVYRSMOKE2 id 9')
    config.commit()

    link = json.loads(cmd(['ip', '-j', 'link', 'show', 'dev', 'pd-NVYRSMOKE-0']))[0]
    assert_equal(link['master'], 'pd-NVYRSMOKE')
    link = json.loads(cmd(['ip', '-j', 'link', 'show', 'dev', 'pd-NVYRSMOKE-9']))[0]
    assert_equal(link['master'], 'pd-NVYRSMOKE2')

    config.delete('delete container name NVYRSMOKE network NVYRSMOKE')
    config.commit()
    link = json.loads(cmd(['ip', '-j', 'link', 'show', 'dev', 'pd-NVYRSMOKE-9']))[0]
    assert_equal(link['master'], 'pd-NVYRSMOKE2')


def test_duplicate_attachment_ids_rejected(config):
    """Two implicit zero IDs fail verification before any image or workload is required."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container network NVYRSMOKE2 subnet 198.18.231.0/24')
    config.set('set container name NVYRSMOKE image alpine')
    config.set('set container name NVYRSMOKE network NVYRSMOKE')
    config.set('set container name NVYRSMOKE network NVYRSMOKE2')
    assert_config_commit_rejected(config, 'duplicate id 0')


def test_interactive_disable_and_restore(config, image):
    """Closing stdin preserves the terminal; deleting the override reopens stdin."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE interactive disable')
    config.commit()

    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['Config']['OpenStdin'], False)
    assert_equal(container['Config']['Tty'], True)

    config.delete('delete container name NVYRSMOKE interactive disable')
    config.commit()
    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['Config']['OpenStdin'], True)
    assert_equal(container['State']['Running'], True)


def test_tty_disable_and_restore(config, image):
    """Removing the terminal preserves open stdin; deleting the override restores the terminal."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE tty disable')
    config.commit()

    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['Config']['OpenStdin'], True)
    assert_equal(container['Config']['Tty'], False)

    config.delete('delete container name NVYRSMOKE tty disable')
    config.commit()
    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['Config']['Tty'], True)
    assert_equal(container['State']['Running'], True)


def test_host_networking(config, image):
    """Host networking is passed explicitly to Podman."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE allow-host-networking')
    config.commit()
    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['HostConfig']['NetworkMode'], 'host')


def test_host_network_conflict_rejected(config):
    """Host networking and bridge attachments cannot describe the same container."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container name NVYRSMOKE image docker.io/library/busybox:1.37')
    config.set('set container name NVYRSMOKE allow-host-networking network NVYRSMOKE')
    assert_config_commit_rejected(config, 'allow-host-networking conflicts')


def test_incomplete_volume_rejected(config):
    """A source without a destination fails verification before native apply."""
    config.set('set container name NVYRSMOKE image docker.io/library/busybox:1.37')
    config.set('set container name NVYRSMOKE volume DATA source NVYRSMOKE/data')
    assert_config_commit_rejected(config, 'requires destination')


def test_ipv6_static_attachment(config, image):
    """An IPv6 attachment receives its configured address and named host veth."""
    config.set('set container network NVYRSMOKE subnet fd00:198:18:230::/64')
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE network NVYRSMOKE address fd00:198:18:230::10')
    config.commit()

    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['NetworkSettings']['Networks']['NVYRSMOKE']['GlobalIPv6Address'],
                 'fd00:198:18:230::10')
    link = json.loads(cmd(['ip', '-j', 'link', 'show', 'dev', 'pd-NVYRSMOKE-0']))[0]
    assert_equal(link['master'], 'pd-NVYRSMOKE')


def test_dual_stack_attachment(config, image):
    """One attachment supports one explicit address from each configured family."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container network NVYRSMOKE subnet fd00:198:18:230::/64')
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE network NVYRSMOKE address 198.18.230.10')
    config.set('set container name NVYRSMOKE network NVYRSMOKE address fd00:198:18:230::10')
    config.commit()

    attachment = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]['NetworkSettings']['Networks']['NVYRSMOKE']
    assert_equal(attachment['IPAddress'], '198.18.230.10')
    assert_equal(attachment['GlobalIPv6Address'], 'fd00:198:18:230::10')


def test_default_network_isolation(config, image):
    """Omitting attachments uses network=none rather than an implicit Podman bridge."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.commit()

    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['HostConfig']['NetworkMode'], 'none')
    assert_equal(container['HostConfig']['Privileged'], False)


def test_resource_overrides_and_removal(config, image):
    """Resource edits recreate the workload; removing overrides restores bounded defaults."""
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE memory 128m cpus 0.5 process-limit 64')
    config.commit()

    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_equal(container['HostConfig']['Memory'], 128 * 1024**2)
    assert_equal(container['HostConfig']['PidsLimit'], 64)
    assert_equal(container['HostConfig']['CpuQuota'] / container['HostConfig']['CpuPeriod'], 0.5)
    original_id = container['Id']

    config.delete('delete container name NVYRSMOKE memory')
    config.delete('delete container name NVYRSMOKE cpus')
    config.delete('delete container name NVYRSMOKE process-limit')
    config.commit()

    container = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]
    assert_not_equal(container['Id'], original_id)
    assert_equal(container['HostConfig']['Memory'], 512 * 1024**2)
    assert_equal(container['HostConfig']['PidsLimit'], 256)
    assert_equal(container['HostConfig']['CpuQuota'] / container['HostConfig']['CpuPeriod'], 1)


def test_registry_priority_order(config):
    """Search order follows numeric priorities without pulling an image."""
    if config.get_config().get('container', {}).get('registry'):
        config.delete('delete container registry')
    config.set('set container registry docker.io priority 20')
    config.set('set container registry quay.io priority 10')
    config.commit()

    settings = tomllib.loads(Path('/etc/containers/registries.conf.d/90-nvyr.conf').read_text())
    assert_equal(settings['unqualified-search-registries'], ['quay.io', 'docker.io'])


def test_published_tcp_port(config, image, ipv4_network):
    """A TCP publication retains its explicit loopback host binding and destination port."""
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE network NVYRBASE')
    config.set('set container name NVYRSMOKE port WEB protocol tcp')
    config.set('set container name NVYRSMOKE port WEB source-address 127.0.0.1')
    config.set(f'set container name NVYRSMOKE port WEB source-port {port}')
    config.set('set container name NVYRSMOKE port WEB destination-port 8080')
    config.commit()

    bindings = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]['HostConfig']['PortBindings']
    assert_equal(bindings['8080/tcp'], [{'HostIp': '127.0.0.1', 'HostPort': str(port)}])


def test_published_udp_port(config, image, ipv4_network):
    """UDP publications preserve the selected protocol rather than defaulting to TCP."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    config.set(f'set container name NVYRSMOKE image {image}')
    idle_container(config)
    config.set('set container name NVYRSMOKE network NVYRBASE')
    config.set('set container name NVYRSMOKE port DNS protocol udp')
    config.set('set container name NVYRSMOKE port DNS source-address 127.0.0.1')
    config.set(f'set container name NVYRSMOKE port DNS source-port {port}')
    config.set('set container name NVYRSMOKE port DNS destination-port 5353')
    config.commit()

    bindings = json.loads(cmd(['podman', 'inspect', 'NVYRSMOKE']))[0]['HostConfig']['PortBindings']
    assert_equal(bindings['5353/udp'], [{'HostIp': '127.0.0.1', 'HostPort': str(port)}])
