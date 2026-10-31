"""Container schema and cross-field failures must not alter running configuration."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import assert_config_commit_rejected, assert_raises
from smoketests.container_support import container_environment, container_suite


def test_network_requires_subnet(config):
    """A named bridge cannot silently allocate an unconfigured subnet."""
    config.set('set container network NVYRSMOKE')
    assert_config_commit_rejected(config, 'requires at least one subnet')


def test_ipv4_overlapping_networks(config):
    """Overlapping IPv4 bridges are rejected before native routing is changed."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container network NVYRSMOKE2 subnet 198.18.230.0/25')
    assert_config_commit_rejected(config, 'overlaps')


def test_ipv6_overlapping_networks(config):
    """IPv6 bridges have the same overlap restriction as IPv4."""
    config.set('set container network NVYRSMOKE subnet fd00:198:18:230::/64')
    config.set('set container network NVYRSMOKE2 subnet fd00:198:18:230::/65')
    assert_config_commit_rejected(config, 'overlaps')


def test_ipv4_gateway_outside_subnet(config):
    """The bridge gateway must belong to its configured IPv4 subnet."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24 gateway 198.18.231.1')
    assert_config_commit_rejected(config, 'not usable')


def test_ipv6_gateway_outside_subnet(config):
    """The bridge gateway must belong to its configured IPv6 subnet."""
    config.set('set container network NVYRSMOKE subnet fd00:198:18:230::/64 gateway fd00:198:18:231::1')
    assert_config_commit_rejected(config, 'not usable')


def test_ipv4_network_too_small(config):
    """Reject insufficient gateway/client space at CLI entry."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set container network NVYRSMOKE subnet 198.18.230.0/31')


def test_ipv6_network_too_small(config):
    """IPv6 subnet size is also a standalone value constraint."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set container network NVYRSMOKE subnet fd00:198:18:230::/127')


def test_reserved_network_name(config):
    """A native network mode cannot enter the candidate as a bridge name."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set container network host')


def test_reserved_container_name(config):
    """The pod operational selector is unavailable as a workload name."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set container name pod')


def test_attachment_id_leading_zero(config):
    """Attachment IDs must consume exactly one character in the interface name."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set container name NVYRSMOKE network NVYRSMOKE id 00')


def test_container_requires_image(config):
    """An incomplete workload must fail verification rather than start a default image."""
    config.set('set container name NVYRSMOKE')
    assert_config_commit_rejected(config, 'requires image')


def test_unknown_network(config):
    """References that never existed fail even though dependency tracking permits staging."""
    config.set('set container name NVYRSMOKE image alpine network NVYRSMOKE')
    assert_config_commit_rejected(config, 'network NVYRSMOKE is not configured')


def test_ipv4_static_address_outside_network(config):
    """Static IPv4 addresses must be drawn from the attached network."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container name NVYRSMOKE image alpine network NVYRSMOKE address 198.18.231.10')
    assert_config_commit_rejected(config, 'outside network')


def test_ipv6_static_address_outside_network(config):
    """Static IPv6 addresses must be drawn from the attached network."""
    config.set('set container network NVYRSMOKE subnet fd00:198:18:230::/64')
    config.set('set container name NVYRSMOKE image alpine network NVYRSMOKE address fd00:198:18:231::10')
    assert_config_commit_rejected(config, 'outside network')


def test_static_gateway_address_reserved(config):
    """A container may not claim its bridge gateway's address."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container name NVYRSMOKE image alpine network NVYRSMOKE address 198.18.230.1')
    assert_config_commit_rejected(config, 'reserved on network')


def test_multiple_ipv4_addresses(config):
    """One attachment permits only one explicitly assigned IPv4 address."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container name NVYRSMOKE image alpine network NVYRSMOKE address 198.18.230.10')
    config.set('set container name NVYRSMOKE network NVYRSMOKE address 198.18.230.11')
    assert_config_commit_rejected(config, 'one static address per family')


def test_multiple_ipv6_addresses(config):
    """One attachment permits only one explicitly assigned IPv6 address."""
    config.set('set container network NVYRSMOKE subnet fd00:198:18:230::/64')
    config.set('set container name NVYRSMOKE image alpine network NVYRSMOKE address fd00:198:18:230::10')
    config.set('set container name NVYRSMOKE network NVYRSMOKE address fd00:198:18:230::11')
    assert_config_commit_rejected(config, 'one static address per family')


def test_duplicate_static_address(config):
    """Two enabled containers cannot claim the same address on one network."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container name NVYRSMOKE image alpine network NVYRSMOKE address 198.18.230.10')
    config.set('set container name NVYRSMOK2 image alpine network NVYRSMOKE address 198.18.230.10')
    assert_config_commit_rejected(config, 'already assigned')


def test_bridge_veth_name_collision(config):
    """Generated bridge and attachment names share one Linux interface namespace."""
    config.set('set container network NVYRSMOKE-0 subnet 198.18.230.0/24')
    config.set('set container name NVYRSMOKE image alpine network NVYRSMOKE-0')
    assert_config_commit_rejected(config, 'conflicts with a configured container network bridge')


def test_dns_without_network(config):
    """DNS settings cannot be passed to Podman's network=none mode."""
    config.set('set container name NVYRSMOKE image alpine name-server 1.1.1.1')
    assert_config_commit_rejected(config, 'DNS options require')


def test_published_port_without_network(config):
    """Published ports need an explicit bridge attachment."""
    config.set('set container name NVYRSMOKE image alpine')
    config.set('set container name NVYRSMOKE port WEB protocol tcp')
    assert_config_commit_rejected(config, 'port publishing requires')


def test_incomplete_published_port(config):
    """Port declarations require both endpoints and a transport protocol."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container name NVYRSMOKE image alpine network NVYRSMOKE')
    config.set('set container name NVYRSMOKE port WEB protocol tcp')
    assert_config_commit_rejected(config, 'requires destination-port, source-port')


def test_duplicate_published_port(config):
    """Competing listeners fail before either container can start."""
    config.set('set container network NVYRSMOKE subnet 198.18.230.0/24')
    config.set('set container name NVYRSMOKE image alpine network NVYRSMOKE')
    config.set('set container name NVYRSMOK2 image alpine network NVYRSMOKE')
    config.set('set container name NVYRSMOKE port WEB protocol tcp')
    config.set('set container name NVYRSMOKE port WEB source-port 53198')
    config.set('set container name NVYRSMOKE port WEB destination-port 80')
    config.set('set container name NVYRSMOK2 port WEB protocol tcp')
    config.set('set container name NVYRSMOK2 port WEB source-port 53198')
    config.set('set container name NVYRSMOK2 port WEB destination-port 8080')
    assert_config_commit_rejected(config, 'published host port conflicts')


def test_environment_requires_value(config):
    """An environment tag is incomplete until its value is entered."""
    config.set('set container name NVYRSMOKE image alpine environment TEST')
    assert_config_commit_rejected(config, 'requires value')


def test_registry_duplicate_priorities(config):
    """Registry ordering must not depend on declaration order."""
    if config.get_config().get('container', {}).get('registry'):
        config.delete('delete container registry')
    config.set('set container registry docker.io priority 10')
    config.set('set container registry quay.io priority 10')
    assert_config_commit_rejected(config, 'priorities must be unique')


def test_volume_path_escape(config):
    """The schema rejects sources outside the persistent container directory."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set container name NVYRSMOKE volume DATA source ../etc')


def test_unknown_capability(config):
    """Capability typos fail at insertion, before reaching Podman."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set container name NVYRSMOKE capability not-a-capability')


def test_attachment_id_range(config):
    """Attachment suffixes are restricted to one decimal digit."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set container name NVYRSMOKE network NVYRSMOKE id 10')


def test_device_outside_dev(config):
    """Device mappings cannot expose arbitrary files from the host."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set container name NVYRSMOKE device /etc/passwd')
