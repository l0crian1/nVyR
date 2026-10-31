"""Firewall map defaults on the shared routed-network scenario.

IPv4/IPv6 catchall counters, nested inet jumps and default-result removal.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_equal, assert_raises, assert_firewall_object, assert_firewall_map_default_counter,
)
from smoketests.firewall_support import send_firewall_udp


def test_ipv4_map_default_and_counter(config):
    """A missing IPv4 tuple uses its default and increments that element's counter."""
    # Baseline: configs/network-features.conf (FN31).

    assert_equal(send_firewall_udp(2, port=54124), 2)
    assert_firewall_map_default_counter('ipv4_map_FN31SERVICES', 2)


def test_ipv6_map_default_and_counter(config):
    """IPv6 defaults have independent element counters and normal tuple matching."""
    # Baseline: configs/network-features.conf (FN32).

    assert_equal(send_firewall_udp(2, family='ipv6', port=54128), 2)
    assert_firewall_map_default_counter('ipv6_map_FN32SERVICES', 2)


def test_inet_default_jump_nested_policy(config):
    """A default-only inet map reaches a named policy through a nested jump."""
    # Baseline: configs/network-features.conf (FN33).

    assert_equal(send_firewall_udp(1, port=54132), 0)
    with assert_raises(RouterError, match='referenced'):
        config.delete('delete firewall inet name FN33OUTER')

    config.set('set firewall inet name FN33INNER default-action accept')
    config.commit()
    assert_equal(send_firewall_udp(1, port=54132), 1)


def test_default_removal_restores_lookup_miss(config):
    """Deleting a fallback lets unmatched traffic proceed to the following rule."""
    # Baseline: configs/network-features.conf (FN34).
    assert_equal(send_firewall_udp(1, port=54136), 0)

    config.delete('delete firewall group map inet FN34SERVICES default-result')
    config.commit()
    assert_equal(send_firewall_udp(1, port=54136), 1)
    assert_firewall_object('map', 'inet_map_FN34SERVICES', absent=(r'\*.*:',))
