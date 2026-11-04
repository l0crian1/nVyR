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
    assert_equal, assert_raises, assert_firewall_object, firewall_map_entries, assert_is_not_none,
)
from smoketests.firewall_support import send_firewall_udp


@pytest.mark.parametrize('family, name, port', [('ipv4', 'FN31SERVICES', 54124), ('ipv6', 'FN32SERVICES', 54128)])
def test_map_default_and_counter(config, family, name, port):
    """The exact key wins, misses use the tracked fallback, and deleting it restores fall-through."""
    assert_equal(send_firewall_udp(2, family=family, port=port), 2)
    entries = firewall_map_entries(f'{family}_map_{name}')
    default, = [entry for entry in entries if entry.get('default')]
    exact, = [entry for entry in entries if not entry.get('default')]
    assert_equal(default['counter']['packets'], 2)
    assert_is_not_none(default['last-used'])
    assert_equal(exact['counter']['packets'], 0)

    assert_equal(send_firewall_udp(1, family=family, port=port + 1), 0)
    config.set(f'set firewall group map {family} {name} default-result action drop')
    config.commit()
    assert_equal(send_firewall_udp(1, family=family, port=port), 0)

    config.delete(f'delete firewall group map {family} {name} default-result')
    config.commit()
    assert_equal(send_firewall_udp(1, family=family, port=port), 1)


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
