"""Firewall inet on the shared routed-network scenario.

Family-neutral lookup misses, nested verdict-map jumps and shared allowances.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from smoketests.assertions import assert_equal, assert_firewall_rule_packets, assert_firewall_object
from smoketests.firewall_support import send_firewall_udp


def test_ipv4_inet_miss_reaches_family_policy(config):
    """An unmatched inet rule leaves the IPv4 policy responsible for the verdict."""
    # Baseline: configs/network-features.conf (FN54).

    assert_equal(send_firewall_udp(1, port=54216), 1)
    assert_firewall_rule_packets('input', 35410, 0)
    assert_firewall_rule_packets('ipv4_input', 35410, 1)


def test_ipv6_inet_miss_reaches_family_policy(config):
    """An unmatched inet rule falls through to IPv6 dispatch."""
    # Baseline: configs/network-features.conf (FN55).

    assert_equal(send_firewall_udp(1, family='ipv6', port=54220), 1)
    assert_firewall_rule_packets('input', 35510, 0)
    assert_firewall_rule_packets('ipv6_input', 35510, 1)


def test_inet_verdict_map_nested_named_chains(config):
    """Neutral maps can jump through named policies using the ordinary registrar."""
    # Baseline: configs/network-features.conf (FN56).

    assert_equal(send_firewall_udp(1, port=54224), 1)
    assert_firewall_rule_packets('inet_name_FN56INNER', 35610, 1)
    assert_firewall_object('map', 'inet_map_FN56SERVICES', 'inet_proto', 'inet_service', 'jump inet_name_FN56OUTER')


def test_inet_match_group_and_shared_limit(config):
    """A neutral group and allowance serve the same rule across both families."""
    # Baseline: configs/network-features.conf (FN57).

    assert_equal(send_firewall_udp(1, port=54228), 1)
    assert_equal(send_firewall_udp(1, family='ipv6', port=54228), 1)
    assert_firewall_rule_packets('input', 35710, 2)
