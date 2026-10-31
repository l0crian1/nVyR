"""Firewall interface patterns on the shared routed-network scenario.

IPv4/IPv6 wildcard interface rules and named interface-group matching.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from smoketests.assertions import (
    assert_equal, assert_firewall_object, assert_firewall_rule_packets,
    assert_firewall_map_counter,
)
from smoketests.firewall_support import send_firewall_udp


def test_ipv4_rule_and_interface_group_prefixes(config):
    """Positive and negative prefix matches work with tracked, included groups."""
    # Baseline: configs/network-features.conf (FN58).

    assert_equal(send_firewall_udp(1, port=54232), 1)
    assert_firewall_rule_packets('ipv4_output', '35810', 1)
    assert_firewall_rule_packets('ipv4_output', '35820', 1)
    assert_firewall_rule_packets('ipv4_output', '35830', 1)
    assert_firewall_object('set', 'interface_group_FN58LOCAL', 'flags interval', 'l\\*', 'counter', 'last')


def test_ipv6_rule_and_interface_group_prefixes(config):
    """IPv6 uses the same native prefixes without expanding current interfaces."""
    # Baseline: configs/network-features.conf (FN59).

    assert_equal(send_firewall_udp(1, family='ipv6', port=54236), 1)
    assert_firewall_rule_packets('ipv6_output', '35910', 1)
    assert_firewall_rule_packets('ipv6_output', '35920', 1)
    assert_firewall_rule_packets('ipv6_output', '35930', 1)
