"""Strict/loose source validation, interface overrides and raw-chain continuation.

These cases deliberately change the mutually exclusive inet/family validation
modes, including disabled defaults and overrides. Their firewall policy is installed
in one transaction and restored afterward; interfaces, VRFs and BGP stay alive.
Compatible ordinary rules are in the other network modules.
"""

import pytest

pytestmark = pytest.mark.exclusive_firewall


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from smoketests.assertions import assert_equal, assert_firewall_rule, assert_firewall_rule_packets
from smoketests.firewall_support import send_firewall_udp


def test_ipv4_disabled_default_and_raw_continuation(config):
    """A strict loopback override passes valid traffic to the user's raw rule."""
    config.set('set firewall ipv4 source-validation interface lo mode strict')
    config.set('set firewall ipv4 prerouting raw rule 10 action continue protocol udp destination-port 53098 counter')
    config.commit()

    assert_equal(send_firewall_udp(1), 1)
    assert_firewall_rule_packets('ipv4_prerouting', 'source-validation-strict', 0)
    assert_firewall_rule_packets('ipv4_prerouting', 10, 1)


def test_ipv6_disabled_default_and_raw_continuation(config):
    """IPv6 successful validation also continues through the ordinary raw rules."""
    config.set('set firewall ipv6 source-validation interface lo mode strict')
    config.set('set firewall ipv6 prerouting raw rule 10 action continue protocol udp destination-port 53098 counter')
    config.commit()

    assert_equal(send_firewall_udp(1, family='ipv6'), 1)
    assert_firewall_rule_packets('ipv6_prerouting', 'source-validation-strict', 0)
    assert_firewall_rule_packets('ipv6_prerouting', 10, 1)


def test_inet_shared_source_validation(config):
    """A single shared rule validates both IP families before their dispatch."""
    config.set('set firewall inet source-validation interface lo mode loose')
    config.set('set firewall inet prerouting raw rule 10 action continue protocol udp destination-port 53098 counter')
    config.commit()

    assert_equal(send_firewall_udp(1), 1)
    assert_equal(send_firewall_udp(1, family='ipv6'), 1)
    assert_firewall_rule_packets('prerouting', 10, 2)
    assert_firewall_rule('prerouting', 'source-validation-loose', 'fib saddr oif 0', 'drop')
