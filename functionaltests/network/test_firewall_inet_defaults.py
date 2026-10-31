"""IPv4/IPv6 inet acceptance before family-specific default-drop policies.

These cases deliberately change default verdicts, which conflict with ordinary
per-service forwarding observations. Their firewall policy is installed
in one transaction and restored afterward; interfaces, VRFs and BGP stay alive.
Compatible ordinary rules are in the other network modules.
"""

import pytest

pytestmark = pytest.mark.exclusive_firewall


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from smoketests.assertions import assert_equal, assert_firewall_rule_packets, assert_firewall_object
from smoketests.firewall_support import send_firewall_udp


def test_ipv4_inet_accept_before_family_default(config):
    """The shared rule accepts IPv4 before its family-specific default drop."""
    config.set('set firewall inet input filter rule 10 action accept protocol udp destination-port 53098 counter')
    config.set('set firewall ipv4 input filter default-action drop')
    config.commit()

    assert_equal(send_firewall_udp(1), 1)
    assert_firewall_rule_packets('input', 10, 1)
    assert_firewall_rule_packets('ipv4_input', 'default', 0)


def test_ipv6_inet_accept_before_family_default(config):
    """The same neutral rule accepts IPv6 without an nfproto-specific duplicate."""
    config.set('set firewall inet input filter rule 10 action accept protocol udp destination-port 53098 counter')
    config.set('set firewall ipv6 input filter default-action drop')
    config.commit()

    assert_equal(send_firewall_udp(1, family='ipv6'), 1)
    assert_firewall_rule_packets('input', 10, 1)
    assert_firewall_rule_packets('ipv6_input', 'default', 0)
