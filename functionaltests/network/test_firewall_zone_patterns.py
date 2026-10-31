"""IPv4/IPv6 wildcard zone membership and local input/output dispatch.

These cases deliberately change default verdicts and wildcard zone ownership,
which conflict with the ordinary rule baseline. Their firewall policy is installed
in one transaction and restored afterward; interfaces, VRFs and BGP stay alive.
Compatible ordinary rules are in the other network modules.
"""

import pytest

pytestmark = pytest.mark.exclusive_firewall


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from smoketests.assertions import (
    assert_equal, assert_firewall_object, assert_firewall_rule_packets,
    assert_firewall_map_counter,
)
from smoketests.firewall_support import send_firewall_udp


def test_ipv4_zone_prefix_local_dispatch(config):
    """Local input and output map elements retain prefix names and packet counters."""
    config.set('set firewall zone LOOP interface l* interface lo default-action accept')
    config.set('set firewall zone LOCAL local-zone default-action accept')
    config.commit()

    assert_equal(send_firewall_udp(1), 1)
    assert_firewall_map_counter('ipv4_zone_input', 'l*', minimum_packets=1)
    assert_firewall_map_counter('ipv4_zone_output', 'l*', minimum_packets=1)
    assert_firewall_object('map', 'ipv4_zone_forward', 'flags interval', 'l\\*.*l\\*.*LOOP to LOOP')


def test_ipv6_zone_prefix_local_dispatch(config):
    """IPv6 zone input and output use the wildcard entry for the same local packet."""
    config.set('set firewall zone LOOP interface l* default-action accept')
    config.set('set firewall zone LOCAL local-zone default-action accept')
    config.commit()

    assert_equal(send_firewall_udp(1, family='ipv6'), 1)
    assert_firewall_map_counter('ipv6_zone_input', 'l*', minimum_packets=1)
    assert_firewall_map_counter('ipv6_zone_output', 'l*', minimum_packets=1)
