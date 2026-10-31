"""Firewall geoip on the shared routed-network scenario.

IPv4/IPv6 country membership, refresh and GeoIP operational status.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.protocol import Client
from smoketests.assertions import (
    assert_equal, assert_is_not_none, assert_firewall_object, assert_firewall_rule,
    firewall_object_handle,
)


def geoip_request(operation):
    """Exercise the same configd endpoint used by the op command and timer."""
    client = Client('/run/nvyr/configd.sock')
    try:
        return client.request(operation)
    finally:
        client.close()


def test_geoip_ipv4(config):
    """Country data populates a referenced IPv4 set; refresh preserves object identity."""
    # Baseline: configs/network-features.conf (FN38).

    assert_firewall_object('set', 'ipv4_address_group_FN38COUNTRY', 'flags interval', 'auto-merge', 'elements =')
    assert_firewall_rule('ipv4_name_FN38GEOIP', 33810, '@ipv4_address_group_FN38COUNTRY')
    handle = firewall_object_handle('set', 'ipv4_address_group_FN38COUNTRY')

    geoip_request('geoip-update')

    assert_equal(firewall_object_handle('set', 'ipv4_address_group_FN38COUNTRY'), handle)
    status = geoip_request('geoip-status')
    assert_is_not_none(status['active'])
    group = next(group for group in status['groups'] if group['name'] == 'FN38COUNTRY')
    assert_equal(group['countries'], ['CA', 'US'])


def test_geoip_ipv6(config):
    """IPv6 country selection supports the existing negative group reference."""
    # Baseline: configs/network-features.conf (FN39).

    assert_firewall_object('set', 'ipv6_address_group_FN39COUNTRY', 'flags interval', 'auto-merge', 'elements =')
    assert_firewall_rule('ipv6_name_FN39GEOIP', 33910, '!= @ipv6_address_group_FN39COUNTRY')
    groups = geoip_request('geoip-status')['groups']
    group = next(group for group in groups if group['name'] == 'FN39COUNTRY')
    assert_equal(group['family'], 'ipv6')
