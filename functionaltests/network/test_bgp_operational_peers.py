"""Established IPv4/IPv6 peer operations on one persistent dual-stack topology.

Tests advertised/received routes, soft refresh without disconnect, and hard reset
with reconvergence. Both families share transports but each test resets its own
peer. Policy deletion, VRF replacement and interface moves are incompatible.
"""

import json

import pytest


if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from nvyr.op_scripts import bgp
from smoketests.assertions import assert_bgp_neighbor, assert_bgp_path, assert_equal, assert_less, assert_in


def test_ipv4_established_peer_operations(config):
    """Soft refresh preserves an IPv4 session; hard reset reconnects and restores routes."""
    original = json.loads(bgp.show('show bgp vrf NVYRLEFT neighbors 198.18.60.2', raw=True))['198.18.60.2']
    assert_equal(original['bgpState'], 'Established')
    advertised = bgp.show('show bgp vrf NVYRRIGHT ipv4 unicast neighbors 198.18.60.1 advertised-routes')
    assert_in('198.18.62.0/24', advertised)
    assert_in('198.18.62.0/24', bgp.show('show bgp vrf NVYRLEFT ipv4 unicast neighbors 198.18.60.2 routes'))

    bgp.clear('clear bgp vrf NVYRLEFT ipv4 unicast 198.18.60.2 soft in')
    bgp.clear('clear bgp vrf NVYRRIGHT ipv4 unicast 198.18.60.1 soft out')
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.18.62.0/24')
    refreshed = json.loads(bgp.show('show bgp vrf NVYRLEFT neighbors 198.18.60.2', raw=True))['198.18.60.2']
    assert_equal(refreshed['connectionsDropped'], original['connectionsDropped'])

    bgp.clear('clear bgp vrf NVYRLEFT 198.18.60.2')
    assert_bgp_neighbor('NVYRLEFT', '198.18.60.2', minimum_drops=original['connectionsDropped'] + 1)
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.18.62.0/24')
    reset = json.loads(bgp.show('show bgp vrf NVYRLEFT neighbors 198.18.60.2', raw=True))['198.18.60.2']
    assert_equal(reset['bgpState'], 'Established')
    assert_less(original['connectionsDropped'], reset['connectionsDropped'])


def test_ipv6_established_peer_operations(config):
    """IPv6 refresh and reset use native ordering and preserve the advertised prefix."""
    original = json.loads(bgp.show('show bgp vrf NVYRLEFT neighbors 2001:db8:60::2', raw=True))['2001:db8:60::2']
    assert_equal(original['bgpState'], 'Established')
    advertised = bgp.show('show bgp vrf NVYRRIGHT ipv6 unicast neighbors 2001:db8:60::1 advertised-routes')
    assert_in('2001:db8:62::/64', advertised)
    assert_in('2001:db8:62::/64', bgp.show('show bgp vrf NVYRLEFT ipv6 unicast neighbors 2001:db8:60::2 routes'))

    bgp.clear('clear bgp vrf NVYRLEFT ipv6 unicast 2001:db8:60::2 soft in')
    bgp.clear('clear bgp vrf NVYRRIGHT ipv6 unicast 2001:db8:60::1 soft out')
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:62::/64')
    refreshed = json.loads(bgp.show('show bgp vrf NVYRLEFT neighbors 2001:db8:60::2', raw=True))['2001:db8:60::2']
    assert_equal(refreshed['connectionsDropped'], original['connectionsDropped'])

    bgp.clear('clear bgp vrf NVYRLEFT 2001:db8:60::2')
    assert_bgp_neighbor('NVYRLEFT', '2001:db8:60::2', minimum_drops=original['connectionsDropped'] + 1)
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:62::/64')
    reset = json.loads(bgp.show('show bgp vrf NVYRLEFT neighbors 2001:db8:60::2', raw=True))['2001:db8:60::2']
    assert_equal(reset['bgpState'], 'Established')
    assert_less(original['connectionsDropped'], reset['connectionsDropped'])
