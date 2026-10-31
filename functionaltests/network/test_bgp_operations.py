"""BGP operational displays share one IPv4/IPv6 route and disabled-peer baseline.

Tests text/JSON routes, filtered output, neighbors, policy counters and scoped
clear commands. No test commits configuration. Live peer reconnection belongs
in test_bgp_operational_peers; deleting routes/policies is incompatible here.
"""

import json

import pytest


if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from nvyr.helpers.process import cmd
from nvyr.op_scripts import bgp, policy
from smoketests.assertions import assert_bgp_path, assert_equal, assert_in, assert_not_in, assert_true


def test_route_map_counters_with_bgp():
    """A real BGP policy hit can be cleared without withdrawing its originated route."""
    assert_bgp_path('NVYRLEFT', 'ipv4', '192.0.2.0/24')

    before = json.loads(policy.show('show route-map RNOPPOLICY', raw=True))
    assert_true(before['bgpd']['RNOPPOLICY']['invoked'] > 0)

    policy.clear('clear route-map counters RNOPPOLICY')

    after = json.loads(policy.show('show route-map RNOPPOLICY', raw=True))
    assert_equal(after['bgpd']['RNOPPOLICY']['invoked'], 0)
    assert_equal(after['bgpd']['RNOPPOLICY']['rules'][0]['type'], 'permit')
    assert_bgp_path('NVYRLEFT', 'ipv4', '192.0.2.0/24')


def test_ipv4_route_display():
    """Native text and JSON expose a VRF's IPv4 route without leaking it to default."""
    assert_bgp_path('NVYRLEFT', 'ipv4', '192.0.2.0/24')

    assert_in('192.0.2.0/24', bgp.show('show bgp vrf NVYRLEFT ipv4 unicast'))
    data = json.loads(bgp.show('show bgp vrf NVYRLEFT ipv4 unicast 192.0.2.0/24', raw=True))
    assert_equal(data['prefix'], '192.0.2.0/24')
    default = json.loads(bgp.show('show bgp ipv4 unicast', raw=True))
    assert_not_in('192.0.2.0/24', default.get('routes', {}))


def test_ipv6_route_display():
    """IPv6 lookup and longer-prefix display preserve FRR's argument order."""
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8::/48')

    assert_in('2001:db8::/48', bgp.show('show bgp vrf NVYRLEFT ipv6 unicast 2001:db8::/32 longer-prefixes'))
    data = json.loads(bgp.show('show bgp vrf NVYRLEFT ipv6 unicast 2001:db8::/48', raw=True))
    assert_equal(data['prefix'], '2001:db8::/48')
    default = json.loads(bgp.show('show bgp ipv6 unicast', raw=True))
    assert_not_in('2001:db8::/48', default.get('routes', {}))


def test_ipv4_neighbor_display():
    """The installed executable reports summary and detailed IPv4 peer state."""

    text = cmd(['bgp.nvyr.op', 'show', 'show bgp vrf NVYRLEFT ipv4 unicast summary'])
    assert_in('192.0.2.2', text)
    summary = json.loads(bgp.show('show bgp vrf NVYRLEFT ipv4 unicast summary', raw=True))
    assert_in('192.0.2.2', summary['peers'])
    neighbor = json.loads(bgp.show('show bgp vrf NVYRLEFT neighbors 192.0.2.2', raw=True))
    assert_equal(neighbor['192.0.2.2']['remoteAs'], 65001)


def test_ipv6_neighbor_display():
    """IPv6 transport peers are visible in the IPv6 summary and native detail."""

    assert_in('2001:db8::2', bgp.show('show bgp vrf NVYRLEFT ipv6 unicast summary'))
    summary = json.loads(bgp.show('show bgp vrf NVYRLEFT ipv6 unicast summary', raw=True))
    assert_in('2001:db8::2', summary['peers'])
    neighbor = json.loads(bgp.show('show bgp vrf NVYRLEFT neighbors 2001:db8::2', raw=True))
    assert_equal(neighbor['2001:db8::2']['remoteAs'], 65001)


def test_policy_filtered_routes():
    """A configured route-map can filter operational route output in the same VRF."""
    assert_bgp_path('NVYRLEFT', 'ipv4', '192.0.2.0/24')

    routes = json.loads(bgp.show('show bgp vrf NVYRLEFT ipv4 unicast route-map RNOPPOLICY', raw=True))
    assert_in('192.0.2.0/24', routes['routes'])


def test_ipv4_peer_reset():
    """Soft refresh, statistics reset and hard reset stay inside the reserved VRF."""

    bgp.clear('clear bgp vrf NVYRLEFT ipv4 unicast 192.0.2.2 soft in')
    bgp.clear('clear bgp vrf NVYRLEFT ipv4 unicast 192.0.2.2 soft out')
    bgp.clear('clear bgp vrf NVYRLEFT 192.0.2.2 message-stats')
    bgp.clear('clear bgp vrf NVYRLEFT 192.0.2.2')
    neighbor = json.loads(bgp.show('show bgp vrf NVYRLEFT neighbors 192.0.2.2', raw=True))
    assert_equal(neighbor['192.0.2.2']['remoteAs'], 65001)


def test_ipv6_peer_reset():
    """IPv6 peer resets do not remove configuration or select peers in other VRFs."""

    bgp.clear('clear bgp vrf NVYRLEFT ipv6 unicast 2001:db8::2 soft in')
    bgp.clear('clear bgp vrf NVYRLEFT ipv6 unicast 2001:db8::2 soft out')
    bgp.clear('clear bgp vrf NVYRLEFT 2001:db8::2 message-stats')
    bgp.clear('clear bgp vrf NVYRLEFT 2001:db8::2')
    neighbor = json.loads(bgp.show('show bgp vrf NVYRLEFT neighbors 2001:db8::2', raw=True))
    assert_equal(neighbor['2001:db8::2']['remoteAs'], 65001)
