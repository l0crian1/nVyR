"""Integrated dual-stack routing, BGP policy and firewall functional suite.

Topology (one setup/commit, one convergence wait, one teardown):
    left host -- NVYRLEFT (AS 65061) -- NVYRRIGHT (AS 65062) -- right host
    namespaces   VRF 42061              VRF 42062              namespaces

Tests:
- IPv4/IPv6 BGP LAN reachability and static host-route forwarding on the same links.
- Standard/large communities, AS-path replacement, ACLs and prefix lists.
- Route-map calls, goto/next, local preference, MED, weight and denied routes.
- Inet accept/drop, family dispatch, verdict maps, nested jumps and match-groups.
- Local output TTL bounds, shared named counters and VRF route operational views.
- Address-group inclusion/negation, port/interface groups, length, DSCP and FIB.
- Packet/connection mark, DSCP and TTL rewrites, ICMP groups, original CT tuples.
- Dynamic address/tuple learning, per-source meters, quotas and scoped flow offload.
- Every traffic test checks delivery or rejection; counters use per-test deltas.

Incompatible with this baseline:
- Interface deletion or VRF moves during traffic observations.
- Global state-policy accept/flow offload, which bypass the rule counters under test.
- NAT, source validation or ingress policies that alter these exact routing paths.
- Exhaustible allowances and dynamic learning without dedicated per-test objects.

Peer refresh and policy mutations share this package and restore their own changes. No
case in this module changes configuration or depends on another test running.
"""

import json

import pytest


if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from nvyr.helpers.process import cmd
from nvyr.op_scripts import bgp, static
from functionaltests.routed_network import assert_traffic, named_packets, assert_offloaded_traffic, assert_tcp_traffic
from smoketests.assertions import (
    assert_bgp_path, assert_equal, assert_in, assert_kernel_route, assert_not_in, firewall_rule_packets,
    assert_operational_output, assert_firewall_map_default_counter,
)
from smoketests.firewall_support import send_firewall_udp


def test_ipv4_community_filter():
    """Standard communities select the route and set local preference."""
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.1/32',
                    attributes={'locPrf': 250, 'community.string': '65062:100'})


def test_ipv4_large_community_regex_and_delete():
    """Regex selection deletes only the matching large community."""
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.2/32',
                    attributes={'largeCommunity.string': '65062:200:300'})


def test_ipv4_as_path_filter_and_replace():
    """An AS-path list selects the prepended path and replaces the chosen AS."""
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.3/32',
                    attributes={'aspath.string': '65062 64502 64502'})


def test_ipv4_call_and_attribute_adjustments():
    """A called policy adjusts attributes and goto skips the deny rule."""
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.4/32',
                    attributes={'locPrf': 250, 'metric': 80})


def test_ipv4_community_delete_and_next():
    """Selective deletion retains the other community and next applies weight."""
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.5/32',
                    attributes={'community.string': '65062:200', 'weight': 150})


def test_ipv4_access_list_selection():
    """The address-family ACL admits this route and selects its policy."""
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.7/32',
                    attributes={'locPrf': 270})


def test_ipv4_prefix_list_selection():
    """The address-family prefix list admits this route and selects its policy."""
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.9/32',
                    attributes={'locPrf': 290})


def test_ipv4_route_map_deny():
    """Explicit deny rejects an advertised route."""
    advertised = bgp.show('show bgp vrf NVYRRIGHT ipv4 unicast neighbors 198.18.60.1 advertised-routes')
    assert_in('198.19.61.6/32', advertised)
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.6/32', present=False)


def test_ipv4_access_list_miss():
    """A route outside the ACL and later permit lists is rejected."""
    advertised = bgp.show('show bgp vrf NVYRRIGHT ipv4 unicast neighbors 198.18.60.1 advertised-routes')
    assert_in('198.19.61.8/32', advertised)
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.8/32', present=False)


def test_ipv4_prefix_list_miss():
    """A route outside the prefix list is rejected."""
    advertised = bgp.show('show bgp vrf NVYRRIGHT ipv4 unicast neighbors 198.18.60.1 advertised-routes')
    assert_in('198.19.61.10/32', advertised)
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.10/32', present=False)


def test_ipv4_inet_accept():
    """The inet rule accepts routed traffic before family dispatch."""
    assert_traffic('ipv4', 52100, allowed=True, counter=('forward', 42000))


def test_ipv4_inet_drop():
    """The inet rule drops routed traffic before family dispatch."""
    assert_traffic('ipv4', 52101, allowed=False, counter=('forward', 42001))


def test_ipv4_map_nested_jump():
    """The shared verdict map jumps through two named chains."""
    assert_traffic('ipv4', 52102, allowed=True, counter=('inet_name_RNINNER', 10))


def test_ipv4_map_drop():
    """The same verdict map drops its denied service."""
    assert_traffic('ipv4', 52103, allowed=False, map_entry='DENY')


def test_ipv4_match_group():
    """The concatenated group permits the expected source/protocol/port."""
    assert_traffic('ipv4', 52104, allowed=True, counter=('ipv4_forward', 42010))


def test_ipv4_family_accept():
    """An inet miss reaches the family-specific accept rule."""
    assert_traffic('ipv4', 52105, allowed=True, counter=('ipv4_forward', 42020))


def test_ipv4_family_drop():
    """An unmatched service reaches the scoped family drop rule."""
    assert_traffic('ipv4', 52199, allowed=False, counter=('ipv4_forward', 42999))


def test_ipv4_static_forwarding():
    """Static routes carry this destination while BGP supplies its return route."""
    assert_kernel_route('198.19.62.2/32', 'via 198.18.60.2', 'proto static', vrf='NVYRLEFT')
    assert_kernel_route('198.19.62.2/32', 'via 198.18.62.2', 'proto static', vrf='NVYRRIGHT')
    assert_traffic('ipv4', 52106, static=True, counter=('ipv4_forward', 42030))


def test_ipv6_community_filter():
    """Standard communities select the route and set local preference."""
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::1/128',
                    attributes={'locPrf': 250, 'community.string': '65062:100'})


def test_ipv6_large_community_regex_and_delete():
    """Regex selection deletes only the matching large community."""
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::2/128',
                    attributes={'largeCommunity.string': '65062:200:300'})


def test_ipv6_as_path_filter_and_replace():
    """An AS-path list selects the prepended path and replaces the chosen AS."""
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::3/128',
                    attributes={'aspath.string': '65062 64502 64502'})


def test_ipv6_call_and_attribute_adjustments():
    """A called policy adjusts attributes and goto skips the deny rule."""
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::4/128',
                    attributes={'locPrf': 250, 'metric': 80})


def test_ipv6_community_delete_and_next():
    """Selective deletion retains the other community and next applies weight."""
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::5/128',
                    attributes={'community.string': '65062:200', 'weight': 150})


def test_ipv6_access_list_selection():
    """The address-family ACL admits this route and selects its policy."""
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::7/128',
                    attributes={'locPrf': 270})


def test_ipv6_prefix_list_selection():
    """The address-family prefix list admits this route and selects its policy."""
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::9/128',
                    attributes={'locPrf': 290})


def test_ipv6_route_map_deny():
    """Explicit deny rejects an advertised route."""
    advertised = bgp.show('show bgp vrf NVYRRIGHT ipv6 unicast neighbors 2001:db8:60::1 advertised-routes')
    assert_in('2001:db8:63::6/128', advertised)
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::6/128', present=False)


def test_ipv6_access_list_miss():
    """A route outside the ACL and later permit lists is rejected."""
    advertised = bgp.show('show bgp vrf NVYRRIGHT ipv6 unicast neighbors 2001:db8:60::1 advertised-routes')
    assert_in('2001:db8:63::8/128', advertised)
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::8/128', present=False)


def test_ipv6_prefix_list_miss():
    """A route outside the prefix list is rejected."""
    advertised = bgp.show('show bgp vrf NVYRRIGHT ipv6 unicast neighbors 2001:db8:60::1 advertised-routes')
    assert_in('2001:db8:63::10/128', advertised)
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::10/128', present=False)


def test_ipv6_inet_accept():
    """The inet rule accepts routed traffic before family dispatch."""
    assert_traffic('ipv6', 52100, allowed=True, counter=('forward', 42000))


def test_ipv6_inet_drop():
    """The inet rule drops routed traffic before family dispatch."""
    assert_traffic('ipv6', 52101, allowed=False, counter=('forward', 42001))


def test_ipv6_map_nested_jump():
    """The shared verdict map jumps through two named chains."""
    assert_traffic('ipv6', 52102, allowed=True, counter=('inet_name_RNINNER', 10))


def test_ipv6_map_drop():
    """The same verdict map drops its denied service."""
    assert_traffic('ipv6', 52103, allowed=False, map_entry='DENY')


def test_ipv6_match_group():
    """The concatenated group permits the expected source/protocol/port."""
    assert_traffic('ipv6', 52104, allowed=True, counter=('ipv6_forward', 42010))


def test_ipv6_family_accept():
    """An inet miss reaches the family-specific accept rule."""
    assert_traffic('ipv6', 52105, allowed=True, counter=('ipv6_forward', 42020))


def test_ipv6_family_drop():
    """An unmatched service reaches the scoped family drop rule."""
    assert_traffic('ipv6', 52199, allowed=False, counter=('ipv6_forward', 42999))


def test_ipv6_static_forwarding():
    """Static routes carry this destination while BGP supplies its return route."""
    assert_kernel_route('2001:db8:64::2/128', 'via 2001:db8:60::2', 'proto static', vrf='NVYRLEFT')
    assert_kernel_route('2001:db8:64::2/128', 'via 2001:db8:62::2', 'proto static', vrf='NVYRRIGHT')
    assert_traffic('ipv6', 52106, static=True, counter=('ipv6_forward', 42030))


def test_opmode_ipv6_vrf_routes():
    """Keep IPv6 VRF lookups scoped in both Zebra and staticd output."""
    assert_kernel_route('2001:db8:100::/64', 'blackhole', vrf='NVYRLEFT')

    assert_operational_output('show ipv6 route vrf NVYRLEFT 2001:db8:100::/64', '2001:db8:100::/64')

    assert_in('2001:db8:100::/64', static.show('show ipv6 route vrf NVYRLEFT 2001:db8:100::/64'))
    routes = json.loads(cmd(['static.nvyr.op', 'show', 'show ipv6 route vrf NVYRLEFT 2001:db8:100::/64', '--raw']))
    assert_equal(routes['2001:db8:100::/64'][0]['vrfName'], 'NVYRLEFT')
    status = json.loads(static.show('show static routes vrf NVYRLEFT', raw=True))
    assert_in('2001:db8:100::/64', [route['prefix'] for route in status['NVYRLEFT']['routes']])
    assert_not_in('2001:db8:100::/64', json.loads(static.show('show ipv6 route static', raw=True)))


def test_opmode_ipv4_vrf_routes():
    """Keep FRR's VRF-before-prefix ordering in text and structured queries."""
    assert_kernel_route('192.0.2.0/24', 'blackhole', vrf='NVYRLEFT')

    assert_operational_output('show ip route vrf NVYRLEFT 192.0.2.0/24', '192.0.2.0/24')

    assert_in('192.0.2.0/24', static.show('show ip route vrf NVYRLEFT 192.0.2.0/24'))
    routes = json.loads(cmd(['static.nvyr.op', 'show', 'show ip route vrf NVYRLEFT 192.0.2.0/24', '--raw']))
    assert_equal(routes['192.0.2.0/24'][0]['vrfName'], 'NVYRLEFT')
    status = json.loads(static.show('show static routes vrf NVYRLEFT', raw=True))
    assert_in('192.0.2.0/24', [route['prefix'] for route in status['NVYRLEFT']['routes']])
    assert_not_in('192.0.2.0/24', json.loads(static.show('show ip route static', raw=True)))


def test_ttl_range_packet_behavior_ipv6():
    """Exclusive TTL bounds reject both endpoints and accept the middle value."""
    within = named_packets('RNTTLWITHIN')
    outside = named_packets('RNTTLOUTSIDE')

    assert_equal(send_firewall_udp(1, family='ipv6', ttl=10), 0)
    assert_equal(send_firewall_udp(1, family='ipv6', ttl=15), 1)
    assert_equal(send_firewall_udp(1, family='ipv6', ttl=20), 0)

    assert_equal(named_packets('RNTTLWITHIN'), within + 1)
    assert_equal(named_packets('RNTTLOUTSIDE'), outside + 2)


def test_ttl_range_packet_behavior_ipv4():
    """Exclusive TTL bounds reject both endpoints and accept the middle value."""
    within = named_packets('RNTTLWITHIN')
    outside = named_packets('RNTTLOUTSIDE')

    assert_equal(send_firewall_udp(1, family='ipv4', ttl=10), 0)
    assert_equal(send_firewall_udp(1, family='ipv4', ttl=15), 1)
    assert_equal(send_firewall_udp(1, family='ipv4', ttl=20), 0)

    assert_equal(named_packets('RNTTLWITHIN'), within + 1)
    assert_equal(named_packets('RNTTLOUTSIDE'), outside + 2)


def test_ipv4_address_group_inclusion():
    """Nested address groups and destination groups match the routed hosts."""
    assert_traffic('ipv4', 52110, counter=('ipv4_forward', 42110))


def test_ipv4_negative_address():
    """Positive and negative address matches coexist in the same rule."""
    assert_traffic('ipv4', 52111, counter=('ipv4_forward', 42111))


def test_ipv4_port_and_interface_groups():
    """Singleton port and interface groups match one independent service."""
    assert_traffic('ipv4', 52112, counter=('ipv4_forward', 42112))


def test_ipv4_packet_length():
    """The packet length includes the IP and UDP headers."""
    assert_traffic('ipv4', 52113, counter=('ipv4_forward', 42113))


def test_ipv4_dscp():
    """The configured DSCP selects marked traffic."""
    assert_traffic('ipv4', 52114, counter=('ipv4_forward', 42114), dscp=46)


def test_ipv4_modify():
    """A later rule observes the rewritten packet mark, connection mark, DSCP and TTL."""
    assert_traffic('ipv4', 52116, counter=('ipv4_forward', 42117))


def test_ipv4_dynamic_address():
    """A packet learns its source and immediately matches that dynamic address group."""
    assert_traffic('ipv4', 52117, counter=('ipv4_forward', 42121))


def test_ipv4_dynamic_tuple():
    """A packet learns and consumes its concatenated source/protocol/port key."""
    assert_traffic('ipv4', 52118, counter=('ipv4_forward', 42123))


def test_ipv4_per_source_limit():
    """A per-source meter permits traffic within its allowance."""
    assert_traffic('ipv4', 52119, counter=('ipv4_forward', 42124))


def test_ipv4_quota():
    """A dedicated quota permits traffic below its byte threshold."""
    assert_traffic('ipv4', 52120, counter=('ipv4_forward', 42125))


def test_ipv4_original_connection():
    """Original conntrack addresses match this routed flow."""
    assert_traffic('ipv4', 52121, counter=('ipv4_forward', 42126))


def test_ipv4_fib():
    """A VRF-scoped FIB lookup finds the source route."""
    assert_traffic('ipv4', 52122, counter=('ipv4_forward', 42127))


def test_ipv4_icmp_group():
    """An ICMP echo traverses the configured type/code group."""
    before = firewall_rule_packets('ipv4_forward', 42128)
    cmd(['ip', 'netns', 'exec', 'nvyr-routed-left', 'ping', '-n', '-c', '1', '-W', '2', '198.18.62.2'])
    assert_equal(firewall_rule_packets('ipv4_forward', 42128), before + 1)


def test_ipv6_address_group_inclusion():
    """Nested address groups and destination groups match the routed hosts."""
    assert_traffic('ipv6', 52110, counter=('ipv6_forward', 42110))


def test_ipv6_negative_address():
    """Positive and negative address matches coexist in the same rule."""
    assert_traffic('ipv6', 52111, counter=('ipv6_forward', 42111))


def test_ipv6_port_and_interface_groups():
    """Singleton port and interface groups match one independent service."""
    assert_traffic('ipv6', 52112, counter=('ipv6_forward', 42112))


def test_ipv6_packet_length():
    """The packet length includes the IP and UDP headers."""
    assert_traffic('ipv6', 52113, counter=('ipv6_forward', 42113))


def test_ipv6_dscp():
    """The configured DSCP selects marked traffic."""
    assert_traffic('ipv6', 52114, counter=('ipv6_forward', 42114), dscp=46)


def test_ipv6_modify():
    """A later rule observes the rewritten packet mark, connection mark, DSCP and TTL."""
    assert_traffic('ipv6', 52116, counter=('ipv6_forward', 42117))


def test_ipv6_dynamic_address():
    """A packet learns its source and immediately matches that dynamic address group."""
    assert_traffic('ipv6', 52117, counter=('ipv6_forward', 42121))


def test_ipv6_dynamic_tuple():
    """A packet learns and consumes its concatenated source/protocol/port key."""
    assert_traffic('ipv6', 52118, counter=('ipv6_forward', 42123))


def test_ipv6_per_source_limit():
    """A per-source meter permits traffic within its allowance."""
    assert_traffic('ipv6', 52119, counter=('ipv6_forward', 42124))


def test_ipv6_quota():
    """A dedicated quota permits traffic below its byte threshold."""
    assert_traffic('ipv6', 52120, counter=('ipv6_forward', 42125))


def test_ipv6_original_connection():
    """Original conntrack addresses match this routed flow."""
    assert_traffic('ipv6', 52121, counter=('ipv6_forward', 42126))


def test_ipv6_fib():
    """A VRF-scoped FIB lookup finds the source route."""
    assert_traffic('ipv6', 52122, counter=('ipv6_forward', 42127))


def test_ipv6_icmp_group():
    """An ICMP echo traverses the configured type/code group."""
    before = firewall_rule_packets('ipv6_forward', 42128)
    cmd(['ip', 'netns', 'exec', 'nvyr-routed-left', 'ping', '-n', '-c', '1', '-W', '2', '2001:db8:62::2'])
    assert_equal(firewall_rule_packets('ipv6_forward', 42128), before + 1)


def test_ipv4_scoped_flowtable():
    """Dedicated IPv4 traffic is enrolled and accounted without offloading other probes."""
    assert_offloaded_traffic("ipv4")


def test_ipv6_scoped_flowtable():
    """Dedicated IPv6 traffic is enrolled and accounted on the same shared links."""
    assert_offloaded_traffic("ipv6")


def test_ipv4_tcp_flags():
    """A real TCP handshake matches SYN without ACK, and data still reaches the peer."""
    assert_tcp_traffic('ipv4')


def test_ipv4_map_known_key():
    """A known key passes through the scoped map without using its catchall."""
    assert_traffic('ipv4', 52132, counter=('ipv4_forward', 42132))


def test_ipv4_map_catchall():
    """An unknown key reaches the default-result and increments its own element counter."""
    assert_traffic('ipv4', 52133, allowed=False)
    assert_firewall_map_default_counter('ipv4_map_RNCATCH', 1)


def test_ipv4_dscp_miss():
    """Unmarked traffic misses the DSCP permit and reaches the service-range drop."""
    assert_traffic('ipv4', 52114, allowed=False, counter=('ipv4_forward', 42999))


def test_ipv6_tcp_flags():
    """A real TCP handshake matches SYN without ACK, and data still reaches the peer."""
    assert_tcp_traffic('ipv6')


def test_ipv6_map_known_key():
    """A known key passes through the scoped map without using its catchall."""
    assert_traffic('ipv6', 52132, counter=('ipv6_forward', 42132))


def test_ipv6_map_catchall():
    """An unknown key reaches the default-result and increments its own element counter."""
    assert_traffic('ipv6', 52133, allowed=False)
    assert_firewall_map_default_counter('ipv6_map_RNCATCH', 1)


def test_ipv6_dscp_miss():
    """Unmarked traffic misses the DSCP permit and reaches the service-range drop."""
    assert_traffic('ipv6', 52114, allowed=False, counter=('ipv6_forward', 42999))
