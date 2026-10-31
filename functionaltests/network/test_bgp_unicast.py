"""Unicast behavior on the shared routing, policy and firewall topology.

Tests cover negotiated capabilities/roles and AddPath, filter-list changes, peer
weight, administrative distance, unnumbered dual-stack exchange, alternate AS,
aggregate suppression/unsuppression and conditional withdrawals. Prefix limits
remain configured above the shared scenario's route inventory.
All interfaces, VRFs, peers and policies are installed once by routed_network.
Shutdown, incompatible roles and removal of the shared links cannot coexist with
the baseline and are covered by smoke/native configuration tests instead.
"""

import json

from nvyr.helpers.process import cmd
from smoketests.assertions import assert_bgp_neighbor, assert_bgp_path


def test_ipv4_negotiated_peer_options():
    peer = assert_bgp_neighbor('NVYRLEFT', '198.18.60.2')
    assert peer['localRole'] == 'provider'
    assert peer['remoteRole'] == 'customer'
    assert peer['bgpTcpMssConfigured'] == 1200
    assert peer['neighborCapabilities']['dynamic'] == 'advertisedAndReceived'
    assert peer['neighborCapabilities']['addPath']['ipv4Unicast']['txAdvertisedAndReceived']
    assert peer['neighborCapabilities']['addPath']['ipv4Unicast']['rxAdvertisedAndReceived']


def test_ipv6_negotiated_peer_options():
    peer = assert_bgp_neighbor('NVYRLEFT', '2001:db8:60::2')
    assert peer['localRole'] == 'provider'
    assert peer['remoteRole'] == 'customer'
    assert peer['bgpTcpMssConfigured'] == 1200
    assert peer['neighborCapabilities']['dynamic'] == 'advertisedAndReceived'
    assert peer['neighborCapabilities']['addPath']['ipv6Unicast']['txAdvertisedAndReceived']
    assert peer['neighborCapabilities']['addPath']['ipv6Unicast']['rxAdvertisedAndReceived']


def test_ipv4_peer_weight_and_distance():
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.18.62.0/24', attributes={'weight': 75})
    routes = json.loads(cmd(['vtysh', '-c', 'show ip route vrf NVYRLEFT 198.18.62.0/24 json']))
    assert any(route['protocol'] == 'bgp' and route['distance'] == 30 for route in routes['198.18.62.0/24'])


def test_ipv6_peer_weight_and_distance():
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:62::/64', attributes={'weight': 75})
    routes = json.loads(cmd(['vtysh', '-c', 'show ipv6 route vrf NVYRLEFT 2001:db8:62::/64 json']))
    assert any(route['protocol'] == 'bgp' and route['distance'] == 30 for route in routes['2001:db8:62::/64'])


def test_ipv4_unnumbered_alternate_as():
    assert_bgp_neighbor('NVYRLEFT', 'veth42067')
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.65.2/32', attributes={'aspath.string': '65162', 'weight': 300})


def test_ipv6_unnumbered_alternate_as():
    assert_bgp_neighbor('NVYRRIGHT', 'veth42068')
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:65::2/128', attributes={'aspath.string': '65162', 'weight': 300})


def test_ipv4_filter_list_replacement(config):
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.18.62.0/24')
    config.set('set policy as-path-list RNUNIMPORT rule 5 action deny regex "^65062$"')
    config.commit()
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.18.62.0/24', present=False)


def test_ipv6_filter_list_replacement(config):
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:62::/64')
    config.set('set policy as-path-list RNUNIMPORT rule 5 action deny regex "^65062$"')
    config.commit()
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:62::/64', present=False)


def test_ipv4_aggregate_and_unsuppressed_component():
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.66.0/24', attributes={'origin': 'incomplete'})
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.66.1/32')


def test_ipv6_aggregate_and_unsuppressed_component():
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:66::/64', attributes={'origin': 'incomplete'})
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:66::1/128')


def test_ipv4_conditional_withdrawal(config):
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.67.1/32')
    config.delete('delete vrf name NVYRRIGHT protocols bgp address-family ipv4-unicast network 198.19.67.2/32')
    config.commit()
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.67.1/32', present=False)


def test_ipv6_conditional_withdrawal(config):
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:67::1/128')
    config.delete('delete vrf name NVYRRIGHT protocols bgp address-family ipv6-unicast network 2001:db8:67::2/128')
    config.commit()
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:67::1/128', present=False)
