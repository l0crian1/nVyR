"""Firewall ingress on the shared routed-network scenario.

IPv4/IPv6 ingress drops, VLAN rule/map/group matches and nested chain jumps.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from smoketests.assertions import firewall_rule_packets, assert_firewall_rule_packets, assert_firewall_chain
from smoketests.firewall_support import send_ingress_udp


def test_ipv4_ingress_packet_filter(config):
    """Only matching transport ports hit the numbered rule before the default drop."""
    # Baseline: configs/network-features.conf (FN60).

    before = firewall_rule_packets('ipv4_ingress', 'default')

    send_ingress_udp(port=54240)
    send_ingress_udp(port=54241)
    assert_firewall_rule_packets('ipv4_ingress', 36010, 1, timeout=5)
    assert_firewall_rule_packets('ipv4_ingress', 'default', before + 1)
    assert_firewall_chain('ingress', hook='ingress', prio=-10)


def test_ipv6_ingress_packet_filter(config):
    """IPv6 transport matching follows its own family dispatch."""
    # Baseline: configs/network-features.conf (FN61).

    send_ingress_udp(family='ipv6', port=54244)
    send_ingress_udp(family='ipv6', port=54245)
    assert_firewall_rule_packets('ipv6_ingress', 36110, 1, timeout=5)


def test_ipv4_ingress_vlan_map(config):
    'VLAN-keyed verdict maps distinguish matching and nonmatching tags.'
    # Baseline: configs/network-features.conf (FN62).

    before = firewall_rule_packets('ipv4_ingress', 'default')

    send_ingress_udp(vlan=100, priority=5, port=54248)
    send_ingress_udp(vlan=101, priority=5, port=54248)
    assert_firewall_rule_packets('ipv4_ingress', 'default', before + 1, timeout=5)


def test_ipv6_ingress_vlan_match_group(config):
    'IPv6 membership groups use the same VLAN key extraction as maps.'
    # Baseline: configs/network-features.conf (FN63).

    send_ingress_udp(family='ipv6', vlan=100, priority=5, port=54252)
    send_ingress_udp(family='ipv6', vlan=100, priority=4, port=54252)
    assert_firewall_rule_packets('ipv6_ingress', 36310, 1, timeout=5)


def test_ipv6_ingress_vlan_map(config):
    'IPv6 verdict-map lookups preserve VLAN ID/priority pairings.'
    # Baseline: configs/network-features.conf (FN64).
    send_ingress_udp(family='ipv6', vlan=100, priority=5, port=54256)
    send_ingress_udp(family='ipv6', vlan=101, priority=5, port=54256)
    assert_firewall_rule_packets('ipv6_ingress', 36420, 1, timeout=5)


def test_ipv4_ingress_vlan_match_group(config):
    """IPv4 membership groups match tagged packets without map results."""
    # Baseline: configs/network-features.conf (FN65).

    send_ingress_udp(vlan=100, priority=5, port=54260)
    send_ingress_udp(vlan=100, priority=4, port=54260)
    assert_firewall_rule_packets('ipv4_ingress', 36510, 1, timeout=5)


def test_ipv4_ingress_vlan_rule(config):
    """Explicit VLAN fields apply an AND condition to ID and priority."""
    # Baseline: configs/network-features.conf (FN66).

    send_ingress_udp(vlan=100, priority=5, port=54264)
    send_ingress_udp(vlan=100, priority=4, port=54264)
    assert_firewall_rule_packets('ipv4_ingress', 36610, 1, timeout=5)


def test_ipv6_ingress_vlan_rule(config):
    """The same explicit VLAN fields work for IPv6 under the tag."""
    # Baseline: configs/network-features.conf (FN67).

    send_ingress_udp(family='ipv6', vlan=100, priority=5, port=54268)
    send_ingress_udp(family='ipv6', vlan=101, priority=5, port=54268)
    assert_firewall_rule_packets('ipv6_ingress', 36710, 1, timeout=5)


def test_ipv4_ingress_nested_named_chains(config):
    """Ingress packets traverse both named jumps before reaching a terminal verdict."""
    # Baseline: configs/network-features.conf (FN68).

    send_ingress_udp(port=54272)
    assert_firewall_rule_packets('ipv4_name_FN68LAST', 36810, 1, timeout=5)


def test_ipv6_ingress_nested_named_chains(config):
    """IPv6 nested policies retain the caller's ingress context."""
    # Baseline: configs/network-features.conf (FN69).

    send_ingress_udp(family='ipv6', port=54276)
    assert_firewall_rule_packets('ipv6_name_FN69LAST', 36910, 1, timeout=5)
