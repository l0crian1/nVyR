"""Firewall ports on the shared routed-network scenario.

IPv4/IPv6 SCTP, UDP-Lite and DCCP ports, dynamic keys and per-port limits.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from smoketests.assertions import assert_firewall_counter, assert_firewall_object
from smoketests.firewall_support import send_firewall_transport


def test_sctp_ports_ipv4(config):
    """Match ports and exclusions before tracking; nonmatching ports reach the fallback."""
    # Baseline: configs/network-features.conf (FN21).

    send_firewall_transport('sctp', family='ipv4', destination_port=54084)
    send_firewall_transport('sctp', family='ipv4', destination_port=54085)
    send_firewall_transport('sctp', family='ipv4', destination_port=54086)

    assert_firewall_counter('FN21MATCHED', 1)
    assert_firewall_counter('FN21MISSED', 2)


def test_udplite_ports_ipv4(config):
    """Match ports and exclusions before tracking; nonmatching ports reach the fallback."""
    # Baseline: configs/network-features.conf (FN22).

    send_firewall_transport('udplite', family='ipv4', destination_port=54088)
    send_firewall_transport('udplite', family='ipv4', destination_port=54089)
    send_firewall_transport('udplite', family='ipv4', destination_port=54090)

    assert_firewall_counter('FN22MATCHED', 1)
    assert_firewall_counter('FN22MISSED', 2)


def test_dccp_ports_ipv4(config):
    """Match ports and exclusions before tracking; nonmatching ports reach the fallback."""
    # Baseline: configs/network-features.conf (FN23).

    send_firewall_transport('dccp', family='ipv4', destination_port=54092)
    send_firewall_transport('dccp', family='ipv4', destination_port=54093)
    send_firewall_transport('dccp', family='ipv4', destination_port=54094)

    assert_firewall_counter('FN23MATCHED', 1)
    assert_firewall_counter('FN23MISSED', 2)


def test_transport_dynamic_ports_ipv4(config):
    """Learn non-TCP/UDP packet ports through the generated transport guard."""
    # Baseline: configs/network-features.conf (FN24).

    send_firewall_transport('sctp', family='ipv4', destination_port=54096)
    send_firewall_transport('udplite', family='ipv4', destination_port=54096)
    send_firewall_transport('dccp', family='ipv4', destination_port=54096)

    assert_firewall_object('set', 'ipv4_match_group_FN24LEARNED', 'sctp . 54096', 'udplite . 54096', 'dccp . 54096')


def test_transport_port_limits_ipv4(config):
    """Per-port rate limits must admit each supported transport through their guard."""
    # Baseline: configs/network-features.conf (FN25).

    send_firewall_transport('sctp', family='ipv4', destination_port=54100)
    send_firewall_transport('udplite', family='ipv4', destination_port=54100)
    send_firewall_transport('dccp', family='ipv4', destination_port=54100)

    assert_firewall_counter('FN25MATCHED', 3)


def test_sctp_ports_ipv6(config):
    """Match ports and exclusions before tracking; nonmatching ports reach the fallback."""
    # Baseline: configs/network-features.conf (FN26).

    send_firewall_transport('sctp', family='ipv6', destination_port=54104)
    send_firewall_transport('sctp', family='ipv6', destination_port=54105)
    send_firewall_transport('sctp', family='ipv6', destination_port=54106)

    assert_firewall_counter('FN26MATCHED', 1)
    assert_firewall_counter('FN26MISSED', 2)


def test_udplite_ports_ipv6(config):
    """Match ports and exclusions before tracking; nonmatching ports reach the fallback."""
    # Baseline: configs/network-features.conf (FN27).

    send_firewall_transport('udplite', family='ipv6', destination_port=54108)
    send_firewall_transport('udplite', family='ipv6', destination_port=54109)
    send_firewall_transport('udplite', family='ipv6', destination_port=54110)

    assert_firewall_counter('FN27MATCHED', 1)
    assert_firewall_counter('FN27MISSED', 2)


def test_dccp_ports_ipv6(config):
    """Match ports and exclusions before tracking; nonmatching ports reach the fallback."""
    # Baseline: configs/network-features.conf (FN28).

    send_firewall_transport('dccp', family='ipv6', destination_port=54112)
    send_firewall_transport('dccp', family='ipv6', destination_port=54113)
    send_firewall_transport('dccp', family='ipv6', destination_port=54114)

    assert_firewall_counter('FN28MATCHED', 1)
    assert_firewall_counter('FN28MISSED', 2)


def test_transport_dynamic_ports_ipv6(config):
    """Learn non-TCP/UDP packet ports through the generated transport guard."""
    # Baseline: configs/network-features.conf (FN29).

    send_firewall_transport('sctp', family='ipv6', destination_port=54116)
    send_firewall_transport('udplite', family='ipv6', destination_port=54116)
    send_firewall_transport('dccp', family='ipv6', destination_port=54116)

    assert_firewall_object('set', 'ipv6_match_group_FN29LEARNED', 'sctp . 54116', 'udplite . 54116', 'dccp . 54116')


def test_transport_port_limits_ipv6(config):
    """Per-port rate limits must admit each supported transport through their guard."""
    # Baseline: configs/network-features.conf (FN30).

    send_firewall_transport('sctp', family='ipv6', destination_port=54120)
    send_firewall_transport('udplite', family='ipv6', destination_port=54120)
    send_firewall_transport('dccp', family='ipv6', destination_port=54120)

    assert_firewall_counter('FN30MATCHED', 3)
