"""Firewall trace on the shared routed-network scenario.

IPv4/IPv6/inet bounded packet traces and saved structured trace output.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

import pytest


if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from smoketests.assertions import assert_firewall_rule, assert_firewall_trace_capture


def test_ipv4_packet_trace(config):
    """IPv4 echo traffic is traced and its rule path is saved without changing verdicts."""
    # Baseline: configs/network-features.conf (FN35).

    assert_firewall_rule('ipv4_output', '33510', 'meta nftrace set 1', 'accept')
    assert_firewall_trace_capture('127.0.0.1', 'firewall ipv4 output filter rule 33510')


def test_ipv6_packet_trace(config):
    """IPv6 traces use the same capture format and retain the IPv6 configuration path."""
    # Baseline: configs/network-features.conf (FN36).

    assert_firewall_rule('ipv6_output', '33610', 'meta nftrace set 1', 'accept')
    assert_firewall_trace_capture('::1', 'firewall ipv6 output filter rule 33610')


def test_inet_packet_trace(config):
    """Family-neutral base-chain rules map back to their inet configuration location."""
    # Baseline: configs/network-features.conf (FN37).

    assert_firewall_rule('output', '33710', 'meta nftrace set 1', 'continue')
    assert_firewall_trace_capture('127.0.0.1', 'firewall inet output filter rule 33710')
