"""CLI tracing flags are installed without generating or monitoring traffic."""

import pytest


if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from smoketests.assertions import assert_firewall_rule
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_ipv4_trace_configuration(config):
    """IPv4 nftrace appears in the installed rule before its verdict."""
    config.set('set firewall ipv4 output filter rule 10 nftrace action accept')
    config.commit()

    assert_firewall_rule('ipv4_output', 10, 'meta nftrace set 1', 'accept')


def test_ipv6_trace_configuration(config):
    """IPv6 nftrace appears in the installed rule before its verdict."""
    config.set('set firewall ipv6 output filter rule 10 nftrace action accept')
    config.commit()

    assert_firewall_rule('ipv6_output', 10, 'meta nftrace set 1', 'accept')


def test_inet_trace_configuration(config):
    """Family-neutral tracing can continue into family-specific dispatch."""
    config.set('set firewall inet output filter rule 10 nftrace action continue')
    config.commit()

    assert_firewall_rule('output', 10, 'meta nftrace set 1', 'continue')
