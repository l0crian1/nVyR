"""Firewall allowances on the shared routed-network scenario.

IPv4/IPv6 rule/shared limit keys and inline/shared quota operational views.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

import pytest


if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from smoketests.assertions import (
    assert_equal, assert_firewall_runtime_keys, assert_operational_output,
    assert_firewall_runtime_quota,
)
from smoketests.firewall_support import send_firewall_udp


def test_ipv4_rule_limit_keys(config):
    """One IPv4 rule exposes both its rate keys and its connection-limit keys."""
    # Baseline: configs/network-features.conf (FN4).

    assert_equal(send_firewall_udp(1, port=54016), 1)
    assert_firewall_runtime_keys('ipv4', 30410, '127.0.0.2')
    assert_operational_output('show firewall ipv4 output filter rule 30410 limit',
                                  'Source address', 'Destination port', 'Expires', 'connection limit')
    assert_operational_output('show firewall ipv4 output filter limits', 'Rule 30410 rate limit')


def test_ipv6_rule_limit_keys(config):
    """IPv6 keys retain their address and do not invent expiry for connection counts."""
    # Baseline: configs/network-features.conf (FN5).

    assert_equal(send_firewall_udp(1, family='ipv6', port=54020), 1)
    assert_firewall_runtime_keys('ipv6', 30510, '::1')
    assert_operational_output('show firewall ipv6 output filter rule 30510 limit',
                                  '::1', 'Destination port', 'Expires', 'connection limit')
    assert_operational_output('show firewall ipv6 output filter limits', 'Rule 30510 rate limit')


def test_ipv4_shared_limit_keys(config):
    """A rule referencing a named allowance shows that group's live shared keys."""
    # Baseline: configs/network-features.conf (FN6).

    assert_operational_output('show firewall ipv4 output filter rule 30610 limit', 'No active keys recorded.')
    assert_equal(send_firewall_udp(1, port=54024), 1)
    assert_firewall_runtime_keys('ipv4', 30610, '127.0.0.2', group='FN6RUNTIME')
    assert_operational_output('show firewall ipv4 output filter rule 30610 limit', 'Group (shared)', 'FN6RUNTIME')


def test_ipv6_shared_limit_keys(config):
    """Shared IPv6 allowances are resolved from their installed rule reference."""
    # Baseline: configs/network-features.conf (FN7).

    assert_equal(send_firewall_udp(1, family='ipv6', port=54028), 1)
    assert_firewall_runtime_keys('ipv6', 30710, '::1', group='FN7RUNTIME')
    assert_operational_output('show firewall ipv6 output filter rule 30710 limit', 'Group (shared)', 'FN7RUNTIME')


def test_ipv4_inline_and_shared_quotas(config):
    """IPv4 collection and single-rule quota views report consumed allowance without resetting it."""
    # Baseline: configs/network-features.conf (FN8).

    assert_equal(send_firewall_udp(1, port=54032), 1)
    assert_firewall_runtime_quota('ipv4', rules=(30810, 30820), group='FN8RUNTIME')
    assert_operational_output('show firewall ipv4 output filter quotas', 'Remaining', 'FN8RUNTIME')
    assert_operational_output('show firewall ipv4 output filter rule 30810 quota', 'Used', '1 MiB')
    assert_operational_output('show firewall ipv4 name FN8RUNTIME quotas', 'Group (shared)')
    assert_operational_output('show firewall ipv4 name FN8RUNTIME rule 30810 quota', 'Remaining')


def test_ipv6_inline_and_shared_quotas(config):
    """IPv6 quota display supports ordinary hooks and named chains consistently."""
    # Baseline: configs/network-features.conf (FN9).

    assert_equal(send_firewall_udp(1, family='ipv6', port=54036), 1)
    assert_firewall_runtime_quota('ipv6', rules=(30910, 30920), group='FN9RUNTIME')
    assert_operational_output('show firewall ipv6 output filter quotas', 'Remaining', 'FN9RUNTIME', 'over')
    assert_operational_output('show firewall ipv6 output filter rule 30910 quota', 'Used', '1 MiB')
    assert_operational_output('show firewall ipv6 name FN9RUNTIME quotas', 'Group (shared)')
    assert_operational_output('show firewall ipv6 name FN9RUNTIME rule 30910 quota', 'Remaining')
