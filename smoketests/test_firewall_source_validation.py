"""Explicit source-validation feature checks using the installed configuration API."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from smoketests.assertions import (
    assert_firewall_rule, assert_firewall_object, assert_firewall_commit_rejected,
)
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_ipv4_global_strict_and_loose_override(config):
    """Strict defaults exclude both loose and disabled interface overrides."""
    config.set('set firewall ipv4 source-validation default strict')
    config.set('set firewall ipv4 source-validation interface dum998 mode loose')
    config.set('set firewall ipv4 source-validation interface dum999 mode disabled')
    config.commit()

    assert_firewall_rule('ipv4_prerouting', 'source-validation-strict', 'iifname != @source_validation_ipv4_overrides', 'fib saddr . iif oif 0', 'counter', 'drop')
    assert_firewall_rule('ipv4_prerouting', 'source-validation-loose', 'iifname @source_validation_ipv4_loose', 'fib saddr oif 0')
    assert_firewall_object('set', 'source_validation_ipv4_overrides', 'dum998', 'dum999')


def test_ipv6_global_strict_and_loose_override(config):
    """IPv6 uses the same two checks in its own prerouting raw chain."""
    config.set('set firewall ipv6 source-validation default strict')
    config.set('set firewall ipv6 source-validation interface dum998 mode loose')
    config.set('set firewall ipv6 source-validation interface dum999 mode disabled')
    config.commit()

    assert_firewall_rule('ipv6_prerouting', 'source-validation-strict', 'iifname != @source_validation_ipv6_overrides', 'fib saddr . iif oif 0')
    assert_firewall_rule('ipv6_prerouting', 'source-validation-loose', 'iifname @source_validation_ipv6_loose', 'fib saddr oif 0')


def test_ipv4_global_loose_and_strict_override(config):
    """An interface can require strict validation while the global mode is loose."""
    config.set('set firewall ipv4 source-validation default loose interface dum998 mode strict')
    config.commit()

    assert_firewall_rule('ipv4_prerouting', 'source-validation-strict', 'iifname @source_validation_ipv4_strict', 'fib saddr . iif oif 0')
    assert_firewall_rule('ipv4_prerouting', 'source-validation-loose', 'iifname != @source_validation_ipv4_overrides', 'fib saddr oif 0')


def test_ipv6_global_loose_and_strict_override(config):
    """IPv6 strict exceptions do not receive the global loose check as well."""
    config.set('set firewall ipv6 source-validation default loose interface dum998 mode strict')
    config.commit()

    assert_firewall_rule('ipv6_prerouting', 'source-validation-strict', 'iifname @source_validation_ipv6_strict', 'fib saddr . iif oif 0')
    assert_firewall_rule('ipv6_prerouting', 'source-validation-loose', 'iifname != @source_validation_ipv6_overrides', 'fib saddr oif 0')


def test_source_validation_mode_change_and_removal(config):
    """Changing then deleting validation keeps existing raw rules installed."""
    config.set('set firewall ipv4 source-validation default strict')
    config.set('set firewall ipv4 prerouting raw rule 10 action continue counter')
    config.commit()

    config.set('set firewall ipv4 source-validation default loose')
    config.commit()
    assert_firewall_rule('ipv4_prerouting', 'source-validation-loose', 'fib saddr oif 0')

    config.delete('delete firewall ipv4 source-validation')
    config.commit()
    assert_firewall_rule('ipv4_prerouting', 10, 'continue')


def test_inet_with_ipv4_source_validation_rejected(config):
    """Shared validation cannot coexist with IPv4 validation, even when disabled."""
    config.set('set firewall inet source-validation default loose')
    config.set('set firewall ipv4 source-validation default disabled')
    assert_firewall_commit_rejected(config, 'cannot be combined')


def test_inet_with_ipv6_source_validation_rejected(config):
    """Shared validation cannot coexist with an IPv6 policy."""
    config.set('set firewall inet source-validation default loose')
    config.set('set firewall ipv6 source-validation default strict')
    assert_firewall_commit_rejected(config, 'cannot be combined')


def test_matching_default_and_override_rejected(config):
    """Redundant explicit interface modes produce an actionable verification error."""
    config.set('set firewall ipv4 source-validation default strict interface dum998 mode strict')
    assert_firewall_commit_rejected(config, 'matches the global default')


def test_implicit_disabled_override_rejected(config):
    """An omitted default already disables validation on unlisted interfaces."""
    config.set('set firewall ipv6 source-validation interface dum998 mode disabled')
    assert_firewall_commit_rejected(config, 'matches the global default')


def test_source_validation_missing_interface_mode_rejected(config):
    """An interface name alone is not a complete source-validation override."""
    config.set('set firewall inet source-validation interface dum998')
    assert_firewall_commit_rejected(config, 'mode is required')
