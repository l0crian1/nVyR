"""Domain-group native configuration and CLI verification."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_raises, assert_firewall_commit_rejected, assert_firewall_object,
    assert_firewall_rule,
)
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_domain_group_ipv4(config):
    """The IPv4 group installs a native address set and rule reference."""
    config.set('set firewall group domain-group ipv4 DNS_TEST domain example.com lookup rounds 3')
    config.set('set firewall group domain-group ipv4 DNS_TEST counter last-used')
    config.set('set firewall ipv4 name DNS_TEST rule 10 action accept destination-domain-group DNS_TEST')
    config.commit()

    assert_firewall_object('set', 'ipv4_domain_group_DNS_TEST', 'type ipv4_addr')
    assert_firewall_rule('ipv4_name_DNS_TEST', 10, '@ipv4_domain_group_DNS_TEST')


def test_domain_group_ipv6(config):
    """The IPv6 group installs a separate address set with a negative rule reference."""
    config.set('set firewall group domain-group ipv6 DNS_TEST domain example.com')
    config.set('set firewall ipv6 name DNS_TEST rule 10 action drop source-domain-group not DNS_TEST')
    config.commit()

    assert_firewall_object('set', 'ipv6_domain_group_DNS_TEST', 'type ipv6_addr')
    assert_firewall_rule('ipv6_name_DNS_TEST', 10, '!= @ipv6_domain_group_DNS_TEST')


def test_domain_group_failed_lookup_is_nonfatal(config):
    """A reserved nonexistent name cannot prevent committing a firewall."""
    config.set('set firewall group domain-group ipv4 MISSING domain nvyr-smoketest.invalid')
    config.commit()

    assert_firewall_object('set', 'ipv4_domain_group_MISSING', 'type ipv4_addr')


def test_domain_group_inclusion(config):
    """Included domains create the parent set and protect its child reference."""
    config.set('set firewall group domain-group ipv4 CHILD domain example.com')
    config.set('set firewall group domain-group ipv4 PARENT include-group CHILD')
    config.commit()

    assert_firewall_object('set', 'ipv4_domain_group_PARENT')
    with assert_raises(RouterError):
        config.delete('delete firewall group domain-group ipv4 CHILD')


def test_domain_group_rejects_empty_selector(config):
    """Empty group names must not become unintentionally nonmatching policy."""
    config.set('set firewall group domain-group ipv4 EMPTY')
    assert_firewall_commit_rejected(config, 'at least one domain')


def test_domain_group_rejects_duplicate_rule_field(config):
    """An address group and domain group cannot both own a positive source match."""
    config.set('set firewall group domain-group ipv4 DNS_TEST domain example.com')
    config.set('set firewall group address-group ipv4 STATIC address 192.0.2.1')
    config.set('set firewall ipv4 name DNS_TEST rule 10 action accept source-domain-group DNS_TEST source-address-group STATIC')
    assert_firewall_commit_rejected(config, 'duplicates source-address')


def test_domain_group_and_geoip_excluded_from_failsafe(config):
    """Early firewall configuration must never require network-backed membership."""
    with assert_raises(RouterError):
        config.set('set firewall fail-safe group domain-group ipv4 DNS_TEST domain example.com')
    with assert_raises(RouterError):
        config.set('set firewall fail-safe group address-group ipv4 GEO geoip country US')
