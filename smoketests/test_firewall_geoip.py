"""GeoIP native set configuration and incompatible-option verification."""

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


def test_geoip_ipv4(config):
    """Country selection installs an interval set and its native rule reference."""
    config.set('set firewall group address-group ipv4 COUNTRY geoip country US country CA')
    config.set('set firewall ipv4 name GEOIP rule 10 action drop source-address-group COUNTRY')
    config.commit()

    assert_firewall_object('set', 'ipv4_address_group_COUNTRY', 'flags interval', 'auto-merge')
    assert_firewall_rule('ipv4_name_GEOIP', 10, '@ipv4_address_group_COUNTRY')


def test_geoip_ipv6(config):
    """IPv6 country selection supports the existing negative group reference."""
    config.set('set firewall group address-group ipv6 COUNTRY geoip country US')
    config.set('set firewall ipv6 name GEOIP rule 10 action drop destination-address-group not COUNTRY')
    config.commit()

    assert_firewall_object('set', 'ipv6_address_group_COUNTRY', 'flags interval', 'auto-merge')
    assert_firewall_rule('ipv6_name_GEOIP', 10, '!= @ipv6_address_group_COUNTRY')


def test_geoip_rejects_configured_addresses(config):
    """A refresh must never erase manually configured membership."""
    config.set('set firewall group address-group ipv4 COUNTRY geoip country US')
    config.set('set firewall group address-group ipv4 COUNTRY address 192.0.2.1')
    assert_firewall_commit_rejected(config, 'geoip cannot be combined')


def test_geoip_rejects_dynamic_membership(config):
    """Packet learning and country updates cannot own the same IPv6 set."""
    config.set('set firewall group address-group ipv6 COUNTRY geoip country US')
    config.set('set firewall group address-group ipv6 COUNTRY dynamic')
    assert_firewall_commit_rejected(config, 'geoip cannot be combined')


def test_geoip_rejects_empty_selection(config):
    """An incomplete GeoIP selector fails verification before downloading."""
    config.set('set firewall group address-group ipv4 COUNTRY geoip')
    assert_firewall_commit_rejected(config, 'geoip requires at least one country')


def test_geoip_rejects_unknown_country(config):
    """A mistyped country is rejected while inserting the command."""
    with assert_raises(RouterError):
        config.set('set firewall group address-group ipv4 COUNTRY geoip country XX')
