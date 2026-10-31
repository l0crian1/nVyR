"""Explicit catch-all feature tests using the same commands as administrators."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from smoketests.assertions import assert_firewall_object, assert_firewall_commit_rejected
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_default_address_nat_map(config):
    """A NAT address map may contain only a default result."""
    config.set('set firewall group map ipv4 TRANSLATE match protocol')
    config.set('set firewall group map ipv4 TRANSLATE result-type address')
    config.set('set firewall group map ipv4 TRANSLATE default-result address 192.0.2.10')
    config.set('set nat destination rule 10 inbound-interface dum998 map TRANSLATE')
    config.commit()
    assert_firewall_object('map', 'ipv4_map_TRANSLATE', r'\*.*: 192.0.2.10')


def test_default_port_nat_map(config):
    """A port fallback keeps the map's TCP/UDP translation guard."""
    config.set('set firewall group map ipv4 TRANSLATE match protocol')
    config.set('set firewall group map ipv4 TRANSLATE result-type port')
    config.set('set firewall group map ipv4 TRANSLATE default-result port 8443')
    config.set('set nat destination rule 10 inbound-interface dum998 map TRANSLATE')
    config.commit()
    assert_firewall_object('map', 'ipv4_map_TRANSLATE', r'\*.*: 8443')


def test_default_address_port_nat_map(config):
    """A concatenated address/port result is one complete fallback."""
    config.set('set firewall group map ipv4 TRANSLATE match protocol')
    config.set('set firewall group map ipv4 TRANSLATE result-type address-port')
    config.set('set firewall group map ipv4 TRANSLATE default-result address 192.0.2.10 port 8443')
    config.set('set nat destination rule 10 inbound-interface dum998 map TRANSLATE')
    config.commit()
    assert_firewall_object('map', 'ipv4_map_TRANSLATE', r'\*.*: 192.0.2.10 . 8443')


def test_empty_default_rejected(config):
    """An empty default node cannot be installed as a partial map element."""
    config.set('set firewall group map ipv4 SERVICES match protocol')
    config.set('set firewall group map ipv4 SERVICES result-type verdict')
    config.set('set firewall group map ipv4 SERVICES default-result')
    assert_firewall_commit_rejected(config, 'default-result: result-type verdict requires exactly')


def test_incomplete_default_translation_rejected(config):
    """An address-port map needs both fields in its fallback."""
    config.set('set firewall group map ipv4 TRANSLATE match protocol')
    config.set('set firewall group map ipv4 TRANSLATE result-type address-port')
    config.set('set firewall group map ipv4 TRANSLATE default-result address 192.0.2.10')
    assert_firewall_commit_rejected(config, 'default-result: result-type address-port requires exactly')


def test_default_jump_ingress_restriction(config):
    """A default jump cannot reach connection tracking from ingress."""
    config.set('set firewall inet name TRACKED rule 10 connection state established action accept')
    config.set('set firewall group map inet SERVICES match protocol')
    config.set('set firewall group map inet SERVICES result-type verdict')
    config.set('set firewall group map inet SERVICES default-result action jump jump-target TRACKED')
    config.set('set firewall inet ingress filter interface dum998')
    config.set('set firewall inet ingress filter rule 10 map SERVICES')
    assert_firewall_commit_rejected(config, 'unavailable in ingress')
