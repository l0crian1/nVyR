"""Native transport-port group configuration for IPv4 and IPv6."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from smoketests.assertions import assert_firewall_rule
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_transport_port_groups_ipv4(config):
    """Use SCTP in a verdict map, UDP-Lite in a match-group, and DCCP with a port group."""
    config.set('set firewall group map ipv4 PORTMAP match protocol destination-port')
    config.set('set firewall group map ipv4 PORTMAP result-type verdict')
    config.set('set firewall group map ipv4 PORTMAP entry SCTP protocol sctp destination-port 53098 result action drop')
    config.set('set firewall group match-group ipv4 PORTMATCH match protocol destination-port')
    config.set('set firewall group match-group ipv4 PORTMATCH entry UDPLITE protocol udplite destination-port 53098')
    config.set('set firewall group port-group PORT port 53098')
    config.set('set firewall ipv4 output raw rule 10 outbound-interface lo map PORTMAP')
    config.set('set firewall ipv4 output raw rule 20 outbound-interface lo match-group PORTMATCH action drop')
    config.set('set firewall ipv4 output raw rule 30 outbound-interface lo protocol dccp destination-port-group PORT action drop')
    config.commit()

    assert_firewall_rule('ipv4_output_raw', 10, '@ipv4_map_PORTMAP')
    assert_firewall_rule('ipv4_output_raw', 20, '@ipv4_match_group_PORTMATCH')
    assert_firewall_rule('ipv4_output_raw', 30, '@port_group_PORT')


def test_transport_port_groups_ipv6(config):
    """Use SCTP in a verdict map, UDP-Lite in a match-group, and DCCP with a port group."""
    config.set('set firewall group map ipv6 PORTMAP match protocol destination-port')
    config.set('set firewall group map ipv6 PORTMAP result-type verdict')
    config.set('set firewall group map ipv6 PORTMAP entry SCTP protocol sctp destination-port 53098 result action drop')
    config.set('set firewall group match-group ipv6 PORTMATCH match protocol destination-port')
    config.set('set firewall group match-group ipv6 PORTMATCH entry UDPLITE protocol udplite destination-port 53098')
    config.set('set firewall group port-group PORT port 53098')
    config.set('set firewall ipv6 output raw rule 10 outbound-interface lo map PORTMAP')
    config.set('set firewall ipv6 output raw rule 20 outbound-interface lo match-group PORTMATCH action drop')
    config.set('set firewall ipv6 output raw rule 30 outbound-interface lo protocol dccp destination-port-group PORT action drop')
    config.commit()

    assert_firewall_rule('ipv6_output_raw', 10, '@ipv6_map_PORTMAP')
    assert_firewall_rule('ipv6_output_raw', 20, '@ipv6_match_group_PORTMATCH')
    assert_firewall_rule('ipv6_output_raw', 30, '@port_group_PORT')


def test_sctp_rule_configuration_ipv4(config):
    """Install native SCTP port matching for IPV4."""
    config.set('set firewall ipv4 output raw rule 10 protocol sctp destination-port 53098 action drop')
    config.commit()

    assert_firewall_rule('ipv4_output_raw', 10, 'sctp', '53098', 'drop')


def test_udplite_rule_configuration_ipv4(config):
    """Install native UDPLITE port matching for IPV4."""
    config.set('set firewall ipv4 output raw rule 10 protocol udplite destination-port 53098 action drop')
    config.commit()

    assert_firewall_rule('ipv4_output_raw', 10, 'udplite', '53098', 'drop')


def test_dccp_rule_configuration_ipv4(config):
    """Install native DCCP port matching for IPV4."""
    config.set('set firewall ipv4 output raw rule 10 protocol dccp destination-port 53098 action drop')
    config.commit()

    assert_firewall_rule('ipv4_output_raw', 10, 'dccp', '53098', 'drop')


def test_sctp_rule_configuration_ipv6(config):
    """Install native SCTP port matching for IPV6."""
    config.set('set firewall ipv6 output raw rule 10 protocol sctp destination-port 53098 action drop')
    config.commit()

    assert_firewall_rule('ipv6_output_raw', 10, 'sctp', '53098', 'drop')


def test_udplite_rule_configuration_ipv6(config):
    """Install native UDPLITE port matching for IPV6."""
    config.set('set firewall ipv6 output raw rule 10 protocol udplite destination-port 53098 action drop')
    config.commit()

    assert_firewall_rule('ipv6_output_raw', 10, 'udplite', '53098', 'drop')


def test_dccp_rule_configuration_ipv6(config):
    """Install native DCCP port matching for IPV6."""
    config.set('set firewall ipv6 output raw rule 10 protocol dccp destination-port 53098 action drop')
    config.commit()

    assert_firewall_rule('ipv6_output_raw', 10, 'dccp', '53098', 'drop')
