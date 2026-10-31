"""Live connection metadata, original/reply fields, labels and accounting matches."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.helpers.process import cmd
from smoketests.assertions import assert_equal, assert_firewall_rule
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_ipv4_connection_state_established(config):
    """Install IPv4 state established and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection state established')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct state.*established')


def test_ipv4_connection_state_not_new(config):
    """Install IPv4 state not new and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection state not new')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct state !=.*new')


def test_ipv4_connection_status_snat_and_dnat(config):
    """Install IPv4 status snat and dnat and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection status snat and dnat')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct status.*(snat.*dnat|dnat.*snat|0x0*30)')


def test_ipv4_connection_status_confirmed_and_offload(config):
    """Install IPv4 status confirmed and offload and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection status confirmed and offload')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct status.*(0x0*4008|confirmed.*0x0*4000)')


def test_ipv4_connection_direction_reply(config):
    """Install IPv4 direction reply and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection direction reply')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct direction.*reply')


def test_ipv4_connection_mark_10_20(config):
    """Install IPv4 mark 10 20 and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection mark 10-20')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct mark')


def test_ipv4_connection_zone_2_3(config):
    """Install IPv4 zone 2 3 and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection zone 2-3')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct zone.*2-3')


def test_ipv4_connection_id_100(config):
    """Install IPv4 id 100 and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection id 100')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct id.*100')


def test_ipv4_connection_helper_ftp(config):
    """Install IPv4 helper ftp and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection helper ftp')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct helper.*"ftp"')


def test_ipv4_connection_label_1_and_2(config):
    """Install IPv4 label 1 and 2 and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection label 1 and 2')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct label')


def test_ipv4_connection_label_not_3(config):
    """Install IPv4 label not 3 and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection label not 3')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct label')


def test_ipv4_connection_expiration_gt_10s(config):
    """Install IPv4 expiration gt 10s and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection expiration gt 10s')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct expiration > 10s')


def test_ipv4_connection_expiration_eq_not_1m(config):
    """Install IPv4 expiration eq not 1m and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection expiration eq not 1m')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct expiration != (1m|60s)')


def test_ipv4_connection_protocol_tcp_original_source_port_53098(config):
    """Install IPv4 protocol tcp original source port 53098 and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection protocol tcp original source-port 53098')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct original proto-src.*53098')


def test_ipv4_connection_protocol_udp_reply_destination_port_53098(config):
    """Install IPv4 protocol udp reply destination port 53098 and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection protocol udp reply destination-port 53098')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct reply proto-dst.*53098')


def test_ipv4_connection_original_zone_2(config):
    """Install IPv4 original zone 2 and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection original zone 2')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct original zone.*2')


def test_ipv4_connection_reply_zone_not_3(config):
    """Install IPv4 reply zone not 3 and check its native conntrack expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection reply zone not 3')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct reply zone !=.*3')


def test_ipv6_connection_state_established(config):
    """Install IPv6 state established and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection state established')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct state.*established')


def test_ipv6_connection_state_not_new(config):
    """Install IPv6 state not new and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection state not new')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct state !=.*new')


def test_ipv6_connection_status_snat_and_dnat(config):
    """Install IPv6 status snat and dnat and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection status snat and dnat')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct status.*(snat.*dnat|dnat.*snat|0x0*30)')


def test_ipv6_connection_status_confirmed_and_offload(config):
    """Install IPv6 status confirmed and offload and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection status confirmed and offload')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct status.*(0x0*4008|confirmed.*0x0*4000)')


def test_ipv6_connection_direction_reply(config):
    """Install IPv6 direction reply and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection direction reply')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct direction.*reply')


def test_ipv6_connection_mark_10_20(config):
    """Install IPv6 mark 10 20 and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection mark 10-20')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct mark')


def test_ipv6_connection_zone_2_3(config):
    """Install IPv6 zone 2 3 and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection zone 2-3')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct zone.*2-3')


def test_ipv6_connection_id_100(config):
    """Install IPv6 id 100 and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection id 100')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct id.*100')


def test_ipv6_connection_helper_ftp(config):
    """Install IPv6 helper ftp and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection helper ftp')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct helper.*"ftp"')


def test_ipv6_connection_label_1_and_2(config):
    """Install IPv6 label 1 and 2 and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection label 1 and 2')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct label')


def test_ipv6_connection_label_not_3(config):
    """Install IPv6 label not 3 and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection label not 3')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct label')


def test_ipv6_connection_expiration_gt_10s(config):
    """Install IPv6 expiration gt 10s and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection expiration gt 10s')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct expiration > 10s')


def test_ipv6_connection_expiration_eq_not_1m(config):
    """Install IPv6 expiration eq not 1m and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection expiration eq not 1m')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct expiration != (1m|60s)')


def test_ipv6_connection_protocol_tcp_original_source_port_53098(config):
    """Install IPv6 protocol tcp original source port 53098 and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection protocol tcp original source-port 53098')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct original proto-src.*53098')


def test_ipv6_connection_protocol_udp_reply_destination_port_53098(config):
    """Install IPv6 protocol udp reply destination port 53098 and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection protocol udp reply destination-port 53098')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct reply proto-dst.*53098')


def test_ipv6_connection_original_zone_2(config):
    """Install IPv6 original zone 2 and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection original zone 2')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct original zone.*2')


def test_ipv6_connection_reply_zone_not_3(config):
    """Install IPv6 reply zone not 3 and check its native conntrack expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection reply zone not 3')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct reply zone !=.*3')


def test_connection_addresses_and_family_ipv4_original(config):
    """Original/reply addresses use the family-specific stored tuple."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection family ipv4')
    config.set('set firewall ipv4 name SMOKE rule 10 connection original source-address 192.0.2.1')
    config.set('set firewall ipv4 name SMOKE rule 10 connection original destination-address not 192.0.2.1')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct original .*saddr', 'ct original .*daddr !=')


def test_connection_addresses_and_family_ipv4_reply(config):
    """Original/reply addresses use the family-specific stored tuple."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection family ipv4')
    config.set('set firewall ipv4 name SMOKE rule 10 connection reply source-address 192.0.2.1')
    config.set('set firewall ipv4 name SMOKE rule 10 connection reply destination-address not 192.0.2.1')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct reply .*saddr', 'ct reply .*daddr !=')


def test_connection_addresses_and_family_ipv6_original(config):
    """Original/reply addresses use the family-specific stored tuple."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection family ipv6')
    config.set('set firewall ipv6 name SMOKE rule 10 connection original source-address 2001:db8::1')
    config.set('set firewall ipv6 name SMOKE rule 10 connection original destination-address not 2001:db8::1')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct original .*saddr', 'ct original .*daddr !=')


def test_connection_addresses_and_family_ipv6_reply(config):
    """Original/reply addresses use the family-specific stored tuple."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection family ipv6')
    config.set('set firewall ipv6 name SMOKE rule 10 connection reply source-address 2001:db8::1')
    config.set('set firewall ipv6 name SMOKE rule 10 connection reply destination-address not 2001:db8::1')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ct reply .*saddr', 'ct reply .*daddr !=')


def test_connection_accounting_original_packets(config):
    """Match original packets with accounting enabled through configd."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection original packets gt 10')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct original packets > 10')
    assert_equal(cmd(['sysctl', '-n', 'net.netfilter.nf_conntrack_acct']).strip(), '1')


def test_connection_accounting_original_bytes(config):
    """Match original bytes with accounting enabled through configd."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection original bytes gt 1k')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct original bytes > 1024')
    assert_equal(cmd(['sysctl', '-n', 'net.netfilter.nf_conntrack_acct']).strip(), '1')


def test_connection_accounting_original_average_packet_size(config):
    """Match original average packet size with accounting enabled through configd."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection original average-packet-size gt 1k')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct original avgpkt > 1024')
    assert_equal(cmd(['sysctl', '-n', 'net.netfilter.nf_conntrack_acct']).strip(), '1')


def test_connection_accounting_reply_packets(config):
    """Match reply packets with accounting enabled through configd."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection reply packets gt 10')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct reply packets > 10')
    assert_equal(cmd(['sysctl', '-n', 'net.netfilter.nf_conntrack_acct']).strip(), '1')


def test_connection_accounting_reply_bytes(config):
    """Match reply bytes with accounting enabled through configd."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection reply bytes gt 1k')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct reply bytes > 1024')
    assert_equal(cmd(['sysctl', '-n', 'net.netfilter.nf_conntrack_acct']).strip(), '1')


def test_connection_accounting_reply_average_packet_size(config):
    """Match reply average packet size with accounting enabled through configd."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection reply average-packet-size gt 1k')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct reply avgpkt > 1024')
    assert_equal(cmd(['sysctl', '-n', 'net.netfilter.nf_conntrack_acct']).strip(), '1')


def test_connection_accounting_total_packets(config):
    """Match total packets with accounting enabled through configd."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection total packets gt 10')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct packets > 10')
    assert_equal(cmd(['sysctl', '-n', 'net.netfilter.nf_conntrack_acct']).strip(), '1')


def test_connection_accounting_total_bytes(config):
    """Match total bytes with accounting enabled through configd."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection total bytes gt 1k')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct bytes > 1024')
    assert_equal(cmd(['sysctl', '-n', 'net.netfilter.nf_conntrack_acct']).strip(), '1')


def test_connection_accounting_total_average_packet_size(config):
    """Match total average packet size with accounting enabled through configd."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection total average-packet-size gt 1k')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct avgpkt > 1024')
    assert_equal(cmd(['sysctl', '-n', 'net.netfilter.nf_conntrack_acct']).strip(), '1')


def test_multi_flag_alternatives_and_negation(config):
    """Separate joined alternatives survive deleting one negative multi value."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol tcp tcp-flags syn and not ack')
    config.set('set firewall ipv4 name SMOKE rule 10 tcp-flags ack and not syn')
    config.set('set firewall ipv4 name SMOKE rule 10 connection label 1 and 2')
    config.set('set firewall ipv4 name SMOKE rule 10 connection label 3 and 4')
    config.set('set firewall ipv4 name SMOKE rule 10 connection label not 5 and 6')
    config.set('set firewall ipv4 name SMOKE rule 10 connection label not 7 and 8')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'tcp flags', 'syn', 'ack', 'ct label')

    config.delete('delete firewall ipv4 name SMOKE rule 10 connection label not 5 and 6')

    config.commit()
    labels = config.get_config()['firewall']['ipv4']['name']['SMOKE']['rule']['10']['connection']

    assert_equal(labels['not']['label'], ['7,8'])
    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ct label')
