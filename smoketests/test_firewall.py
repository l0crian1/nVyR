"""Live firewall coverage: CLI -> configd -> native nftables, including datapath state."""

from contextlib import closing

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.protocol import Client
from smoketests.assertions import (
    assert_in, assert_firewall_object, assert_firewall_rule, assert_firewall_rule_absent,
)
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_ipv4_input_filter_actions(config):
    """Install each hook and its verdicts; restrict all packet effects to dummy links."""
    config.set('set firewall ipv4 input filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv4 input filter rule 11 inbound-interface dum998 action drop')
    config.set('set firewall ipv4 input filter rule 12 inbound-interface dum998 action continue')
    config.set('set firewall ipv4 input filter rule 13 inbound-interface dum998 action return')
    config.set('set firewall ipv4 input filter rule 14 inbound-interface dum998 action reject')

    config.commit()

    assert_firewall_rule('ipv4_input', 10, 'accept', 'dum998')
    assert_firewall_rule('ipv4_input', 11, 'drop', 'dum998')
    assert_firewall_rule('ipv4_input', 12, 'continue', 'dum998')
    assert_firewall_rule('ipv4_input', 13, 'return', 'dum998')
    assert_firewall_rule('ipv4_input', 14, 'reject', 'dum998')
    assert_firewall_rule('ipv4_input', 'default', 'accept')

    # A hooked dispatch chain must use the requested priority, not just its name.
    assert_firewall_object('chain', 'input', 'hook input', 'priority filter|0')


def test_ipv4_forward_filter_actions(config):
    """Install each hook and its verdicts; restrict all packet effects to dummy links."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv4 forward filter rule 11 inbound-interface dum998 action drop')
    config.set('set firewall ipv4 forward filter rule 12 inbound-interface dum998 action continue')
    config.set('set firewall ipv4 forward filter rule 13 inbound-interface dum998 action return')
    config.set('set firewall ipv4 forward filter rule 14 inbound-interface dum998 action reject')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'accept', 'dum998')
    assert_firewall_rule('ipv4_forward', 11, 'drop', 'dum998')
    assert_firewall_rule('ipv4_forward', 12, 'continue', 'dum998')
    assert_firewall_rule('ipv4_forward', 13, 'return', 'dum998')
    assert_firewall_rule('ipv4_forward', 14, 'reject', 'dum998')
    assert_firewall_rule('ipv4_forward', 'default', 'accept')

    # A hooked dispatch chain must use the requested priority, not just its name.
    assert_firewall_object('chain', 'forward', 'hook forward', 'priority filter|0')


def test_ipv4_output_filter_actions(config):
    """Install each hook and its verdicts; restrict all packet effects to dummy links."""
    config.set('set firewall ipv4 output filter rule 10 outbound-interface dum998 action accept')
    config.set('set firewall ipv4 output filter rule 11 outbound-interface dum998 action drop')
    config.set('set firewall ipv4 output filter rule 12 outbound-interface dum998 action continue')
    config.set('set firewall ipv4 output filter rule 13 outbound-interface dum998 action return')
    config.set('set firewall ipv4 output filter rule 14 outbound-interface dum998 action reject')

    config.commit()

    assert_firewall_rule('ipv4_output', 10, 'accept', 'dum998')
    assert_firewall_rule('ipv4_output', 11, 'drop', 'dum998')
    assert_firewall_rule('ipv4_output', 12, 'continue', 'dum998')
    assert_firewall_rule('ipv4_output', 13, 'return', 'dum998')
    assert_firewall_rule('ipv4_output', 14, 'reject', 'dum998')
    assert_firewall_rule('ipv4_output', 'default', 'accept')

    # A hooked dispatch chain must use the requested priority, not just its name.
    assert_firewall_object('chain', 'output', 'hook output', 'priority filter|0')


def test_ipv4_prerouting_raw_actions(config):
    """Install each hook and its verdicts; restrict all packet effects to dummy links."""
    config.set('set firewall ipv4 prerouting raw rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv4 prerouting raw rule 11 inbound-interface dum998 action drop')
    config.set('set firewall ipv4 prerouting raw rule 12 inbound-interface dum998 action continue')
    config.set('set firewall ipv4 prerouting raw rule 13 inbound-interface dum998 action return')
    config.set('set firewall ipv4 prerouting raw rule 14 inbound-interface dum998 action reject')
    config.set('set firewall ipv4 prerouting raw rule 10 notrack')

    config.commit()

    assert_firewall_rule('ipv4_prerouting', 10, 'accept', 'dum998')
    assert_firewall_rule('ipv4_prerouting', 11, 'drop', 'dum998')
    assert_firewall_rule('ipv4_prerouting', 12, 'continue', 'dum998')
    assert_firewall_rule('ipv4_prerouting', 13, 'return', 'dum998')
    assert_firewall_rule('ipv4_prerouting', 14, 'reject', 'dum998')
    assert_firewall_rule('ipv4_prerouting', 10, 'notrack')
    assert_firewall_rule('ipv4_prerouting', 'default', 'accept')

    # A hooked dispatch chain must use the requested priority, not just its name.
    assert_firewall_object('chain', 'prerouting', 'hook prerouting', 'priority raw|-300')


def test_ipv4_output_raw_actions(config):
    """Install each hook and its verdicts; restrict all packet effects to dummy links."""
    config.set('set firewall ipv4 output raw rule 10 outbound-interface dum998 action accept')
    config.set('set firewall ipv4 output raw rule 11 outbound-interface dum998 action drop')
    config.set('set firewall ipv4 output raw rule 12 outbound-interface dum998 action continue')
    config.set('set firewall ipv4 output raw rule 13 outbound-interface dum998 action return')
    config.set('set firewall ipv4 output raw rule 14 outbound-interface dum998 action reject')
    config.set('set firewall ipv4 output raw rule 10 notrack')

    config.commit()

    assert_firewall_rule('ipv4_output_raw', 10, 'accept', 'dum998')
    assert_firewall_rule('ipv4_output_raw', 11, 'drop', 'dum998')
    assert_firewall_rule('ipv4_output_raw', 12, 'continue', 'dum998')
    assert_firewall_rule('ipv4_output_raw', 13, 'return', 'dum998')
    assert_firewall_rule('ipv4_output_raw', 14, 'reject', 'dum998')
    assert_firewall_rule('ipv4_output_raw', 10, 'notrack')
    assert_firewall_rule('ipv4_output_raw', 'default', 'accept')

    # A hooked dispatch chain must use the requested priority, not just its name.
    assert_firewall_object('chain', 'output_raw', 'hook output', 'priority raw|-300')


def test_ipv6_input_filter_actions(config):
    """Install each hook and its verdicts; restrict all packet effects to dummy links."""
    config.set('set firewall ipv6 input filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv6 input filter rule 11 inbound-interface dum998 action drop')
    config.set('set firewall ipv6 input filter rule 12 inbound-interface dum998 action continue')
    config.set('set firewall ipv6 input filter rule 13 inbound-interface dum998 action return')
    config.set('set firewall ipv6 input filter rule 14 inbound-interface dum998 action reject')

    config.commit()

    assert_firewall_rule('ipv6_input', 10, 'accept', 'dum998')
    assert_firewall_rule('ipv6_input', 11, 'drop', 'dum998')
    assert_firewall_rule('ipv6_input', 12, 'continue', 'dum998')
    assert_firewall_rule('ipv6_input', 13, 'return', 'dum998')
    assert_firewall_rule('ipv6_input', 14, 'reject', 'dum998')
    assert_firewall_rule('ipv6_input', 'default', 'accept')

    # A hooked dispatch chain must use the requested priority, not just its name.
    assert_firewall_object('chain', 'input', 'hook input', 'priority filter|0')


def test_ipv6_forward_filter_actions(config):
    """Install each hook and its verdicts; restrict all packet effects to dummy links."""
    config.set('set firewall ipv6 forward filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv6 forward filter rule 11 inbound-interface dum998 action drop')
    config.set('set firewall ipv6 forward filter rule 12 inbound-interface dum998 action continue')
    config.set('set firewall ipv6 forward filter rule 13 inbound-interface dum998 action return')
    config.set('set firewall ipv6 forward filter rule 14 inbound-interface dum998 action reject')

    config.commit()

    assert_firewall_rule('ipv6_forward', 10, 'accept', 'dum998')
    assert_firewall_rule('ipv6_forward', 11, 'drop', 'dum998')
    assert_firewall_rule('ipv6_forward', 12, 'continue', 'dum998')
    assert_firewall_rule('ipv6_forward', 13, 'return', 'dum998')
    assert_firewall_rule('ipv6_forward', 14, 'reject', 'dum998')
    assert_firewall_rule('ipv6_forward', 'default', 'accept')

    # A hooked dispatch chain must use the requested priority, not just its name.
    assert_firewall_object('chain', 'forward', 'hook forward', 'priority filter|0')


def test_ipv6_output_filter_actions(config):
    """Install each hook and its verdicts; restrict all packet effects to dummy links."""
    config.set('set firewall ipv6 output filter rule 10 outbound-interface dum998 action accept')
    config.set('set firewall ipv6 output filter rule 11 outbound-interface dum998 action drop')
    config.set('set firewall ipv6 output filter rule 12 outbound-interface dum998 action continue')
    config.set('set firewall ipv6 output filter rule 13 outbound-interface dum998 action return')
    config.set('set firewall ipv6 output filter rule 14 outbound-interface dum998 action reject')

    config.commit()

    assert_firewall_rule('ipv6_output', 10, 'accept', 'dum998')
    assert_firewall_rule('ipv6_output', 11, 'drop', 'dum998')
    assert_firewall_rule('ipv6_output', 12, 'continue', 'dum998')
    assert_firewall_rule('ipv6_output', 13, 'return', 'dum998')
    assert_firewall_rule('ipv6_output', 14, 'reject', 'dum998')
    assert_firewall_rule('ipv6_output', 'default', 'accept')

    # A hooked dispatch chain must use the requested priority, not just its name.
    assert_firewall_object('chain', 'output', 'hook output', 'priority filter|0')


def test_ipv6_prerouting_raw_actions(config):
    """Install each hook and its verdicts; restrict all packet effects to dummy links."""
    config.set('set firewall ipv6 prerouting raw rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv6 prerouting raw rule 11 inbound-interface dum998 action drop')
    config.set('set firewall ipv6 prerouting raw rule 12 inbound-interface dum998 action continue')
    config.set('set firewall ipv6 prerouting raw rule 13 inbound-interface dum998 action return')
    config.set('set firewall ipv6 prerouting raw rule 14 inbound-interface dum998 action reject')
    config.set('set firewall ipv6 prerouting raw rule 10 notrack')

    config.commit()

    assert_firewall_rule('ipv6_prerouting', 10, 'accept', 'dum998')
    assert_firewall_rule('ipv6_prerouting', 11, 'drop', 'dum998')
    assert_firewall_rule('ipv6_prerouting', 12, 'continue', 'dum998')
    assert_firewall_rule('ipv6_prerouting', 13, 'return', 'dum998')
    assert_firewall_rule('ipv6_prerouting', 14, 'reject', 'dum998')
    assert_firewall_rule('ipv6_prerouting', 10, 'notrack')
    assert_firewall_rule('ipv6_prerouting', 'default', 'accept')

    # A hooked dispatch chain must use the requested priority, not just its name.
    assert_firewall_object('chain', 'prerouting', 'hook prerouting', 'priority raw|-300')


def test_ipv6_output_raw_actions(config):
    """Install each hook and its verdicts; restrict all packet effects to dummy links."""
    config.set('set firewall ipv6 output raw rule 10 outbound-interface dum998 action accept')
    config.set('set firewall ipv6 output raw rule 11 outbound-interface dum998 action drop')
    config.set('set firewall ipv6 output raw rule 12 outbound-interface dum998 action continue')
    config.set('set firewall ipv6 output raw rule 13 outbound-interface dum998 action return')
    config.set('set firewall ipv6 output raw rule 14 outbound-interface dum998 action reject')
    config.set('set firewall ipv6 output raw rule 10 notrack')

    config.commit()

    assert_firewall_rule('ipv6_output_raw', 10, 'accept', 'dum998')
    assert_firewall_rule('ipv6_output_raw', 11, 'drop', 'dum998')
    assert_firewall_rule('ipv6_output_raw', 12, 'continue', 'dum998')
    assert_firewall_rule('ipv6_output_raw', 13, 'return', 'dum998')
    assert_firewall_rule('ipv6_output_raw', 14, 'reject', 'dum998')
    assert_firewall_rule('ipv6_output_raw', 10, 'notrack')
    assert_firewall_rule('ipv6_output_raw', 'default', 'accept')

    # A hooked dispatch chain must use the requested priority, not just its name.
    assert_firewall_object('chain', 'output_raw', 'hook output', 'priority raw|-300')


def test_ipv4_protocol_tcp(config):
    """Install IPv4 protocol tcp and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol tcp')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, '(meta l4proto|ip protocol|ip6 nexthdr).*tcp', 'accept')


def test_ipv4_protocol_not_udp(config):
    """Install IPv4 protocol not udp and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol not udp')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, '(l4proto|protocol|nexthdr) !=.*udp', 'accept')


def test_ipv4_packet_mark_42(config):
    """Install IPv4 packet mark 42 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept packet-mark 42')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'meta mark.*(0x0*2a|42)', 'accept')


def test_ipv4_packet_mark_10_20(config):
    """Install IPv4 packet mark 10 20 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept packet-mark 10-20')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'meta mark.*(0x0*a|10)-(0x0*14|20)', 'accept')


def test_ipv4_packet_mark_not_42(config):
    """Install IPv4 packet mark not 42 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept packet-mark not 42')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'meta mark !=', 'accept')


def test_ipv4_dscp_8_16(config):
    """Install IPv4 dscp 8 16 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept dscp 8-16')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'dscp.*(cs1|0x08|8).*(cs2|0x10|16)', 'accept')


def test_ipv4_dscp_not_8(config):
    """Install IPv4 dscp not 8 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept dscp not 8')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'dscp !=', 'accept')


def test_ipv4_protocol_tcp_tcp_mss_1200_1400(config):
    """Install IPv4 protocol tcp tcp mss 1200 1400 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol tcp tcp-mss 1200-1400')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'tcp option maxseg size.*1200-1400', 'accept')


def test_ipv4_protocol_tcp_tcp_mss_not_1460(config):
    """Install IPv4 protocol tcp tcp mss not 1460 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol tcp tcp-mss not 1460')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'tcp option maxseg size !=.*1460', 'accept')


def test_ipv4_protocol_tcp_tcp_flags_syn_and_not_ack_and_not_fin_and_not_rst(config):
    """Install IPv4 protocol tcp tcp flags syn and not ack and not fin and not rst and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol tcp tcp-flags syn and not ack and not fin and not rst')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'tcp flags.*syn', 'accept')


def test_ipv4_packet_length_64_1500(config):
    """Install IPv4 packet length 64 1500 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept packet-length 64-1500')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'meta length.*64-1500', 'accept')


def test_ipv4_packet_length_not_100(config):
    """Install IPv4 packet length not 100 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept packet-length not 100')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'meta length !=.*100', 'accept')


def test_ipv4_source_mac_02_00_00_00_00_01(config):
    """Install IPv4 source mac 02 00 00 00 00 01 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept source-mac 02:00:00:00:00:01')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ether saddr.*02:00:00:00:00:01', 'accept')


def test_ipv4_destination_mac_02_00_00_00_00_02(config):
    """Install IPv4 destination mac 02 00 00 00 00 02 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept destination-mac 02:00:00:00:00:02')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ether daddr.*02:00:00:00:00:02', 'accept')


def test_ipv4_source_mac_not_02_00_00_00_00_01(config):
    """Install IPv4 source mac not 02 00 00 00 00 01 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept source-mac not 02:00:00:00:00:01')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ether saddr !=', 'accept')


def test_ipv4_destination_mac_02_00_00_00_00_02_mask_ff_ff_ff_00_00_00(config):
    """Install IPv4 destination mac 02 00 00 00 00 02 mask ff ff ff 00 00 00 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept destination-mac 02:00:00:00:00:02 mask ff:ff:ff:00:00:00')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ether daddr & ff:ff:ff:00:00:00', 'accept')


def test_ipv4_inbound_interface_dum998(config):
    """Install IPv4 inbound interface dum998 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept inbound-interface dum998')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'iifname.*"dum998"', 'accept')


def test_ipv4_outbound_interface_not_dum999(config):
    """Install IPv4 outbound interface not dum999 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept outbound-interface not dum999')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'oifname !=.*"dum999"', 'accept')


def test_ipv4_protocol_tcp_source_port_53098(config):
    """Install IPv4 protocol tcp source port 53098 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol tcp source-port 53098')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'tcp sport.*53098', 'accept')


def test_ipv4_protocol_udp_destination_port_53098_53100(config):
    """Install IPv4 protocol udp destination port 53098 53100 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol udp destination-port 53098-53100')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'udp dport.*53098-53100', 'accept')


def test_ipv4_protocol_tcp_destination_port_not_53098(config):
    """Install IPv4 protocol tcp destination port not 53098 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol tcp destination-port not 53098')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'tcp dport !=.*53098', 'accept')


def test_ipv4_ttl_eq_64(config):
    """Install IPv4 ttl eq 64 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept ttl eq 64')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, '(ttl|hoplimit).*64', 'accept')


def test_ipv4_ttl_eq_not_64(config):
    """Install IPv4 ttl eq not 64 and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept ttl eq not 64')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, '(ttl|hoplimit) != 64', 'accept')


def test_ipv4_packet_type_host(config):
    """Install IPv4 packet type host and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept packet-type host')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'pkttype host', 'accept')


def test_ipv4_packet_type_not_multicast(config):
    """Install IPv4 packet type not multicast and check its native packet expression."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept packet-type not multicast')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'pkttype != multicast', 'accept')


def test_ipv6_protocol_tcp(config):
    """Install IPv6 protocol tcp and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept protocol tcp')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, '(meta l4proto|ip protocol|ip6 nexthdr).*tcp', 'accept')


def test_ipv6_protocol_not_udp(config):
    """Install IPv6 protocol not udp and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept protocol not udp')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, '(l4proto|protocol|nexthdr) !=.*udp', 'accept')


def test_ipv6_packet_mark_42(config):
    """Install IPv6 packet mark 42 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept packet-mark 42')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'meta mark.*(0x0*2a|42)', 'accept')


def test_ipv6_packet_mark_10_20(config):
    """Install IPv6 packet mark 10 20 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept packet-mark 10-20')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'meta mark.*(0x0*a|10)-(0x0*14|20)', 'accept')


def test_ipv6_packet_mark_not_42(config):
    """Install IPv6 packet mark not 42 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept packet-mark not 42')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'meta mark !=', 'accept')


def test_ipv6_dscp_8_16(config):
    """Install IPv6 dscp 8 16 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept dscp 8-16')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'dscp.*(cs1|0x08|8).*(cs2|0x10|16)', 'accept')


def test_ipv6_dscp_not_8(config):
    """Install IPv6 dscp not 8 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept dscp not 8')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'dscp !=', 'accept')


def test_ipv6_protocol_tcp_tcp_mss_1200_1400(config):
    """Install IPv6 protocol tcp tcp mss 1200 1400 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept protocol tcp tcp-mss 1200-1400')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'tcp option maxseg size.*1200-1400', 'accept')


def test_ipv6_protocol_tcp_tcp_mss_not_1460(config):
    """Install IPv6 protocol tcp tcp mss not 1460 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept protocol tcp tcp-mss not 1460')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'tcp option maxseg size !=.*1460', 'accept')


def test_ipv6_protocol_tcp_tcp_flags_syn_and_not_ack_and_not_fin_and_not_rst(config):
    """Install IPv6 protocol tcp tcp flags syn and not ack and not fin and not rst and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept protocol tcp tcp-flags syn and not ack and not fin and not rst')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'tcp flags.*syn', 'accept')


def test_ipv6_packet_length_64_1500(config):
    """Install IPv6 packet length 64 1500 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept packet-length 64-1500')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'meta length.*64-1500', 'accept')


def test_ipv6_packet_length_not_100(config):
    """Install IPv6 packet length not 100 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept packet-length not 100')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'meta length !=.*100', 'accept')


def test_ipv6_source_mac_02_00_00_00_00_01(config):
    """Install IPv6 source mac 02 00 00 00 00 01 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept source-mac 02:00:00:00:00:01')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ether saddr.*02:00:00:00:00:01', 'accept')


def test_ipv6_destination_mac_02_00_00_00_00_02(config):
    """Install IPv6 destination mac 02 00 00 00 00 02 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept destination-mac 02:00:00:00:00:02')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ether daddr.*02:00:00:00:00:02', 'accept')


def test_ipv6_source_mac_not_02_00_00_00_00_01(config):
    """Install IPv6 source mac not 02 00 00 00 00 01 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept source-mac not 02:00:00:00:00:01')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ether saddr !=', 'accept')


def test_ipv6_destination_mac_02_00_00_00_00_02_mask_ff_ff_ff_00_00_00(config):
    """Install IPv6 destination mac 02 00 00 00 00 02 mask ff ff ff 00 00 00 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept destination-mac 02:00:00:00:00:02 mask ff:ff:ff:00:00:00')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ether daddr & ff:ff:ff:00:00:00', 'accept')


def test_ipv6_inbound_interface_dum998(config):
    """Install IPv6 inbound interface dum998 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept inbound-interface dum998')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'iifname.*"dum998"', 'accept')


def test_ipv6_outbound_interface_not_dum999(config):
    """Install IPv6 outbound interface not dum999 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept outbound-interface not dum999')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'oifname !=.*"dum999"', 'accept')


def test_ipv6_protocol_tcp_source_port_53098(config):
    """Install IPv6 protocol tcp source port 53098 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept protocol tcp source-port 53098')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'tcp sport.*53098', 'accept')


def test_ipv6_protocol_udp_destination_port_53098_53100(config):
    """Install IPv6 protocol udp destination port 53098 53100 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept protocol udp destination-port 53098-53100')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'udp dport.*53098-53100', 'accept')


def test_ipv6_protocol_tcp_destination_port_not_53098(config):
    """Install IPv6 protocol tcp destination port not 53098 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept protocol tcp destination-port not 53098')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'tcp dport !=.*53098', 'accept')


def test_ipv6_ttl_eq_64(config):
    """Install IPv6 ttl eq 64 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept ttl eq 64')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, '(ttl|hoplimit).*64', 'accept')


def test_ipv6_ttl_eq_not_64(config):
    """Install IPv6 ttl eq not 64 and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept ttl eq not 64')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, '(ttl|hoplimit) != 64', 'accept')


def test_ipv6_packet_type_host(config):
    """Install IPv6 packet type host and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept packet-type host')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'pkttype host', 'accept')


def test_ipv6_packet_type_not_multicast(config):
    """Install IPv6 packet type not multicast and check its native packet expression."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept packet-type not multicast')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'pkttype != multicast', 'accept')


def test_addresses_multi_masks_and_delete_one_negative_ipv4_source(config):
    """Multiple exclusions remain independent; deleting one must not delete its siblings."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept')
    config.set('set firewall ipv4 name SMOKE rule 10 source-address 192.0.2.1')
    config.set('set firewall ipv4 name SMOKE rule 10 source-address 198.51.100.1')
    config.set('set firewall ipv4 name SMOKE rule 10 source-address not 192.0.2.1')
    config.set('set firewall ipv4 name SMOKE rule 10 source-address not 198.51.100.1')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ip saddr', '!=', '192.0.2.1', '198.51.100.1')
    config.delete('delete firewall ipv4 name SMOKE rule 10 source-address not 198.51.100.1')

    config.commit()
    rule = assert_firewall_rule('ipv4_name_SMOKE', 10, '!=')

    assert_in('ip saddr != 192.0.2.1', rule)
    config.delete('delete firewall ipv4 name SMOKE rule 10 source-address')
    config.set('set firewall ipv4 name SMOKE rule 10 source-address 192.0.2.1 mask 255.0.255.0')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ip saddr & 255.0.255.0')


def test_addresses_multi_masks_and_delete_one_negative_ipv4_destination(config):
    """Multiple exclusions remain independent; deleting one must not delete its siblings."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept')
    config.set('set firewall ipv4 name SMOKE rule 10 destination-address 192.0.2.1')
    config.set('set firewall ipv4 name SMOKE rule 10 destination-address 198.51.100.1')
    config.set('set firewall ipv4 name SMOKE rule 10 destination-address not 192.0.2.1')
    config.set('set firewall ipv4 name SMOKE rule 10 destination-address not 198.51.100.1')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ip daddr', '!=', '192.0.2.1', '198.51.100.1')
    config.delete('delete firewall ipv4 name SMOKE rule 10 destination-address not 198.51.100.1')

    config.commit()
    rule = assert_firewall_rule('ipv4_name_SMOKE', 10, '!=')

    assert_in('ip daddr != 192.0.2.1', rule)
    config.delete('delete firewall ipv4 name SMOKE rule 10 destination-address')
    config.set('set firewall ipv4 name SMOKE rule 10 destination-address 192.0.2.1 mask 255.0.255.0')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ip daddr & 255.0.255.0')


def test_addresses_multi_masks_and_delete_one_negative_ipv6_source(config):
    """Multiple exclusions remain independent; deleting one must not delete its siblings."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept')
    config.set('set firewall ipv6 name SMOKE rule 10 source-address 2001:db8:1::1')
    config.set('set firewall ipv6 name SMOKE rule 10 source-address 2001:db8:2::1')
    config.set('set firewall ipv6 name SMOKE rule 10 source-address not 2001:db8:1::1')
    config.set('set firewall ipv6 name SMOKE rule 10 source-address not 2001:db8:2::1')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ip6 saddr', '!=', '2001:db8:1::1', '2001:db8:2::1')
    config.delete('delete firewall ipv6 name SMOKE rule 10 source-address not 2001:db8:2::1')

    config.commit()
    rule = assert_firewall_rule('ipv6_name_SMOKE', 10, '!=')

    assert_in('ip6 saddr != 2001:db8:1::1', rule)
    config.delete('delete firewall ipv6 name SMOKE rule 10 source-address')
    config.set('set firewall ipv6 name SMOKE rule 10 source-address 2001:db8:1::1 mask ffff:0:ffff::ffff')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ip6 saddr & ffff:0:ffff::ffff')


def test_addresses_multi_masks_and_delete_one_negative_ipv6_destination(config):
    """Multiple exclusions remain independent; deleting one must not delete its siblings."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept')
    config.set('set firewall ipv6 name SMOKE rule 10 destination-address 2001:db8:1::1')
    config.set('set firewall ipv6 name SMOKE rule 10 destination-address 2001:db8:2::1')
    config.set('set firewall ipv6 name SMOKE rule 10 destination-address not 2001:db8:1::1')
    config.set('set firewall ipv6 name SMOKE rule 10 destination-address not 2001:db8:2::1')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ip6 daddr', '!=', '2001:db8:1::1', '2001:db8:2::1')
    config.delete('delete firewall ipv6 name SMOKE rule 10 destination-address not 2001:db8:2::1')

    config.commit()
    rule = assert_firewall_rule('ipv6_name_SMOKE', 10, '!=')

    assert_in('ip6 daddr != 2001:db8:1::1', rule)
    config.delete('delete firewall ipv6 name SMOKE rule 10 destination-address')
    config.set('set firewall ipv6 name SMOKE rule 10 destination-address 2001:db8:1::1 mask ffff:0:ffff::ffff')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'ip6 daddr & ffff:0:ffff::ffff')


def test_icmp_types_codes_and_groups_ipv4(config):
    """Named types, multi codes/ranges and both ICMP group modes remain separate pairs."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol icmp icmp-type echo-request')
    config.set('set firewall ipv4 name SMOKE rule 10 icmp-type echo-reply')
    config.set('set firewall ipv4 name SMOKE rule 20 action accept protocol icmp icmp-type destination-unreachable icmp-code 0')
    config.set('set firewall group icmp-group ipv4 TYPES match type')
    config.set('set firewall group icmp-group ipv4 TYPES type echo-request')
    config.set('set firewall group icmp-group ipv4 PAIRS match type-code')
    config.set('set firewall group icmp-group ipv4 PAIRS type destination-unreachable code 0')
    config.set('set firewall group icmp-group ipv4 PAIRS type destination-unreachable code 3')
    config.set('set firewall group icmp-group ipv4 PAIRS counter')
    config.set('set firewall group icmp-group ipv4 PAIRS last-used')
    config.set('set firewall ipv4 name SMOKE rule 30 action accept protocol icmp icmp-group TYPES')
    config.set('set firewall ipv4 name SMOKE rule 40 action drop protocol icmp icmp-group not PAIRS')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'echo-request', 'echo-reply')
    assert_firewall_rule('ipv4_name_SMOKE', 20, 'destination-unreachable', 'code')
    assert_firewall_rule('ipv4_name_SMOKE', 40, '!= @ipv4_icmp_group_PAIRS')
    assert_firewall_object('set', 'ipv4_icmp_group_PAIRS', 'destination-unreachable \\. 0', 'destination-unreachable \\. 3', 'counter', 'last')


def test_icmp_types_codes_and_groups_ipv6(config):
    """Named types, multi codes/ranges and both ICMP group modes remain separate pairs."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept protocol ipv6-icmp icmp-type echo-request')
    config.set('set firewall ipv6 name SMOKE rule 10 icmp-type echo-reply')
    config.set('set firewall ipv6 name SMOKE rule 20 action accept protocol ipv6-icmp icmp-type destination-unreachable icmp-code 0')
    config.set('set firewall group icmp-group ipv6 TYPES match type')
    config.set('set firewall group icmp-group ipv6 TYPES type echo-request')
    config.set('set firewall group icmp-group ipv6 PAIRS match type-code')
    config.set('set firewall group icmp-group ipv6 PAIRS type destination-unreachable code 0')
    config.set('set firewall group icmp-group ipv6 PAIRS type destination-unreachable code 3')
    config.set('set firewall group icmp-group ipv6 PAIRS counter')
    config.set('set firewall group icmp-group ipv6 PAIRS last-used')
    config.set('set firewall ipv6 name SMOKE rule 30 action accept protocol ipv6-icmp icmp-group TYPES')
    config.set('set firewall ipv6 name SMOKE rule 40 action drop protocol ipv6-icmp icmp-group not PAIRS')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'echo-request', 'echo-reply')
    assert_firewall_rule('ipv6_name_SMOKE', 20, 'destination-unreachable', 'code')
    assert_firewall_rule('ipv6_name_SMOKE', 40, '!= @ipv6_icmp_group_PAIRS')
    assert_firewall_object('set', 'ipv6_icmp_group_PAIRS', 'destination-unreachable \\. 0', 'destination-unreachable \\. 3', 'counter', 'last')


def test_fib_ipv4_source_address_outbound_interface_exists(config):
    """Route lookups preserve selected packet inputs and explicit result type."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv4 forward filter rule 10 fib lookup source-address')
    config.set('set firewall ipv4 forward filter rule 10 fib result outbound-interface exists')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'fib saddr (oif exists|check exists)')


def test_fib_ipv4_source_address_inbound_interface_outbound_interface_missing(config):
    """Route lookups preserve selected packet inputs and explicit result type."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv4 forward filter rule 10 fib lookup source-address inbound-interface')
    config.set('set firewall ipv4 forward filter rule 10 fib result outbound-interface missing')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'fib saddr \\. iif (oif missing|check missing)')


def test_fib_ipv4_destination_address_packet_mark_route_type_local(config):
    """Route lookups preserve selected packet inputs and explicit result type."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv4 forward filter rule 10 fib lookup destination-address packet-mark')
    config.set('set firewall ipv4 forward filter rule 10 fib result route-type local')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'fib daddr \\. mark type local')


def test_fib_ipv4_destination_address_outbound_interface_route_type_not_unicast(config):
    """Route lookups preserve selected packet inputs and explicit result type."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv4 forward filter rule 10 fib lookup destination-address outbound-interface')
    config.set('set firewall ipv4 forward filter rule 10 fib result route-type not unicast')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'fib daddr \\. oif type != unicast')


def test_fib_ipv4_source_address_outbound_interface_dum998(config):
    """Route lookups preserve selected packet inputs and explicit result type."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv4 forward filter rule 10 fib lookup source-address')
    config.set('set firewall ipv4 forward filter rule 10 fib result outbound-interface dum998')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'fib saddr oifname "dum998"')


def test_fib_ipv6_source_address_outbound_interface_exists(config):
    """Route lookups preserve selected packet inputs and explicit result type."""
    config.set('set firewall ipv6 forward filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv6 forward filter rule 10 fib lookup source-address')
    config.set('set firewall ipv6 forward filter rule 10 fib result outbound-interface exists')

    config.commit()

    assert_firewall_rule('ipv6_forward', 10, 'fib saddr (oif exists|check exists)')


def test_fib_ipv6_source_address_inbound_interface_outbound_interface_missing(config):
    """Route lookups preserve selected packet inputs and explicit result type."""
    config.set('set firewall ipv6 forward filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv6 forward filter rule 10 fib lookup source-address inbound-interface')
    config.set('set firewall ipv6 forward filter rule 10 fib result outbound-interface missing')

    config.commit()

    assert_firewall_rule('ipv6_forward', 10, 'fib saddr \\. iif (oif missing|check missing)')


def test_fib_ipv6_destination_address_packet_mark_route_type_local(config):
    """Route lookups preserve selected packet inputs and explicit result type."""
    config.set('set firewall ipv6 forward filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv6 forward filter rule 10 fib lookup destination-address packet-mark')
    config.set('set firewall ipv6 forward filter rule 10 fib result route-type local')

    config.commit()

    assert_firewall_rule('ipv6_forward', 10, 'fib daddr \\. mark type local')


def test_fib_ipv6_destination_address_outbound_interface_route_type_not_unicast(config):
    """Route lookups preserve selected packet inputs and explicit result type."""
    config.set('set firewall ipv6 forward filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv6 forward filter rule 10 fib lookup destination-address outbound-interface')
    config.set('set firewall ipv6 forward filter rule 10 fib result route-type not unicast')

    config.commit()

    assert_firewall_rule('ipv6_forward', 10, 'fib daddr \\. oif type != unicast')


def test_fib_ipv6_source_address_outbound_interface_dum998(config):
    """Route lookups preserve selected packet inputs and explicit result type."""
    config.set('set firewall ipv6 forward filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv6 forward filter rule 10 fib lookup source-address')
    config.set('set firewall ipv6 forward filter rule 10 fib result outbound-interface dum998')

    config.commit()

    assert_firewall_rule('ipv6_forward', 10, 'fib saddr oifname "dum998"')


def test_reject_responses_ipv4_port_unreachable(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv4 name SMOKE rule 10 action reject protocol tcp reject-response port-unreachable')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'reject')


def test_reject_responses_ipv4_admin_prohibited(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv4 name SMOKE rule 10 action reject protocol tcp reject-response admin-prohibited')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv4_no_route(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv4 name SMOKE rule 10 action reject protocol tcp reject-response no-route')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv4_host_unreachable(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv4 name SMOKE rule 10 action reject protocol tcp reject-response host-unreachable')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv4_tcp_reset(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv4 name SMOKE rule 10 action reject protocol tcp reject-response tcp-reset')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'reject with tcp reset')


def test_reject_responses_ipv4_net_unreachable(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv4 name SMOKE rule 10 action reject protocol tcp reject-response net-unreachable')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv4_prot_unreachable(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv4 name SMOKE rule 10 action reject protocol tcp reject-response prot-unreachable')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv4_frag_needed(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv4 name SMOKE rule 10 action reject protocol tcp reject-response frag-needed')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv4_net_prohibited(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv4 name SMOKE rule 10 action reject protocol tcp reject-response net-prohibited')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv4_host_prohibited(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv4 name SMOKE rule 10 action reject protocol tcp reject-response host-prohibited')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv6_port_unreachable(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv6 name SMOKE rule 10 action reject protocol tcp reject-response port-unreachable')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'reject')


def test_reject_responses_ipv6_admin_prohibited(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv6 name SMOKE rule 10 action reject protocol tcp reject-response admin-prohibited')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv6_no_route(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv6 name SMOKE rule 10 action reject protocol tcp reject-response no-route')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv6_host_unreachable(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv6 name SMOKE rule 10 action reject protocol tcp reject-response host-unreachable')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv6_tcp_reset(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv6 name SMOKE rule 10 action reject protocol tcp reject-response tcp-reset')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'reject with tcp reset')


def test_reject_responses_ipv6_addr_unreachable(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv6 name SMOKE rule 10 action reject protocol tcp reject-response addr-unreachable')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv6_policy_fail(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv6 name SMOKE rule 10 action reject protocol tcp reject-response policy-fail')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'reject with icmp')


def test_reject_responses_ipv6_reject_route(config):
    """Every advertised reject response loads into a real, unreferenced named chain."""
    config.set('set firewall ipv6 name SMOKE rule 10 action reject protocol tcp reject-response reject-route')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'reject with icmp')


def test_logging_levels_and_flags_emerg(config):
    """Logging remains a statement before the verdict, with all supported diagnostic flags."""
    config.set('set firewall ipv4 name SMOKE rule 10 action drop protocol tcp log level emerg')
    config.set('set firewall ipv4 name SMOKE rule 10 log flags tcp-sequence and tcp-options and ip-options and skuid and ether')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'log prefix', 'flags', 'drop')
    assert_firewall_rule('ipv4_name_SMOKE', 10, 'level emerg')


def test_logging_levels_and_flags_alert(config):
    """Logging remains a statement before the verdict, with all supported diagnostic flags."""
    config.set('set firewall ipv4 name SMOKE rule 10 action drop protocol tcp log level alert')
    config.set('set firewall ipv4 name SMOKE rule 10 log flags tcp-sequence and tcp-options and ip-options and skuid and ether')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'log prefix', 'flags', 'drop')
    assert_firewall_rule('ipv4_name_SMOKE', 10, 'level alert')


def test_logging_levels_and_flags_crit(config):
    """Logging remains a statement before the verdict, with all supported diagnostic flags."""
    config.set('set firewall ipv4 name SMOKE rule 10 action drop protocol tcp log level crit')
    config.set('set firewall ipv4 name SMOKE rule 10 log flags tcp-sequence and tcp-options and ip-options and skuid and ether')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'log prefix', 'flags', 'drop')
    assert_firewall_rule('ipv4_name_SMOKE', 10, 'level crit')


def test_logging_levels_and_flags_err(config):
    """Logging remains a statement before the verdict, with all supported diagnostic flags."""
    config.set('set firewall ipv4 name SMOKE rule 10 action drop protocol tcp log level err')
    config.set('set firewall ipv4 name SMOKE rule 10 log flags tcp-sequence and tcp-options and ip-options and skuid and ether')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'log prefix', 'flags', 'drop')
    assert_firewall_rule('ipv4_name_SMOKE', 10, 'level err')


def test_logging_levels_and_flags_warn(config):
    """Logging remains a statement before the verdict, with all supported diagnostic flags."""
    config.set('set firewall ipv4 name SMOKE rule 10 action drop protocol tcp log level warn')
    config.set('set firewall ipv4 name SMOKE rule 10 log flags tcp-sequence and tcp-options and ip-options and skuid and ether')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'log prefix', 'flags', 'drop')


def test_logging_levels_and_flags_notice(config):
    """Logging remains a statement before the verdict, with all supported diagnostic flags."""
    config.set('set firewall ipv4 name SMOKE rule 10 action drop protocol tcp log level notice')
    config.set('set firewall ipv4 name SMOKE rule 10 log flags tcp-sequence and tcp-options and ip-options and skuid and ether')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'log prefix', 'flags', 'drop')
    assert_firewall_rule('ipv4_name_SMOKE', 10, 'level notice')


def test_logging_levels_and_flags_info(config):
    """Logging remains a statement before the verdict, with all supported diagnostic flags."""
    config.set('set firewall ipv4 name SMOKE rule 10 action drop protocol tcp log level info')
    config.set('set firewall ipv4 name SMOKE rule 10 log flags tcp-sequence and tcp-options and ip-options and skuid and ether')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'log prefix', 'flags', 'drop')
    assert_firewall_rule('ipv4_name_SMOKE', 10, 'level info')


def test_logging_levels_and_flags_debug(config):
    """Logging remains a statement before the verdict, with all supported diagnostic flags."""
    config.set('set firewall ipv4 name SMOKE rule 10 action drop protocol tcp log level debug')
    config.set('set firewall ipv4 name SMOKE rule 10 log flags tcp-sequence and tcp-options and ip-options and skuid and ether')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'log prefix', 'flags', 'drop')
    assert_firewall_rule('ipv4_name_SMOKE', 10, 'level debug')


def test_logging_all_flags(config):
    """The shorthand all option survives native generation without altering the verdict."""
    config.set('set firewall ipv4 name SMOKE rule 10 action drop protocol tcp log flags all')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'flags all', 'drop')


def test_global_options_and_disabled_rules(config):
    """Global tracking/reject defaults are inherited; disabled rules disappear and can return."""
    config.set('set firewall global-options counter')
    config.set('set firewall global-options last-used')
    config.set('set firewall global-options reject-response admin-prohibited')
    config.set('set firewall global-options state-policy established action accept related action accept invalid action drop')
    config.set('set firewall ipv4 name SMOKE default-action reject')
    config.set('set firewall ipv4 name SMOKE rule 10 action reject description "smoke description"')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'counter', 'last', 'reject', 'smoke description')
    assert_firewall_rule('ipv4_name_SMOKE', 'default', 'reject')

    config.set('set firewall ipv4 name SMOKE rule 10 disable')

    config.commit()

    assert_firewall_rule_absent('ipv4_name_SMOKE', 10)
    config.delete('delete firewall ipv4 name SMOKE rule 10 disable')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'reject')

    # Activate a safe hook to check the generated global policy dispatch.
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept')

    config.commit()

    assert_firewall_object('chain', 'forward', 'established.*accept', 'related.*accept', 'invalid.*drop')


def test_flowtable_ipv4(config):
    """Software flow enrollment continues evaluation rather than implicitly accepting."""
    config.set('set firewall flowtable SMOKE interface dum998 interface dum999 offload software')
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action offload offload-target SMOKE')

    config.commit()

    assert_firewall_object('flowtable', 'flowtable_SMOKE', 'hook ingress', 'dum998', 'dum999')
    assert_firewall_rule('ipv4_forward', 10, 'flow add @flowtable_SMOKE', absent=['accept'])


def test_flowtable_ipv6(config):
    """Software flow enrollment continues evaluation rather than implicitly accepting."""
    config.set('set firewall flowtable SMOKE interface dum998 interface dum999 offload software')
    config.set('set firewall ipv6 forward filter rule 10 inbound-interface dum998 action offload offload-target SMOKE')

    config.commit()

    assert_firewall_object('flowtable', 'flowtable_SMOKE', 'hook ingress', 'dum998', 'dum999')
    assert_firewall_rule('ipv6_forward', 10, 'flow add @flowtable_SMOKE', absent=['accept'])


def test_rate_connection_and_shared_limits_ipv4(config):
    """Inline and named rate buckets support byte/packet units, subnet keys and connection counts."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit rate bytes 1g/s')
    config.set('set firewall ipv4 name SMOKE rule 10 limit burst bytes 64k over')
    config.set('set firewall ipv4 name SMOKE rule 20 action accept limit rate packets 10/s')
    config.set('set firewall ipv4 name SMOKE rule 20 limit per source-address and destination-address size 128 timeout 1m')
    config.set('set firewall ipv4 name SMOKE rule 20 limit source-prefix-length 24 destination-prefix-length 16')
    config.set('set firewall ipv4 name SMOKE rule 30 action drop connection limit over 2 per source-address size 128')
    config.set('set firewall group limit-group ipv4 SHARED rate packets 10/s burst packets 5')
    config.set('set firewall ipv4 name SMOKE rule 40 action accept limit group SHARED')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'limit rate over 1024 mbytes/second', 'burst 64 kbytes')
    assert_firewall_rule('ipv4_name_SMOKE', 20, 'update @', '&')
    assert_firewall_rule('ipv4_name_SMOKE', 30, 'ct count over 2')
    assert_firewall_rule('ipv4_name_SMOKE', 40, 'limit name "ipv4_limit_group_SHARED"')


def test_rate_connection_and_shared_limits_ipv6(config):
    """Inline and named rate buckets support byte/packet units, subnet keys and connection counts."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept limit rate bytes 1g/s')
    config.set('set firewall ipv6 name SMOKE rule 10 limit burst bytes 64k over')
    config.set('set firewall ipv6 name SMOKE rule 20 action accept limit rate packets 10/s')
    config.set('set firewall ipv6 name SMOKE rule 20 limit per source-address and destination-address size 128 timeout 1m')
    config.set('set firewall ipv6 name SMOKE rule 20 limit source-prefix-length 24 destination-prefix-length 16')
    config.set('set firewall ipv6 name SMOKE rule 30 action drop connection limit over 2 per source-address size 128')
    config.set('set firewall group limit-group ipv6 SHARED rate packets 10/s burst packets 5')
    config.set('set firewall ipv6 name SMOKE rule 40 action accept limit group SHARED')

    config.commit()

    assert_firewall_rule('ipv6_name_SMOKE', 10, 'limit rate over 1024 mbytes/second', 'burst 64 kbytes')
    assert_firewall_rule('ipv6_name_SMOKE', 20, 'update @', '&')
    assert_firewall_rule('ipv6_name_SMOKE', 30, 'ct count over 2')
    assert_firewall_rule('ipv6_name_SMOKE', 40, 'limit name "ipv6_limit_group_SHARED"')


def test_limit_key_fields_source_address(config):
    """Every advertised per-key field supports both rate and connection allowances."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept limit rate packets 10/s per source-address')
    config.set('set firewall ipv4 forward filter rule 20 inbound-interface dum998 action drop connection limit over 5 per source-address')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'update @', 'limit rate 10/second')
    assert_firewall_rule('ipv4_forward', 20, 'add @', 'ct count over 5')


def test_limit_key_fields_destination_address(config):
    """Every advertised per-key field supports both rate and connection allowances."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept limit rate packets 10/s per destination-address')
    config.set('set firewall ipv4 forward filter rule 20 inbound-interface dum998 action drop connection limit over 5 per destination-address')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'update @', 'limit rate 10/second')
    assert_firewall_rule('ipv4_forward', 20, 'add @', 'ct count over 5')


def test_limit_key_fields_source_port(config):
    """Every advertised per-key field supports both rate and connection allowances."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept limit rate packets 10/s per source-port')
    config.set('set firewall ipv4 forward filter rule 20 inbound-interface dum998 action drop connection limit over 5 per source-port')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'update @', 'limit rate 10/second')
    assert_firewall_rule('ipv4_forward', 20, 'add @', 'ct count over 5')


def test_limit_key_fields_destination_port(config):
    """Every advertised per-key field supports both rate and connection allowances."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept limit rate packets 10/s per destination-port')
    config.set('set firewall ipv4 forward filter rule 20 inbound-interface dum998 action drop connection limit over 5 per destination-port')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'update @', 'limit rate 10/second')
    assert_firewall_rule('ipv4_forward', 20, 'add @', 'ct count over 5')


def test_limit_key_fields_protocol(config):
    """Every advertised per-key field supports both rate and connection allowances."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept limit rate packets 10/s per protocol')
    config.set('set firewall ipv4 forward filter rule 20 inbound-interface dum998 action drop connection limit over 5 per protocol')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'update @', 'limit rate 10/second')
    assert_firewall_rule('ipv4_forward', 20, 'add @', 'ct count over 5')


def test_limit_key_fields_inbound_interface(config):
    """Every advertised per-key field supports both rate and connection allowances."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept limit rate packets 10/s per inbound-interface')
    config.set('set firewall ipv4 forward filter rule 20 inbound-interface dum998 action drop connection limit over 5 per inbound-interface')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'update @', 'limit rate 10/second')
    assert_firewall_rule('ipv4_forward', 20, 'add @', 'ct count over 5')


def test_limit_key_fields_outbound_interface(config):
    """Every advertised per-key field supports both rate and connection allowances."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept limit rate packets 10/s per outbound-interface')
    config.set('set firewall ipv4 forward filter rule 20 inbound-interface dum998 action drop connection limit over 5 per outbound-interface')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'update @', 'limit rate 10/second')
    assert_firewall_rule('ipv4_forward', 20, 'add @', 'ct count over 5')


def test_limit_key_fields_source_mac(config):
    """Every advertised per-key field supports both rate and connection allowances."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept limit rate packets 10/s per source-mac')
    config.set('set firewall ipv4 forward filter rule 20 inbound-interface dum998 action drop connection limit over 5 per source-mac')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'update @', 'limit rate 10/second')
    assert_firewall_rule('ipv4_forward', 20, 'add @', 'ct count over 5')


def test_limit_key_fields_destination_mac(config):
    """Every advertised per-key field supports both rate and connection allowances."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept limit rate packets 10/s per destination-mac')
    config.set('set firewall ipv4 forward filter rule 20 inbound-interface dum998 action drop connection limit over 5 per destination-mac')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'update @', 'limit rate 10/second')
    assert_firewall_rule('ipv4_forward', 20, 'add @', 'ct count over 5')


def test_limit_key_fields_packet_mark(config):
    """Every advertised per-key field supports both rate and connection allowances."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept limit rate packets 10/s per packet-mark')
    config.set('set firewall ipv4 forward filter rule 20 inbound-interface dum998 action drop connection limit over 5 per packet-mark')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'update @', 'limit rate 10/second')
    assert_firewall_rule('ipv4_forward', 20, 'add @', 'ct count over 5')


def test_limit_key_fields_connection_mark(config):
    """Every advertised per-key field supports both rate and connection allowances."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept limit rate packets 10/s per connection-mark')
    config.set('set firewall ipv4 forward filter rule 20 inbound-interface dum998 action drop connection limit over 5 per connection-mark')

    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'update @', 'limit rate 10/second')
    assert_firewall_rule('ipv4_forward', 20, 'add @', 'ct count over 5')


def test_inline_quota_over(config):
    """Inline quota modes and short units appear in the installed statement."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept quota bytes 64k over')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'quota over 64 kbytes')


def test_inline_quota_until(config):
    """Inline quota modes and short units appear in the installed statement."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept quota bytes 64k until')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'quota 64 kbytes')


def test_scoped_operational_output(config):
    """Ordinary rule scope remains a table; detail, state policy and group views are callable."""
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action accept description "smoke rule"')
    config.set('set firewall global-options state-policy established action accept')

    config.commit()

    with closing(Client('/run/nvyr/configd.sock')) as client:
        table = client.request('execute', text='show firewall ipv4 forward filter rule 10')['text']

        assert_in('default', table)
        assert_in('smoke rule', table)
        detail = client.request('execute', text='show firewall ipv4 forward filter detail')['text']

        assert_in('Inbound interface', detail)
        policy = client.request('execute', text='show firewall state-policy')['text']

        assert_in('established', policy)
