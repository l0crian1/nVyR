"""Installed rule setters and verification through direct and nested callers."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from smoketests.assertions import assert_firewall_commit_rejected, assert_firewall_rule
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_modify_forward_ipv4(config):
    """IPv4 forwarding installs all five setters before continue."""
    config.set('set firewall ipv4 forward filter rule 10 protocol tcp tcp-flags syn action continue')
    config.set('set firewall ipv4 forward filter rule 10 modify packet-mark 0x20 connection-mark 0x40 dscp ef ttl 63 tcp-mss 1360')
    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'meta mark set', 'ct mark set', 'ip dscp set ef',
                         'ip ttl set 63', 'tcp option maxseg size set 1360', 'continue')


def test_modify_forward_ipv6(config):
    """IPv6 forwarding writes hop limit and DSCP with both marks and MSS."""
    config.set('set firewall ipv6 forward filter rule 10 protocol tcp tcp-flags syn action continue')
    config.set('set firewall ipv6 forward filter rule 10 modify packet-mark 0x20 connection-mark 0x40 dscp ef ttl 63 tcp-mss 1360')
    config.commit()

    assert_firewall_rule('ipv6_forward', 10, 'meta mark set', 'ct mark set', 'ip6 dscp set ef',
                         'ip6 hoplimit set 63', 'tcp option maxseg size set 1360', 'continue')


def test_modify_input_ipv4(config):
    """Local IPv4 TCP SYN-ACK packets may use fixed MSS and tracked marks."""
    config.set('set firewall ipv4 input filter rule 10 protocol tcp tcp-flags syn and ack action continue')
    config.set('set firewall ipv4 input filter rule 10 modify connection-mark 5 packet-mark 6 dscp cs1 ttl 42 tcp-mss 1200')
    config.commit()

    assert_firewall_rule('ipv4_input', 10, 'ct mark set', 'ip dscp set cs1', 'ip ttl set 42',
                         'tcp option maxseg size set 1200')


def test_modify_input_ipv6(config):
    """Local IPv6 TCP SYN-ACK packets may use fixed MSS and tracked marks."""
    config.set('set firewall ipv6 input filter rule 10 protocol tcp tcp-flags syn and ack action continue')
    config.set('set firewall ipv6 input filter rule 10 modify connection-mark 5 packet-mark 6 dscp cs1 ttl 42 tcp-mss 1200')
    config.commit()

    assert_firewall_rule('ipv6_input', 10, 'ct mark set', 'ip6 dscp set cs1', 'ip6 hoplimit set 42',
                         'tcp option maxseg size set 1200')


def test_modify_output_and_raw_ipv4(config):
    """IPv4 output supports route clamping both before and after tracking."""
    config.set('set firewall ipv4 output filter rule 10 protocol tcp tcp-flags syn action continue')
    config.set('set firewall ipv4 output filter rule 10 modify connection-mark 1 tcp-mss clamp-to-pmtu')
    config.set('set firewall ipv4 output raw rule 10 protocol tcp tcp-flags syn action continue')
    config.set('set firewall ipv4 output raw rule 10 modify packet-mark 2 dscp af41 ttl 62 tcp-mss clamp-to-pmtu')
    config.commit()

    assert_firewall_rule('ipv4_output', 10, 'ct mark set', 'tcp option maxseg size set rt mtu')
    assert_firewall_rule('ipv4_output_raw', 10, 'meta mark set', 'ip dscp set af41',
                         'ip ttl set 62', 'tcp option maxseg size set rt mtu')


def test_modify_output_and_raw_ipv6(config):
    """IPv6 output supports route clamping both before and after tracking."""
    config.set('set firewall ipv6 output filter rule 10 protocol tcp tcp-flags syn action continue')
    config.set('set firewall ipv6 output filter rule 10 modify connection-mark 1 tcp-mss clamp-to-pmtu')
    config.set('set firewall ipv6 output raw rule 10 protocol tcp tcp-flags syn action continue')
    config.set('set firewall ipv6 output raw rule 10 modify packet-mark 2 dscp af41 ttl 62 tcp-mss clamp-to-pmtu')
    config.commit()

    assert_firewall_rule('ipv6_output', 10, 'ct mark set', 'tcp option maxseg size set rt mtu')
    assert_firewall_rule('ipv6_output_raw', 10, 'meta mark set', 'ip6 dscp set af41',
                         'ip6 hoplimit set 62', 'tcp option maxseg size set rt mtu')


def test_modify_prerouting_ipv4(config):
    """IPv4 prerouting exposes packet-only setters and fixed MSS."""
    config.set('set firewall ipv4 prerouting raw rule 10 protocol tcp tcp-flags syn action continue')
    config.set('set firewall ipv4 prerouting raw rule 10 modify packet-mark 7 dscp le ttl 61 tcp-mss 1280')
    config.commit()

    assert_firewall_rule('ipv4_prerouting', 10, 'meta mark set', 'ip dscp set le', 'ip ttl set 61',
                         'tcp option maxseg size set 1280')


def test_modify_prerouting_ipv6(config):
    """IPv6 prerouting exposes packet-only setters and fixed MSS."""
    config.set('set firewall ipv6 prerouting raw rule 10 protocol tcp tcp-flags syn action continue')
    config.set('set firewall ipv6 prerouting raw rule 10 modify packet-mark 7 dscp le ttl 61 tcp-mss 1280')
    config.commit()

    assert_firewall_rule('ipv6_prerouting', 10, 'meta mark set', 'ip6 dscp set le', 'ip6 hoplimit set 61',
                         'tcp option maxseg size set 1280')


def test_modify_inet_named_chain(config):
    """A neutral named chain changes marks and clamps both IP families."""
    config.set('set firewall inet name MODIFY rule 10 protocol tcp tcp-flags syn action return')
    config.set('set firewall inet name MODIFY rule 10 modify packet-mark 8 connection-mark 9 tcp-mss clamp-to-pmtu')
    config.set('set firewall inet forward filter rule 10 action jump jump-target MODIFY')
    config.commit()

    assert_firewall_rule('inet_name_MODIFY', 10, 'meta mark set', 'ct mark set',
                         'tcp option maxseg size set rt mtu', 'return')


def test_modify_empty_rejected(config):
    """A bare modify node cannot silently produce a rule with no setters."""
    config.set('set firewall ipv4 forward filter rule 10 action continue modify')
    assert_firewall_commit_rejected(config, 'modify requires at least one setting')


def test_modify_mss_requires_tcp(config):
    """Unrestricted transport traffic cannot rewrite a TCP MSS option."""
    config.set('set firewall ipv4 forward filter rule 10 action continue modify tcp-mss 1360')
    assert_firewall_commit_rejected(config, 'modify tcp-mss requires protocol tcp')


def test_modify_mss_requires_syn(config):
    """TCP alone is insufficient without a positive SYN requirement."""
    config.set('set firewall ipv6 forward filter rule 10 protocol tcp action continue modify tcp-mss 1360')
    assert_firewall_commit_rejected(config, 'positive SYN match')


def test_modify_mss_rejects_non_syn_alternative(config):
    """Every repeated flag expression must require SYN."""
    config.set('set firewall ipv4 forward filter rule 10 protocol tcp tcp-flags syn tcp-flags ack action continue modify tcp-mss 1360')
    assert_firewall_commit_rejected(config, 'positive SYN match')


def test_modify_nested_raw_connection_mark_rejected(config):
    """Nested jumps retain the raw caller restriction on connection marks."""
    config.set('set firewall ipv4 name BOTTOM rule 10 action continue modify connection-mark 1')
    config.set('set firewall ipv4 name TOP rule 10 action jump jump-target BOTTOM')
    config.set('set firewall ipv4 prerouting raw rule 10 action jump jump-target TOP')
    assert_firewall_commit_rejected(config, 'modify connection-mark is unavailable before connection tracking')


def test_modify_nested_input_clamp_rejected(config):
    """Nested jumps cannot bypass the input route-clamping restriction."""
    config.set('set firewall ipv6 name BOTTOM rule 10 protocol tcp tcp-flags syn action continue modify tcp-mss clamp-to-pmtu')
    config.set('set firewall ipv6 name TOP rule 10 action jump jump-target BOTTOM')
    config.set('set firewall ipv6 input filter rule 10 action jump jump-target TOP')
    assert_firewall_commit_rejected(config, 'clamp-to-pmtu requires forward or output')
