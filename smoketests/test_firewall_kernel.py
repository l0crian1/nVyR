"""Firewall-owned kernel settings, defaults and new-interface inheritance."""

from pathlib import Path

import pytest

# Direct execution still lets pytest establish the installed smoketest package.
if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from smoketests.assertions import assert_operational_output, assert_raises, assert_sysctl
from smoketests.firewall_support import firewall_environment, firewall_suite
from nvyr.errors import RouterError


def test_global_defaults_without_explicit_kernel_nodes(config):
    """A state policy activates the global defaults in both the all view and kernel."""
    config.set('set firewall global-options state-policy established action accept')
    config.commit()

    assert_operational_output(
        'show running-configuration all firewall | commands',
        'set global-options ipv4 echo-request enable',
        'set global-options ipv6 multicast-ping disable',
        'set global-options syn-cookies enable',
        'set global-options connection-tracking timeout tcp established 5d',
        'set global-options flowtable-timeout tcp 30s',
    )
    assert_sysctl('net/ipv4/icmp_echo_ignore_all', 0)
    assert_sysctl('net/ipv6/icmp/echo_ignore_multicast', 1)
    assert_sysctl('net/ipv4/tcp_syncookies', 1)


def test_ipv4_echo_and_broadcast(config):
    """Map positive CLI choices to inverse ignore flags and restore deletion defaults."""
    config.set('set firewall global-options ipv4 echo-request disable broadcast-ping enable')
    config.commit()
    assert_sysctl('net/ipv4/icmp_echo_ignore_all', 1)
    assert_sysctl('net/ipv4/icmp_echo_ignore_broadcasts', 0)

    config.delete('delete firewall global-options ipv4')
    config.commit()
    assert_sysctl('net/ipv4/icmp_echo_ignore_all', 0)
    assert_sysctl('net/ipv4/icmp_echo_ignore_broadcasts', 1)


def test_ipv6_echo_multicast_and_anycast(config):
    """IPv6 ping controls remain independent of IPv4 and reset when removed."""
    config.set('set firewall global-options ipv6 echo-request disable multicast-ping enable anycast-ping disable')
    config.commit()
    assert_sysctl('net/ipv6/icmp/echo_ignore_all', 1)
    assert_sysctl('net/ipv6/icmp/echo_ignore_multicast', 0)
    assert_sysctl('net/ipv6/icmp/echo_ignore_anycast', 1)
    assert_sysctl('net/ipv4/icmp_echo_ignore_all', 0)

    config.delete('delete firewall global-options ipv6')
    config.commit()
    assert_sysctl('net/ipv6/icmp/echo_ignore_all', 0)
    assert_sysctl('net/ipv6/icmp/echo_ignore_multicast', 1)
    assert_sysctl('net/ipv6/icmp/echo_ignore_anycast', 0)


def test_ipv4_redirects_source_route_and_broadcast(config):
    """Global interface behavior reaches existing links without enabling rp_filter."""
    config.set('set firewall global-options ipv4 receive-redirects enable send-redirects enable source-route enable directed-broadcast enable log-martians enable')
    config.commit()
    assert_sysctl('net/ipv4/conf/dum998/accept_redirects', 1)
    assert_sysctl('net/ipv4/conf/dum998/send_redirects', 1)
    assert_sysctl('net/ipv4/conf/dum998/accept_source_route', 1)
    assert_sysctl('net/ipv4/conf/dum998/bc_forwarding', 1)
    assert_sysctl('net/ipv4/conf/dum998/log_martians', 1)
    assert_sysctl('net/ipv4/conf/dum998/rp_filter', 0)


def test_ipv6_redirects_and_source_route(config):
    """IPv6 routing headers use a restricted mode rather than an unrestricted enable."""
    config.set('set firewall global-options ipv6 receive-redirects enable source-route disable')
    config.commit()
    assert_sysctl('net/ipv6/conf/dum998/accept_redirects', 1)
    assert_sysctl('net/ipv6/conf/dum998/accept_source_route', -1)

    config.delete('delete firewall global-options ipv6')
    config.commit()
    assert_sysctl('net/ipv6/conf/dum998/accept_redirects', 0)
    assert_sysctl('net/ipv6/conf/dum998/accept_source_route', 0)


def test_arp_cache_and_response_policy(config):
    """ARP durations convert to milliseconds and choice modes preserve their values."""
    config.set('set firewall global-options ipv4 arp cache-timeout 2m filter enable announce best-local ignore 2')
    config.commit()
    assert_sysctl('net/ipv4/neigh/dum998/base_reachable_time_ms', 120000)
    assert_sysctl('net/ipv4/conf/dum998/arp_filter', 1)
    assert_sysctl('net/ipv4/conf/dum998/arp_announce', 2)
    assert_sysctl('net/ipv4/conf/dum998/arp_ignore', 2)


def test_arp_gratuitous_and_proxy(config):
    """Gratuitous learning and proxy ARP are independently configurable."""
    config.set('set firewall global-options ipv4 arp accept same-subnet notify enable proxy enable proxy-pvlan enable')
    config.commit()
    assert_sysctl('net/ipv4/conf/dum998/arp_accept', 2)
    assert_sysctl('net/ipv4/conf/dum998/arp_notify', 1)
    assert_sysctl('net/ipv4/conf/dum998/proxy_arp', 1)
    assert_sysctl('net/ipv4/conf/dum998/proxy_arp_pvlan', 1)


def test_ipv4_new_interface_inherits_globals(config):
    """A recreated interface inherits globals despite the packaged boot sysctl globs."""
    config.set('set firewall global-options ipv4 arp proxy enable cache-timeout 45s')
    config.commit()
    config.delete('delete interfaces dummy dum999')
    config.commit()
    config.set('set interfaces dummy dum999')
    config.commit()
    assert_sysctl('net/ipv4/conf/dum999/proxy_arp', 1)
    assert_sysctl('net/ipv4/neigh/dum999/base_reachable_time_ms', 45000)


def test_ipv6_new_interface_inherits_globals(config):
    """New IPv6 links inherit configured header policy independently of IPv4."""
    config.set('set firewall global-options ipv6 source-route disable')
    config.commit()
    config.delete('delete interfaces dummy dum999')
    config.commit()
    config.set('set interfaces dummy dum999')
    config.commit()
    assert_sysctl('net/ipv6/conf/dum999/accept_source_route', -1)


def test_ipv4_icmp_rate_limits(config):
    """ICMP spacing accepts milliseconds alongside independent global rate and burst."""
    # Use an interval exactly representable at the supported kernel timer rates.
    config.set('set firewall global-options ipv4 icmp-rate-limit interval 200ms rate 1200 burst 75')
    config.commit()
    assert_sysctl('net/ipv4/icmp_ratelimit', 200)
    assert_sysctl('net/ipv4/icmp_msgs_per_sec', 1200)
    assert_sysctl('net/ipv4/icmp_msgs_burst', 75)


def test_ipv6_icmp_rate_interval(config):
    """Zero disables spacing, while deletion restores the IPv6 baseline."""
    config.set('set firewall global-options ipv6 icmp-rate-limit interval 0ms')
    config.commit()
    assert_sysctl('net/ipv6/icmp/ratelimit', 0)
    config.delete('delete firewall global-options ipv6 icmp-rate-limit')
    config.commit()
    assert_sysctl('net/ipv6/icmp/ratelimit', 100)


def test_syn_cookies(config):
    """Removing a local TCP protection override restores enabled SYN cookies."""
    config.set('set firewall global-options syn-cookies disable')
    config.commit()
    assert_sysctl('net/ipv4/tcp_syncookies', 0)
    config.delete('delete firewall global-options syn-cookies')
    config.commit()
    assert_sysctl('net/ipv4/tcp_syncookies', 1)


def test_connection_tracking_capacity_and_auto(config):
    """Explicit capacities revert to their original boot values, not the last override."""
    original = Path('/proc/sys/net/netfilter/nf_conntrack_max').read_text().strip()
    config.set('set firewall global-options connection-tracking maximum-entries 524288 maximum-expectations 512')
    config.commit()
    assert_sysctl('net/netfilter/nf_conntrack_max', 524288)
    assert_sysctl('net/netfilter/nf_conntrack_expect_max', 512)
    config.set('set firewall global-options connection-tracking maximum-entries auto')
    config.commit()
    assert_sysctl('net/netfilter/nf_conntrack_max', original)


def test_connection_tracking_hash_size(config):
    """Exercise a bounded hash resize, then restore its boot-sized allocation."""
    original = Path('/proc/sys/net/netfilter/nf_conntrack_buckets').read_text().strip()
    config.set('set firewall global-options connection-tracking hash-size 131072')
    config.commit()
    assert_sysctl('net/netfilter/nf_conntrack_buckets', 131072)
    config.delete('delete firewall global-options connection-tracking hash-size')
    config.commit()
    assert_sysctl('net/netfilter/nf_conntrack_buckets', original)


def test_connection_tracking_diagnostics(config):
    """Events, timestamps, checksums and ICMPv6 diagnostics have distinct native values."""
    config.set('set firewall global-options connection-tracking checksum-validation disable events enable timestamp log-invalid icmpv6')
    config.commit()
    assert_sysctl('net/netfilter/nf_conntrack_checksum', 0)
    assert_sysctl('net/netfilter/nf_conntrack_events', 1)
    assert_sysctl('net/netfilter/nf_conntrack_timestamp', 1)
    assert_sysctl('net/netfilter/nf_conntrack_log_invalid', 58)


def test_connection_tracking_tcp_behavior(config):
    """TCP pickup, window checking and retransmission handling remain separate knobs."""
    config.set('set firewall global-options connection-tracking tcp loose disable liberal ignore-invalid-rst maximum-retransmissions 5')
    config.commit()
    assert_sysctl('net/netfilter/nf_conntrack_tcp_loose', 0)
    assert_sysctl('net/netfilter/nf_conntrack_tcp_be_liberal', 1)
    assert_sysctl('net/netfilter/nf_conntrack_tcp_ignore_invalid_rst', 1)
    assert_sysctl('net/netfilter/nf_conntrack_tcp_max_retrans', 5)


def test_tcp_handshake_and_established_timeouts(config):
    """Convert long established lifetimes and shorter handshake lifetimes to seconds."""
    config.set('set firewall global-options connection-tracking timeout tcp established 2d syn-sent 3m syn-received 90s')
    config.commit()
    assert_sysctl('net/netfilter/nf_conntrack_tcp_timeout_established', 172800)
    assert_sysctl('net/netfilter/nf_conntrack_tcp_timeout_syn_sent', 180)
    assert_sysctl('net/netfilter/nf_conntrack_tcp_timeout_syn_recv', 90)


def test_tcp_closing_and_retransmission_timeouts(config):
    """Each closing and stalled-connection lifetime maps to its own kernel setting."""
    config.set('set firewall global-options connection-tracking timeout tcp fin-wait 3m close-wait 2m last-ack 45s time-wait 3m close 15s unacknowledged 6m max-retransmissions 7m')
    config.commit()
    assert_sysctl('net/netfilter/nf_conntrack_tcp_timeout_fin_wait', 180)
    assert_sysctl('net/netfilter/nf_conntrack_tcp_timeout_close_wait', 120)
    assert_sysctl('net/netfilter/nf_conntrack_tcp_timeout_last_ack', 45)
    assert_sysctl('net/netfilter/nf_conntrack_tcp_timeout_time_wait', 180)
    assert_sysctl('net/netfilter/nf_conntrack_tcp_timeout_close', 15)
    assert_sysctl('net/netfilter/nf_conntrack_tcp_timeout_unacknowledged', 360)
    assert_sysctl('net/netfilter/nf_conntrack_tcp_timeout_max_retrans', 420)


def test_udp_gre_and_generic_timeouts(config):
    """Unreplied traffic and established streams use distinct UDP/GRE lifetimes."""
    config.set('set firewall global-options connection-tracking timeout udp unreplied 45s stream 4m')
    config.set('set firewall global-options connection-tracking timeout gre unreplied 40s stream 5m')
    config.set('set firewall global-options connection-tracking timeout generic 15m')
    config.commit()
    assert_sysctl('net/netfilter/nf_conntrack_udp_timeout', 45)
    assert_sysctl('net/netfilter/nf_conntrack_udp_timeout_stream', 240)
    assert_sysctl('net/netfilter/nf_conntrack_gre_timeout', 40)
    assert_sysctl('net/netfilter/nf_conntrack_gre_timeout_stream', 300)
    assert_sysctl('net/netfilter/nf_conntrack_generic_timeout', 900)


def test_ipv4_icmp_tracking_timeout(config):
    """IPv4 ICMP tracking has its own timeout, independent of response rate limits."""
    config.set('set firewall global-options connection-tracking timeout icmp 45s')
    config.commit()
    assert_sysctl('net/netfilter/nf_conntrack_icmp_timeout', 45)


def test_ipv6_icmp_tracking_timeout(config):
    """IPv6 ICMP tracking does not change the IPv4 lifetime."""
    config.set('set firewall global-options connection-tracking timeout icmpv6 50s')
    config.commit()
    assert_sysctl('net/netfilter/nf_conntrack_icmpv6_timeout', 50)
    assert_sysctl('net/netfilter/nf_conntrack_icmp_timeout', 30)


def test_sctp_tracking_timeouts(config):
    """Every exposed SCTP state retains a separate connection lifetime."""
    config.set('set firewall global-options connection-tracking timeout sctp closed 15s cookie-wait 5s cookie-echoed 6s established 5m')
    config.set('set firewall global-options connection-tracking timeout sctp shutdown-sent 7s shutdown-received 8s shutdown-ack-sent 9s heartbeat-sent 40s')
    config.commit()
    assert_sysctl('net/netfilter/nf_conntrack_sctp_timeout_closed', 15)
    assert_sysctl('net/netfilter/nf_conntrack_sctp_timeout_cookie_wait', 5)
    assert_sysctl('net/netfilter/nf_conntrack_sctp_timeout_cookie_echoed', 6)
    assert_sysctl('net/netfilter/nf_conntrack_sctp_timeout_established', 300)
    assert_sysctl('net/netfilter/nf_conntrack_sctp_timeout_shutdown_sent', 7)
    assert_sysctl('net/netfilter/nf_conntrack_sctp_timeout_shutdown_recd', 8)
    assert_sysctl('net/netfilter/nf_conntrack_sctp_timeout_shutdown_ack_sent', 9)
    assert_sysctl('net/netfilter/nf_conntrack_sctp_timeout_heartbeat_sent', 40)


def test_flowtable_idle_timeouts(config):
    """Offload lifetimes are global and do not require creating a flowtable."""
    config.set('set firewall global-options flowtable-timeout tcp 1m udp 45s')
    config.commit()
    assert_sysctl('net/netfilter/nf_flowtable_tcp_timeout', 60)
    assert_sysctl('net/netfilter/nf_flowtable_udp_timeout', 45)


def test_reject_reserved_arp_mode(config):
    """Reserved ARP response modes fail at CLI validation."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set firewall global-options ipv4 arp ignore 4')


def test_reject_overflowing_timeout(config):
    """A duration beyond the safe kernel jiffy range cannot reach apply."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set firewall global-options connection-tracking timeout tcp established 999999d')
