"""Live schema and verify rejection tests; failed candidates must not change the kernel."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_equal, assert_raises, assert_firewall_commit_rejected, assert_firewall_rule,
)
from smoketests.firewall_support import firewall_environment, firewall_suite


# Each case supplies complete rule options. No valid action is silently added:
# that lets the missing-action and disabled-rule contracts be tested honestly.


def test_rule_verify_rejection_missing_action(config):
    """Reject a rule with missing action before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 description "missing action"')

    assert_firewall_commit_rejected(config, 'action is required')


def test_rule_verify_rejection_jump_target_required(config):
    """Reject a rule with jump target required before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action jump')

    assert_firewall_commit_rejected(config, 'requires jump-target')


def test_rule_verify_rejection_jump_target_missing(config):
    """Reject a rule with jump target missing before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action jump jump-target MISSING')

    assert_firewall_commit_rejected(config, 'not a named chain')


def test_rule_verify_rejection_jump_without_action(config):
    """Reject a rule with jump without action before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept jump-target MISSING')

    assert_firewall_commit_rejected(config, 'requires action jump')


def test_rule_verify_rejection_map_missing(config):
    """Reject a rule with map missing before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 map MISSING')

    assert_firewall_commit_rejected(config, 'not configured')


def test_rule_verify_rejection_match_group_missing(config):
    """Reject a rule with match group missing before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept match-group MISSING')

    assert_firewall_commit_rejected(config, 'not configured')


def test_rule_verify_rejection_negative_group_missing(config):
    """Reject a rule with negative group missing before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept match-group not MISSING')

    assert_firewall_commit_rejected(config, 'not configured')


def test_rule_verify_rejection_address_group_missing(config):
    """Reject a rule with address group missing before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept source-address-group MISSING')

    assert_firewall_commit_rejected(config, 'not configured')


def test_rule_verify_rejection_icmp_group_missing(config):
    """Reject a rule with icmp group missing before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol icmp icmp-group MISSING')

    assert_firewall_commit_rejected(config, 'not configured')


def test_rule_verify_rejection_counter_missing(config):
    """Reject a rule with counter missing before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept counter group MISSING')

    assert_firewall_commit_rejected(config, 'not configured')


def test_rule_verify_rejection_quota_empty(config):
    """Reject a rule with quota empty before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept quota')

    assert_firewall_commit_rejected(config, 'requires bytes')


def test_rule_verify_rejection_quota_conflicting_mode(config):
    """Reject a rule with quota conflicting mode before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept quota bytes 1m over until')

    assert_firewall_commit_rejected(config, 'mutually exclusive')


def test_rule_verify_rejection_quota_missing(config):
    """Reject a rule with quota missing before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept quota group MISSING')

    assert_firewall_commit_rejected(config, 'not configured')


def test_rule_verify_rejection_quota_inline_and_group(config):
    """Reject a rule with quota inline and group before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept quota bytes 1m group MISSING')

    assert_firewall_commit_rejected(config, 'inline quota')


def test_rule_verify_rejection_limit_empty(config):
    """Reject a rule with limit empty before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit')

    assert_firewall_commit_rejected(config, 'requires rate')


def test_rule_verify_rejection_limit_missing(config):
    """Reject a rule with limit missing before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit group MISSING')

    assert_firewall_commit_rejected(config, 'not configured')


def test_rule_verify_rejection_limit_inline_and_group(config):
    """Reject a rule with limit inline and group before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit rate packets 10/s group MISSING')

    assert_firewall_commit_rejected(config, 'inline limit')


def test_rule_verify_rejection_limit_two_rates(config):
    """Reject a rule with limit two rates before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit rate packets 10/s')
    config.set('set firewall ipv4 name SMOKE rule 10 limit rate bytes 1m/s')

    assert_firewall_commit_rejected(config, 'exactly one')


def test_rule_verify_rejection_limit_burst_units(config):
    """Reject a rule with limit burst units before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit rate packets 10/s')
    config.set('set firewall ipv4 name SMOKE rule 10 limit burst bytes 1k')

    assert_firewall_commit_rejected(config, 'same packet or byte')


def test_rule_verify_rejection_limit_duplicate_key(config):
    """Reject a rule with limit duplicate key before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit rate packets 10/s per source-address and source-address')

    assert_firewall_commit_rejected(config, 'must not repeat')


def test_rule_verify_rejection_limit_size_without_key(config):
    """Reject a rule with limit size without key before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit rate packets 10/s size 10')

    assert_firewall_commit_rejected(config, 'require per')


def test_rule_verify_rejection_limit_timeout_without_key(config):
    """Reject a rule with limit timeout without key before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit rate packets 10/s timeout 1m')

    assert_firewall_commit_rejected(config, 'require per')


def test_rule_verify_rejection_limit_prefix_without_key(config):
    """Reject a rule with limit prefix without key before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit rate packets 10/s source-prefix-length 24')

    assert_firewall_commit_rejected(config, 'requires per')


def test_rule_verify_rejection_limit_ipv4_prefix(config):
    """Reject a rule with limit IPv4 prefix before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit rate packets 10/s per source-address source-prefix-length 33')

    assert_firewall_commit_rejected(config, 'between 0 and 32')


def test_rule_verify_rejection_limit_ports_protocol(config):
    """Reject a rule with limit ports protocol before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol icmp limit rate packets 10/s per destination-port')

    assert_firewall_commit_rejected(config, 'port protocol')


def test_rule_verify_rejection_limit_refill(config):
    """Reject a rule with limit refill before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit rate packets 1/m burst packets 10 per source-address timeout 1m')

    assert_firewall_commit_rejected(config, 'full bucket refill')


def test_rule_verify_rejection_limit_overflow(config):
    """Reject a rule with limit overflow before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit rate bytes 18446744073/s burst bytes 1')

    assert_firewall_commit_rejected(config, 'bucket capacity')


def test_rule_verify_rejection_limit_clock_resolution(config):
    """Reject a rule with limit clock resolution before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept limit rate packets 1000000001/s')

    assert_firewall_commit_rejected(config, 'timer resolution')


def test_rule_verify_rejection_connection_limit_empty(config):
    """Reject a rule with connection limit empty before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection limit')

    assert_firewall_commit_rejected(config, 'requires over')


def test_rule_verify_rejection_ttl_equality_range(config):
    """Reject a rule with ttl equality range before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept ttl eq 64 ttl lt 100')

    assert_firewall_commit_rejected(config, 'eq cannot')


def test_rule_verify_rejection_ttl_impossible_range(config):
    """Reject a rule with ttl impossible range before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept ttl gt 10 ttl lt 11')

    assert_firewall_commit_rejected(config, 'cannot match')


def test_rule_verify_rejection_ttl_below_zero(config):
    """Reject a rule with ttl below zero before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept ttl lt 0')

    assert_firewall_commit_rejected(config, 'cannot match')


def test_rule_verify_rejection_ttl_excluded_only_value(config):
    """Reject a rule with ttl excluded only value before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept ttl gt 10 ttl lt 12 ttl eq not 11')

    assert_firewall_commit_rejected(config, 'only permitted value')


def test_rule_verify_rejection_mask_with_multiple_addresses(config):
    """Reject a rule with mask with multiple addresses before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept source-address 192.0.2.1 mask 255.255.255.0')
    config.set('set firewall ipv4 name SMOKE rule 10 source-address 192.0.2.2')

    assert_firewall_commit_rejected(config, 'mask requires exactly one')


def test_rule_verify_rejection_negative_mask_with_multiple_addresses(config):
    """Reject a rule with negative mask with multiple addresses before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept destination-address not 192.0.2.1 mask 255.255.255.0')
    config.set('set firewall ipv4 name SMOKE rule 10 destination-address not 192.0.2.2')

    assert_firewall_commit_rejected(config, 'mask requires exactly one')


def test_rule_verify_rejection_mask_with_multiple_macs(config):
    """Reject a rule with mask with multiple macs before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept source-mac 02:00:00:00:00:01 mask ff:ff:ff:00:00:00')
    config.set('set firewall ipv4 name SMOKE rule 10 source-mac 02:00:00:00:00:02')

    assert_firewall_commit_rejected(config, 'mask requires exactly one')


def test_rule_verify_rejection_mss_with_udp(config):
    """Reject a rule with mss with udp before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol udp tcp-mss 1460')

    assert_firewall_commit_rejected(config, 'requires protocol tcp')


def test_rule_verify_rejection_flags_without_protocol(config):
    """Reject a rule with flags without protocol before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept tcp-flags syn')

    assert_firewall_commit_rejected(config, 'requires protocol tcp')


def test_rule_verify_rejection_flags_with_udp(config):
    """Reject a rule with flags with udp before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol udp tcp-flags syn')

    assert_firewall_commit_rejected(config, 'requires protocol tcp')


def test_rule_verify_rejection_ports_without_protocol(config):
    """Reject a rule with ports without protocol before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept destination-port 53098')

    assert_firewall_commit_rejected(config, 'requires an explicit port protocol')


def test_rule_verify_rejection_icmp_without_protocol(config):
    """Reject a rule with icmp without protocol before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept icmp-type echo-request')

    assert_firewall_commit_rejected(config, 'requires protocol icmp')


def test_rule_verify_rejection_icmp_wrong_protocol(config):
    """Reject a rule with icmp wrong protocol before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol tcp icmp-code 0')

    assert_firewall_commit_rejected(config, 'requires protocol icmp')


def test_rule_verify_rejection_icmp_ambiguous_pair(config):
    """Reject a rule with icmp ambiguous pair before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol icmp icmp-type echo-request')
    config.set('set firewall ipv4 name SMOKE rule 10 icmp-type echo-reply')
    config.set('set firewall ipv4 name SMOKE rule 10 icmp-code 0')

    assert_firewall_commit_rejected(config, 'exactly one of each')


def test_rule_verify_rejection_icmp_conflicts_port(config):
    """Reject a rule with icmp conflicts port before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol icmp icmp-type echo-request destination-port 53098')

    assert_firewall_commit_rejected(config, 'ICMP matching cannot')


def test_rule_verify_rejection_offload_confirmed_required(config):
    """Reject a rule with offload confirmed required before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection status offload')

    assert_firewall_commit_rejected(config, 'requires confirmed')


def test_rule_verify_rejection_offload_helper(config):
    """Reject a rule with offload helper before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection status confirmed and offload and helper')

    assert_firewall_commit_rejected(config, 'cannot be combined')


def test_rule_verify_rejection_offload_dying(config):
    """Reject a rule with offload dying before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection status confirmed and offload and dying')

    assert_firewall_commit_rejected(config, 'cannot be combined')


def test_rule_verify_rejection_reject_action(config):
    """Reject a rule with reject action before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept reject-response admin-prohibited')

    assert_firewall_commit_rejected(config, 'requires action reject')


def test_rule_verify_rejection_tcp_reset_protocol(config):
    """Reject a rule with tcp reset protocol before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action reject reject-response tcp-reset protocol udp')

    assert_firewall_commit_rejected(config, 'requires protocol tcp only')


def test_rule_verify_rejection_log_all_with_flags(config):
    """Reject a rule with log all with flags before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept log flags all and ether')

    assert_firewall_commit_rejected(config, 'all cannot be combined')


def test_ipv4_rule_verify_rejection_empty_connection(config):
    """An empty connection node must not silently broaden an IPv4 rule."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection')

    assert_firewall_commit_rejected(config, 'connection requires at least one')


def test_ipv6_rule_verify_rejection_empty_connection(config):
    """An empty connection node must not silently broaden an IPv6 rule."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection')

    assert_firewall_commit_rejected(config, 'connection requires at least one')


def test_ipv4_rule_verify_rejection_empty_fib(config):
    """An IPv4 FIB condition requires a lookup address and a result."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept fib')

    assert_firewall_commit_rejected(config, 'lookup requires exactly one')


def test_ipv6_rule_verify_rejection_empty_fib(config):
    """An IPv6 FIB condition requires a lookup address and a result."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept fib')

    assert_firewall_commit_rejected(config, 'lookup requires exactly one')


def test_ipv4_rule_verify_rejection_empty_connection_original(config):
    """Reject an empty original section even alongside a valid connection match."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection state established')
    config.set('set firewall ipv4 name SMOKE rule 10 connection original')

    assert_firewall_commit_rejected(config, 'connection original requires at least one')


def test_ipv4_rule_verify_rejection_empty_connection_reply(config):
    """Reject an empty reply section even alongside a valid connection match."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection state established')
    config.set('set firewall ipv4 name SMOKE rule 10 connection reply')

    assert_firewall_commit_rejected(config, 'connection reply requires at least one')


def test_ipv4_rule_verify_rejection_empty_connection_total(config):
    """Reject an empty total section even alongside a valid connection match."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection state established')
    config.set('set firewall ipv4 name SMOKE rule 10 connection total')

    assert_firewall_commit_rejected(config, 'connection total requires at least one')


def test_ipv4_rule_verify_rejection_empty_connection_expiration(config):
    """Reject an empty expiration section even alongside a valid connection match."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection state established')
    config.set('set firewall ipv4 name SMOKE rule 10 connection expiration')

    assert_firewall_commit_rejected(config, 'requires eq, lt or gt')


def test_ipv6_rule_verify_rejection_empty_connection_original(config):
    """Reject an empty original section even alongside a valid connection match."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection state established')
    config.set('set firewall ipv6 name SMOKE rule 10 connection original')

    assert_firewall_commit_rejected(config, 'connection original requires at least one')


def test_ipv6_rule_verify_rejection_empty_connection_reply(config):
    """Reject an empty reply section even alongside a valid connection match."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection state established')
    config.set('set firewall ipv6 name SMOKE rule 10 connection reply')

    assert_firewall_commit_rejected(config, 'connection reply requires at least one')


def test_ipv6_rule_verify_rejection_empty_connection_total(config):
    """Reject an empty total section even alongside a valid connection match."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection state established')
    config.set('set firewall ipv6 name SMOKE rule 10 connection total')

    assert_firewall_commit_rejected(config, 'connection total requires at least one')


def test_ipv6_rule_verify_rejection_empty_connection_expiration(config):
    """Reject an empty expiration section even alongside a valid connection match."""
    config.set('set firewall ipv6 name SMOKE rule 10 action accept connection state established')
    config.set('set firewall ipv6 name SMOKE rule 10 connection expiration')

    assert_firewall_commit_rejected(config, 'requires eq, lt or gt')


def test_rule_verify_rejection_fib_address_required(config):
    """Reject a rule with fib address required before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept fib lookup packet-mark')
    config.set('set firewall ipv4 name SMOKE rule 10 fib result route-type local')

    assert_firewall_commit_rejected(config, 'exactly one')


def test_rule_verify_rejection_fib_two_addresses(config):
    """Reject a rule with fib two addresses before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept fib lookup source-address destination-address')
    config.set('set firewall ipv4 name SMOKE rule 10 fib result route-type local')

    assert_firewall_commit_rejected(config, 'exactly one')


def test_rule_verify_rejection_fib_two_interfaces(config):
    """Reject a rule with fib two interfaces before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept fib lookup source-address inbound-interface outbound-interface')
    config.set('set firewall ipv4 name SMOKE rule 10 fib result route-type local')

    assert_firewall_commit_rejected(config, 'mutually exclusive')


def test_rule_verify_rejection_fib_result_required(config):
    """Reject a rule with fib result required before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept fib lookup source-address')

    assert_firewall_commit_rejected(config, 'result requires')


def test_rule_verify_rejection_fib_two_results(config):
    """Reject a rule with fib two results before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept fib lookup source-address')
    config.set('set firewall ipv4 name SMOKE rule 10 fib result route-type local')
    config.set('set firewall ipv4 name SMOKE rule 10 fib result outbound-interface exists')

    assert_firewall_commit_rejected(config, 'result requires')


def test_rule_verify_rejection_fib_negated_existence(config):
    """Reject a rule with fib negated existence before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept fib lookup source-address')
    config.set('set firewall ipv4 name SMOKE rule 10 fib result outbound-interface not exists')

    assert_firewall_commit_rejected(config, 'negate an interface name')


def test_rule_verify_rejection_fib_existence_and_name(config):
    """Reject a rule with fib existence and name before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept fib lookup source-address')
    config.set('set firewall ipv4 name SMOKE rule 10 fib result outbound-interface exists')
    config.set('set firewall ipv4 name SMOKE rule 10 fib result outbound-interface dum998')

    assert_firewall_commit_rejected(config, 'exists and missing cannot')


def test_rule_verify_rejection_fib_outgoing_result(config):
    """Reject a rule with fib outgoing result before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept fib lookup source-address outbound-interface')
    config.set('set firewall ipv4 name SMOKE rule 10 fib result outbound-interface exists')

    assert_firewall_commit_rejected(config, 'requires result route-type')


def test_rule_verify_rejection_connection_port_protocol(config):
    """Reject a rule with connection port protocol before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection original destination-port 53098')

    assert_firewall_commit_rejected(config, 'connection ports require')


def test_rule_verify_rejection_connection_wrong_family(config):
    """Reject a rule with connection wrong family before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection family ipv6')

    assert_firewall_commit_rejected(config, 'family must be ipv4')


def test_rule_verify_rejection_connection_untracked_metadata(config):
    """Reject a rule with connection untracked metadata before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection state untracked mark 1')

    assert_firewall_commit_rejected(config, 'invalid/untracked')


def test_rule_verify_rejection_connection_accounting_required(config):
    """Reject a rule with connection accounting required before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection total packets gt 0')

    assert_firewall_commit_rejected(config, 'connection-accounting')


def test_rule_verify_rejection_connection_comparison_empty(config):
    """Reject a rule with connection comparison empty before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection expiration')

    assert_firewall_commit_rejected(config, 'requires eq, lt or gt')


def test_rule_verify_rejection_connection_comparison_conflict(config):
    """Reject a rule with connection comparison conflict before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection expiration eq 10s lt 20s')

    assert_firewall_commit_rejected(config, 'eq cannot')


def test_rule_verify_rejection_connection_comparison_impossible(config):
    """Reject a rule with connection comparison impossible before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection expiration gt 10s lt 10s')

    assert_firewall_commit_rejected(config, 'cannot match')


def test_rule_verify_rejection_connection_comparison_excluded(config):
    """Reject a rule with connection comparison excluded before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection expiration eq 10s eq not 10s')

    assert_firewall_commit_rejected(config, 'only matching value')


def test_rule_verify_rejection_connection_label_excluded(config):
    """Reject a rule with connection label excluded before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection label 1 and 2')
    config.set('set firewall ipv4 name SMOKE rule 10 connection label not 1')

    assert_firewall_commit_rejected(config, 'all excluded')


def test_rule_verify_rejection_connection_label_expansion(config):
    """Reject a rule with connection label expansion before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept connection label 0 and 1')
    config.set('set firewall ipv4 name SMOKE rule 10 connection label 2 and 3 and 4 and 5 and 6 and 7 and 8 and 9 and 10 and 11 and 12 and 13 and 14 and 15')

    assert_firewall_commit_rejected(config, '4096')


def test_rule_verify_rejection_update_no_target(config):
    """Reject a rule with update no target before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept add-to-group timeout 1m')

    assert_firewall_commit_rejected(config, 'exactly one')


def test_rule_verify_rejection_update_missing_group(config):
    """Reject a rule with update missing group before changing installed configuration."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept add-to-group source-address MISSING')

    assert_firewall_commit_rejected(config, 'not a configured')


def test_group_verify_rejection_quota_missing_size(config):
    """Reject quota missing size even when the group is not referenced by a rule."""
    config.set('set firewall group quota-group TEST')

    assert_firewall_commit_rejected(config, 'requires bytes')


def test_group_verify_rejection_quota_conflicting_mode(config):
    """Reject quota conflicting mode even when the group is not referenced by a rule."""
    config.set('set firewall group quota-group TEST bytes 1m over until')

    assert_firewall_commit_rejected(config, 'mutually exclusive')


def test_group_verify_rejection_limit_unused_invalid(config):
    """Reject limit unused invalid even when the group is not referenced by a rule."""
    config.set('set firewall group limit-group ipv4 TEST')

    assert_firewall_commit_rejected(config, 'requires rate')


def test_group_verify_rejection_map_empty_key(config):
    """Reject map empty key even when the group is not referenced by a rule."""
    config.set('set firewall group map ipv4 TEST result-type verdict')

    assert_firewall_commit_rejected(config, 'at least one match field')


def test_group_verify_rejection_map_missing_result_type(config):
    """Reject map missing result type even when the group is not referenced by a rule."""
    config.set('set firewall group map ipv4 TEST match source-address')

    assert_firewall_commit_rejected(config, 'result-type is required')


def test_group_verify_rejection_match_group_empty(config):
    """Reject match group empty even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv4 TEST')

    assert_firewall_commit_rejected(config, 'at least one match field')


def test_group_verify_rejection_too_many_fields(config):
    """Reject too many fields even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv4 TEST match source-address destination-address protocol source-port destination-port packet-mark')

    assert_firewall_commit_rejected(config, 'maximum 5')


def test_group_verify_rejection_oversized_key(config):
    """Reject oversized key even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv6 TEST match source-address destination-address inbound-interface outbound-interface destination-port')

    assert_firewall_commit_rejected(config, 'maximum 64')


def test_group_verify_rejection_icmp_key_protocol(config):
    """Reject icmp key protocol even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv4 TEST match icmp-type')

    assert_firewall_commit_rejected(config, 'protocol in')


def test_group_verify_rejection_tcp_key_protocol(config):
    """Reject tcp key protocol even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv4 TEST match tcp-flags')

    assert_firewall_commit_rejected(config, 'protocol in')


def test_group_verify_rejection_entry_missing_field(config):
    """Reject entry missing field even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv4 TEST match source-address destination-address')
    config.set('set firewall group match-group ipv4 TEST entry first source-address 192.0.2.1')

    assert_firewall_commit_rejected(config, 'missing match fields')


def test_group_verify_rejection_entry_extra_field(config):
    """Reject entry extra field even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv4 TEST match source-address')
    config.set('set firewall group match-group ipv4 TEST entry first source-address 192.0.2.1 destination-address 198.51.100.1')

    assert_firewall_commit_rejected(config, 'undeclared match fields')


def test_group_verify_rejection_entry_comment_size(config):
    """Reject entry comment size even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv4 TEST match source-address')
    config.set('set firewall group match-group ipv4 TEST entry longer_entry_name source-address 192.0.2.1 description "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"')

    assert_firewall_commit_rejected(config, '128-byte')


def test_group_verify_rejection_entry_duplicate(config):
    """Reject entry duplicate even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv4 TEST match source-address')
    config.set('set firewall group match-group ipv4 TEST entry first source-address 192.0.2.1')
    config.set('set firewall group match-group ipv4 TEST entry second source-address 192.0.2.1')

    assert_firewall_commit_rejected(config, 'duplicate or overlapping')


def test_group_verify_rejection_entry_overlap(config):
    """Reject entry overlap even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv4 TEST match source-address')
    config.set('set firewall group match-group ipv4 TEST entry first source-address 192.0.2.0/24')
    config.set('set firewall group match-group ipv4 TEST entry second source-address 192.0.2.128/25')

    assert_firewall_commit_rejected(config, 'duplicate or overlapping')


def test_group_verify_rejection_entry_port_protocol(config):
    """Reject an ICMP entry with a transport port, even in an unreferenced group."""
    config.set('set firewall group match-group ipv4 TEST match protocol destination-port')
    config.set('set firewall group match-group ipv4 TEST entry first protocol icmp destination-port 53098')

    assert_firewall_commit_rejected(config, 'port lookup requires a port protocol')


def test_group_verify_rejection_entry_flags_protocol(config):
    """Reject entry flags protocol even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv4 TEST match protocol tcp-flags')
    config.set('set firewall group match-group ipv4 TEST entry first protocol udp tcp-flags syn')

    assert_firewall_commit_rejected(config, 'TCP flags require protocol tcp')


def test_group_verify_rejection_map_result_incomplete(config):
    """Reject map result incomplete even when the group is not referenced by a rule."""
    config.set('set firewall group map ipv4 TEST match source-address')
    config.set('set firewall group map ipv4 TEST result-type verdict')
    config.set('set firewall group map ipv4 TEST entry first source-address 192.0.2.1')

    assert_firewall_commit_rejected(config, 'requires exactly')


def test_group_verify_rejection_map_result_extra(config):
    """Reject map result extra even when the group is not referenced by a rule."""
    config.set('set firewall group map ipv4 TEST match source-address')
    config.set('set firewall group map ipv4 TEST result-type verdict')
    config.set('set firewall group map ipv4 TEST entry first source-address 192.0.2.1 result action accept')
    config.set('set firewall group map ipv4 TEST entry first result port 53098')

    assert_firewall_commit_rejected(config, 'requires exactly')


def test_group_verify_rejection_map_jump_target_missing(config):
    """Reject map jump target missing even when the group is not referenced by a rule."""
    config.set('set firewall group map ipv4 TEST match source-address')
    config.set('set firewall group map ipv4 TEST result-type verdict')
    config.set('set firewall group map ipv4 TEST entry first source-address 192.0.2.1 result action jump result jump-target MISSING')

    assert_firewall_commit_rejected(config, 'not a named chain')


def test_dynamic_ipv4_address_group_rejects_configured_members(config):
    """Keep configured IPv4 addresses out of packet-learned groups."""
    config.set('set firewall group address-group ipv4 TEST dynamic')
    config.set('set firewall group address-group ipv4 TEST address 192.0.2.1')

    assert_firewall_commit_rejected(config, 'dynamic groups cannot contain configured members')


def test_dynamic_ipv6_address_group_rejects_configured_members(config):
    """Keep configured IPv6 addresses out of packet-learned groups."""
    config.set('set firewall group address-group ipv6 TEST dynamic')
    config.set('set firewall group address-group ipv6 TEST address 2001:db8::1')

    assert_firewall_commit_rejected(config, 'dynamic groups cannot contain configured members')


def test_dynamic_ipv4_match_group_rejects_configured_entries(config):
    """Reject enabling learning on a populated IPv4 match-group."""
    config.set('set firewall group match-group ipv4 TEST match source-address')
    config.set('set firewall group match-group ipv4 TEST entry first source-address 192.0.2.1')
    config.set('set firewall group match-group ipv4 TEST dynamic')

    assert_firewall_commit_rejected(config, 'dynamic groups cannot contain configured members')


def test_dynamic_ipv6_match_group_rejects_configured_entries(config):
    """Reject enabling learning on a populated IPv6 match-group."""
    config.set('set firewall group match-group ipv6 TEST match source-address')
    config.set('set firewall group match-group ipv6 TEST entry first source-address 2001:db8::1')
    config.set('set firewall group match-group ipv6 TEST dynamic')

    assert_firewall_commit_rejected(config, 'dynamic groups cannot contain configured members')


def test_group_verify_rejection_icmp_mode_required(config):
    """Reject icmp mode required even when the group is not referenced by a rule."""
    config.set('set firewall group icmp-group ipv4 TEST')

    assert_firewall_commit_rejected(config, 'match must be')


def test_group_verify_rejection_icmp_code_with_type_mode(config):
    """Reject icmp code with type mode even when the group is not referenced by a rule."""
    config.set('set firewall group icmp-group ipv4 TEST match type')
    config.set('set firewall group icmp-group ipv4 TEST type echo-request code 0')

    assert_firewall_commit_rejected(config, 'code requires match type-code')


def test_group_verify_rejection_icmp_code_required(config):
    """Reject icmp code required even when the group is not referenced by a rule."""
    config.set('set firewall group icmp-group ipv4 TEST match type-code')
    config.set('set firewall group icmp-group ipv4 TEST type echo-request')

    assert_firewall_commit_rejected(config, 'code is required')


def test_group_verify_rejection_icmp_code_invalid_for_type(config):
    """Reject icmp code invalid for type even when the group is not referenced by a rule."""
    config.set('set firewall group icmp-group ipv4 TEST match type-code')
    config.set('set firewall group icmp-group ipv4 TEST type echo-request code 1')

    assert_firewall_commit_rejected(config, 'invalid code')


def test_group_verify_rejection_icmp_code_overlap(config):
    """Reject icmp code overlap even when the group is not referenced by a rule."""
    config.set('set firewall group icmp-group ipv4 TEST match type-code')
    config.set('set firewall group icmp-group ipv4 TEST type destination-unreachable code 0-3')
    config.set('set firewall group icmp-group ipv4 TEST type destination-unreachable code 3')

    assert_firewall_commit_rejected(config, 'overlaps')


def test_group_verify_rejection_icmp_type_alias(config):
    """Reject icmp type alias even when the group is not referenced by a rule."""
    config.set('set firewall group icmp-group ipv6 TEST match type')
    config.set('set firewall group icmp-group ipv6 TEST type mld-listener-done')
    config.set('set firewall group icmp-group ipv6 TEST type mld-listener-reduction')

    assert_firewall_commit_rejected(config, 'duplicates')


def test_group_verify_rejection_flowtable_interface_required(config):
    """Reject flowtable interface required even when the group is not referenced by a rule."""
    config.set('set firewall flowtable TEST offload software')

    assert_firewall_commit_rejected(config, 'at least one interface')


def test_group_verify_rejection_flowtable_interface_shared(config):
    """Reject flowtable interface shared even when the group is not referenced by a rule."""
    config.set('set firewall flowtable FIRST interface dum998')
    config.set('set firewall flowtable SECOND interface dum998')

    assert_firewall_commit_rejected(config, 'already used')


def test_group_verify_rejection_state_policy_action(config):
    """Reject state policy action even when the group is not referenced by a rule."""
    config.set('set firewall global-options state-policy established')

    assert_firewall_commit_rejected(config, 'action is required')


def test_group_verify_rejection_connection_group_accounting(config):
    """Reject connection group accounting even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv4 TEST match connection total bytes')

    assert_firewall_commit_rejected(config, 'connection-accounting')


def test_group_verify_rejection_connection_group_protocol(config):
    """Reject connection group protocol even when the group is not referenced by a rule."""
    config.set('set firewall group match-group ipv4 TEST match connection original destination-port')

    assert_firewall_commit_rejected(config, 'protocol in the group')


def test_map_conflicting_explicit_fields_source_address(config):
    """A map owns only its declared fields; an explicit duplicate must fail verification."""
    config.set('set firewall group map ipv4 TEST match source-address')
    config.set('set firewall group map ipv4 TEST result-type verdict')
    config.set('set firewall ipv4 name SMOKE rule 10 map TEST source-address 192.0.2.1')

    assert_firewall_commit_rejected(config, 'map cannot be combined')


def test_map_conflicting_explicit_fields_destination_address(config):
    """A map owns only its declared fields; an explicit duplicate must fail verification."""
    config.set('set firewall group map ipv4 TEST match destination-address')
    config.set('set firewall group map ipv4 TEST result-type verdict')
    config.set('set firewall ipv4 name SMOKE rule 10 map TEST destination-address 192.0.2.1')

    assert_firewall_commit_rejected(config, 'map cannot be combined')


def test_map_conflicting_explicit_fields_protocol(config):
    """A map owns only its declared fields; an explicit duplicate must fail verification."""
    config.set('set firewall group map ipv4 TEST match protocol')
    config.set('set firewall group map ipv4 TEST result-type verdict')
    config.set('set firewall ipv4 name SMOKE rule 10 map TEST protocol tcp')

    assert_firewall_commit_rejected(config, 'map cannot be combined')


def test_group_conflicts_explicit(config):
    """Explicit fields, map keys, singleton references and ICMP groups cannot compete for a key."""
    config.set('set firewall group match-group ipv4 MATCH match source-address')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept match-group MATCH source-address 192.0.2.1')

    assert_firewall_commit_rejected(config, 'duplicates')


def test_group_conflicts_map(config):
    """Explicit fields, map keys, singleton references and ICMP groups cannot compete for a key."""
    config.set('set firewall group match-group ipv4 MATCH match source-address')
    config.set('set firewall group map ipv4 MAP match source-address')
    config.set('set firewall group map ipv4 MAP result-type verdict')
    config.set('set firewall ipv4 name SMOKE rule 10 map MAP match-group MATCH')

    assert_firewall_commit_rejected(config, 'duplicates')


def test_group_conflicts_singleton(config):
    """Explicit fields, map keys, singleton references and ICMP groups cannot compete for a key."""
    config.set('set firewall group match-group ipv4 MATCH match source-address')
    config.set('set firewall group address-group ipv4 ADDR address 192.0.2.1')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept match-group MATCH source-address-group ADDR')

    assert_firewall_commit_rejected(config, 'duplicates')


def test_group_conflicts_icmp(config):
    """Explicit fields, map keys, singleton references and ICMP groups cannot compete for a key."""
    config.set('set firewall group match-group ipv4 MATCH match icmp-type')
    config.set('set firewall group match-group ipv4 MATCH match protocol')
    config.set('set firewall group icmp-group ipv4 ICMP match type')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept match-group MATCH icmp-group ICMP')

    assert_firewall_commit_rejected(config, 'cannot be combined')


def test_dynamic_update_targets_source_address(config):
    """Learning needs exactly one dynamic provider, independently of ordinary rule matches."""
    config.set('set firewall group address-group ipv4 TEST')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept add-to-group source-address TEST')

    assert_firewall_commit_rejected(config, 'requires dynamic')


def test_dynamic_update_targets_source_address_dynamic(config):
    """Learning needs exactly one dynamic provider, independently of ordinary rule matches."""
    config.set('set firewall group address-group ipv4 TEST dynamic')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept add-to-group source-address TEST')
    config.set('set firewall ipv4 name SMOKE rule 10 add-to-group destination-address TEST')

    assert_firewall_commit_rejected(config, 'exactly one')


def test_dynamic_update_targets_match_group_match_destination_port_protocol(config):
    """Learning needs exactly one dynamic provider, independently of ordinary rule matches."""
    config.set('set firewall group match-group ipv4 TEST match destination-port protocol')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept add-to-group match-group TEST')

    assert_firewall_commit_rejected(config, 'requires dynamic')


def test_update_protocol_guards_destination_port_protocol_icmp(config):
    """A packet update cannot contradict the transport header selected by its rule."""
    config.set('set firewall group match-group ipv4 TEST match destination-port protocol')
    config.set('set firewall group match-group ipv4 TEST dynamic')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol icmp add-to-group match-group TEST')

    assert_firewall_commit_rejected(config, 'port fields require')


def test_update_protocol_guards_icmp_type_protocol_tcp(config):
    """A packet update cannot contradict the transport header selected by its rule."""
    config.set('set firewall group match-group ipv4 TEST match icmp-type protocol')
    config.set('set firewall group match-group ipv4 TEST dynamic')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol tcp add-to-group match-group TEST')

    assert_firewall_commit_rejected(config, 'ICMP fields require')


def test_update_protocol_guards_tcp_flags_protocol_udp(config):
    """A packet update cannot contradict the transport header selected by its rule."""
    config.set('set firewall group match-group ipv4 TEST match tcp-flags protocol')
    config.set('set firewall group match-group ipv4 TEST dynamic')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol udp add-to-group match-group TEST')

    assert_firewall_commit_rejected(config, 'TCP flags require')


def test_hook_restrictions_output_filter_limit_rate_packets_10_s_per_inbound_interface(config):
    """Hook-specific relationships fail before touching the live ruleset."""
    config.set('set firewall ipv4 output filter rule 10 action accept limit rate packets 10/s per inbound-interface')

    assert_firewall_commit_rejected(config, 'inbound-interface in output')


def test_hook_restrictions_input_filter_limit_rate_packets_10_s_per_outbound_interface(config):
    """Hook-specific relationships fail before touching the live ruleset."""
    config.set('set firewall ipv4 input filter rule 10 action accept limit rate packets 10/s per outbound-interface')

    assert_firewall_commit_rejected(config, 'outbound-interface in input')


def test_hook_restrictions_output_filter_limit_rate_packets_10_s_per_source_mac(config):
    """Hook-specific relationships fail before touching the live ruleset."""
    config.set('set firewall ipv4 output filter rule 10 action accept limit rate packets 10/s per source-mac')

    assert_firewall_commit_rejected(config, 'MAC keys require')


def test_hook_restrictions_prerouting_raw_connection_limit_over_5(config):
    """Hook-specific relationships fail before touching the live ruleset."""
    config.set('set firewall ipv4 prerouting raw rule 10 action accept connection limit over 5')

    assert_firewall_commit_rejected(config, 'connection tracking is unavailable')


def test_hook_restrictions_prerouting_raw_limit_rate_packets_10_s_per_connection_mark(config):
    """Hook-specific relationships fail before touching the live ruleset."""
    config.set('set firewall ipv4 prerouting raw rule 10 action accept limit rate packets 10/s per connection-mark')

    assert_firewall_commit_rejected(config, 'connection tracking is unavailable')


def test_hook_restrictions_output_raw_connection_mark_1(config):
    """Hook-specific relationships fail before touching the live ruleset."""
    config.set('set firewall ipv4 output raw rule 10 action accept connection mark 1')

    assert_firewall_commit_rejected(config, 'before connection tracking')


def test_hook_restrictions_prerouting_raw_connection_state_established(config):
    """Hook-specific relationships fail before touching the live ruleset."""
    config.set('set firewall ipv4 prerouting raw rule 10 action accept connection state established')

    assert_firewall_commit_rejected(config, 'tracked connection states')


def test_hook_restrictions_output_filter_fib_lookup_source_address(config):
    """Hook-specific relationships fail before touching the live ruleset."""
    config.set('set firewall ipv4 output filter rule 10 action accept fib lookup source-address')

    assert_firewall_commit_rejected(config, 'result requires')


def test_nested_jump_hook_restrictions_direct(config):
    """A nested named chain inherits the raw hook through direct and map-returned jumps."""
    config.set('set firewall ipv4 name INNER rule 10 action accept connection mark 1')
    config.set('set firewall ipv4 name OUTER rule 10 action jump jump-target INNER')
    config.set('set firewall ipv4 prerouting raw rule 10 action jump jump-target OUTER')

    assert_firewall_commit_rejected(config, 'before connection tracking')


def test_nested_jump_hook_restrictions_verdict_map(config):
    """A nested named chain inherits the raw hook through direct and map-returned jumps."""
    config.set('set firewall ipv4 name INNER rule 10 action accept connection mark 1')
    config.set('set firewall ipv4 name OUTER rule 10 action jump jump-target INNER')
    config.set('set firewall group map ipv4 JUMPS match source-address')
    config.set('set firewall group map ipv4 JUMPS result-type verdict')
    config.set('set firewall group map ipv4 JUMPS entry first source-address 192.0.2.1 result action jump result jump-target OUTER')
    config.set('set firewall ipv4 prerouting raw rule 10 map JUMPS')

    assert_firewall_commit_rejected(config, 'before connection tracking')


def test_offload_verify_rejection_action_offload(config):
    """Forward offload requires an existing flowtable and the offload action."""
    config.set('set firewall ipv4 forward filter rule 10 action offload')

    assert_firewall_commit_rejected(config, 'requires offload-target')


def test_offload_verify_rejection_action_offload_offload_target_missing(config):
    """Forward offload requires an existing flowtable and the offload action."""
    config.set('set firewall ipv4 forward filter rule 10 action offload offload-target MISSING')

    assert_firewall_commit_rejected(config, 'not a configured flowtable')


def test_offload_verify_rejection_action_accept_offload_target_missing(config):
    """Forward offload requires an existing flowtable and the offload action."""
    config.set('set firewall ipv4 forward filter rule 10 action accept offload-target MISSING')

    assert_firewall_commit_rejected(config, 'requires action offload')


def test_schema_rejects_invalid_values_packet_mark_4294967296(config):
    """Reject packet mark 4294967296 during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 packet-mark 4294967296')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_dscp_64(config):
    """Reject dscp 64 during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 dscp 64')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_tcp_mss_65536(config):
    """Reject tcp mss 65536 during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 tcp-mss 65536')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_packet_length_4294967296(config):
    """Reject packet length 4294967296 during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 packet-length 4294967296')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_ttl_eq_256(config):
    """Reject ttl eq 256 during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 ttl eq 256')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_source_address_999_0_0_1(config):
    """Reject source address 999 0 0 1 during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 source-address 999.0.0.1')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_source_mac_not_a_mac(config):
    """Reject source mac not a mac during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 source-mac not-a-mac')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_protocol_all(config):
    """Reject protocol all during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 protocol all')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_icmp_type_8(config):
    """Reject icmp type 8 during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 icmp-type 8')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_icmp_code_256(config):
    """Reject icmp code 256 during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 icmp-code 256')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_tcp_flags_syn_and_not_syn(config):
    """Reject tcp flags syn and not syn during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 tcp-flags syn and not syn')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_connection_status_typo(config):
    """Reject connection status typo during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 connection status typo')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_connection_label_128(config):
    """Reject connection label 128 during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 connection label 128')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_connection_expiration_eq_4294968s(config):
    """Reject connection expiration eq 4294968s during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 connection expiration eq 4294968s')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_connection_total_bytes_eq_1(config):
    """Reject connection total bytes eq 1 during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 connection total bytes eq -1')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_quota_bytes_9223372036854775808(config):
    """Reject quota bytes 9223372036854775808 during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 quota bytes 9223372036854775808')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_limit_rate_packets_1_fortnight(config):
    """Reject limit rate packets 1 fortnight during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 limit rate packets 1/fortnight')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_limit_burst_bytes_1t(config):
    """Reject limit burst bytes 1t during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 limit burst bytes 1t')

    assert_equal(config.get_config(source='candidate'), before)


def test_schema_rejects_invalid_values_description_invalid_quote(config):
    """Reject description invalid quote during insertion without changing the candidate."""
    before = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set firewall ipv4 name SMOKE rule 10 description \'invalid " quote\'')

    assert_equal(config.get_config(source='candidate'), before)


def test_failed_commit_preserves_existing_rules_and_can_be_corrected(config):
    """A failed verify must keep a previously installed rule and allow a later correction."""
    config.set('set firewall ipv4 name SMOKE rule 10 action accept description "installed"')

    config.commit()
    config.set('set firewall ipv4 name SMOKE rule 10 ttl gt 10 ttl lt 11')

    assert_firewall_commit_rejected(config, 'cannot match')
    assert_firewall_rule('ipv4_name_SMOKE', 10, 'installed', absent=['ttl'])

    config.delete('delete firewall ipv4 name SMOKE rule 10 ttl lt')

    config.commit()

    assert_firewall_rule('ipv4_name_SMOKE', 10, 'ttl > 10')
