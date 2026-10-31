"""Live firewall group fields, results, consumers and object lifecycle."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_equal, assert_not_equal, assert_raises, assert_firewall_object, assert_firewall_rule,
    firewall_object_handle, assert_firewall_commit_rejected,
)
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_singleton_groups_ipv4(config):
    """All singleton groups support tracking, positive/negative references and descriptions."""
    config.set('set firewall group address-group ipv4 ADDR address 192.0.2.1')
    config.set('set firewall group address-group ipv4 ADDR counter')
    config.set('set firewall group address-group ipv4 ADDR last-used')
    config.set('set firewall group interface-group IFACE interface dum998')
    config.set('set firewall group mac-group MAC address 02:00:00:00:00:01')
    config.set('set firewall group port-group PORT port 53098-53100')
    config.set('set firewall group interface-group IFACE counter')
    config.set('set firewall group interface-group IFACE last-used')
    config.set('set firewall group interface-group IFACE description "smoke group"')
    config.set('set firewall group mac-group MAC counter')
    config.set('set firewall group mac-group MAC last-used')
    config.set('set firewall group mac-group MAC description "smoke group"')
    config.set('set firewall group port-group PORT counter')
    config.set('set firewall group port-group PORT last-used')
    config.set('set firewall group port-group PORT description "smoke group"')
    config.set('set firewall ipv4 name SMOKE rule 10 action accept protocol tcp source-address-group ADDR destination-address-group not ADDR')
    config.set('set firewall ipv4 name SMOKE rule 10 inbound-interface-group IFACE outbound-interface-group not IFACE')
    config.set('set firewall ipv4 name SMOKE rule 10 source-mac-group MAC destination-mac-group not MAC')
    config.set('set firewall ipv4 name SMOKE rule 10 source-port-group PORT destination-port-group not PORT')

    config.commit()

    assert_firewall_object('set', 'ipv4_address_group_ADDR', 'counter', 'last', 'elements')
    assert_firewall_rule('ipv4_name_SMOKE', 10, '@ipv4_address_group_ADDR', '!= @ipv4_address_group_ADDR')
    assert_firewall_object('set', 'interface_group_IFACE', 'counter', 'last', 'elements')
    assert_firewall_rule('ipv4_name_SMOKE', 10, '@interface_group_IFACE', '!= @interface_group_IFACE')
    assert_firewall_object('set', 'mac_group_MAC', 'counter', 'last', 'elements')
    assert_firewall_rule('ipv4_name_SMOKE', 10, '@mac_group_MAC', '!= @mac_group_MAC')
    assert_firewall_object('set', 'port_group_PORT', 'counter', 'last', 'elements')
    assert_firewall_rule('ipv4_name_SMOKE', 10, '@port_group_PORT', '!= @port_group_PORT')


def test_singleton_groups_ipv6(config):
    """All singleton groups support tracking, positive/negative references and descriptions."""
    config.set('set firewall group address-group ipv6 ADDR address 2001:db8::1')
    config.set('set firewall group address-group ipv6 ADDR counter')
    config.set('set firewall group address-group ipv6 ADDR last-used')
    config.set('set firewall group interface-group IFACE interface dum998')
    config.set('set firewall group mac-group MAC address 02:00:00:00:00:01')
    config.set('set firewall group port-group PORT port 53098-53100')
    config.set('set firewall group interface-group IFACE counter')
    config.set('set firewall group interface-group IFACE last-used')
    config.set('set firewall group interface-group IFACE description "smoke group"')
    config.set('set firewall group mac-group MAC counter')
    config.set('set firewall group mac-group MAC last-used')
    config.set('set firewall group mac-group MAC description "smoke group"')
    config.set('set firewall group port-group PORT counter')
    config.set('set firewall group port-group PORT last-used')
    config.set('set firewall group port-group PORT description "smoke group"')
    config.set('set firewall ipv6 name SMOKE rule 10 action accept protocol tcp source-address-group ADDR destination-address-group not ADDR')
    config.set('set firewall ipv6 name SMOKE rule 10 inbound-interface-group IFACE outbound-interface-group not IFACE')
    config.set('set firewall ipv6 name SMOKE rule 10 source-mac-group MAC destination-mac-group not MAC')
    config.set('set firewall ipv6 name SMOKE rule 10 source-port-group PORT destination-port-group not PORT')

    config.commit()

    assert_firewall_object('set', 'ipv6_address_group_ADDR', 'counter', 'last', 'elements')
    assert_firewall_rule('ipv6_name_SMOKE', 10, '@ipv6_address_group_ADDR', '!= @ipv6_address_group_ADDR')
    assert_firewall_object('set', 'interface_group_IFACE', 'counter', 'last', 'elements')
    assert_firewall_rule('ipv6_name_SMOKE', 10, '@interface_group_IFACE', '!= @interface_group_IFACE')
    assert_firewall_object('set', 'mac_group_MAC', 'counter', 'last', 'elements')
    assert_firewall_rule('ipv6_name_SMOKE', 10, '@mac_group_MAC', '!= @mac_group_MAC')
    assert_firewall_object('set', 'port_group_PORT', 'counter', 'last', 'elements')
    assert_firewall_rule('ipv6_name_SMOKE', 10, '@port_group_PORT', '!= @port_group_PORT')


def test_map_match_group_composition_and_lifecycle_ipv4(config):
    """Disjoint explicit/map/set matches compose; provider changes rebuild nested callers only."""
    config.set('set firewall group map ipv4 VERDICT match source-address')
    config.set('set firewall group map ipv4 VERDICT result-type verdict')
    config.set('set firewall group map ipv4 VERDICT description "map description"')
    config.set('set firewall group map ipv4 VERDICT entry first source-address 192.0.2.1 description "entry description" result action return')
    config.set('set firewall group match-group ipv4 MATCH match protocol destination-port')
    config.set('set firewall group match-group ipv4 MATCH entry first protocol tcp destination-port 53098')
    config.set('set firewall global-options counter')
    config.set('set firewall global-options last-used')
    config.set('set firewall ipv4 name INNER rule 10 map VERDICT match-group MATCH inbound-interface dum998')
    config.set('set firewall ipv4 name OUTER rule 10 action jump jump-target INNER')
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 action jump jump-target OUTER')
    config.set('set firewall ipv4 name UNRELATED rule 10 action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_VERDICT', 'type .* : verdict', 'counter', 'last', 'map description', 'first\\|entry description')
    assert_firewall_rule('ipv4_name_INNER', 10, 'vmap @ipv4_map_VERDICT', '@ipv4_match_group_MATCH', 'dum998')
    unchanged = firewall_object_handle('chain', 'ipv4_name_UNRELATED')
    changed = firewall_object_handle('chain', 'ipv4_name_OUTER')
    config.set('set firewall group map ipv4 VERDICT entry first result action accept')

    config.commit()

    assert_not_equal(firewall_object_handle('chain', 'ipv4_name_OUTER'), changed)
    assert_equal(firewall_object_handle('chain', 'ipv4_name_UNRELATED'), unchanged)
    with assert_raises(RouterError, match='referenced'):
        config.delete('delete firewall group map ipv4 VERDICT')


def test_map_match_group_composition_and_lifecycle_ipv6(config):
    """Disjoint explicit/map/set matches compose; provider changes rebuild nested callers only."""
    config.set('set firewall group map ipv6 VERDICT match source-address')
    config.set('set firewall group map ipv6 VERDICT result-type verdict')
    config.set('set firewall group map ipv6 VERDICT description "map description"')
    config.set('set firewall group map ipv6 VERDICT entry first source-address 2001:db8::1 description "entry description" result action return')
    config.set('set firewall group match-group ipv6 MATCH match protocol destination-port')
    config.set('set firewall group match-group ipv6 MATCH entry first protocol tcp destination-port 53098')
    config.set('set firewall global-options counter')
    config.set('set firewall global-options last-used')
    config.set('set firewall ipv6 name INNER rule 10 map VERDICT match-group MATCH inbound-interface dum998')
    config.set('set firewall ipv6 name OUTER rule 10 action jump jump-target INNER')
    config.set('set firewall ipv6 forward filter rule 10 inbound-interface dum998 action jump jump-target OUTER')
    config.set('set firewall ipv6 name UNRELATED rule 10 action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_VERDICT', 'type .* : verdict', 'counter', 'last', 'map description', 'first\\|entry description')
    assert_firewall_rule('ipv6_name_INNER', 10, 'vmap @ipv6_map_VERDICT', '@ipv6_match_group_MATCH', 'dum998')
    unchanged = firewall_object_handle('chain', 'ipv6_name_UNRELATED')
    changed = firewall_object_handle('chain', 'ipv6_name_OUTER')
    config.set('set firewall group map ipv6 VERDICT entry first result action accept')

    config.commit()

    assert_not_equal(firewall_object_handle('chain', 'ipv6_name_OUTER'), changed)
    assert_equal(firewall_object_handle('chain', 'ipv6_name_UNRELATED'), unchanged)
    with assert_raises(RouterError, match='referenced'):
        config.delete('delete firewall group map ipv6 VERDICT')


def test_map_verdicts_accept(config):
    """Every result verdict compiles; jump resolves to the family-specific named chain."""
    config.set('set firewall ipv4 name TARGET default-action drop')
    config.set('set firewall group map ipv4 VERDICT match source-address')
    config.set('set firewall group map ipv4 VERDICT result-type verdict')
    config.set('set firewall group map ipv4 VERDICT entry first source-address 192.0.2.1 result action accept')
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 map VERDICT')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_VERDICT', ': accept')
    assert_firewall_rule('ipv4_name_TARGET', 'default', 'drop')


def test_map_verdicts_drop(config):
    """Every result verdict compiles; jump resolves to the family-specific named chain."""
    config.set('set firewall ipv4 name TARGET default-action drop')
    config.set('set firewall group map ipv4 VERDICT match source-address')
    config.set('set firewall group map ipv4 VERDICT result-type verdict')
    config.set('set firewall group map ipv4 VERDICT entry first source-address 192.0.2.1 result action drop')
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 map VERDICT')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_VERDICT', ': drop')
    assert_firewall_rule('ipv4_name_TARGET', 'default', 'drop')


def test_map_verdicts_continue(config):
    """Every result verdict compiles; jump resolves to the family-specific named chain."""
    config.set('set firewall ipv4 name TARGET default-action drop')
    config.set('set firewall group map ipv4 VERDICT match source-address')
    config.set('set firewall group map ipv4 VERDICT result-type verdict')
    config.set('set firewall group map ipv4 VERDICT entry first source-address 192.0.2.1 result action continue')
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 map VERDICT')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_VERDICT', ': continue')
    assert_firewall_rule('ipv4_name_TARGET', 'default', 'drop')


def test_map_verdicts_return(config):
    """Every result verdict compiles; jump resolves to the family-specific named chain."""
    config.set('set firewall ipv4 name TARGET default-action drop')
    config.set('set firewall group map ipv4 VERDICT match source-address')
    config.set('set firewall group map ipv4 VERDICT result-type verdict')
    config.set('set firewall group map ipv4 VERDICT entry first source-address 192.0.2.1 result action return')
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 map VERDICT')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_VERDICT', ': return')
    assert_firewall_rule('ipv4_name_TARGET', 'default', 'drop')


def test_map_verdicts_jump(config):
    """Every result verdict compiles; jump resolves to the family-specific named chain."""
    config.set('set firewall ipv4 name TARGET default-action drop')
    config.set('set firewall group map ipv4 VERDICT match source-address')
    config.set('set firewall group map ipv4 VERDICT result-type verdict')
    config.set('set firewall group map ipv4 VERDICT entry first source-address 192.0.2.1 result action jump')
    config.set('set firewall group map ipv4 VERDICT entry first result jump-target TARGET')
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 map VERDICT')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_VERDICT', ': jump ipv4_name_TARGET')
    assert_firewall_rule('ipv4_name_TARGET', 'default', 'drop')


def test_translation_maps_address(config):
    """Non-verdict map result types work through the jointly applied NAT consumer."""
    config.set('set firewall group map ipv4 TRANSLATE match protocol destination-port')
    config.set('set firewall group map ipv4 TRANSLATE result-type address')
    config.set('set firewall group map ipv4 TRANSLATE entry web protocol tcp destination-port 53098 result address 192.0.2.2')
    config.set('set nat destination rule 10 inbound-interface dum998 map TRANSLATE')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_TRANSLATE', '53098', '192.0.2.2')
    assert_firewall_rule('ipv4_nat_prerouting', 10, 'dnat ip to .*map', '@ipv4_map_TRANSLATE')


def test_translation_maps_port(config):
    """Non-verdict map result types work through the jointly applied NAT consumer."""
    config.set('set firewall group map ipv4 TRANSLATE match protocol destination-port')
    config.set('set firewall group map ipv4 TRANSLATE result-type port')
    config.set('set firewall group map ipv4 TRANSLATE entry web protocol tcp destination-port 53098 result port 53099')
    config.set('set nat destination rule 10 inbound-interface dum998 map TRANSLATE')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_TRANSLATE', '53098', '53099')
    assert_firewall_rule('ipv4_nat_prerouting', 10, 'dnat.*map', '@ipv4_map_TRANSLATE')


def test_translation_maps_address_port(config):
    """Non-verdict map result types work through the jointly applied NAT consumer."""
    config.set('set firewall group map ipv4 TRANSLATE match protocol destination-port')
    config.set('set firewall group map ipv4 TRANSLATE result-type address-port')
    config.set('set firewall group map ipv4 TRANSLATE entry web protocol tcp destination-port 53098 result address 192.0.2.2 result port 53099')
    config.set('set nat destination rule 10 inbound-interface dum998 map TRANSLATE')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_TRANSLATE', '53098', '53099')
    assert_firewall_object('map', 'ipv4_map_TRANSLATE', 'ipv4_addr \\. inet_service', '192\\.0\\.2\\.2 \\. 53099')
    assert_firewall_rule('ipv4_nat_prerouting', 10, 'dnat ip to .*map', '@ipv4_map_TRANSLATE')


def test_icmp_and_tcp_flag_group_keys_ipv4_map(config):
    """Compound ICMP and masked TCP-flag keys work in both map and membership objects."""
    config.set('set firewall group map ipv4 ICMP match protocol icmp-type icmp-code')
    config.set('set firewall group map ipv4 ICMP entry ping protocol icmp icmp-type echo-request icmp-code 0')
    config.set('set firewall group map ipv4 TCP match protocol tcp-flags')
    config.set('set firewall group map ipv4 TCP entry syn protocol tcp tcp-flags syn and not ack')
    config.set('set firewall group map ipv4 ICMP result-type verdict')
    config.set('set firewall group map ipv4 ICMP entry ping result action accept')
    config.set('set firewall group map ipv4 TCP result-type verdict')
    config.set('set firewall group map ipv4 TCP entry syn result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_ICMP', 'echo-request', '\\. 0')
    assert_firewall_object('map', 'ipv4_map_TCP', 'tcp_flag', 'syn')


def test_icmp_and_tcp_flag_group_keys_ipv4_match_group(config):
    """Compound ICMP and masked TCP-flag keys work in both map and membership objects."""
    config.set('set firewall group match-group ipv4 ICMP match protocol icmp-type icmp-code')
    config.set('set firewall group match-group ipv4 ICMP entry ping protocol icmp icmp-type echo-request icmp-code 0')
    config.set('set firewall group match-group ipv4 TCP match protocol tcp-flags')
    config.set('set firewall group match-group ipv4 TCP entry syn protocol tcp tcp-flags syn and not ack')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_ICMP', 'echo-request', '\\. 0')
    assert_firewall_object('set', 'ipv4_match_group_TCP', 'tcp_flag', 'syn')


def test_icmp_and_tcp_flag_group_keys_ipv6_map(config):
    """Compound ICMP and masked TCP-flag keys work in both map and membership objects."""
    config.set('set firewall group map ipv6 ICMP match protocol icmp-type icmp-code')
    config.set('set firewall group map ipv6 ICMP entry ping protocol ipv6-icmp icmp-type echo-request icmp-code 0')
    config.set('set firewall group map ipv6 TCP match protocol tcp-flags')
    config.set('set firewall group map ipv6 TCP entry syn protocol tcp tcp-flags syn and not ack')
    config.set('set firewall group map ipv6 ICMP result-type verdict')
    config.set('set firewall group map ipv6 ICMP entry ping result action accept')
    config.set('set firewall group map ipv6 TCP result-type verdict')
    config.set('set firewall group map ipv6 TCP entry syn result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_ICMP', 'echo-request', '\\. 0')
    assert_firewall_object('map', 'ipv6_map_TCP', 'tcp_flag', 'syn')


def test_icmp_and_tcp_flag_group_keys_ipv6_match_group(config):
    """Compound ICMP and masked TCP-flag keys work in both map and membership objects."""
    config.set('set firewall group match-group ipv6 ICMP match protocol icmp-type icmp-code')
    config.set('set firewall group match-group ipv6 ICMP entry ping protocol ipv6-icmp icmp-type echo-request icmp-code 0')
    config.set('set firewall group match-group ipv6 TCP match protocol tcp-flags')
    config.set('set firewall group match-group ipv6 TCP entry syn protocol tcp tcp-flags syn and not ack')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_ICMP', 'echo-request', '\\. 0')
    assert_firewall_object('set', 'ipv6_match_group_TCP', 'tcp_flag', 'syn')


def test_ipv4_map_connection_id(config):
    """Store map connection id and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 CT match connection id')
    config.set('set firewall group map ipv4 CT entry first connection id 100')
    config.set('set firewall group map ipv4 CT result-type verdict')
    config.set('set firewall group map ipv4 CT entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_CT', '100', 'elements')


def test_ipv4_map_connection_zone(config):
    """Reject single-field map connection zone before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 CT match connection zone')
    config.set('set firewall group map ipv4 CT entry first connection zone 3')
    config.set('set firewall group map ipv4 CT result-type verdict')
    config.set('set firewall group map ipv4 CT entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv4_map_connection_helper(config):
    """Store map connection helper and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 CT match connection helper')
    config.set('set firewall group map ipv4 CT entry first connection helper ftp')
    config.set('set firewall group map ipv4 CT result-type verdict')
    config.set('set firewall group map ipv4 CT entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_CT', '"ftp"', 'elements')


def test_ipv4_map_connection_mark(config):
    """Store map connection mark and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 CT match connection mark')
    config.set('set firewall group map ipv4 CT entry first connection mark 42')
    config.set('set firewall group map ipv4 CT result-type verdict')
    config.set('set firewall group map ipv4 CT entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_CT', '(42|0x0*2a)', 'elements')


def test_ipv4_map_connection_original_bytes(config):
    """Reject single-field map connection original bytes before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 CT match connection original bytes')
    config.set('set firewall group map ipv4 CT entry first connection original bytes 1k')
    config.set('set firewall group map ipv4 CT result-type verdict')
    config.set('set firewall group map ipv4 CT entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv4_map_connection_total_packets(config):
    """Reject single-field map connection total packets before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 CT match connection total packets')
    config.set('set firewall group map ipv4 CT entry first connection total packets 10')
    config.set('set firewall group map ipv4 CT result-type verdict')
    config.set('set firewall group map ipv4 CT entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv6_map_connection_zone(config):
    """Reject a standalone IPv6 zone map before nftables swaps its key."""
    config.set('set firewall group map ipv6 CT match connection zone')
    config.set('set firewall group map ipv6 CT entry first connection zone 3')
    config.set('set firewall group map ipv6 CT result-type verdict')
    config.set('set firewall group map ipv6 CT entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv6_map_connection_original_bytes(config):
    """Reject a standalone IPv6 accounting map before nftables swaps its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 CT match connection original bytes')
    config.set('set firewall group map ipv6 CT entry first connection original bytes 1k')
    config.set('set firewall group map ipv6 CT result-type verdict')
    config.set('set firewall group map ipv6 CT entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv6_map_connection_total_packets(config):
    """Reject a standalone IPv6 packet-count map before nftables swaps its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 CT match connection total packets')
    config.set('set firewall group map ipv6 CT entry first connection total packets 10')
    config.set('set firewall group map ipv6 CT result-type verdict')
    config.set('set firewall group map ipv6 CT entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv4_map_connection_five_fields(config):
    """Reject five-field IPv4 conntrack maps whose native listing is corrupted."""
    config.set('set firewall group map ipv4 CT match packet-mark protocol source-port destination-port connection zone')
    config.set('set firewall group map ipv4 CT result-type verdict')
    config.set('set firewall group map ipv4 CT entry first packet-mark 42 protocol udp source-port 53099 destination-port 53098 connection zone 3')
    config.set('set firewall group map ipv4 CT entry first result action accept')

    assert_firewall_commit_rejected(config, 'five-field maps')


def test_ipv6_map_connection_five_fields(config):
    """Reject five-field IPv6 conntrack maps whose native listing is corrupted."""
    config.set('set firewall group map ipv6 CT match packet-mark protocol source-port destination-port connection zone')
    config.set('set firewall group map ipv6 CT result-type verdict')
    config.set('set firewall group map ipv6 CT entry first packet-mark 42 protocol udp source-port 53099 destination-port 53098 connection zone 3')
    config.set('set firewall group map ipv6 CT entry first result action accept')

    assert_firewall_commit_rejected(config, 'five-field maps')


def test_ipv4_map_connection_concatenation(config):
    """A supported two-field IPv4 map retains both original key values."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 CT match connection zone original bytes')
    config.set('set firewall group map ipv4 CT result-type verdict')
    config.set('set firewall group map ipv4 CT entry first connection zone 3 original bytes 1k')
    config.set('set firewall group map ipv4 CT entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_CT', r'3 \. 1024', 'elements')


def test_ipv6_map_connection_concatenation(config):
    """A supported two-field IPv6 map retains both original key values."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 CT match connection zone original bytes')
    config.set('set firewall group map ipv6 CT result-type verdict')
    config.set('set firewall group map ipv6 CT entry first connection zone 3 original bytes 1k')
    config.set('set firewall group map ipv6 CT entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_CT', r'3 \. 1024', 'elements')


def test_ipv4_match_group_connection_id(config):
    """Store match group connection id and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 CT match connection id')
    config.set('set firewall group match-group ipv4 CT entry first connection id 100')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_CT', '100', 'elements')


def test_ipv4_match_group_connection_zone(config):
    """Store match group connection zone and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 CT match connection zone')
    config.set('set firewall group match-group ipv4 CT entry first connection zone 3')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_CT', '3', 'elements')


def test_ipv4_match_group_connection_helper(config):
    """Store match group connection helper and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 CT match connection helper')
    config.set('set firewall group match-group ipv4 CT entry first connection helper ftp')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_CT', '"ftp"', 'elements')


def test_ipv4_match_group_connection_mark(config):
    """Store match group connection mark and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 CT match connection mark')
    config.set('set firewall group match-group ipv4 CT entry first connection mark 42')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_CT', '(42|0x0*2a)', 'elements')


def test_ipv4_match_group_connection_original_bytes(config):
    """Store match group connection original bytes and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 CT match connection original bytes')
    config.set('set firewall group match-group ipv4 CT entry first connection original bytes 1k')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_CT', '1024', 'elements')


def test_ipv4_match_group_connection_total_packets(config):
    """Store match group connection total packets and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 CT match connection total packets')
    config.set('set firewall group match-group ipv4 CT entry first connection total packets 10')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_CT', '10', 'elements')


def test_ipv4_map_packet_type(config):
    """Store IPv4 map packet type and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match packet-type')
    config.set('set firewall group map ipv4 FIELD entry first packet-type host')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', 'host', 'elements')


def test_ipv4_map_inbound_interface(config):
    """Store IPv4 map inbound interface and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match inbound-interface')
    config.set('set firewall group map ipv4 FIELD entry first inbound-interface dum998')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', '"dum998"', 'elements')


def test_ipv4_map_outbound_interface(config):
    """Store IPv4 map outbound interface and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match outbound-interface')
    config.set('set firewall group map ipv4 FIELD entry first outbound-interface dum999')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', '"dum999"', 'elements')


def test_ipv4_map_source_mac(config):
    """Store IPv4 map source mac and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match source-mac')
    config.set('set firewall group map ipv4 FIELD entry first source-mac 02:00:00:00:00:01')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', '02:00:00:00:00:01', 'elements')


def test_ipv4_map_destination_mac(config):
    """Store IPv4 map destination mac and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match destination-mac')
    config.set('set firewall group map ipv4 FIELD entry first destination-mac 02:00:00:00:00:02')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', '02:00:00:00:00:02', 'elements')


def test_ipv4_map_packet_mark(config):
    """Store IPv4 map packet mark and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match packet-mark')
    config.set('set firewall group map ipv4 FIELD entry first packet-mark 42')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', '0x0*2a', 'elements')


def test_ipv4_map_dscp(config):
    """Store IPv4 map dscp and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match dscp')
    config.set('set firewall group map ipv4 FIELD entry first dscp 8')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', '(cs1|0x08)', 'elements')


def test_ipv4_map_protocol(config):
    """Store IPv4 map protocol and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match protocol')
    config.set('set firewall group map ipv4 FIELD entry first protocol tcp')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', 'tcp', 'elements')


def test_ipv4_map_connection_state(config):
    """Store IPv4 map connection state and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection state')
    config.set('set firewall group map ipv4 FIELD entry first connection state established')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', 'established', 'elements')


def test_ipv4_map_connection_status(config):
    """Store IPv4 map connection status and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection status')
    config.set('set firewall group map ipv4 FIELD entry first connection status confirmed')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', 'confirmed', 'elements')


def test_ipv4_map_connection_direction(config):
    """Store IPv4 map connection direction and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection direction')
    config.set('set firewall group map ipv4 FIELD entry first connection direction original')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', 'original', 'elements')


def test_ipv4_map_connection_protocol(config):
    """Store IPv4 map connection protocol and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection protocol')
    config.set('set firewall group map ipv4 FIELD entry first connection protocol udp')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', 'udp', 'elements')


def test_ipv4_map_connection_expiration(config):
    """Store IPv4 map connection expiration and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection expiration')
    config.set('set firewall group map ipv4 FIELD entry first connection expiration 10s')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_FIELD', '10s', 'elements')


def test_ipv4_map_connection_original_zone(config):
    """Reject single-field IPv4 map connection original zone before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection original zone')
    config.set('set firewall group map ipv4 FIELD entry first connection original zone 3')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv4_map_connection_reply_zone(config):
    """Reject single-field IPv4 map connection reply zone before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection reply zone')
    config.set('set firewall group map ipv4 FIELD entry first connection reply zone 3')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv4_map_connection_original_packets(config):
    """Reject single-field IPv4 map connection original packets before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection original packets')
    config.set('set firewall group map ipv4 FIELD entry first connection original packets 10')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv4_map_connection_reply_packets(config):
    """Reject single-field IPv4 map connection reply packets before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection reply packets')
    config.set('set firewall group map ipv4 FIELD entry first connection reply packets 10')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv4_map_connection_reply_bytes(config):
    """Reject single-field IPv4 map connection reply bytes before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection reply bytes')
    config.set('set firewall group map ipv4 FIELD entry first connection reply bytes 1k')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv4_map_connection_total_bytes(config):
    """Reject single-field IPv4 map connection total bytes before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection total bytes')
    config.set('set firewall group map ipv4 FIELD entry first connection total bytes 1k')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv4_map_connection_original_average_packet_size(config):
    """Reject single-field IPv4 map connection original average packet size before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection original average-packet-size')
    config.set('set firewall group map ipv4 FIELD entry first connection original average-packet-size 1k')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv4_map_connection_reply_average_packet_size(config):
    """Reject single-field IPv4 map connection reply average packet size before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection reply average-packet-size')
    config.set('set firewall group map ipv4 FIELD entry first connection reply average-packet-size 1k')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv4_map_connection_total_average_packet_size(config):
    """Reject single-field IPv4 map connection total average packet size before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv4 FIELD match connection total average-packet-size')
    config.set('set firewall group map ipv4 FIELD entry first connection total average-packet-size 1k')
    config.set('set firewall group map ipv4 FIELD result-type verdict')
    config.set('set firewall group map ipv4 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv4_match_group_packet_type(config):
    """Store IPv4 match group packet type and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match packet-type')
    config.set('set firewall group match-group ipv4 FIELD entry first packet-type host')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', 'host', 'elements')


def test_ipv4_match_group_inbound_interface(config):
    """Store IPv4 match group inbound interface and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match inbound-interface')
    config.set('set firewall group match-group ipv4 FIELD entry first inbound-interface dum998')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '"dum998"', 'elements')


def test_ipv4_match_group_outbound_interface(config):
    """Store IPv4 match group outbound interface and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match outbound-interface')
    config.set('set firewall group match-group ipv4 FIELD entry first outbound-interface dum999')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '"dum999"', 'elements')


def test_ipv4_match_group_source_mac(config):
    """Store IPv4 match group source mac and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match source-mac')
    config.set('set firewall group match-group ipv4 FIELD entry first source-mac 02:00:00:00:00:01')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '02:00:00:00:00:01', 'elements')


def test_ipv4_match_group_destination_mac(config):
    """Store IPv4 match group destination mac and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match destination-mac')
    config.set('set firewall group match-group ipv4 FIELD entry first destination-mac 02:00:00:00:00:02')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '02:00:00:00:00:02', 'elements')


def test_ipv4_match_group_packet_mark(config):
    """Store IPv4 match group packet mark and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match packet-mark')
    config.set('set firewall group match-group ipv4 FIELD entry first packet-mark 42')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '0x0*2a', 'elements')


def test_ipv4_match_group_dscp(config):
    """Store IPv4 match group dscp and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match dscp')
    config.set('set firewall group match-group ipv4 FIELD entry first dscp 8')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '(cs1|0x08)', 'elements')


def test_ipv4_match_group_protocol(config):
    """Store IPv4 match group protocol and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match protocol')
    config.set('set firewall group match-group ipv4 FIELD entry first protocol tcp')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', 'tcp', 'elements')


def test_ipv4_match_group_connection_state(config):
    """Store IPv4 match group connection state and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection state')
    config.set('set firewall group match-group ipv4 FIELD entry first connection state established')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', 'established', 'elements')


def test_ipv4_match_group_connection_status(config):
    """Store IPv4 match group connection status and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection status')
    config.set('set firewall group match-group ipv4 FIELD entry first connection status confirmed')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', 'confirmed', 'elements')


def test_ipv4_match_group_connection_direction(config):
    """Store IPv4 match group connection direction and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection direction')
    config.set('set firewall group match-group ipv4 FIELD entry first connection direction original')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', 'original', 'elements')


def test_ipv4_match_group_connection_protocol(config):
    """Store IPv4 match group connection protocol and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection protocol')
    config.set('set firewall group match-group ipv4 FIELD entry first connection protocol udp')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', 'udp', 'elements')


def test_ipv4_match_group_connection_expiration(config):
    """Store IPv4 match group connection expiration and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection expiration')
    config.set('set firewall group match-group ipv4 FIELD entry first connection expiration 10s')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '10s', 'elements')


def test_ipv4_match_group_connection_original_zone(config):
    """Store IPv4 match group connection original zone and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection original zone')
    config.set('set firewall group match-group ipv4 FIELD entry first connection original zone 3')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '\\b3\\b', 'elements')


def test_ipv4_match_group_connection_reply_zone(config):
    """Store IPv4 match group connection reply zone and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection reply zone')
    config.set('set firewall group match-group ipv4 FIELD entry first connection reply zone 3')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '\\b3\\b', 'elements')


def test_ipv4_match_group_connection_original_packets(config):
    """Store IPv4 match group connection original packets and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection original packets')
    config.set('set firewall group match-group ipv4 FIELD entry first connection original packets 10')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '\\b10\\b', 'elements')


def test_ipv4_match_group_connection_reply_packets(config):
    """Store IPv4 match group connection reply packets and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection reply packets')
    config.set('set firewall group match-group ipv4 FIELD entry first connection reply packets 10')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '\\b10\\b', 'elements')


def test_ipv4_match_group_connection_reply_bytes(config):
    """Store IPv4 match group connection reply bytes and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection reply bytes')
    config.set('set firewall group match-group ipv4 FIELD entry first connection reply bytes 1k')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '\\b1024\\b', 'elements')


def test_ipv4_match_group_connection_total_bytes(config):
    """Store IPv4 match group connection total bytes and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection total bytes')
    config.set('set firewall group match-group ipv4 FIELD entry first connection total bytes 1k')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '\\b1024\\b', 'elements')


def test_ipv4_match_group_connection_original_average_packet_size(config):
    """Store IPv4 match group connection original average packet size and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection original average-packet-size')
    config.set('set firewall group match-group ipv4 FIELD entry first connection original average-packet-size 1k')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '\\b1024\\b', 'elements')


def test_ipv4_match_group_connection_reply_average_packet_size(config):
    """Store IPv4 match group connection reply average packet size and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection reply average-packet-size')
    config.set('set firewall group match-group ipv4 FIELD entry first connection reply average-packet-size 1k')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '\\b1024\\b', 'elements')


def test_ipv4_match_group_connection_total_average_packet_size(config):
    """Store IPv4 match group connection total average packet size and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv4 FIELD match connection total average-packet-size')
    config.set('set firewall group match-group ipv4 FIELD entry first connection total average-packet-size 1k')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_FIELD', '\\b1024\\b', 'elements')


def test_ipv6_map_packet_type(config):
    """Store IPv6 map packet type and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match packet-type')
    config.set('set firewall group map ipv6 FIELD entry first packet-type host')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', 'host', 'elements')


def test_ipv6_map_inbound_interface(config):
    """Store IPv6 map inbound interface and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match inbound-interface')
    config.set('set firewall group map ipv6 FIELD entry first inbound-interface dum998')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', '"dum998"', 'elements')


def test_ipv6_map_outbound_interface(config):
    """Store IPv6 map outbound interface and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match outbound-interface')
    config.set('set firewall group map ipv6 FIELD entry first outbound-interface dum999')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', '"dum999"', 'elements')


def test_ipv6_map_source_mac(config):
    """Store IPv6 map source mac and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match source-mac')
    config.set('set firewall group map ipv6 FIELD entry first source-mac 02:00:00:00:00:01')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', '02:00:00:00:00:01', 'elements')


def test_ipv6_map_destination_mac(config):
    """Store IPv6 map destination mac and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match destination-mac')
    config.set('set firewall group map ipv6 FIELD entry first destination-mac 02:00:00:00:00:02')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', '02:00:00:00:00:02', 'elements')


def test_ipv6_map_packet_mark(config):
    """Store IPv6 map packet mark and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match packet-mark')
    config.set('set firewall group map ipv6 FIELD entry first packet-mark 42')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', '0x0*2a', 'elements')


def test_ipv6_map_dscp(config):
    """Store IPv6 map dscp and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match dscp')
    config.set('set firewall group map ipv6 FIELD entry first dscp 8')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', '(cs1|0x08)', 'elements')


def test_ipv6_map_protocol(config):
    """Store IPv6 map protocol and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match protocol')
    config.set('set firewall group map ipv6 FIELD entry first protocol tcp')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', 'tcp', 'elements')


def test_ipv6_map_connection_state(config):
    """Store IPv6 map connection state and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection state')
    config.set('set firewall group map ipv6 FIELD entry first connection state established')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', 'established', 'elements')


def test_ipv6_map_connection_status(config):
    """Store IPv6 map connection status and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection status')
    config.set('set firewall group map ipv6 FIELD entry first connection status confirmed')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', 'confirmed', 'elements')


def test_ipv6_map_connection_direction(config):
    """Store IPv6 map connection direction and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection direction')
    config.set('set firewall group map ipv6 FIELD entry first connection direction original')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', 'original', 'elements')


def test_ipv6_map_connection_protocol(config):
    """Store IPv6 map connection protocol and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection protocol')
    config.set('set firewall group map ipv6 FIELD entry first connection protocol udp')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', 'udp', 'elements')


def test_ipv6_map_connection_expiration(config):
    """Store IPv6 map connection expiration and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection expiration')
    config.set('set firewall group map ipv6 FIELD entry first connection expiration 10s')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_FIELD', '10s', 'elements')


def test_ipv6_map_connection_original_zone(config):
    """Reject single-field IPv6 map connection original zone before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection original zone')
    config.set('set firewall group map ipv6 FIELD entry first connection original zone 3')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv6_map_connection_reply_zone(config):
    """Reject single-field IPv6 map connection reply zone before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection reply zone')
    config.set('set firewall group map ipv6 FIELD entry first connection reply zone 3')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv6_map_connection_original_packets(config):
    """Reject single-field IPv6 map connection original packets before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection original packets')
    config.set('set firewall group map ipv6 FIELD entry first connection original packets 10')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv6_map_connection_reply_packets(config):
    """Reject single-field IPv6 map connection reply packets before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection reply packets')
    config.set('set firewall group map ipv6 FIELD entry first connection reply packets 10')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv6_map_connection_reply_bytes(config):
    """Reject single-field IPv6 map connection reply bytes before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection reply bytes')
    config.set('set firewall group map ipv6 FIELD entry first connection reply bytes 1k')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv6_map_connection_total_bytes(config):
    """Reject single-field IPv6 map connection total bytes before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection total bytes')
    config.set('set firewall group map ipv6 FIELD entry first connection total bytes 1k')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv6_map_connection_original_average_packet_size(config):
    """Reject single-field IPv6 map connection original average packet size before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection original average-packet-size')
    config.set('set firewall group map ipv6 FIELD entry first connection original average-packet-size 1k')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv6_map_connection_reply_average_packet_size(config):
    """Reject single-field IPv6 map connection reply average packet size before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection reply average-packet-size')
    config.set('set firewall group map ipv6 FIELD entry first connection reply average-packet-size 1k')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv6_map_connection_total_average_packet_size(config):
    """Reject single-field IPv6 map connection total average packet size before nftables can corrupt its key."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group map ipv6 FIELD match connection total average-packet-size')
    config.set('set firewall group map ipv6 FIELD entry first connection total average-packet-size 1k')
    config.set('set firewall group map ipv6 FIELD result-type verdict')
    config.set('set firewall group map ipv6 FIELD entry first result action accept')

    assert_firewall_commit_rejected(config, 'incorrect byte order')


def test_ipv6_match_group_packet_type(config):
    """Store IPv6 match group packet type and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match packet-type')
    config.set('set firewall group match-group ipv6 FIELD entry first packet-type host')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', 'host', 'elements')


def test_ipv6_match_group_inbound_interface(config):
    """Store IPv6 match group inbound interface and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match inbound-interface')
    config.set('set firewall group match-group ipv6 FIELD entry first inbound-interface dum998')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '"dum998"', 'elements')


def test_ipv6_match_group_outbound_interface(config):
    """Store IPv6 match group outbound interface and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match outbound-interface')
    config.set('set firewall group match-group ipv6 FIELD entry first outbound-interface dum999')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '"dum999"', 'elements')


def test_ipv6_match_group_source_mac(config):
    """Store IPv6 match group source mac and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match source-mac')
    config.set('set firewall group match-group ipv6 FIELD entry first source-mac 02:00:00:00:00:01')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '02:00:00:00:00:01', 'elements')


def test_ipv6_match_group_destination_mac(config):
    """Store IPv6 match group destination mac and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match destination-mac')
    config.set('set firewall group match-group ipv6 FIELD entry first destination-mac 02:00:00:00:00:02')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '02:00:00:00:00:02', 'elements')


def test_ipv6_match_group_packet_mark(config):
    """Store IPv6 match group packet mark and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match packet-mark')
    config.set('set firewall group match-group ipv6 FIELD entry first packet-mark 42')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '0x0*2a', 'elements')


def test_ipv6_match_group_dscp(config):
    """Store IPv6 match group dscp and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match dscp')
    config.set('set firewall group match-group ipv6 FIELD entry first dscp 8')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '(cs1|0x08)', 'elements')


def test_ipv6_match_group_protocol(config):
    """Store IPv6 match group protocol and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match protocol')
    config.set('set firewall group match-group ipv6 FIELD entry first protocol tcp')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', 'tcp', 'elements')


def test_ipv6_match_group_connection_state(config):
    """Store IPv6 match group connection state and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection state')
    config.set('set firewall group match-group ipv6 FIELD entry first connection state established')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', 'established', 'elements')


def test_ipv6_match_group_connection_status(config):
    """Store IPv6 match group connection status and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection status')
    config.set('set firewall group match-group ipv6 FIELD entry first connection status confirmed')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', 'confirmed', 'elements')


def test_ipv6_match_group_connection_direction(config):
    """Store IPv6 match group connection direction and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection direction')
    config.set('set firewall group match-group ipv6 FIELD entry first connection direction original')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', 'original', 'elements')


def test_ipv6_match_group_connection_protocol(config):
    """Store IPv6 match group connection protocol and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection protocol')
    config.set('set firewall group match-group ipv6 FIELD entry first connection protocol udp')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', 'udp', 'elements')


def test_ipv6_match_group_connection_expiration(config):
    """Store IPv6 match group connection expiration and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection expiration')
    config.set('set firewall group match-group ipv6 FIELD entry first connection expiration 10s')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '10s', 'elements')


def test_ipv6_match_group_connection_original_zone(config):
    """Store IPv6 match group connection original zone and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection original zone')
    config.set('set firewall group match-group ipv6 FIELD entry first connection original zone 3')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '\\b3\\b', 'elements')


def test_ipv6_match_group_connection_reply_zone(config):
    """Store IPv6 match group connection reply zone and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection reply zone')
    config.set('set firewall group match-group ipv6 FIELD entry first connection reply zone 3')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '\\b3\\b', 'elements')


def test_ipv6_match_group_connection_original_packets(config):
    """Store IPv6 match group connection original packets and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection original packets')
    config.set('set firewall group match-group ipv6 FIELD entry first connection original packets 10')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '\\b10\\b', 'elements')


def test_ipv6_match_group_connection_reply_packets(config):
    """Store IPv6 match group connection reply packets and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection reply packets')
    config.set('set firewall group match-group ipv6 FIELD entry first connection reply packets 10')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '\\b10\\b', 'elements')


def test_ipv6_match_group_connection_reply_bytes(config):
    """Store IPv6 match group connection reply bytes and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection reply bytes')
    config.set('set firewall group match-group ipv6 FIELD entry first connection reply bytes 1k')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '\\b1024\\b', 'elements')


def test_ipv6_match_group_connection_total_bytes(config):
    """Store IPv6 match group connection total bytes and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection total bytes')
    config.set('set firewall group match-group ipv6 FIELD entry first connection total bytes 1k')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '\\b1024\\b', 'elements')


def test_ipv6_match_group_connection_original_average_packet_size(config):
    """Store IPv6 match group connection original average packet size and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection original average-packet-size')
    config.set('set firewall group match-group ipv6 FIELD entry first connection original average-packet-size 1k')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '\\b1024\\b', 'elements')


def test_ipv6_match_group_connection_reply_average_packet_size(config):
    """Store IPv6 match group connection reply average packet size and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection reply average-packet-size')
    config.set('set firewall group match-group ipv6 FIELD entry first connection reply average-packet-size 1k')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '\\b1024\\b', 'elements')


def test_ipv6_match_group_connection_total_average_packet_size(config):
    """Store IPv6 match group connection total average packet size and check the installed element value."""
    config.set('set firewall global-options connection-accounting')
    config.set('set firewall group match-group ipv6 FIELD match connection total average-packet-size')
    config.set('set firewall group match-group ipv6 FIELD entry first connection total average-packet-size 1k')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_FIELD', '\\b1024\\b', 'elements')


def test_connection_tuple_groups_ipv4_map_original(config):
    """Stored address/port tuples retain all four components and their own protocol selector."""
    config.set('set firewall group map ipv4 TUPLE match connection protocol')
    config.set('set firewall group map ipv4 TUPLE match connection original source-address destination-address source-port destination-port')
    config.set('set firewall group map ipv4 TUPLE entry first connection protocol tcp')
    config.set('set firewall group map ipv4 TUPLE entry first connection original source-address 192.0.2.1 destination-address 192.0.2.1 source-port 53098 destination-port 53099')
    config.set('set firewall group map ipv4 TUPLE result-type verdict')
    config.set('set firewall group map ipv4 TUPLE entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_TUPLE', '192.0.2.1', '53098', '53099', 'tcp')


def test_connection_tuple_groups_ipv4_map_reply(config):
    """Stored address/port tuples retain all four components and their own protocol selector."""
    config.set('set firewall group map ipv4 TUPLE match connection protocol')
    config.set('set firewall group map ipv4 TUPLE match connection reply source-address destination-address source-port destination-port')
    config.set('set firewall group map ipv4 TUPLE entry first connection protocol tcp')
    config.set('set firewall group map ipv4 TUPLE entry first connection reply source-address 192.0.2.1 destination-address 192.0.2.1 source-port 53098 destination-port 53099')
    config.set('set firewall group map ipv4 TUPLE result-type verdict')
    config.set('set firewall group map ipv4 TUPLE entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv4_map_TUPLE', '192.0.2.1', '53098', '53099', 'tcp')


def test_connection_tuple_groups_ipv4_match_group_original(config):
    """Stored address/port tuples retain all four components and their own protocol selector."""
    config.set('set firewall group match-group ipv4 TUPLE match connection protocol')
    config.set('set firewall group match-group ipv4 TUPLE match connection original source-address destination-address source-port destination-port')
    config.set('set firewall group match-group ipv4 TUPLE entry first connection protocol tcp')
    config.set('set firewall group match-group ipv4 TUPLE entry first connection original source-address 192.0.2.1 destination-address 192.0.2.1 source-port 53098 destination-port 53099')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_TUPLE', '192.0.2.1', '53098', '53099', 'tcp')


def test_connection_tuple_groups_ipv4_match_group_reply(config):
    """Stored address/port tuples retain all four components and their own protocol selector."""
    config.set('set firewall group match-group ipv4 TUPLE match connection protocol')
    config.set('set firewall group match-group ipv4 TUPLE match connection reply source-address destination-address source-port destination-port')
    config.set('set firewall group match-group ipv4 TUPLE entry first connection protocol tcp')
    config.set('set firewall group match-group ipv4 TUPLE entry first connection reply source-address 192.0.2.1 destination-address 192.0.2.1 source-port 53098 destination-port 53099')

    config.commit()

    assert_firewall_object('set', 'ipv4_match_group_TUPLE', '192.0.2.1', '53098', '53099', 'tcp')


def test_connection_tuple_groups_ipv6_map_original(config):
    """Stored address/port tuples retain all four components and their own protocol selector."""
    config.set('set firewall group map ipv6 TUPLE match connection protocol')
    config.set('set firewall group map ipv6 TUPLE match connection original source-address destination-address source-port destination-port')
    config.set('set firewall group map ipv6 TUPLE entry first connection protocol tcp')
    config.set('set firewall group map ipv6 TUPLE entry first connection original source-address 2001:db8::1 destination-address 2001:db8::1 source-port 53098 destination-port 53099')
    config.set('set firewall group map ipv6 TUPLE result-type verdict')
    config.set('set firewall group map ipv6 TUPLE entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_TUPLE', '2001:db8::1', '53098', '53099', 'tcp')


def test_connection_tuple_groups_ipv6_map_reply(config):
    """Stored address/port tuples retain all four components and their own protocol selector."""
    config.set('set firewall group map ipv6 TUPLE match connection protocol')
    config.set('set firewall group map ipv6 TUPLE match connection reply source-address destination-address source-port destination-port')
    config.set('set firewall group map ipv6 TUPLE entry first connection protocol tcp')
    config.set('set firewall group map ipv6 TUPLE entry first connection reply source-address 2001:db8::1 destination-address 2001:db8::1 source-port 53098 destination-port 53099')
    config.set('set firewall group map ipv6 TUPLE result-type verdict')
    config.set('set firewall group map ipv6 TUPLE entry first result action accept')

    config.commit()

    assert_firewall_object('map', 'ipv6_map_TUPLE', '2001:db8::1', '53098', '53099', 'tcp')


def test_connection_tuple_groups_ipv6_match_group_original(config):
    """Stored address/port tuples retain all four components and their own protocol selector."""
    config.set('set firewall group match-group ipv6 TUPLE match connection protocol')
    config.set('set firewall group match-group ipv6 TUPLE match connection original source-address destination-address source-port destination-port')
    config.set('set firewall group match-group ipv6 TUPLE entry first connection protocol tcp')
    config.set('set firewall group match-group ipv6 TUPLE entry first connection original source-address 2001:db8::1 destination-address 2001:db8::1 source-port 53098 destination-port 53099')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_TUPLE', '2001:db8::1', '53098', '53099', 'tcp')


def test_connection_tuple_groups_ipv6_match_group_reply(config):
    """Stored address/port tuples retain all four components and their own protocol selector."""
    config.set('set firewall group match-group ipv6 TUPLE match connection protocol')
    config.set('set firewall group match-group ipv6 TUPLE match connection reply source-address destination-address source-port destination-port')
    config.set('set firewall group match-group ipv6 TUPLE entry first connection protocol tcp')
    config.set('set firewall group match-group ipv6 TUPLE entry first connection reply source-address 2001:db8::1 destination-address 2001:db8::1 source-port 53098 destination-port 53099')

    config.commit()

    assert_firewall_object('set', 'ipv6_match_group_TUPLE', '2001:db8::1', '53098', '53099', 'tcp')
