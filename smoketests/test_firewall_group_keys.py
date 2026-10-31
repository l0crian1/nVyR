"""Live concatenation boundaries for firewall maps and match-groups."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from smoketests.assertions import (
    assert_firewall_object, assert_firewall_rule, assert_firewall_commit_rejected,
)
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_ipv4_map_one_field(config):
    """Install 1 IPv4 key field and verify types, ordered values, and rule lookup."""
    config.set('set firewall group map ipv4 KEYS match source-address')
    config.set('set firewall group map ipv4 KEYS result-type verdict')
    config.set('set firewall group map ipv4 KEYS entry first source-address 192.0.2.1 result action accept')
    config.set('set firewall ipv4 forward filter rule 10 map KEYS')

    config.commit()

    assert_firewall_object(
        'map', 'ipv4_map_KEYS',
        r'type ipv4_addr : verdict\n',
        r'elements = \{ 192\.0\.2\.1 comment "first\|" : accept \}',
    )
    assert_firewall_rule(
        'ipv4_forward', 10,
        r'ip saddr vmap @ipv4_map_KEYS',
    )


def test_ipv4_map_two_fields(config):
    """Install 2 IPv4 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group map ipv4 KEYS match source-address destination-address')
    config.set('set firewall group map ipv4 KEYS result-type verdict')
    config.set('set firewall group map ipv4 KEYS entry first source-address 192.0.2.1 destination-address 198.51.100.2 result action accept')
    config.set('set firewall ipv4 forward filter rule 10 map KEYS')

    config.commit()

    assert_firewall_object(
        'map', 'ipv4_map_KEYS',
        r'type ipv4_addr \. ipv4_addr : verdict\n',
        r'elements = \{ 192\.0\.2\.1 \. 198\.51\.100\.2 comment "first\|" : accept \}',
    )
    assert_firewall_rule(
        'ipv4_forward', 10,
        r'ip saddr \. ip daddr vmap @ipv4_map_KEYS',
    )


def test_ipv4_map_three_fields(config):
    """Install 3 IPv4 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group map ipv4 KEYS match source-address destination-address protocol')
    config.set('set firewall group map ipv4 KEYS result-type verdict')
    config.set('set firewall group map ipv4 KEYS entry first source-address 192.0.2.1 destination-address 198.51.100.2 protocol tcp result action accept')
    config.set('set firewall ipv4 forward filter rule 10 map KEYS')

    config.commit()

    assert_firewall_object(
        'map', 'ipv4_map_KEYS',
        r'type ipv4_addr \. ipv4_addr \. inet_proto : verdict\n',
        r'elements = \{ 192\.0\.2\.1 \. 198\.51\.100\.2 \. tcp comment "first\|" : accept \}',
    )
    assert_firewall_rule(
        'ipv4_forward', 10,
        r'ip saddr \. ip daddr \. meta l4proto vmap @ipv4_map_KEYS',
    )


def test_ipv4_map_four_fields(config):
    """Install 4 IPv4 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group map ipv4 KEYS match source-address destination-address protocol destination-port')
    config.set('set firewall group map ipv4 KEYS result-type verdict')
    config.set('set firewall group map ipv4 KEYS entry first source-address 192.0.2.1 destination-address 198.51.100.2 protocol tcp destination-port 443 result action accept')
    config.set('set firewall ipv4 forward filter rule 10 map KEYS')

    config.commit()

    assert_firewall_object(
        'map', 'ipv4_map_KEYS',
        r'type ipv4_addr \. ipv4_addr \. inet_proto \. inet_service : verdict\n',
        r'elements = \{ 192\.0\.2\.1 \. 198\.51\.100\.2 \. tcp \. 443 comment "first\|" : accept \}',
    )
    assert_firewall_rule(
        'ipv4_forward', 10,
        r'ip saddr \. ip daddr \. meta l4proto \. th dport vmap @ipv4_map_KEYS',
    )


def test_ipv4_map_five_fields(config):
    """Install 5 IPv4 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group map ipv4 KEYS match source-address destination-address protocol destination-port source-port')
    config.set('set firewall group map ipv4 KEYS result-type verdict')
    config.set('set firewall group map ipv4 KEYS entry first source-address 192.0.2.1 destination-address 198.51.100.2 protocol tcp destination-port 443 source-port 12345 result action accept')
    config.set('set firewall ipv4 forward filter rule 10 map KEYS')

    config.commit()

    assert_firewall_object(
        'map', 'ipv4_map_KEYS',
        r'type ipv4_addr \. ipv4_addr \. inet_proto \. inet_service \. inet_service : verdict\n',
        r'elements = \{ 192\.0\.2\.1 \. 198\.51\.100\.2 \. tcp \. 12345 \. 443 comment "first\|" : accept \}',
    )
    assert_firewall_rule(
        'ipv4_forward', 10,
        r'ip saddr \. ip daddr \. meta l4proto \. th sport \. th dport vmap @ipv4_map_KEYS',
    )


def test_ipv4_map_six_fields_rejected(config):
    """Reject six fields before replacing installed firewall objects."""
    config.set('set firewall group map ipv4 KEYS match source-address destination-address protocol source-port destination-port packet-mark')
    config.set('set firewall group map ipv4 KEYS result-type verdict')

    assert_firewall_commit_rejected(config, r'6 key fields \(maximum 5\)')


def test_ipv4_match_group_one_field(config):
    """Install 1 IPv4 key field and verify types, ordered values, and rule lookup."""
    config.set('set firewall group match-group ipv4 KEYS match source-address')
    config.set('set firewall group match-group ipv4 KEYS entry first source-address 192.0.2.1')
    config.set('set firewall ipv4 forward filter rule 10 match-group KEYS action accept')

    config.commit()

    assert_firewall_object(
        'set', 'ipv4_match_group_KEYS',
        r'type ipv4_addr\n',
        r'elements = \{ 192\.0\.2\.1 comment "first\|" \}',
    )
    assert_firewall_rule(
        'ipv4_forward', 10,
        r'ip saddr @ipv4_match_group_KEYS',
    )


def test_ipv4_match_group_two_fields(config):
    """Install 2 IPv4 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group match-group ipv4 KEYS match source-address destination-address')
    config.set('set firewall group match-group ipv4 KEYS entry first source-address 192.0.2.1 destination-address 198.51.100.2')
    config.set('set firewall ipv4 forward filter rule 10 match-group KEYS action accept')

    config.commit()

    assert_firewall_object(
        'set', 'ipv4_match_group_KEYS',
        r'type ipv4_addr \. ipv4_addr\n',
        r'elements = \{ 192\.0\.2\.1 \. 198\.51\.100\.2 comment "first\|" \}',
    )
    assert_firewall_rule(
        'ipv4_forward', 10,
        r'ip saddr \. ip daddr @ipv4_match_group_KEYS',
    )


def test_ipv4_match_group_three_fields(config):
    """Install 3 IPv4 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group match-group ipv4 KEYS match source-address destination-address protocol')
    config.set('set firewall group match-group ipv4 KEYS entry first source-address 192.0.2.1 destination-address 198.51.100.2 protocol tcp')
    config.set('set firewall ipv4 forward filter rule 10 match-group KEYS action accept')

    config.commit()

    assert_firewall_object(
        'set', 'ipv4_match_group_KEYS',
        r'type ipv4_addr \. ipv4_addr \. inet_proto\n',
        r'elements = \{ 192\.0\.2\.1 \. 198\.51\.100\.2 \. tcp comment "first\|" \}',
    )
    assert_firewall_rule(
        'ipv4_forward', 10,
        r'ip saddr \. ip daddr \. meta l4proto @ipv4_match_group_KEYS',
    )


def test_ipv4_match_group_four_fields(config):
    """Install 4 IPv4 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group match-group ipv4 KEYS match source-address destination-address protocol destination-port')
    config.set('set firewall group match-group ipv4 KEYS entry first source-address 192.0.2.1 destination-address 198.51.100.2 protocol tcp destination-port 443')
    config.set('set firewall ipv4 forward filter rule 10 match-group KEYS action accept')

    config.commit()

    assert_firewall_object(
        'set', 'ipv4_match_group_KEYS',
        r'type ipv4_addr \. ipv4_addr \. inet_proto \. inet_service\n',
        r'elements = \{ 192\.0\.2\.1 \. 198\.51\.100\.2 \. tcp \. 443 comment "first\|" \}',
    )
    assert_firewall_rule(
        'ipv4_forward', 10,
        r'ip saddr \. ip daddr \. meta l4proto \. th dport @ipv4_match_group_KEYS',
    )


def test_ipv4_match_group_five_fields(config):
    """Install 5 IPv4 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group match-group ipv4 KEYS match source-address destination-address protocol destination-port source-port')
    config.set('set firewall group match-group ipv4 KEYS entry first source-address 192.0.2.1 destination-address 198.51.100.2 protocol tcp destination-port 443 source-port 12345')
    config.set('set firewall ipv4 forward filter rule 10 match-group KEYS action accept')

    config.commit()

    assert_firewall_object(
        'set', 'ipv4_match_group_KEYS',
        r'type ipv4_addr \. ipv4_addr \. inet_proto \. inet_service \. inet_service\n',
        r'elements = \{ 192\.0\.2\.1 \. 198\.51\.100\.2 \. tcp \. 12345 \. 443 comment "first\|" \}',
    )
    assert_firewall_rule(
        'ipv4_forward', 10,
        r'ip saddr \. ip daddr \. meta l4proto \. th sport \. th dport @ipv4_match_group_KEYS',
    )


def test_ipv4_match_group_six_fields_rejected(config):
    """Reject six fields before replacing installed firewall objects."""
    config.set('set firewall group match-group ipv4 KEYS match source-address destination-address protocol source-port destination-port packet-mark')

    assert_firewall_commit_rejected(config, r'6 key fields \(maximum 5\)')


def test_ipv6_map_one_field(config):
    """Install 1 IPv6 key field and verify types, ordered values, and rule lookup."""
    config.set('set firewall group map ipv6 KEYS match source-address')
    config.set('set firewall group map ipv6 KEYS result-type verdict')
    config.set('set firewall group map ipv6 KEYS entry first source-address 2001:db8::1 result action accept')
    config.set('set firewall ipv6 forward filter rule 10 map KEYS')

    config.commit()

    assert_firewall_object(
        'map', 'ipv6_map_KEYS',
        r'type ipv6_addr : verdict\n',
        r'elements = \{ 2001:db8::1 comment "first\|" : accept \}',
    )
    assert_firewall_rule(
        'ipv6_forward', 10,
        r'ip6 saddr vmap @ipv6_map_KEYS',
    )


def test_ipv6_map_two_fields(config):
    """Install 2 IPv6 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group map ipv6 KEYS match source-address destination-address')
    config.set('set firewall group map ipv6 KEYS result-type verdict')
    config.set('set firewall group map ipv6 KEYS entry first source-address 2001:db8::1 destination-address 2001:db8:1::2 result action accept')
    config.set('set firewall ipv6 forward filter rule 10 map KEYS')

    config.commit()

    assert_firewall_object(
        'map', 'ipv6_map_KEYS',
        r'type ipv6_addr \. ipv6_addr : verdict\n',
        r'elements = \{ 2001:db8::1 \. 2001:db8:1::2 comment "first\|" : accept \}',
    )
    assert_firewall_rule(
        'ipv6_forward', 10,
        r'ip6 saddr \. ip6 daddr vmap @ipv6_map_KEYS',
    )


def test_ipv6_map_three_fields(config):
    """Install 3 IPv6 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group map ipv6 KEYS match source-address destination-address protocol')
    config.set('set firewall group map ipv6 KEYS result-type verdict')
    config.set('set firewall group map ipv6 KEYS entry first source-address 2001:db8::1 destination-address 2001:db8:1::2 protocol tcp result action accept')
    config.set('set firewall ipv6 forward filter rule 10 map KEYS')

    config.commit()

    assert_firewall_object(
        'map', 'ipv6_map_KEYS',
        r'type ipv6_addr \. ipv6_addr \. inet_proto : verdict\n',
        r'elements = \{ 2001:db8::1 \. 2001:db8:1::2 \. tcp comment "first\|" : accept \}',
    )
    assert_firewall_rule(
        'ipv6_forward', 10,
        r'ip6 saddr \. ip6 daddr \. meta l4proto vmap @ipv6_map_KEYS',
    )


def test_ipv6_map_four_fields(config):
    """Install 4 IPv6 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group map ipv6 KEYS match source-address destination-address protocol destination-port')
    config.set('set firewall group map ipv6 KEYS result-type verdict')
    config.set('set firewall group map ipv6 KEYS entry first source-address 2001:db8::1 destination-address 2001:db8:1::2 protocol tcp destination-port 443 result action accept')
    config.set('set firewall ipv6 forward filter rule 10 map KEYS')

    config.commit()

    assert_firewall_object(
        'map', 'ipv6_map_KEYS',
        r'type ipv6_addr \. ipv6_addr \. inet_proto \. inet_service : verdict\n',
        r'elements = \{ 2001:db8::1 \. 2001:db8:1::2 \. tcp \. 443 comment "first\|" : accept \}',
    )
    assert_firewall_rule(
        'ipv6_forward', 10,
        r'ip6 saddr \. ip6 daddr \. meta l4proto \. th dport vmap @ipv6_map_KEYS',
    )


def test_ipv6_map_five_fields(config):
    """Install 5 IPv6 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group map ipv6 KEYS match source-address destination-address protocol destination-port source-port')
    config.set('set firewall group map ipv6 KEYS result-type verdict')
    config.set('set firewall group map ipv6 KEYS entry first source-address 2001:db8::1 destination-address 2001:db8:1::2 protocol tcp destination-port 443 source-port 12345 result action accept')
    config.set('set firewall ipv6 forward filter rule 10 map KEYS')

    config.commit()

    assert_firewall_object(
        'map', 'ipv6_map_KEYS',
        r'type ipv6_addr \. ipv6_addr \. inet_proto \. inet_service \. inet_service : verdict\n',
        r'elements = \{ 2001:db8::1 \. 2001:db8:1::2 \. tcp \. 12345 \. 443 comment "first\|" : accept \}',
    )
    assert_firewall_rule(
        'ipv6_forward', 10,
        r'ip6 saddr \. ip6 daddr \. meta l4proto \. th sport \. th dport vmap @ipv6_map_KEYS',
    )


def test_ipv6_map_six_fields_rejected(config):
    """Reject six fields before replacing installed firewall objects."""
    config.set('set firewall group map ipv6 KEYS match source-address destination-address protocol source-port destination-port packet-mark')
    config.set('set firewall group map ipv6 KEYS result-type verdict')

    assert_firewall_commit_rejected(config, r'6 key fields \(maximum 5\)')


def test_ipv6_match_group_one_field(config):
    """Install 1 IPv6 key field and verify types, ordered values, and rule lookup."""
    config.set('set firewall group match-group ipv6 KEYS match source-address')
    config.set('set firewall group match-group ipv6 KEYS entry first source-address 2001:db8::1')
    config.set('set firewall ipv6 forward filter rule 10 match-group KEYS action accept')

    config.commit()

    assert_firewall_object(
        'set', 'ipv6_match_group_KEYS',
        r'type ipv6_addr\n',
        r'elements = \{ 2001:db8::1 comment "first\|" \}',
    )
    assert_firewall_rule(
        'ipv6_forward', 10,
        r'ip6 saddr @ipv6_match_group_KEYS',
    )


def test_ipv6_match_group_two_fields(config):
    """Install 2 IPv6 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group match-group ipv6 KEYS match source-address destination-address')
    config.set('set firewall group match-group ipv6 KEYS entry first source-address 2001:db8::1 destination-address 2001:db8:1::2')
    config.set('set firewall ipv6 forward filter rule 10 match-group KEYS action accept')

    config.commit()

    assert_firewall_object(
        'set', 'ipv6_match_group_KEYS',
        r'type ipv6_addr \. ipv6_addr\n',
        r'elements = \{ 2001:db8::1 \. 2001:db8:1::2 comment "first\|" \}',
    )
    assert_firewall_rule(
        'ipv6_forward', 10,
        r'ip6 saddr \. ip6 daddr @ipv6_match_group_KEYS',
    )


def test_ipv6_match_group_three_fields(config):
    """Install 3 IPv6 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group match-group ipv6 KEYS match source-address destination-address protocol')
    config.set('set firewall group match-group ipv6 KEYS entry first source-address 2001:db8::1 destination-address 2001:db8:1::2 protocol tcp')
    config.set('set firewall ipv6 forward filter rule 10 match-group KEYS action accept')

    config.commit()

    assert_firewall_object(
        'set', 'ipv6_match_group_KEYS',
        r'type ipv6_addr \. ipv6_addr \. inet_proto\n',
        r'elements = \{ 2001:db8::1 \. 2001:db8:1::2 \. tcp comment "first\|" \}',
    )
    assert_firewall_rule(
        'ipv6_forward', 10,
        r'ip6 saddr \. ip6 daddr \. meta l4proto @ipv6_match_group_KEYS',
    )


def test_ipv6_match_group_four_fields(config):
    """Install 4 IPv6 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group match-group ipv6 KEYS match source-address destination-address protocol destination-port')
    config.set('set firewall group match-group ipv6 KEYS entry first source-address 2001:db8::1 destination-address 2001:db8:1::2 protocol tcp destination-port 443')
    config.set('set firewall ipv6 forward filter rule 10 match-group KEYS action accept')

    config.commit()

    assert_firewall_object(
        'set', 'ipv6_match_group_KEYS',
        r'type ipv6_addr \. ipv6_addr \. inet_proto \. inet_service\n',
        r'elements = \{ 2001:db8::1 \. 2001:db8:1::2 \. tcp \. 443 comment "first\|" \}',
    )
    assert_firewall_rule(
        'ipv6_forward', 10,
        r'ip6 saddr \. ip6 daddr \. meta l4proto \. th dport @ipv6_match_group_KEYS',
    )


def test_ipv6_match_group_five_fields(config):
    """Install 5 IPv6 key fields and verify types, ordered values, and rule lookup."""
    config.set('set firewall group match-group ipv6 KEYS match source-address destination-address protocol destination-port source-port')
    config.set('set firewall group match-group ipv6 KEYS entry first source-address 2001:db8::1 destination-address 2001:db8:1::2 protocol tcp destination-port 443 source-port 12345')
    config.set('set firewall ipv6 forward filter rule 10 match-group KEYS action accept')

    config.commit()

    assert_firewall_object(
        'set', 'ipv6_match_group_KEYS',
        r'type ipv6_addr \. ipv6_addr \. inet_proto \. inet_service \. inet_service\n',
        r'elements = \{ 2001:db8::1 \. 2001:db8:1::2 \. tcp \. 12345 \. 443 comment "first\|" \}',
    )
    assert_firewall_rule(
        'ipv6_forward', 10,
        r'ip6 saddr \. ip6 daddr \. meta l4proto \. th sport \. th dport @ipv6_match_group_KEYS',
    )


def test_ipv6_match_group_six_fields_rejected(config):
    """Reject six fields before replacing installed firewall objects."""
    config.set('set firewall group match-group ipv6 KEYS match source-address destination-address protocol source-port destination-port packet-mark')

    assert_firewall_commit_rejected(config, r'6 key fields \(maximum 5\)')


def test_ipv6_map_exactly_64_bytes(config):
    """Accept four 16-byte fields at the exact 64-byte limit."""
    config.set('set firewall group map ipv6 KEYS match source-address destination-address inbound-interface outbound-interface')
    config.set('set firewall group map ipv6 KEYS result-type verdict')
    config.set('set firewall group map ipv6 KEYS entry first source-address 2001:db8::1 destination-address 2001:db8:1::2 inbound-interface dum998 outbound-interface dum999 result action accept')
    config.set('set firewall ipv6 forward filter rule 10 map KEYS')

    config.commit()

    assert_firewall_object(
        'map', 'ipv6_map_KEYS',
        r'type ifname \. ifname \. ipv6_addr \. ipv6_addr : verdict\n',
        r'"dum998" \. "dum999" \. 2001:db8::1 \. 2001:db8:1::2 comment "first\|" : accept',
    )
    assert_firewall_rule(
        'ipv6_forward', 10,
        r'iifname \. oifname \. ip6 saddr \. ip6 daddr vmap @ipv6_map_KEYS',
    )


def test_ipv6_map_over_64_bytes_rejected(config):
    """Reject five otherwise-valid fields totaling 68 bytes."""
    config.set('set firewall group map ipv6 KEYS match source-address destination-address inbound-interface outbound-interface packet-mark')
    config.set('set firewall group map ipv6 KEYS result-type verdict')

    assert_firewall_commit_rejected(
        config,
        r'(?s)Flow group key size is 68 bytes \(maximum 64 bytes\).*'
        r'Parameter sizes:.*inbound-interface\s+16 bytes.*outbound-interface\s+16 bytes.*'
        r'source-address\s+16 bytes.*destination-address\s+16 bytes.*packet-mark\s+4 bytes',
    )


def test_ipv6_match_group_exactly_64_bytes(config):
    """Accept four 16-byte fields at the exact 64-byte limit."""
    config.set('set firewall group match-group ipv6 KEYS match source-address destination-address inbound-interface outbound-interface')
    config.set('set firewall group match-group ipv6 KEYS entry first source-address 2001:db8::1 destination-address 2001:db8:1::2 inbound-interface dum998 outbound-interface dum999')
    config.set('set firewall ipv6 forward filter rule 10 match-group KEYS action accept')

    config.commit()

    assert_firewall_object(
        'set', 'ipv6_match_group_KEYS',
        r'type ifname \. ifname \. ipv6_addr \. ipv6_addr\n',
        r'"dum998" \. "dum999" \. 2001:db8::1 \. 2001:db8:1::2',
    )
    assert_firewall_rule(
        'ipv6_forward', 10,
        r'iifname \. oifname \. ip6 saddr \. ip6 daddr @ipv6_match_group_KEYS',
    )


def test_ipv6_match_group_over_64_bytes_rejected(config):
    """Reject five otherwise-valid fields totaling 68 bytes."""
    config.set('set firewall group match-group ipv6 KEYS match source-address destination-address inbound-interface outbound-interface packet-mark')

    assert_firewall_commit_rejected(
        config,
        r'(?s)Flow group key size is 68 bytes \(maximum 64 bytes\).*'
        r'Parameter sizes:.*inbound-interface\s+16 bytes.*outbound-interface\s+16 bytes.*'
        r'source-address\s+16 bytes.*destination-address\s+16 bytes.*packet-mark\s+4 bytes',
    )
