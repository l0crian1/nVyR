"""Native singleton inclusion, dependency updates and validation checks."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_equal, assert_not_equal, assert_raises, assert_firewall_object,
    assert_firewall_commit_rejected, firewall_object_handle,
)
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_mac_inclusion(config):
    """Repeated MACs from a shared child are deduplicated in the native parent."""
    config.set('set firewall group mac-group DEVICES address 02:00:00:00:00:01')
    config.set('set firewall group mac-group SITE include-group DEVICES')
    config.set('set firewall group mac-group ALLOWED include-group DEVICES include-group SITE address 02:00:00:00:00:02')
    config.commit()

    output = assert_firewall_object('set', 'mac_group_ALLOWED', '02:00:00:00:00:01', '02:00:00:00:00:02')
    assert_equal(output.count('02:00:00:00:00:01'), 1)


def test_inclusion_rejects_self_reference(config):
    """A self-reference fails verification without altering the installed firewall."""
    config.set('set firewall group port-group SELF include-group SELF')
    assert_firewall_commit_rejected(config, 'SELF -> SELF')


def test_inclusion_rejects_cycle(config):
    """An indirect cycle reports its path instead of recursing indefinitely."""
    config.set('set firewall group port-group FIRST include-group SECOND')
    config.set('set firewall group port-group SECOND include-group THIRD')
    config.set('set firewall group port-group THIRD include-group FIRST')
    assert_firewall_commit_rejected(config, 'circular include-group reference')


def test_inclusion_depth_boundary(config):
    """Eight inclusion links work; a ninth link is rejected with the full path."""
    config.set('set firewall group port-group LEVEL0 port 443')
    config.set('set firewall group port-group LEVEL1 include-group LEVEL0')
    config.set('set firewall group port-group LEVEL2 include-group LEVEL1')
    config.set('set firewall group port-group LEVEL3 include-group LEVEL2')
    config.set('set firewall group port-group LEVEL4 include-group LEVEL3')
    config.set('set firewall group port-group LEVEL5 include-group LEVEL4')
    config.set('set firewall group port-group LEVEL6 include-group LEVEL5')
    config.set('set firewall group port-group LEVEL7 include-group LEVEL6')
    config.set('set firewall group port-group LEVEL8 include-group LEVEL7')
    config.commit()

    assert_firewall_object('set', 'port_group_LEVEL8', '443')

    config.set('set firewall group port-group LEVEL9 include-group LEVEL8')
    assert_firewall_commit_rejected(config, 'exceeds 8 levels: LEVEL9 -> LEVEL8.*LEVEL0')


def test_inclusion_rejects_other_family(config):
    """An IPv6 group cannot satisfy an IPv4 include-group reference."""
    config.set('set firewall group address-group ipv6 HOSTS address 2001:db8::1')
    config.set('set firewall group address-group ipv4 PARENT include-group HOSTS')
    assert_firewall_commit_rejected(config, 'HOSTS')


def test_inclusion_rejects_other_type(config):
    """An unrelated group with the same name cannot satisfy a port inclusion."""
    config.set('set firewall group mac-group DEVICES address 02:00:00:00:00:01')
    config.set('set firewall group port-group PARENT include-group DEVICES')
    assert_firewall_commit_rejected(config, 'DEVICES')


def test_inclusion_rejects_dynamic_source(config):
    """Learned membership cannot be copied into a static parent."""
    config.set('set firewall group address-group ipv4 LEARNED dynamic')
    config.set('set firewall group address-group ipv4 PARENT include-group LEARNED')
    assert_firewall_commit_rejected(config, 'cannot include dynamic or geoip')


def test_inclusion_rejects_dynamic_parent(config):
    """One group cannot mix runtime learning and included static members."""
    config.set('set firewall group address-group ipv4 CHILD address 192.0.2.1')
    config.set('set firewall group address-group ipv4 PARENT dynamic include-group CHILD')
    assert_firewall_commit_rejected(config, 'include-group cannot be combined')


def test_inclusion_rejects_geoip_source(config):
    """GeoIP inclusions fail before any database download or ruleset change."""
    config.set('set firewall group address-group ipv4 GEO geoip country US')
    config.set('set firewall group address-group ipv4 PARENT include-group GEO')
    assert_firewall_commit_rejected(config, 'cannot include dynamic or geoip')


def test_inclusion_rejects_geoip_parent(config):
    """GeoIP refresh must not own a parent with configured inclusion sources."""
    config.set('set firewall group address-group ipv4 CHILD address 192.0.2.1')
    config.set('set firewall group address-group ipv4 PARENT geoip country US include-group CHILD')
    assert_firewall_commit_rejected(config, 'include-group cannot be combined')


def test_configured_address_inclusion_ipv4(config):
    """Nested IPv4 membership expands members, then a child edit updates every consumer."""
    config.set('set firewall group address-group ipv4 HOSTS address 127.0.0.2')
    config.set('set firewall group address-group ipv4 SITE include-group HOSTS')
    config.set('set firewall group address-group ipv4 ALLOWED include-group HOSTS include-group SITE address 192.0.2.1')
    config.set('set firewall ipv4 name INNER rule 10 source-address-group ALLOWED action drop')
    config.set('set firewall ipv4 name OUTER rule 10 action jump jump-target INNER')
    config.set('set firewall ipv4 output filter rule 10 outbound-interface lo action jump jump-target OUTER')
    config.set('set firewall group port-group UNRELATED port 443 counter')
    config.commit()

    assert_firewall_object('set', 'ipv4_address_group_ALLOWED', '127.0.0.2', '192.0.2.1')
    parent = firewall_object_handle('set', 'ipv4_address_group_ALLOWED')
    caller = firewall_object_handle('chain', 'ipv4_name_OUTER')
    unrelated = firewall_object_handle('set', 'port_group_UNRELATED')

    # Editing only the leaf group must rebuild both parent sets and nested callers.
    config.delete('delete firewall group address-group ipv4 HOSTS address 127.0.0.2')
    config.set('set firewall group address-group ipv4 HOSTS address 192.0.2.2')
    config.commit()

    assert_firewall_object('set', 'ipv4_address_group_ALLOWED', '192.0.2.2', absent=('127.0.0.2',))
    assert_not_equal(firewall_object_handle('set', 'ipv4_address_group_ALLOWED'), parent)
    assert_not_equal(firewall_object_handle('chain', 'ipv4_name_OUTER'), caller)
    assert_equal(firewall_object_handle('set', 'port_group_UNRELATED'), unrelated)


def test_configured_address_inclusion_ipv6(config):
    """IPv6 parents combine local and included members and refresh installed members."""
    config.set('set firewall group address-group ipv6 HOSTS address ::1')
    config.set('set firewall group address-group ipv6 SITE include-group HOSTS')
    config.set('set firewall group address-group ipv6 ALLOWED include-group SITE address 2001:db8::1')
    config.set('set firewall ipv6 output filter rule 10 outbound-interface lo destination-address-group ALLOWED action drop')
    config.commit()

    assert_firewall_object('set', 'ipv6_address_group_ALLOWED', '::1', '2001:db8::1')

    config.delete('delete firewall group address-group ipv6 HOSTS address ::1')
    config.set('set firewall group address-group ipv6 HOSTS address 2001:db8::2')
    config.commit()

    assert_firewall_object('set', 'ipv6_address_group_ALLOWED', '2001:db8::2')


def test_configured_interface_inclusion(config):
    """Interface inclusion expands names into the parent used by an output rule."""
    config.set('set firewall group interface-group LOOPBACK interface lo')
    config.set('set firewall group interface-group LOCAL include-group LOOPBACK interface dum998')
    config.set('set firewall ipv4 output filter rule 10 outbound-interface-group LOCAL protocol udp destination-port 53098 action drop')
    config.commit()

    assert_firewall_object('set', 'interface_group_LOCAL', '"lo"', '"dum998"')

    config.delete('delete firewall group interface-group LOCAL include-group LOOPBACK')
    config.commit()

    assert_firewall_object('set', 'interface_group_LOCAL', '"dum998"', absent=('"lo"',))


def test_configured_port_inclusion_and_reference_removal(config):
    """Port ranges merge; removing one inclusion preserves the other dependency."""
    config.set('set firewall group port-group WEB port 443')
    config.set('set firewall group port-group TEST port 53097-53099')
    config.set('set firewall group port-group ALLOWED include-group WEB include-group TEST port 53098')
    config.set('set firewall ipv4 output filter rule 10 outbound-interface lo protocol udp destination-port-group ALLOWED action drop')
    config.commit()

    assert_firewall_object('set', 'port_group_ALLOWED', '443', '53097-53099')
    with assert_raises(RouterError, match='referenced'):
        config.delete('delete firewall group port-group WEB')

    config.delete('delete firewall group port-group ALLOWED include-group TEST')
    config.delete('delete firewall group port-group ALLOWED port 53098')
    config.delete('delete firewall group port-group TEST')
    config.commit()

    assert_firewall_object('set', 'port_group_ALLOWED', '443', absent=('53098',))
    with assert_raises(RouterError, match='referenced'):
        config.delete('delete firewall group port-group WEB')
