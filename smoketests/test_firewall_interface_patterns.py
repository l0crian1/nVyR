"""Native interface prefixes in rules, groups and zones."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_raises, assert_firewall_object, assert_firewall_commit_rejected, assert_firewall_rule,
)
from smoketests.firewall_support import firewall_environment, firewall_suite, vrf_environment, firewall_vrf_suite


def test_zone_prefix_rejects_exact_member_in_another_zone(config):
    """Ownership is checked against possible names, not just existing interfaces."""
    config.set('set firewall zone VPN interface wg*')
    config.set('set firewall zone OTHER interface wg20')
    assert_firewall_commit_rejected(config, 'already belongs to zone')


def test_zone_prefix_rejects_nested_prefix_in_another_zone(config):
    """A more specific prefix cannot steal part of another zone's membership."""
    config.set('set firewall zone VPN interface wg*')
    config.set('set firewall zone OTHER interface wg2*')
    assert_firewall_commit_rejected(config, 'already belongs to zone')


def test_flowtable_prefix_without_existing_interface(config):
    """A native prefix may subscribe before any matching device exists."""
    config.set('set firewall flowtable FUTURE interface nvfuture*')
    config.commit()

    assert_firewall_object('flowtable', 'flowtable_FUTURE', 'nvfuture\\*')


def test_flowtable_prefix_rejects_another_tables_overlapping_prefix(config):
    """Two tables cannot claim the same future ingress device at equal priority."""
    config.set('set firewall flowtable FIRST interface nvfuture*')
    config.set('set firewall flowtable SECOND interface nvfuture1*')

    assert_firewall_commit_rejected(config, 'same ingress priority cannot share interfaces')


def test_flowtable_exact_name_without_existing_interface(config):
    """An exact name may subscribe before its device exists, just like a prefix."""
    config.set('set firewall flowtable FUTURE interface nvfuture0')
    config.commit()

    assert_firewall_object('flowtable', 'flowtable_FUTURE', 'nvfuture0')


def test_map_interface_key_rejects_prefix(config):
    """User-defined map keys remain exact, independent of generated zone maps."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set firewall group map ipv4 EXACT entry one inbound-interface wg*')


def test_match_group_interface_key_rejects_prefix(config):
    """Match-group keys do not accept interface patterns."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set firewall group match-group ipv4 EXACT entry one inbound-interface wg*')


def test_interface_prefix_rejects_bare_wildcard(config):
    """A selector must have a nonempty prefix instead of matching every device."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set firewall zone ALL interface *')


def test_ipv4_prefix_reapplies_on_member_vrf_change(config, vrf_environment):
    """A wildcard consumer switches to slave matching when its member joins a VRF."""
    config.set('set firewall ipv4 input filter rule 10 inbound-interface dum998* action accept')
    config.commit()
    assert_firewall_rule('ipv4_input', 10, 'iifname.*dum998', absent=('sdifname',))

    config.set('set interfaces dummy dum998 vrf NVYRFWSMOKE')
    config.commit()
    assert_firewall_rule('ipv4_input', 10, 'sdifname.*dum998')

    config.delete('delete interfaces dummy dum998 vrf')
    config.commit()
    assert_firewall_rule('ipv4_input', 10, 'iifname.*dum998', absent=('sdifname',))


def test_ipv6_negative_prefix_reapplies_on_member_vrf_change(config, vrf_environment):
    """Negated IPv6 prefixes retain the same VRF dependency behavior."""
    config.set('set firewall ipv6 input filter rule 10 inbound-interface not dum998* action accept')
    config.commit()

    config.set('set interfaces dummy dum998 vrf NVYRFWSMOKE')
    config.commit()
    assert_firewall_rule('ipv6_input', 10, 'sdifname !=.*dum998')

    config.delete('delete interfaces dummy dum998 vrf')
    config.commit()
    assert_firewall_rule('ipv6_input', 10, 'iifname !=.*dum998', absent=('sdifname',))
