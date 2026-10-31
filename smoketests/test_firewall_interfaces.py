"""Linux link groups and VRF-aware INPUT matching through the configuration API."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from smoketests.assertions import (
    assert_equal, assert_not_equal,
    assert_firewall_rule, assert_firewall_object, assert_firewall_commit_rejected, firewall_object_handle,
)
from smoketests.firewall_support import firewall_environment, firewall_suite, vrf_environment, firewall_vrf_suite


def test_ipv4_member_change_reapplies_input_and_preserves_output(config, vrf_environment):
    """Only an interface edit is needed to rebuild its INPUT consumer."""
    config.set('set firewall ipv4 input filter rule 10 inbound-interface dum998 action accept')
    config.set('set firewall ipv4 output filter rule 10 outbound-interface dum999 action accept')
    config.commit()
    original_input = firewall_object_handle('chain', 'ipv4_input')
    original_output = firewall_object_handle('chain', 'ipv4_output')

    config.set('set interfaces dummy dum998 vrf NVYRFWSMOKE')
    config.commit()
    assert_firewall_rule('ipv4_input', 10, 'sdifname.*dum998')
    assert_not_equal(firewall_object_handle('chain', 'ipv4_input'), original_input)
    assert_equal(firewall_object_handle('chain', 'ipv4_output'), original_output)

    # Detaching must restore the ordinary expression without editing the firewall.
    config.delete('delete interfaces dummy dum998 vrf')
    config.commit()
    assert_firewall_rule('ipv4_input', 10, 'iifname.*dum998', absent=('sdifname',))


def test_ipv6_member_change_reapplies_input_and_preserves_output(config, vrf_environment):
    """IPv6 uses the same reapply contract, including a negated member match."""
    config.set('set firewall ipv6 input filter rule 10 inbound-interface not dum998 action accept')
    config.set('set firewall ipv6 output filter rule 10 outbound-interface dum999 action accept')
    config.commit()
    output = firewall_object_handle('chain', 'ipv6_output')

    config.set('set interfaces dummy dum998 vrf NVYRFWSMOKE')
    config.commit()
    assert_firewall_rule('ipv6_input', 10, 'sdifname !=.*dum998')
    assert_equal(firewall_object_handle('chain', 'ipv6_output'), output)

    config.delete('delete interfaces dummy dum998 vrf')
    config.commit()
    assert_firewall_rule('ipv6_input', 10, 'iifname !=.*dum998', absent=('sdifname',))


def test_ipv4_vrf_interface_group_and_nested_jump(config, vrf_environment):
    """A declared group retains one shared set; INPUT changes only its lookup."""
    config.set('set firewall group interface-group MEMBERS interface dum998 vrf')
    config.set('set firewall ipv4 name BOTTOM rule 10 inbound-interface-group MEMBERS action accept')
    config.set('set firewall ipv4 name TOP rule 10 action jump jump-target BOTTOM')
    config.set('set firewall ipv4 input filter rule 10 action jump jump-target TOP')
    config.commit()
    assert_firewall_rule('ipv4_name_BOTTOM', 10, 'sdifname @interface_group_MEMBERS')

    # A shared native chain cannot switch its expression depending on its caller.
    config.set('set firewall ipv4 forward filter rule 10 action jump jump-target TOP')
    assert_firewall_commit_rejected(config, 'VRF-aware inbound matches cannot be shared')


def test_ipv6_vrf_interface_group_and_nested_jump(config, vrf_environment):
    """Negated declared groups inherit INPUT through nested IPv6 jumps."""
    config.set('set firewall group interface-group MEMBERS interface dum998 vrf')
    config.set('set firewall ipv6 name BOTTOM rule 10 inbound-interface-group not MEMBERS action accept')
    config.set('set firewall ipv6 name TOP rule 10 action jump jump-target BOTTOM')
    config.set('set firewall ipv6 input filter rule 10 action jump jump-target TOP')
    config.commit()
    assert_firewall_rule('ipv6_name_BOTTOM', 10, 'sdifname != @interface_group_MEMBERS')

    config.set('set firewall ipv6 forward filter rule 10 action jump jump-target TOP')
    assert_firewall_commit_rejected(config, 'VRF-aware inbound matches cannot be shared')


def test_ipv4_link_group_matching(config):
    """Install positive multi-value and negative Linux link-group matches."""
    config.set('set interfaces dummy dum998 link-group 41002')
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 inbound-link-group 41002 inbound-link-group 41003 outbound-link-group not 41004 action accept')
    config.commit()
    assert_firewall_rule('ipv4_forward', 10, r'iifgroup \{ 41002, 41003 \}', 'oifgroup != 41004')


def test_ipv6_link_group_matching(config):
    """The same device groups apply to IPv6 packet metadata."""
    config.set('set interfaces dummy dum998 link-group 41002')
    config.set('set firewall ipv6 forward filter rule 10 inbound-interface dum998 inbound-link-group 41002 outbound-link-group not 41004 action accept')
    config.commit()
    assert_firewall_rule('ipv6_forward', 10, 'iifgroup 41002', 'oifgroup != 41004')


def test_input_outbound_link_group_is_rejected(config):
    """INPUT cannot provide an outbound device, including a per-key allowance."""
    config.set('set firewall ipv4 input filter rule 10 inbound-interface dum998 limit rate packets 10/s per outbound-link-group action accept')
    assert_firewall_commit_rejected(config, 'outbound-link-group in input')


def test_ipv4_link_groups_in_maps_sets_and_limits(config):
    """Shared keys and per-key limits use the same numeric device group type."""
    config.set('set firewall group map ipv4 INBOUND match inbound-link-group')
    config.set('set firewall group map ipv4 INBOUND result-type verdict')
    config.set('set firewall group map ipv4 INBOUND entry one inbound-link-group 41002 result action accept')
    config.set('set firewall group match-group ipv4 OUTBOUND match outbound-link-group')
    config.set('set firewall group match-group ipv4 OUTBOUND entry one outbound-link-group 41003')
    config.set('set firewall ipv4 forward filter rule 10 inbound-interface dum998 map INBOUND match-group OUTBOUND')
    config.set('set firewall ipv4 forward filter rule 20 inbound-interface dum998 limit rate packets 10/s per inbound-link-group and outbound-link-group action accept')
    config.commit()

    assert_firewall_rule('ipv4_forward', 10, 'iifgroup vmap @ipv4_map_INBOUND', 'oifgroup @ipv4_match_group_OUTBOUND')
    assert_firewall_rule('ipv4_forward', 20, 'iifgroup . oifgroup limit rate')
    assert_firewall_object('map', 'ipv4_map_INBOUND', 'type devgroup : verdict')


def test_ipv6_link_groups_in_maps_sets_and_limits(config):
    """IPv6 rules reuse link-group maps, membership sets and keyed allowances."""
    config.set('set firewall group map ipv6 INBOUND match inbound-link-group')
    config.set('set firewall group map ipv6 INBOUND result-type verdict')
    config.set('set firewall group map ipv6 INBOUND entry one inbound-link-group 41002 result action accept')
    config.set('set firewall group match-group ipv6 OUTBOUND match outbound-link-group')
    config.set('set firewall group match-group ipv6 OUTBOUND entry one outbound-link-group 41003')
    config.set('set firewall ipv6 forward filter rule 10 inbound-interface dum998 map INBOUND match-group OUTBOUND')
    config.set('set firewall ipv6 forward filter rule 20 inbound-interface dum998 limit rate packets 10/s per inbound-link-group and outbound-link-group action accept')
    config.commit()

    assert_firewall_rule('ipv6_forward', 10, 'iifgroup vmap @ipv6_map_INBOUND', 'oifgroup @ipv6_match_group_OUTBOUND')
    assert_firewall_rule('ipv6_forward', 20, 'iifgroup . oifgroup limit rate')
    assert_firewall_object('map', 'ipv6_map_INBOUND', 'type devgroup : verdict')


def test_output_inbound_link_group_is_rejected(config):
    """OUTPUT cannot provide an incoming device through a map either."""
    config.set('set firewall group map ipv6 LINKS match inbound-link-group')
    config.set('set firewall group map ipv6 LINKS result-type verdict')
    config.set('set firewall group map ipv6 LINKS entry one inbound-link-group 41002 result action accept')
    config.set('set firewall ipv6 output filter rule 10 outbound-interface dum998 map LINKS')
    assert_firewall_commit_rejected(config, 'inbound-link-group is unavailable in output')


def test_zone_cannot_contain_vrf_master(config, vrf_environment):
    """Zone membership must use the physical/member identity rather than a VRF master."""
    config.set('set firewall zone USERS interface NVYRFWSMOKE')
    assert_firewall_commit_rejected(config, 'VRF master.*cannot belong to a zone')


def test_ipv4_zone_vrf_members_can_belong_to_different_zones(config, vrf_environment):
    """Two members of one VRF can have separate zone policies."""
    config.set('set interfaces dummy dum998 vrf NVYRFWSMOKE')
    config.set('set interfaces dummy dum999 vrf NVYRFWSMOKE')
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum999')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv4 name IN rule 10 inbound-interface dum998 action accept')
    config.set('set firewall zone-policy from-zone USERS to-zone LOCAL ipv4-policy IN')
    config.commit()

    assert_firewall_rule('ipv4_name_IN', 10, 'sdifname.*dum998')
    assert_firewall_object('map', 'ipv4_zone_forward', 'comment "USERS to WAN"', 'comment "WAN to USERS"')
    assert_firewall_object('chain', 'ipv4_input', 'sdifname vmap @ipv4_zone_input')

    # The same member-aware native policy cannot also serve FORWARD.
    config.set('set firewall zone-policy from-zone USERS to-zone WAN ipv4-policy IN')
    assert_firewall_commit_rejected(config, 'VRF-aware inbound matches cannot be shared')


def test_ipv6_zone_vrf_members_can_belong_to_different_zones(config, vrf_environment):
    """IPv6 zones remain independent from VRF membership and inherit INPUT metadata."""
    config.set('set interfaces dummy dum998 vrf NVYRFWSMOKE')
    config.set('set interfaces dummy dum999 vrf NVYRFWSMOKE')
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum999')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv6 name IN rule 10 inbound-interface dum998 action accept')
    config.set('set firewall zone-policy from-zone USERS to-zone LOCAL ipv6-policy IN')
    config.commit()

    assert_firewall_rule('ipv6_name_IN', 10, 'sdifname.*dum998')
    assert_firewall_object('map', 'ipv6_zone_forward', 'comment "USERS to WAN"', 'comment "WAN to USERS"')
    assert_firewall_object('chain', 'ipv6_input', 'sdifname vmap @ipv6_zone_input')

    config.set('set firewall zone-policy from-zone USERS to-zone WAN ipv6-policy IN')
    assert_firewall_commit_rejected(config, 'VRF-aware inbound matches cannot be shared')
