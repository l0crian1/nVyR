"""Zone displays, element counters and IPv4/IPv6 VRF output policy enforcement.

These cases deliberately change default verdicts and zone ownership, including
explicit-rule precedence and unassigned members. Their firewall policy is installed
in one transaction and restored afterward; interfaces, VRFs and BGP stay alive.
Compatible ordinary rules are in the other network modules.
"""

import pytest

pytestmark = pytest.mark.exclusive_firewall


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.op_scripts import firewall
from smoketests.assertions import (
    assert_equal, assert_in, assert_not_in, firewall_object_handle, assert_firewall_map_counter,
    firewall_rule_packets, assert_firewall_rule_packets, assert_link_addresses,
)
from smoketests.firewall_support import (
    send_firewall_udp, send_firewall_vrf_udp,
)


def test_zone_operational_display(config, capsys):
    """Installed maps expose readable zone relationships and interface names."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum999')
    config.commit()
    firewall.show(section='zone')
    output = capsys.readouterr().out
    assert_in('USERS to WAN', output)
    assert_in('IPv4 zone forward', output)
    assert_in('IPv6 zone forward', output)
    assert_in('Packets', output)
    assert_in('Bytes', output)

    firewall.show(section='zone', zone_name='USERS')
    output = capsys.readouterr().out
    assert_in('USERS to WAN', output)
    assert_not_in('WAN to USERS', output)


def test_ipv4_zone_display_family_source_and_detail(config, capsys):
    """Filter the installed output by IPv4 source zone, with explicit detail formatting."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum999')
    config.set('set firewall zone LOCAL local-zone')
    config.commit()

    firewall.show(section='zone', family='ipv4', zone_name='USERS')
    output = capsys.readouterr().out
    assert_in('IPv4 zone forward (from USERS)', output)
    assert_in('IPv4 zone input (from USERS)', output)
    assert_in('USERS to WAN', output)
    assert_in('=' * 72, output)
    assert_not_in('WAN to USERS', output)
    assert_not_in('zone output', output)
    assert_not_in('IPv6', output)

    firewall.show(section='zone', family='ipv4', zone_name='LOCAL', detail=True)
    output = capsys.readouterr().out
    assert_in('IPv4 zone output (from LOCAL)', output)
    assert_in('Outbound interface', output)
    assert_in(' | ', output)
    assert_not_in('zone input', output)
    assert_not_in('zone forward', output)


def test_ipv6_zone_display_family_source_and_detail(config, capsys):
    """IPv6 source scoping also identifies the local zone as the OUTPUT source."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum999')
    config.set('set firewall zone LOCAL local-zone')
    config.commit()

    firewall.show(section='zone', family='ipv6', zone_name='USERS')
    output = capsys.readouterr().out
    assert_in('IPv6 zone forward (from USERS)', output)
    assert_in('IPv6 zone input (from USERS)', output)
    assert_in('USERS to WAN', output)
    assert_not_in('WAN to USERS', output)
    assert_not_in('zone output', output)
    assert_not_in('IPv4', output)

    firewall.show(section='zone', family='ipv6', zone_name='LOCAL', detail=True)
    output = capsys.readouterr().out
    assert_in('IPv6 zone output (from LOCAL)', output)
    assert_in('Outbound interface', output)
    assert_in(' | ', output)
    assert_not_in('zone input', output)
    assert_not_in('zone forward', output)


def test_ipv4_zone_element_counters_track_and_preserve_traffic(config):
    """Local probes hit INPUT/OUTPUT elements; an unrelated rule edit preserves their totals."""
    config.set('set firewall zone LOOP interface lo default-action accept')
    config.set('set firewall zone LOCAL local-zone default-action accept')
    config.commit()

    assert_equal(send_firewall_udp(5), 5)
    assert_firewall_map_counter('ipv4_zone_input', 'lo', minimum_packets=5)
    assert_firewall_map_counter('ipv4_zone_output', 'lo', minimum_packets=5)
    input_map = firewall_object_handle('map', 'ipv4_zone_input')

    config.set('set firewall ipv4 input filter rule 10 inbound-interface dum998 action accept')
    config.commit()
    assert_equal(firewall_object_handle('map', 'ipv4_zone_input'), input_map)
    assert_firewall_map_counter('ipv4_zone_input', 'lo', minimum_packets=5)


def test_ipv6_zone_element_counters_track_and_preserve_traffic(config):
    """IPv6 packets increment their own element counters, which survive unrelated edits."""
    config.set('set firewall zone LOOP interface lo default-action accept')
    config.set('set firewall zone LOCAL local-zone default-action accept')
    config.commit()

    assert_equal(send_firewall_udp(5, family='ipv6'), 5)
    assert_firewall_map_counter('ipv6_zone_input', 'lo', minimum_packets=5)
    assert_firewall_map_counter('ipv6_zone_output', 'lo', minimum_packets=5)
    input_map = firewall_object_handle('map', 'ipv6_zone_input')

    config.set('set firewall ipv6 input filter rule 10 inbound-interface dum998 action accept')
    config.commit()
    assert_equal(firewall_object_handle('map', 'ipv6_zone_input'), input_map)
    assert_firewall_map_counter('ipv6_zone_input', 'lo', minimum_packets=5)


def test_ipv4_zone_vrf_output_policy_accept_and_drop(config):
    """The VRF pass bypasses default drop, but the member pass still enforces zone policy."""
    config.set('set interfaces dummy dum998 vrf NVYRFWSMOKE')
    config.set('set interfaces dummy dum998 address 198.18.98.1/24')
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv4 output filter rule 5 destination-address not 198.18.98.2 action accept')
    config.set('set firewall ipv4 output filter default-action drop')
    config.set('set firewall ipv4 name OUT default-action accept')
    config.set('set firewall zone-policy from-zone LOCAL to-zone USERS ipv4-policy OUT')
    config.commit()
    assert_link_addresses('dum998', '198.18.98.1/24')

    before = firewall_rule_packets('ipv4_output', 'vrf-bypass')
    send_firewall_vrf_udp('198.18.98.2')
    assert_firewall_rule_packets('ipv4_output', 'vrf-bypass', before + 1)
    assert_firewall_rule_packets('ipv4_name_OUT', 'default', 1)
    assert_firewall_rule_packets('ipv4_output', 'default', 0)

    # Changing the policy must still drop at the member pass, after bypassing the master.
    config.set('set firewall ipv4 name OUT default-action drop')
    config.commit()
    before = firewall_rule_packets('ipv4_output', 'vrf-bypass')
    send_firewall_vrf_udp('198.18.98.2')
    assert_firewall_rule_packets('ipv4_output', 'vrf-bypass', before + 1)
    assert_firewall_rule_packets('ipv4_name_OUT', 'default', 1)
    assert_firewall_rule_packets('ipv4_output', 'default', 0)


def test_ipv4_zone_vrf_output_explicit_rule_precedence(config):
    """A user OUTPUT drop stops the preliminary pass before the generated bypass."""
    config.set('set interfaces dummy dum998 vrf NVYRFWSMOKE')
    config.set('set interfaces dummy dum998 address 198.18.98.1/24')
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv4 output filter rule 5 destination-address not 198.18.98.2 action accept')
    config.set('set firewall ipv4 output filter default-action drop')
    config.set('set firewall zone USERS default-action accept')
    config.set('set firewall ipv4 output filter rule 10 destination-address 198.18.98.2 counter action drop')
    config.commit()
    assert_link_addresses('dum998', '198.18.98.1/24')

    send_firewall_vrf_udp('198.18.98.2')
    assert_firewall_rule_packets('ipv4_output', '10', 1)
    assert_firewall_rule_packets('ipv4_output', 'vrf-bypass', 0)
    assert_firewall_rule_packets('ipv4_output', 'default', 0)


def test_ipv4_zone_vrf_output_unassigned_member_default(config):
    """A VRF member absent from every zone still reaches the normal output default."""
    config.set('set interfaces dummy dum998 vrf NVYRFWSMOKE')
    config.set('set interfaces dummy dum998 address 198.18.98.1/24')
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv4 output filter rule 5 destination-address not 198.18.98.2 action accept')
    config.set('set firewall ipv4 output filter default-action drop')
    config.delete('delete firewall zone USERS interface dum998')
    config.set('set firewall zone USERS interface dum999')
    config.commit()
    assert_link_addresses('dum998', '198.18.98.1/24')

    before = firewall_rule_packets('ipv4_output', 'vrf-bypass')
    send_firewall_vrf_udp('198.18.98.2')
    assert_firewall_rule_packets('ipv4_output', 'vrf-bypass', before + 1)
    assert_firewall_rule_packets('ipv4_output', 'default', 1)


def test_ipv6_zone_vrf_output_policy_accept_and_drop(config):
    """The VRF pass bypasses default drop, but the member pass still enforces zone policy."""
    config.set('set interfaces dummy dum998 vrf NVYRFWSMOKE')
    config.set('set interfaces dummy dum998 address 2001:db8:98::1/64')
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv6 output filter rule 5 destination-address not 2001:db8:98::2 action accept')
    config.set('set firewall ipv6 output filter default-action drop')
    config.set('set firewall ipv6 name OUT default-action accept')
    config.set('set firewall zone-policy from-zone LOCAL to-zone USERS ipv6-policy OUT')
    config.commit()
    assert_link_addresses('dum998', '2001:db8:98::1/64')

    before = firewall_rule_packets('ipv6_output', 'vrf-bypass')
    send_firewall_vrf_udp('2001:db8:98::2')
    assert_firewall_rule_packets('ipv6_output', 'vrf-bypass', before + 1)
    assert_firewall_rule_packets('ipv6_name_OUT', 'default', 1)
    assert_firewall_rule_packets('ipv6_output', 'default', 0)

    # Changing the policy must still drop at the member pass, after bypassing the master.
    config.set('set firewall ipv6 name OUT default-action drop')
    config.commit()
    before = firewall_rule_packets('ipv6_output', 'vrf-bypass')
    send_firewall_vrf_udp('2001:db8:98::2')
    assert_firewall_rule_packets('ipv6_output', 'vrf-bypass', before + 1)
    assert_firewall_rule_packets('ipv6_name_OUT', 'default', 1)
    assert_firewall_rule_packets('ipv6_output', 'default', 0)


def test_ipv6_zone_vrf_output_explicit_rule_precedence(config):
    """A user OUTPUT drop stops the preliminary pass before the generated bypass."""
    config.set('set interfaces dummy dum998 vrf NVYRFWSMOKE')
    config.set('set interfaces dummy dum998 address 2001:db8:98::1/64')
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv6 output filter rule 5 destination-address not 2001:db8:98::2 action accept')
    config.set('set firewall ipv6 output filter default-action drop')
    config.set('set firewall zone USERS default-action accept')
    config.set('set firewall ipv6 output filter rule 10 destination-address 2001:db8:98::2 counter action drop')
    config.commit()
    assert_link_addresses('dum998', '2001:db8:98::1/64')

    send_firewall_vrf_udp('2001:db8:98::2')
    assert_firewall_rule_packets('ipv6_output', '10', 1)
    assert_firewall_rule_packets('ipv6_output', 'vrf-bypass', 0)
    assert_firewall_rule_packets('ipv6_output', 'default', 0)


def test_ipv6_zone_vrf_output_unassigned_member_default(config):
    """A VRF member absent from every zone still reaches the normal output default."""
    config.set('set interfaces dummy dum998 vrf NVYRFWSMOKE')
    config.set('set interfaces dummy dum998 address 2001:db8:98::1/64')
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv6 output filter rule 5 destination-address not 2001:db8:98::2 action accept')
    config.set('set firewall ipv6 output filter default-action drop')
    config.delete('delete firewall zone USERS interface dum998')
    config.set('set firewall zone USERS interface dum999')
    config.commit()
    assert_link_addresses('dum998', '2001:db8:98::1/64')

    before = firewall_rule_packets('ipv6_output', 'vrf-bypass')
    send_firewall_vrf_udp('2001:db8:98::2')
    assert_firewall_rule_packets('ipv6_output', 'vrf-bypass', before + 1)
    assert_firewall_rule_packets('ipv6_output', 'default', 1)
