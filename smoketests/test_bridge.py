"""Bridge features exercised through configd and native switching state."""


import pytest

if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from nvyr.helpers.process import cmd
from smoketests.assertions import (
    assert_bridge, assert_bridge_port, assert_bridge_vlans, assert_bridge_mac,
    assert_bridge_multicast, assert_config_commit_rejected, assert_equal, assert_in, assert_link,
    assert_link_absent, assert_configured_link_addresses, assert_raises,
)
from smoketests.interface_support import interface_case, interface_suite


@pytest.fixture(scope='module')
def bridge_suite(config, request):
    """Reserve a bridge and dummy ports once; retain their identities between tests."""
    with interface_suite(config, request,
                         {'bridge': ['br990'], 'dummy': ['dum990', 'dum991']}, [
                             'set interfaces dummy dum990',
                             'set interfaces dummy dum991',
                             'set interfaces bridge br990 member interface dum990',
                             'set interfaces bridge br990 member interface dum991',
                         ]) as reset:
        yield reset


@pytest.fixture(autouse=True)
def bridge_environment(request, bridge_suite):
    """Reset feature settings without deleting and recreating bridge devices."""
    with interface_case(request, bridge_suite):
        yield


def test_creation_and_member_removal(config):
    """Member removal detaches the port while preserving the bridge identity."""
    index = assert_link('br990', kind='bridge', up=True)['ifindex']
    assert_link('dum990', master='br990')
    config.delete('delete interfaces bridge br990 member interface dum990')
    config.commit()
    assert_link('dum990', master='')
    assert_equal(assert_link('br990')['ifindex'], index)


def test_bridge_deletion(config):
    """Deleting a bridge detaches its ports without deleting those interfaces."""
    config.delete('delete interfaces bridge br990')
    config.commit()
    assert_link_absent('br990')
    assert_link('dum990', master='')
    assert_link('dum991', master='')


def test_ipv4_addresses(config):
    """Bridge IPv4 addresses are installed and individually removable."""
    config.set('set interfaces bridge br990 address 198.18.190.1/24')
    config.commit()
    assert_configured_link_addresses('br990', '198.18.190.1/24')
    config.delete('delete interfaces bridge br990 address 198.18.190.1/24')
    config.commit()
    assert_configured_link_addresses('br990', absent=('198.18.190.1/24',))


def test_ipv6_addresses(config):
    """Bridge IPv6 addresses complete duplicate-address detection."""
    config.set('set interfaces bridge br990 address 2001:db8:190::1/64')
    config.commit()
    assert_configured_link_addresses('br990', '2001:db8:190::1/64')


def test_attributes_and_removal(config):
    """MAC, alias and link-group settings update in place and removal resets them."""
    before = assert_link('br990')
    config.set('set interfaces bridge br990 mac 02:00:00:00:99:01 description "Bridge smoketest" link-group 90')
    config.commit()
    assert_link('br990', mac='02:00:00:00:99:01', description='Bridge smoketest', group=90)
    config.delete('delete interfaces bridge br990 mac')
    config.delete('delete interfaces bridge br990 description')
    config.delete('delete interfaces bridge br990 link-group')
    config.commit()
    assert_link('br990', mac=before['address'], description='', group=0)
    assert_equal(assert_link('br990')['ifindex'], before['ifindex'])


def test_mtu(config):
    """A bridge may use jumbo frames when all its members can carry them."""
    config.set('set interfaces dummy dum990 mtu 9000')
    config.set('set interfaces dummy dum991 mtu 9000')
    config.set('set interfaces bridge br990 mtu 9000')
    config.commit()
    assert_link('br990', mtu=9000)


def test_disable_and_reenable(config):
    """Disabling removes L3 addresses; enabling restores them on the same bridge."""
    config.set('set interfaces bridge br990 address 198.18.190.1/24 disable')
    config.commit()
    assert_link('br990', up=False)
    config.delete('delete interfaces bridge br990 disable')
    config.commit()
    assert_link('br990', up=True)
    assert_configured_link_addresses('br990', '198.18.190.1/24')


def test_vrf_membership(config):
    """The bridge joins a VRF while switched ports retain their bridge master."""
    config.set('set vrf name NVYRIFSMOKE table 41010')
    config.set('set interfaces bridge br990 vrf NVYRIFSMOKE')
    config.commit()
    assert_link('br990', master='NVYRIFSMOKE')
    assert_link('dum990', master='br990')


def test_ipv4_vif(config):
    """A bridge VIF receives its address and implicit local VLAN membership."""
    config.set('set interfaces bridge br990 vlan-filtering default-pvid 0 vif 10 address 198.18.190.1/24')
    config.commit()
    assert_link('br990.10', kind='vlan')
    assert_configured_link_addresses('br990.10', '198.18.190.1/24')
    assert_bridge_vlans('br990', {10: (False, False)})


def test_ipv6_vif(config):
    """An IPv6 bridge VIF shares the general VLAN-child lifecycle."""
    config.set('set interfaces bridge br990 vif 10 address 2001:db8:190::1/64')
    config.commit()
    assert_configured_link_addresses('br990.10', '2001:db8:190::1/64')


def test_default_pvid_zero(config):
    """Disabling implicit VLAN 1 removes it from existing ports and the local port."""
    config.set('set interfaces bridge br990 vlan-filtering default-pvid 0')
    config.commit()
    assert_bridge_vlans('br990', {})
    assert_bridge_vlans('dum990', {})
    assert_bridge_vlans('dum991', {})


def test_access_port(config):
    """PVID and untagged flags jointly implement an access port."""
    config.set('set interfaces bridge br990 vlan-filtering default-pvid 0 member interface dum990 vlan 10 pvid untagged')
    config.commit()
    assert_bridge_vlans('dum990', {10: (True, True)})


def test_trunk_port(config):
    """Multiple admitted VLANs remain tagged unless untagged is requested."""
    config.set('set interfaces bridge br990 vlan-filtering default-pvid 0')
    config.set('set interfaces bridge br990 member interface dum990 vlan 10')
    config.set('set interfaces bridge br990 member interface dum990 vlan 20')
    config.commit()
    assert_bridge_vlans('dum990', {10: (False, False), 20: (False, False)})


def test_native_vlan_and_explicit_vlan_one(config):
    """Default-PVID zero does not forbid an explicitly configured native VLAN 1."""
    config.set('set interfaces bridge br990 vlan-filtering default-pvid 0')
    config.set('set interfaces bridge br990 member interface dum990 vlan 1 pvid untagged')
    config.set('set interfaces bridge br990 member interface dum990 vlan 20')
    config.commit()
    assert_bridge_vlans('dum990', {1: (True, True), 20: (False, False)})


def test_local_vlan_membership(config):
    """Explicit local membership controls the router-facing bridge port."""
    config.set('set interfaces bridge br990 vlan-filtering default-pvid 0 vlan 10 local pvid untagged')
    config.commit()
    assert_bridge_vlans('br990', {10: (True, True)})


def test_vlan_statistics(config):
    """Per-port counters can be enabled on an existing bridge without losing VLANs."""
    config.set('set interfaces bridge br990 vlan-filtering vlan-statistics vlan-statistics-per-port')
    config.commit()
    assert_bridge('br990', vlan_stats_enabled=1, vlan_stats_per_port=1)
    assert_bridge_vlans('dum990', {1: (True, True)})


def test_vlan_protocol(config):
    """802.1ad switching protocol selection is reflected by the kernel."""
    config.set('set interfaces bridge br990 vlan-filtering vlan-protocol 802.1ad')
    config.commit()
    assert_bridge('br990', vlan_protocol='802.1ad')


def test_spanning_tree(config):
    """An empty node enables STP; removing it restores the disabled default."""
    config.set('set interfaces bridge br990 spanning-tree')
    config.commit()
    assert_bridge('br990', stp_state=1)
    config.delete('delete interfaces bridge br990 spanning-tree')
    config.commit()
    assert_bridge('br990', stp_state=0)


def test_spanning_tree_timers_and_priority(config):
    """Consistent STP timers and root priority are passed in native units."""
    config.set('set interfaces bridge br990 spanning-tree priority 4096 hello-time 2s forward-delay 10s max-age 12s')
    config.commit()
    assert_bridge('br990', priority=4096, hello_time=200, forward_delay=1000, max_age=1200)


def test_port_spanning_tree(config):
    """Cost, priority and both protection flags are independently configurable."""
    config.set('set interfaces bridge br990 spanning-tree')
    config.set('set interfaces bridge br990 member interface dum990 spanning-tree cost 500 priority 16 bpdu-guard root-guard')
    config.commit()
    assert_bridge_port('dum990', cost=500, priority=16, guard=True, root_block=True)


def test_learning_hairpin_isolation(config):
    """Valueless flags enable features while the learning disable child negates a default."""
    config.set('set interfaces bridge br990 member interface dum990 learning disable hairpin isolated')
    config.commit()
    assert_bridge_port('dum990', learning=False, hairpin=True, isolated=True)


def test_flood_controls(config):
    """Each flooding class can be disabled without changing the other classes."""
    config.set('set interfaces bridge br990 member interface dum990 flood unknown-unicast disable')
    config.set('set interfaces bridge br990 member interface dum990 flood unknown-multicast disable')
    config.set('set interfaces bridge br990 member interface dum990 flood broadcast disable')
    config.commit()
    assert_bridge_port('dum990', flood=False, mcast_flood=False, bcast_flood=False)


def test_backup_interface(config):
    """A failover port must be an existing different member of the same bridge."""
    config.set('set interfaces bridge br990 member interface dum990 backup-interface dum991')
    config.commit()
    assert_bridge_port('dum990', backup_port='dum991')


def test_mac_learning_controls(config):
    """Bridge learning limits and retention settings reach the native driver."""
    config.set('set interfaces bridge br990 mac-learning ageing-time 10m maximum-entries 100 link-local disable')
    config.commit()
    assert_bridge('br990', ageing_time=60000, fdb_max_learned=100, no_linklocal_learn=1)


def test_locked_port_and_static_mac(config):
    """A locked port can have an explicitly authorized source MAC entry."""
    config.set('set interfaces bridge br990 member interface dum990 locked')
    config.set('set interfaces bridge br990 static-mac 02:00:00:00:99:10 interface dum990')
    config.commit()
    assert_bridge_port('dum990', locked=True)
    assert_bridge_mac('br990', '02:00:00:00:99:10', port='dum990')


def test_vlan_static_mac(config):
    """A VLAN-specific forwarding entry targets an admitted member VLAN."""
    config.set('set interfaces bridge br990 vlan-filtering default-pvid 0 member interface dum990 vlan 10')
    config.set('set interfaces bridge br990 static-mac 02:00:00:00:99:10 vlan 10 interface dum990')
    config.commit()
    assert_bridge_mac('br990', '02:00:00:00:99:10', port='dum990', vlan=10)


def test_multicast_snooping_disable(config):
    """The snooping disable child turns off the default-enabled facility."""
    config.set('set interfaces bridge br990 multicast snooping disable')
    config.commit()
    assert_bridge('br990', mcast_snooping=0)


def test_multicast_querier_versions_and_statistics(config):
    """Querier, protocol versions, source selection and statistics are opt-in."""
    config.set('set interfaces bridge br990 multicast querier igmp-version 3 mld-version 2 query-use-interface-address statistics router permanent')
    config.commit()
    assert_bridge('br990', mcast_querier=1, mcast_igmp_version=3, mcast_mld_version=2,
                  mcast_query_use_ifaddr=1, mcast_stats_enabled=1, mcast_router=2)


def test_multicast_timers(config):
    """All multicast timers and query counts can be configured together."""
    config.set('set interfaces bridge br990 multicast last-member-count 3 last-member-interval 2s startup-query-count 3 startup-query-interval 15s membership-interval 3m querier-interval 2m query-interval 1m query-response-interval 5s')
    config.commit()
    assert_bridge('br990', mcast_last_member_cnt=3, mcast_last_member_intvl=200,
                  mcast_startup_query_cnt=3, mcast_startup_query_intvl=1500,
                  mcast_membership_intvl=18000, mcast_querier_intvl=12000,
                  mcast_query_intvl=6000, mcast_query_response_intvl=500)


def test_port_multicast(config):
    """Port multicast forwarding settings remain separate from bridge settings."""
    config.set('set interfaces bridge br990 member interface dum990 multicast fast-leave to-unicast router permanent maximum-groups 100')
    config.commit()
    assert_bridge_port('dum990', fastleave=True, mcast_to_unicast=True, mcast_router=2, mcast_max_groups=100)


def test_vlan_multicast(config):
    """VLAN contexts support their own querier and port router settings."""
    config.set('set interfaces bridge br990 vlan-filtering multicast vlan-snooping')
    config.set('set interfaces bridge br990 member interface dum990 vlan 10 multicast router permanent maximum-groups 20')
    config.set('set interfaces bridge br990 vlan 10 multicast querier igmp-version 3 mld-version 2')
    config.commit()
    assert_bridge('br990', mcast_vlan_snooping=1)
    output = cmd(['bridge', '-j', 'vlan', 'global', 'show', 'dev', 'br990', 'vid', '10'])
    assert_in('"mcast_igmp_version":3', output.replace(' ', ''))


def test_ipv4_static_multicast(config):
    """An IPv4 multicast group can have more than one configured receiving port."""
    config.set('set interfaces bridge br990 multicast static-group TV address 239.190.0.1 interface dum990 interface dum991')
    config.commit()
    assert_bridge_multicast('br990', '239.190.0.1', port='dum990')
    assert_bridge_multicast('br990', '239.190.0.1', port='dum991')


def test_ipv6_static_multicast(config):
    """IPv6 static memberships use the same group and per-port configuration."""
    config.set('set interfaces bridge br990 multicast static-group TV address ff3e::190 interface dum990')
    config.commit()
    assert_bridge_multicast('br990', 'ff3e::190', port='dum990')


def test_ipv4_source_specific_multicast(config):
    """A multicast entry may select one IPv4 source rather than all senders."""
    config.set('set interfaces bridge br990 multicast static-group TV address 232.190.0.1 source 198.18.190.2 interface dum990')
    config.commit()
    assert_bridge_multicast('br990', '232.190.0.1', source='198.18.190.2')


def test_ipv6_source_specific_multicast(config):
    """A multicast entry may select one IPv6 source rather than all senders."""
    config.set('set interfaces bridge br990 multicast static-group TV address ff3e::190 source 2001:db8:190::2 interface dum990')
    config.commit()
    assert_bridge_multicast('br990', 'ff3e::190', source='2001:db8:190::2')


def test_neighbor_suppression(config):
    """Port and VLAN-specific ARP/ND suppression are explicit opt-ins."""
    config.set('set interfaces bridge br990 vlan-filtering')
    config.set('set interfaces bridge br990 member interface dum990 neighbor-suppression neighbor-vlan-suppression vlan 10 neighbor-suppression')
    config.commit()
    assert_bridge_port('dum990', neigh_suppress=True, neigh_vlan_suppress=True)


def test_link_local_forwarding(config):
    """Named protocol selections are converted to their forwarding-mask bits."""
    config.set('set interfaces bridge br990 link-local-forward lldp')
    config.set('set interfaces bridge br990 link-local-forward eapol')
    config.set('set interfaces bridge br990 member interface dum990 link-local-forward lldp')
    config.commit()
    data = assert_bridge('br990')
    assert_equal(int(str(data['group_fwd_mask']), 0), 16392)


def test_multiple_pvids_rejected(config):
    """A port cannot classify the same untagged frame into two VLANs."""
    config.set('set interfaces bridge br990 vlan-filtering')
    config.set('set interfaces bridge br990 member interface dum990 vlan 10 pvid')
    config.set('set interfaces bridge br990 member interface dum990 vlan 20 pvid')
    assert_config_commit_rejected(config, 'only one VLAN')


def test_routed_member_rejected(config):
    """Changing the member owner cannot bypass bridge L3 ownership checks."""
    config.set('set interfaces dummy dum990 address 198.18.190.1/24')
    assert_config_commit_rejected(config, 'bridge member cannot have')


def test_backup_cycle_rejected(config):
    """Two failed links cannot redirect frames back to each other indefinitely."""
    config.set('set interfaces bridge br990 member interface dum990 backup-interface dum991')
    config.set('set interfaces bridge br990 member interface dum991 backup-interface dum990')
    assert_config_commit_rejected(config, 'cycle')


def test_stp_timer_relationship_rejected(config):
    """Individually valid timers must still form a valid STP relationship."""
    config.set('set interfaces bridge br990 spanning-tree max-age 40s')
    assert_config_commit_rejected(config, 'STP requires')


def test_vlan_without_filtering_rejected(config):
    """Membership settings cannot silently do nothing on an unaware bridge."""
    config.set('set interfaces bridge br990 member interface dum990 vlan 10')
    assert_config_commit_rejected(config, 'require vlan-filtering')


def test_missing_multicast_fields_rejected(config):
    """An empty named multicast membership must not reach native apply."""
    config.set('set interfaces bridge br990 multicast static-group TV')
    assert_config_commit_rejected(config, 'address and interface')


def test_multicast_source_family_rejected(config):
    """A multicast source and group must use the same IP family."""
    config.set('set interfaces bridge br990 multicast static-group TV address 239.190.0.1 source 2001:db8:190::2 interface dum990')
    assert_config_commit_rejected(config, 'same family')


def test_static_mac_nonmember_rejected(config):
    """Static forwarding cannot target a nonmember device."""
    config.set('set interfaces bridge br990 static-mac 02:00:00:00:99:10 interface lo')
    assert_config_commit_rejected(config, 'must be a bridge member')


def test_smaller_member_mtu_rejected(config):
    """A jumbo bridge must not silently shrink when a smaller port is attached."""
    config.set('set interfaces bridge br990 mtu 9000')
    assert_config_commit_rejected(config, 'member MTU')


def test_member_deletion_protected(config):
    """The dependency registrar blocks removing a still-referenced member."""
    with assert_raises(RouterError, match='referenced'):
        config.delete('delete interfaces dummy dum990')


def test_invalid_vlan_rejected(config):
    """Reserved VLAN identifiers fail at candidate insertion."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set interfaces bridge br990 member interface dum990 vlan 4095')
