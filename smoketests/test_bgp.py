"""Direct BGP translation and rejection checks with one persistent VRF and base policy.

Cases reset configuration without removing the routing domain or waiting for peers.
Packet forwarding and BGP convergence belong to the functional routing suite.
"""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.config_session import CommitError
from nvyr.errors import RouterError
from nvyr.tree import lookup
from smoketests.assertions import (
    assert_bgp_commands, assert_bgp_resources_unused, assert_config_names_unused, assert_raises,
)
from smoketests.support import configuration_case, prepared_test


def standup(config, resources):
    """Keep real neighbors untouched by reserving an isolated BGP routing domain."""
    running = config.get_config()
    assert_config_names_unused(running, 'NVYRBGP', 'NVYRBGPPOLICY', 'NVYRBGPMISSING')
    assert_bgp_resources_unused(running)
    resources['prepared'] = True
    config.set('set vrf name NVYRBGP table 41040')
    config.set('set vrf name NVYRBGP protocols bgp local-as 65000 parameters router-id 192.0.2.1')
    config.set('set policy route-map NVYRBGPPOLICY rule 10 action permit')
    config.commit()


def cleanup(config, resources):
    """Withdraw BGP before removing its VRF and policy references."""
    if not resources['prepared']:
        return
    config.discard()
    if lookup(config.get_config(), ('vrf', 'name', 'NVYRBGP', 'protocols', 'bgp'), None) is not None:
        config.delete('delete vrf name NVYRBGP protocols bgp')
        config.commit()

    running = config.get_config()
    changed = False
    for path in (('vrf', 'name', 'NVYRBGP'), ('policy', 'route-map', 'NVYRBGPPOLICY'),
                 ('policy', 'as-path-list', 'NVYRBGPPOLICY'),
                 ('policy', 'prefix-list', 'ipv4', 'NVYRBGPPOLICY'),
                 ('policy', 'prefix-list', 'ipv6', 'NVYRBGPPOLICY'),
                 ('policy', 'access-list', 'ipv4', 'NVYRBGPPOLICY'),
                 ('policy', 'access-list', 'ipv6', 'NVYRBGPPOLICY')):
        if lookup(running, path, None) is not None:
            config.delete('delete ' + ' '.join(path))
            changed = True
    if changed:
        config.commit()


@pytest.fixture(scope='module')
def bgp_suite(config, request):
    """Create the routing domain once and withdraw it after the module finishes."""
    resources = {'prepared': False}

    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, lambda session: standup(session, resources),
                       lambda session: cleanup(session, resources), stop=stop):
        yield config.get_config()


@pytest.fixture(autouse=True)
def bgp_environment(config, request, bgp_suite):
    """Remove case-specific settings in one commit without destroying the VRF."""
    with configuration_case(config, request, bgp_suite):
        yield


def test_alternate_local_as_and_transport(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as external shutdown passive')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 local-as number 65100')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 local-as no-prepend replace-as dual-as')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 port 1179 tcp-mss 1200 disable-connected-route-check disable-enforce-first-as')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 timers advertisement-interval 5 delay-open 3')
    config.commit()

    assert_bgp_commands('neighbor 192.0.2.2 local-as 65100 no-prepend replace-as dual-as',
                        'neighbor 192.0.2.2 remote-as external', 'neighbor 192.0.2.2 shutdown',
                        'neighbor 192.0.2.2 passive', 'neighbor 192.0.2.2 port 1179',
                        'neighbor 192.0.2.2 tcp-mss 1200', 'neighbor 192.0.2.2 disable-connected-check',
                        'no neighbor 192.0.2.2 enforce-first-as',
                        'neighbor 192.0.2.2 advertisement-interval 5', 'neighbor 192.0.2.2 timers delayopen 3')


def test_remote_as_auto(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as auto shutdown')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 remote-as auto')


def test_peer_capabilities_role_and_restart(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as external shutdown graceful-shutdown graceful-restart helper')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 role type provider strict')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 capability extended-nexthop dynamic link-local software-version disable-fqdn strict-match')
    config.commit()

    assert_bgp_commands('neighbor 192.0.2.2 graceful-shutdown', 'neighbor 192.0.2.2 graceful-restart-helper',
                        'neighbor 192.0.2.2 local-role provider strict-mode',
                        'neighbor 192.0.2.2 capability extended-nexthop', 'neighbor 192.0.2.2 capability dynamic',
                        'neighbor 192.0.2.2 capability link-local', 'neighbor 192.0.2.2 capability software-version',
                        'no neighbor 192.0.2.2 capability fqdn', 'neighbor 192.0.2.2 strict-capability-match')


def test_peer_capability_override_and_restart_disable(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as external shutdown graceful-restart disable capability override')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 graceful-restart-disable', 'neighbor 192.0.2.2 override-capability')


def test_peer_capability_negotiation_disabled(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as external shutdown capability disable-negotiation')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 dont-capability-negotiate')


def test_ipv4_extended_family_options(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as external shutdown')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast next-hop-self force')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast allowas-in count 2 route-map NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast as-override remove-private-as all replace')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast soft-reconfiguration inbound')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast maximum-prefix limit 200 threshold 90 warning-only force')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast maximum-prefix-out 250 weight 200')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast conditional-advertisement advertise-map NVYRBGPPOLICY exist-map NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast addpath transmit best-selected 3')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast addpath receive-limit 5')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast attribute-unchanged as-path next-hop med')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast unsuppress-map NVYRBGPPOLICY')
    config.commit()

    assert_bgp_commands('neighbor 192.0.2.2 next-hop-self force',
                        'neighbor 192.0.2.2 allowas-in route-map NVYRBGPPOLICY 2',
                        'neighbor 192.0.2.2 as-override', 'neighbor 192.0.2.2 remove-private-AS all replace-AS',
                        'neighbor 192.0.2.2 soft-reconfiguration inbound',
                        'neighbor 192.0.2.2 maximum-prefix 200 90 warning-only force',
                        'neighbor 192.0.2.2 maximum-prefix-out 250', 'neighbor 192.0.2.2 weight 200',
                        'neighbor 192.0.2.2 advertise-map NVYRBGPPOLICY exist-map NVYRBGPPOLICY',
                        'neighbor 192.0.2.2 addpath-tx-best-selected 3', 'neighbor 192.0.2.2 addpath-rx-paths-limit 5',
                        'neighbor 192.0.2.2 attribute-unchanged as-path next-hop med',
                        'neighbor 192.0.2.2 unsuppress-map NVYRBGPPOLICY', family='ipv4')


def test_ipv6_extended_family_options(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 remote-as external shutdown')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast next-hop-self force')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast allowas-in origin route-map NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast as-override remove-private-as all')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast soft-reconfiguration inbound')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast maximum-prefix limit 200 threshold 80 restart 2 force')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast maximum-prefix-out 250 weight 200')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast conditional-advertisement advertise-map NVYRBGPPOLICY non-exist-map NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast addpath transmit all')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast addpath disable-receive')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast attribute-unchanged med')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast unsuppress-map NVYRBGPPOLICY')
    config.commit()

    assert_bgp_commands('neighbor 2001:db8::2 next-hop-self force',
                        'neighbor 2001:db8::2 allowas-in route-map NVYRBGPPOLICY origin',
                        'neighbor 2001:db8::2 as-override', 'neighbor 2001:db8::2 remove-private-AS all',
                        'neighbor 2001:db8::2 soft-reconfiguration inbound',
                        'neighbor 2001:db8::2 maximum-prefix 200 80 restart 2 force',
                        'neighbor 2001:db8::2 maximum-prefix-out 250', 'neighbor 2001:db8::2 weight 200',
                        'neighbor 2001:db8::2 advertise-map NVYRBGPPOLICY non-exist-map NVYRBGPPOLICY',
                        'neighbor 2001:db8::2 addpath-tx-all-paths', 'neighbor 2001:db8::2 disable-addpath-rx',
                        'neighbor 2001:db8::2 attribute-unchanged med',
                        'neighbor 2001:db8::2 unsuppress-map NVYRBGPPOLICY', family='ipv6')


def test_ipv4_as_path_filter(config):
    config.set('set policy as-path-list NVYRBGPPOLICY rule 10 action permit regex ".*"')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as external address-family ipv4-unicast as-path-list import NVYRBGPPOLICY export NVYRBGPPOLICY')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 filter-list NVYRBGPPOLICY in',
                        'neighbor 192.0.2.2 filter-list NVYRBGPPOLICY out', family='ipv4')


def test_ipv6_as_path_filter(config):
    config.set('set policy as-path-list NVYRBGPPOLICY rule 10 action permit regex ".*"')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 remote-as external address-family ipv6-unicast as-path-list import NVYRBGPPOLICY export NVYRBGPPOLICY')
    config.commit()
    assert_bgp_commands('neighbor 2001:db8::2 filter-list NVYRBGPPOLICY in',
                        'neighbor 2001:db8::2 filter-list NVYRBGPPOLICY out', family='ipv6')


def test_ipv4_aggregate_attributes_distances_and_metrics(config):
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv4-unicast aggregate-address 192.0.0.0/16 route-map NVYRBGPPOLICY origin incomplete matching-med-only suppress-map NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv4-unicast redistribute kernel metric 50 route-map NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv4-unicast redistribute connected metric 100')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv4-unicast redistribute static metric 200')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv4-unicast distance external 30 internal 210 local 220')
    config.commit()
    assert_bgp_commands('aggregate-address 192.0.0.0/16 route-map NVYRBGPPOLICY origin incomplete matching-MED-only suppress-map NVYRBGPPOLICY',
                        'redistribute kernel metric 50 route-map NVYRBGPPOLICY', 'redistribute connected metric 100',
                        'redistribute static metric 200', 'distance bgp 30 210 220', family='ipv4')


def test_ipv6_aggregate_attributes_distances_and_metrics(config):
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv6-unicast aggregate-address 2001:db8::/32 route-map NVYRBGPPOLICY origin igp matching-med-only suppress-map NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv6-unicast redistribute kernel metric 50 route-map NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv6-unicast redistribute connected metric 100')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv6-unicast redistribute static metric 200')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv6-unicast distance external 30 internal 210 local 220')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv6-unicast next-hop prefer-global')
    config.commit()
    assert_bgp_commands('aggregate-address 2001:db8::/32 route-map NVYRBGPPOLICY origin igp matching-MED-only suppress-map NVYRBGPPOLICY',
                        'redistribute kernel metric 50 route-map NVYRBGPPOLICY', 'redistribute connected metric 100',
                        'redistribute static metric 200', 'distance bgp 30 210 220', 'nexthop prefer-global', family='ipv6')


def test_ipv4_route_server_client(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as external role type rs-server')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast route-server-client')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 route-server-client',
                        'neighbor 192.0.2.2 attribute-unchanged next-hop', family='ipv4')


def test_ipv6_route_server_client(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 remote-as external role type rs-server')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast route-server-client')
    config.commit()
    assert_bgp_commands('neighbor 2001:db8::2 route-server-client',
                        'neighbor 2001:db8::2 attribute-unchanged next-hop', family='ipv6')


def test_interface_neighbor(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor dum41040 remote-as external ipv6-only shutdown')
    config.set('set vrf name NVYRBGP protocols bgp neighbor dum41040 address-family ipv4-unicast')
    config.set('set vrf name NVYRBGP protocols bgp neighbor dum41040 address-family ipv6-unicast')
    config.commit()
    assert_bgp_commands('neighbor dum41040 interface v6only remote-as external')


def test_link_local_neighbor(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor fe80::2 interface dum41040 remote-as external shutdown address-family ipv6-unicast')
    config.commit()
    assert_bgp_commands('neighbor fe80::2 interface dum41040', 'neighbor fe80::2 remote-as external')


def test_reject_link_local_without_interface(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor fe80::2 remote-as external')
    with assert_raises(CommitError, match='link-local neighbor requires interface'):
        config.commit()


def test_reject_local_as_without_number(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as external local-as no-prepend')
    with assert_raises(CommitError, match='local-as requires number'):
        config.commit()


def test_reject_maximum_prefix_force_without_storage(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as external address-family ipv4-unicast maximum-prefix limit 100 force')
    with assert_raises(CommitError, match='requires soft-reconfiguration inbound'):
        config.commit()


def test_reject_conditional_advertisement_without_condition(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 remote-as external address-family ipv6-unicast conditional-advertisement advertise-map NVYRBGPPOLICY')
    with assert_raises(CommitError, match='exactly one of exist-map or non-exist-map'):
        config.commit()


def test_reject_conflicting_addpath_transmit(config):
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as external address-family ipv4-unicast addpath transmit all best-selected 2')
    with assert_raises(CommitError, match='exactly one strategy'):
        config.commit()


def test_ipv4_neighbor(config):
    """IPv4 unicast is explicitly activated and IPv6 remains inactive."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000 address-family ipv4-unicast')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 activate', family='ipv4')
    assert_bgp_commands(absent=('neighbor 192.0.2.2 activate',), family='ipv6')


def test_ipv6_neighbor(config):
    """An IPv6-only peer does not acquire implicit IPv4 unicast activation."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 remote-as 65000 address-family ipv6-unicast')
    config.commit()
    assert_bgp_commands('neighbor 2001:db8::2 activate', family='ipv6')
    assert_bgp_commands(absent=('neighbor 2001:db8::2 activate',), family='ipv4')


def test_ipv4_external_policies(config):
    """External IPv4 peers use explicit inbound and outbound route maps."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65001')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast route-map import NVYRBGPPOLICY export NVYRBGPPOLICY')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 route-map NVYRBGPPOLICY in', 'neighbor 192.0.2.2 route-map NVYRBGPPOLICY out')


def test_ipv6_external_policies(config):
    """External IPv6 peers use their own address-family policy configuration."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 remote-as 65001')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 address-family ipv6-unicast route-map import NVYRBGPPOLICY export NVYRBGPPOLICY')
    config.commit()
    assert_bgp_commands('neighbor 2001:db8::2 route-map NVYRBGPPOLICY in', 'neighbor 2001:db8::2 route-map NVYRBGPPOLICY out')


def test_ipv4_prefix_filter(config):
    """IPv4 prefix-list references become native neighbor prefix filters."""
    config.set('set policy prefix-list ipv4 NVYRBGPPOLICY rule 10 action permit prefix 192.0.2.0/24')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000 address-family ipv4-unicast prefix-list in NVYRBGPPOLICY')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 prefix-list NVYRBGPPOLICY in')


def test_ipv6_prefix_filter(config):
    """IPv6 prefix filters resolve the IPv6 policy namespace."""
    config.set('set policy prefix-list ipv6 NVYRBGPPOLICY rule 10 action permit prefix 2001:db8::/32')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 remote-as 65000 address-family ipv6-unicast prefix-list out NVYRBGPPOLICY')
    config.commit()
    assert_bgp_commands('neighbor 2001:db8::2 prefix-list NVYRBGPPOLICY out')


def test_ipv4_access_filter(config):
    """IPv4 access-list syntax maps to a native distribute-list."""
    config.set('set policy access-list ipv4 NVYRBGPPOLICY rule 10 action permit any')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000 address-family ipv4-unicast access-list in NVYRBGPPOLICY')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 distribute-list NVYRBGPPOLICY in')


def test_ipv6_access_filter(config):
    """IPv6 access-list syntax resolves and installs independently."""
    config.set('set policy access-list ipv6 NVYRBGPPOLICY rule 10 action permit any')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 remote-as 65000 address-family ipv6-unicast access-list out NVYRBGPPOLICY')
    config.commit()
    assert_bgp_commands('neighbor 2001:db8::2 distribute-list NVYRBGPPOLICY out')


def test_ipv4_peer_group(config):
    """Members inherit the group's remote AS and explicitly activated family."""
    config.set('set vrf name NVYRBGP protocols bgp peer-group INTERNAL remote-as 65000 address-family ipv4-unicast next-hop-self')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 peer-group INTERNAL')
    config.commit()
    assert_bgp_commands('neighbor INTERNAL peer-group', 'neighbor INTERNAL activate', 'neighbor 192.0.2.2 peer-group INTERNAL')


def test_ipv6_peer_group(config):
    """IPv6 peer groups activate no unrequested IPv4 family."""
    config.set('set vrf name NVYRBGP protocols bgp peer-group INTERNAL remote-as 65000 address-family ipv6-unicast next-hop-self')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 peer-group INTERNAL')
    config.commit()
    assert_bgp_commands('neighbor INTERNAL activate', family='ipv6')
    assert_bgp_commands(absent=('neighbor INTERNAL activate', 'neighbor 2001:db8::2 activate'), family='ipv4')


def test_update_source_interface(config):
    """The source accepts an interface name rather than only an address."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000 update-source NVYRBGP')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 update-source NVYRBGP')


def test_update_source_ipv4(config):
    """IPv4 transport accepts a matching IPv4 source address."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000 update-source 192.0.2.1')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 update-source 192.0.2.1')


def test_update_source_ipv6(config):
    """IPv6 transport accepts a matching IPv6 source address."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 remote-as 65000 update-source 2001:db8::1')
    config.commit()
    assert_bgp_commands('neighbor 2001:db8::2 update-source 2001:db8::1')


def test_neighbor_attributes_and_timers(config):
    """Descriptions, TCP MD5, passive mode, and neighbor timers reach FRR."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000 description "Smoke neighbor" password smoke-secret passive')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 timers keepalive 10 holdtime 30 connect 5')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 description Smoke neighbor', 'neighbor 192.0.2.2 password smoke-secret',
                        'neighbor 192.0.2.2 passive', 'neighbor 192.0.2.2 timers 10 30', 'neighbor 192.0.2.2 timers connect 5')


def test_instance_attributes(config):
    """Instance timers, logging, and multipath selection are independent of peers."""
    config.set('set vrf name NVYRBGP protocols bgp parameters timers keepalive 10 holdtime 30')
    config.set('set vrf name NVYRBGP protocols bgp parameters log-neighbor-changes enable bestpath as-path multipath-relax enable')
    config.commit()
    assert_bgp_commands('timers bgp 10 30', 'bgp log-neighbor-changes', 'bgp bestpath as-path multipath-relax')


def test_disable_and_reenable(config):
    """Global and individual shutdowns preserve configuration and can be removed."""
    config.set('set vrf name NVYRBGP protocols bgp parameters shutdown enable neighbor 192.0.2.2 remote-as 65000 shutdown')
    config.commit()
    assert_bgp_commands('bgp shutdown', 'neighbor 192.0.2.2 shutdown')
    config.delete('delete vrf name NVYRBGP protocols bgp parameters shutdown')
    config.delete('delete vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 shutdown')
    config.commit()
    assert_bgp_commands(absent=('bgp shutdown', 'neighbor 192.0.2.2 shutdown'))


def test_multihop_then_ttl_security(config):
    """Replace the two mutually exclusive external-session TTL mechanisms."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65001 ebgp-multihop 5')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 ebgp-multihop 5')
    config.delete('delete vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 ebgp-multihop')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 ttl-security hops 2')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 ttl-security hops 2')


def test_ipv4_family_options(config):
    """Per-family reflection, next-hop, default advertisement, and prefix cap coexist."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000 address-family ipv4-unicast next-hop-self route-reflector-client maximum-prefix limit 100')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast default-originate route-map NVYRBGPPOLICY')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 next-hop-self', 'neighbor 192.0.2.2 route-reflector-client',
                        'neighbor 192.0.2.2 maximum-prefix 100', 'neighbor 192.0.2.2 default-originate route-map NVYRBGPPOLICY')


def test_ipv6_family_options(config):
    """IPv6 reflection and default advertisement use their own family context."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 remote-as 65000 address-family ipv6-unicast next-hop-self route-reflector-client maximum-prefix limit 100 default-originate')
    config.commit()
    assert_bgp_commands('neighbor 2001:db8::2 next-hop-self', 'neighbor 2001:db8::2 route-reflector-client',
                        'neighbor 2001:db8::2 maximum-prefix 100', 'neighbor 2001:db8::2 default-originate')


def test_ipv4_send_communities(config):
    """Selecting extended/large explicitly suppresses standard communities."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000 address-family ipv4-unicast send-community extended send-community large')
    config.commit()
    assert_bgp_commands('no neighbor 192.0.2.2 send-community standard')


def test_ipv6_send_communities(config):
    """Selecting standard explicitly suppresses extended and large communities."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 remote-as 65000 address-family ipv6-unicast send-community standard')
    config.commit()
    assert_bgp_commands('no neighbor 2001:db8::2 send-community extended', 'no neighbor 2001:db8::2 send-community large')


def test_ipv4_advertisements(config):
    """Network policy, redistribution, aggregation, and ECMP are installed together."""
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv4-unicast network 192.0.2.0/24 route-map NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv4-unicast redistribute connected')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv4-unicast redistribute static route-map NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv4-unicast aggregate-address 192.0.0.0/16 summary-only as-set')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv4-unicast maximum-paths ebgp 4 ibgp 2')
    config.commit()
    assert_bgp_commands('network 192.0.2.0/24 route-map NVYRBGPPOLICY', 'redistribute connected',
                        'redistribute static route-map NVYRBGPPOLICY', 'aggregate-address 192.0.0.0/16 as-set summary-only',
                        'maximum-paths 4', 'maximum-paths ibgp 2')


def test_ipv6_advertisements(config):
    """IPv6 advertisements retain the corresponding family and prefix lengths."""
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv6-unicast network 2001:db8::/48 route-map NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv6-unicast redistribute connected route-map NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv6-unicast redistribute static')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv6-unicast aggregate-address 2001:db8::/32 summary-only')
    config.set('set vrf name NVYRBGP protocols bgp address-family ipv6-unicast maximum-paths ebgp 2 ibgp 4')
    config.commit()
    assert_bgp_commands('network 2001:db8::/48 route-map NVYRBGPPOLICY', 'redistribute connected route-map NVYRBGPPOLICY',
                        'redistribute static', 'aggregate-address 2001:db8::/32 summary-only', 'maximum-paths 2', 'maximum-paths ibgp 4')


def test_missing_local_as_rejected(config):
    """An incomplete BGP instance cannot be applied."""
    config.delete('delete vrf name NVYRBGP protocols bgp local-as')
    with assert_raises(CommitError, match='local-as is required'):
        config.commit()


def test_missing_remote_as_rejected(config):
    """A neighbor cannot silently use an unspecified remote AS."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2')
    with assert_raises(CommitError, match='remote-as is required'):
        config.commit()


def test_external_filtering_required(config):
    """Opt-in policy enforcement rejects an unfiltered external family."""
    config.set('set vrf name NVYRBGP protocols bgp parameters ebgp-requires-policy enable')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65001 address-family ipv4-unicast')
    with assert_raises(CommitError, match='explicit import policy'):
        config.commit()


def test_parameter_defaults(config):
    """The four nVyR defaults remain explicit in native FRR configuration."""
    assert_bgp_commands('no bgp ebgp-requires-policy', 'no bgp reject-as-sets',
                        'no bgp default ipv4-unicast', 'no bgp network import-check')


def test_ipv4_implicit_activation(config):
    """IPv4 default activation applies to a neighbor without an explicit family."""
    config.set('set vrf name NVYRBGP protocols bgp parameters default ipv4-unicast enable')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000')
    config.commit()
    assert_bgp_commands('neighbor 192.0.2.2 remote-as 65000', absent=('no bgp default ipv4-unicast',))


def test_ipv6_implicit_activation(config):
    """IPv6 default activation is independent from IPv4 activation."""
    config.set('set vrf name NVYRBGP protocols bgp parameters default ipv6-unicast enable')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8::2 remote-as 65000')
    config.commit()
    assert_bgp_commands('bgp default ipv6-unicast', 'no bgp default ipv4-unicast')


def test_bestpath_parameters(config):
    """MED, AS-path and bandwidth selection survive native readback together."""
    config.set('set vrf name NVYRBGP protocols bgp parameters bestpath med confed enable missing-as-worst enable')
    config.set('set vrf name NVYRBGP protocols bgp parameters bestpath bandwidth skip-missing compare-routerid enable')
    config.commit()
    assert_bgp_commands('bgp bestpath med confed missing-as-worst',
                        'bgp bestpath bandwidth skip-missing', 'bgp bestpath compare-routerid')


def test_confederation(config):
    """A confederation retains its public AS and multiple member ASes."""
    config.set('set vrf name NVYRBGP protocols bgp parameters confederation identifier 64512 peers 65001 peers 65002')
    config.commit()
    assert_bgp_commands('bgp confederation identifier 64512', 'bgp confederation peers 65001 65002')


def test_graceful_restart(config):
    """Restart mode and timers can be removed to return to helper mode."""
    config.set('set vrf name NVYRBGP protocols bgp parameters graceful-restart mode restart restart-time 90 stalepath-time 240 select-defer-time 60 rib-stale-time 300')
    config.commit()
    assert_bgp_commands('bgp graceful-restart', 'bgp graceful-restart restart-time 90',
                        'bgp graceful-restart stalepath-time 240')
    config.delete('delete vrf name NVYRBGP protocols bgp parameters graceful-restart')
    config.commit()
    assert_bgp_commands(absent=('bgp graceful-restart restart-time 90', 'bgp graceful-restart-disable'))


def test_long_lived_graceful_restart(config):
    """Long-lived graceful restart advertises a configurable stale lifetime."""
    config.set('set vrf name NVYRBGP protocols bgp parameters long-lived-graceful-restart stale-time 300')
    config.commit()
    assert_bgp_commands('bgp long-lived-graceful-restart stale-time 300')


def test_dynamic_ipv4_listener(config):
    """IPv4 dynamic peers are assigned a configured peer group."""
    config.set('set vrf name NVYRBGP protocols bgp peer-group DYNAMIC remote-as 65000 address-family ipv4-unicast')
    config.set('set vrf name NVYRBGP protocols bgp parameters listen limit 25 range 192.0.2.0/24 peer-group DYNAMIC')
    config.commit()
    assert_bgp_commands('bgp listen limit 25', 'bgp listen range 192.0.2.0/24 peer-group DYNAMIC')


def test_dynamic_ipv6_listener(config):
    """IPv6 dynamic peers use a separate prefix and IPv6 family."""
    config.set('set vrf name NVYRBGP protocols bgp peer-group DYNAMIC remote-as 65000 address-family ipv6-unicast')
    config.set('set vrf name NVYRBGP protocols bgp parameters listen range 2001:db8::/32 peer-group DYNAMIC')
    config.commit()
    assert_bgp_commands('bgp listen range 2001:db8::/32 peer-group DYNAMIC')


def test_maximum_med(config):
    """Administrative and startup MED controls remain distinct native settings."""
    config.set('set vrf name NVYRBGP protocols bgp parameters max-med administrative 1000 on-startup time 30 med 500')
    config.commit()
    assert_bgp_commands('bgp max-med administrative 1000', 'bgp max-med on-startup 30 500')


def test_tcp_keepalive(config):
    """The complete socket keepalive tuple is passed to FRR."""
    config.set('set vrf name NVYRBGP protocols bgp parameters tcp-keepalive idle 10 interval 5 probes 3')
    config.commit()
    assert_bgp_commands('bgp tcp-keepalive 10 5 3')


def test_partial_tcp_keepalive_rejected(config):
    """An incomplete native TCP keepalive tuple fails before reload."""
    config.set('set vrf name NVYRBGP protocols bgp parameters tcp-keepalive idle 10')
    with assert_raises(CommitError, match='requires idle, interval and probes'):
        config.commit()


def test_confederation_local_as_rejected(config):
    """The public confederation AS cannot also identify this member."""
    config.set('set vrf name NVYRBGP protocols bgp parameters confederation identifier 65000')
    with assert_raises(CommitError, match='must differ'):
        config.commit()


def test_dynamic_missing_group_rejected(config):
    """A listening range must resolve to a usable local peer group."""
    config.set('set vrf name NVYRBGP protocols bgp parameters listen range 192.0.2.0/24 peer-group MISSING')
    with assert_raises(CommitError, match='configured peer-group'):
        config.commit()


def test_minimum_holdtime(config):
    """A minimum accepted hold time is retained by the native instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters minimum-holdtime 30')
    config.commit()
    assert_bgp_commands('bgp minimum-holdtime 30')


def test_minimum_holdtime_writer_bug_rejected(config):
    """Reject the minimum hold value lost by FRR's writer at CLI entry."""
    with assert_raises(RouterError, match='integer'):
        config.set('set vrf name NVYRBGP protocols bgp parameters minimum-holdtime 180')


def test_reserved_holdtime_rejected(config):
    """Reserved BGP hold times fail at entry instead of waiting for commit."""
    with assert_raises(RouterError, match='integer'):
        config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 timers holdtime 2')


def test_password_whitespace_rejected(config):
    """FRR must preserve the exact secret supplied at CLI entry."""
    with assert_raises(RouterError, match='whitespace'):
        config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 password "two  spaces"')


def test_dampening_vrf_rejected(config):
    """FRR's documented VRF dampening limitation is visible before application."""
    config.set('set vrf name NVYRBGP protocols bgp parameters dampening state enable')
    with assert_raises(CommitError, match='default VRF'):
        config.commit()


def test_missing_policy_rejected(config):
    """Missing policy names fail before any FRR reload."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000 address-family ipv4-unicast route-map import NVYRBGPMISSING')
    with assert_raises(CommitError, match='not configured'):
        config.commit()


def test_conflicting_filters_rejected(config):
    """Access-list and prefix-list cannot occupy one direction's native filter slot."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000 address-family ipv4-unicast access-list in NVYRBGPPOLICY')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast prefix-list in NVYRBGPPOLICY')
    with assert_raises(CommitError, match='mutually exclusive'):
        config.commit()


def test_ttl_conflict_rejected(config):
    """External multihop and GTSM cannot be enabled simultaneously."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65001 ebgp-multihop 2 ttl-security hops 2')
    with assert_raises(CommitError, match='mutually exclusive'):
        config.commit()


def test_timer_relationship_rejected(config):
    """Keepalive intervals must fit the configured hold time."""
    config.set('set vrf name NVYRBGP protocols bgp parameters timers keepalive 60 holdtime 30')
    with assert_raises(CommitError, match='one third'):
        config.commit()


def test_update_source_family_rejected(config):
    """Transport source and neighbor addresses must share their IP family."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000 update-source 2001:db8::1')
    with assert_raises(CommitError, match='address family'):
        config.commit()


def test_external_reflector_rejected(config):
    """Only internal neighbors may be route-reflector clients."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65001 shutdown address-family ipv4-unicast route-reflector-client')
    with assert_raises(CommitError, match='internal neighbor'):
        config.commit()


def test_policy_deletion_protected(config):
    """The dependency registrar prevents deleting a referenced BGP policy."""
    config.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as 65000 address-family ipv4-unicast route-map import NVYRBGPPOLICY')
    with assert_raises(RouterError, match='referenc'):
        config.delete('delete policy route-map NVYRBGPPOLICY')


def test_invalid_as_rejected(config):
    """The ASN validator rejects zero before it enters the candidate."""
    with assert_raises(RouterError):
        config.set('set vrf name NVYRBGP protocols bgp local-as 0')


def test_invalid_neighbor_rejected(config):
    """Multicast addresses cannot identify a TCP BGP neighbor."""
    with assert_raises(RouterError):
        config.set('set vrf name NVYRBGP protocols bgp neighbor 224.0.0.1 remote-as 65000')


def test_parameter_allow_martian_nexthop(config):
    """Explicit allow-martian-nexthop enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters allow-martian-nexthop enable')
    config.commit()
    assert_bgp_commands('bgp allow-martian-nexthop')


def test_parameter_client_to_client_reflection(config):
    """Explicit client-to-client reflection disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters client-to-client reflection disable')
    config.commit()
    assert_bgp_commands('no bgp client-to-client reflection')


def test_parameter_ebgp_connected_route_check(config):
    """Explicit ebgp-connected-route-check disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters ebgp-connected-route-check disable')
    config.commit()
    assert_bgp_commands('bgp disable-ebgp-connected-route-check')


def test_parameter_ebgp_requires_policy(config):
    """Explicit ebgp-requires-policy disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters ebgp-requires-policy disable')
    config.commit()
    assert_bgp_commands('no bgp ebgp-requires-policy')


def test_parameter_enforce_first_as(config):
    """Explicit enforce-first-as disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters enforce-first-as disable')
    config.commit()
    assert_bgp_commands('no bgp enforce-first-as')


def test_parameter_fast_convergence(config):
    """Explicit fast-convergence enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters fast-convergence enable')
    config.commit()
    assert_bgp_commands('bgp fast-convergence')


def test_parameter_fast_external_failover(config):
    """Explicit fast-external-failover disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters fast-external-failover disable')
    config.commit()
    assert_bgp_commands('no bgp fast-external-failover')


def test_parameter_graceful_shutdown(config):
    """Explicit graceful-shutdown enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters graceful-shutdown enable')
    config.commit()
    assert_bgp_commands('bgp graceful-shutdown')


def test_parameter_hard_administrative_reset(config):
    """Explicit hard-administrative-reset disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters hard-administrative-reset disable')
    config.commit()
    assert_bgp_commands('no bgp hard-administrative-reset')


def test_parameter_ipv6_auto_ra(config):
    """Explicit ipv6-auto-ra disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters ipv6-auto-ra disable')
    config.commit()
    assert_bgp_commands('no bgp ipv6-auto-ra')


def test_parameter_log_neighbor_changes(config):
    """Explicit log-neighbor-changes enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters log-neighbor-changes enable')
    config.commit()
    assert_bgp_commands('bgp log-neighbor-changes')


def test_parameter_reject_as_sets(config):
    """Explicit reject-as-sets disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters reject-as-sets disable')
    config.commit()
    assert_bgp_commands('no bgp reject-as-sets')


def test_parameter_shutdown(config):
    """Explicit shutdown enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters shutdown enable')
    config.commit()
    assert_bgp_commands('bgp shutdown')


def test_parameter_suppress_duplicates(config):
    """Explicit suppress-duplicates disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters suppress-duplicates disable')
    config.commit()
    assert_bgp_commands('no bgp suppress-duplicates')


def test_parameter_default_ipv4_unicast(config):
    """Explicit default ipv4-unicast disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters default ipv4-unicast disable')
    config.commit()
    assert_bgp_commands('no bgp default ipv4-unicast')


def test_parameter_default_ipv6_unicast(config):
    """Explicit default ipv6-unicast enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters default ipv6-unicast enable')
    config.commit()
    assert_bgp_commands('bgp default ipv6-unicast')


def test_parameter_default_show_hostname(config):
    """Explicit default show-hostname enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters default show-hostname enable')
    config.commit()
    assert_bgp_commands('bgp default show-hostname')


def test_parameter_default_show_nexthop_hostname(config):
    """Explicit default show-nexthop-hostname enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters default show-nexthop-hostname enable')
    config.commit()
    assert_bgp_commands('bgp default show-nexthop-hostname')


def test_parameter_default_dynamic_capability(config):
    """Explicit default dynamic-capability enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters default dynamic-capability enable')
    config.commit()
    assert_bgp_commands('bgp default dynamic-capability')


def test_parameter_default_link_local_capability(config):
    """Explicit default link-local-capability enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters default link-local-capability enable')
    config.commit()
    assert_bgp_commands('bgp default link-local-capability')


def test_parameter_default_shutdown(config):
    """Explicit default shutdown enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters default shutdown enable')
    config.commit()
    assert_bgp_commands('bgp default shutdown')


def test_parameter_network_import_check(config):
    """Explicit network import-check disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters network import-check disable')
    config.commit()
    assert_bgp_commands('no bgp network import-check')


def test_parameter_route_reflector_allow_outbound_policy(config):
    """Explicit route-reflector allow-outbound-policy enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters route-reflector allow-outbound-policy enable')
    config.commit()
    assert_bgp_commands('bgp route-reflector allow-outbound-policy')


def test_parameter_bestpath_aigp(config):
    """Explicit bestpath aigp enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters bestpath aigp enable')
    config.commit()
    assert_bgp_commands('bgp bestpath aigp')


def test_parameter_bestpath_compare_routerid(config):
    """Explicit bestpath compare-routerid enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters bestpath compare-routerid enable')
    config.commit()
    assert_bgp_commands('bgp bestpath compare-routerid')


def test_parameter_bestpath_as_path_ignore(config):
    """Explicit bestpath as-path ignore enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters bestpath as-path ignore enable')
    config.commit()
    assert_bgp_commands('bgp bestpath as-path ignore')


def test_parameter_bestpath_as_path_confed(config):
    """Explicit bestpath as-path confed enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters bestpath as-path confed enable')
    config.commit()
    assert_bgp_commands('bgp bestpath as-path confed')


def test_parameter_bestpath_peer_type_multipath_relax(config):
    """Explicit bestpath peer-type multipath-relax enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters bestpath peer-type multipath-relax enable')
    config.commit()
    assert_bgp_commands('bgp bestpath peer-type multipath-relax')


def test_parameter_graceful_restart_notification(config):
    """Explicit graceful-restart notification disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters graceful-restart notification disable')
    config.commit()
    assert_bgp_commands('no bgp graceful-restart notification')


def test_parameter_graceful_restart_preserve_fw_state(config):
    """Explicit graceful-restart preserve-fw-state enable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters graceful-restart preserve-fw-state enable')
    config.commit()
    assert_bgp_commands('bgp graceful-restart preserve-fw-state')


def test_parameter_graceful_restart_end_of_rib(config):
    """Explicit graceful-restart end-of-rib disable reaches the native BGP instance."""
    config.set('set vrf name NVYRBGP protocols bgp parameters graceful-restart end-of-rib disable')
    config.commit()
    assert_bgp_commands('bgp graceful-restart disable-eor')


def test_parameter_cluster_id(config):
    """Apply cluster id and verify its removal in FRR."""
    config.set('set vrf name NVYRBGP protocols bgp parameters cluster-id 192.0.2.10')
    config.commit()
    assert_bgp_commands('bgp cluster-id 192.0.2.10')

    config.delete('delete vrf name NVYRBGP protocols bgp parameters cluster-id')
    config.commit()
    assert_bgp_commands(absent=('bgp cluster-id 192.0.2.10',))


def test_parameter_conditional_advertisement_timer(config):
    """Apply conditional advertisement timer and verify its removal in FRR."""
    config.set('set vrf name NVYRBGP protocols bgp parameters conditional-advertisement timer 10')
    config.commit()
    assert_bgp_commands('bgp conditional-advertisement timer 10')

    config.delete('delete vrf name NVYRBGP protocols bgp parameters conditional-advertisement')
    config.commit()
    assert_bgp_commands(absent=('bgp conditional-advertisement timer 10',))


def test_parameter_default_local_preference(config):
    """Apply default local preference and verify its removal in FRR."""
    config.set('set vrf name NVYRBGP protocols bgp parameters default local-preference 200')
    config.commit()
    assert_bgp_commands('bgp default local-preference 200')

    config.delete('delete vrf name NVYRBGP protocols bgp parameters default local-preference')
    config.commit()
    assert_bgp_commands(absent=('bgp default local-preference 200',))


def test_parameter_default_subgroup_queue(config):
    """Apply default subgroup queue and verify its removal in FRR."""
    config.set('set vrf name NVYRBGP protocols bgp parameters default subgroup-pkt-queue-max 50')
    config.commit()
    assert_bgp_commands('bgp default subgroup-pkt-queue-max 50')

    config.delete('delete vrf name NVYRBGP protocols bgp parameters default subgroup-pkt-queue-max')
    config.commit()
    assert_bgp_commands(absent=('bgp default subgroup-pkt-queue-max 50',))


def test_parameter_legacy_software_capability(config):
    """Apply legacy software capability and verify its removal in FRR."""
    config.set('set vrf name NVYRBGP protocols bgp parameters default software-version-capability legacy')
    config.commit()
    assert_bgp_commands('bgp default software-version-capability')

    config.delete('delete vrf name NVYRBGP protocols bgp parameters default software-version-capability')
    config.commit()
    assert_bgp_commands(absent=('bgp default software-version-capability',))


def test_parameter_suppress_fib_pending(config):
    """Apply suppress fib pending and verify its removal in FRR."""
    config.set('set vrf name NVYRBGP protocols bgp parameters suppress-fib-pending enable suppress-fib-pending-delay 2000')
    config.commit()
    assert_bgp_commands('bgp suppress-fib-pending 2000')

    config.delete('delete vrf name NVYRBGP protocols bgp parameters suppress-fib-pending-delay')
    config.commit()
    assert_bgp_commands(absent=('bgp suppress-fib-pending 2000',))


def test_parameter_bestpath_multipath_as_set(config):
    """Apply bestpath multipath as set and verify its removal in FRR."""
    config.set('set vrf name NVYRBGP protocols bgp parameters bestpath as-path multipath-relax enable multipath-relax-as-set enable')
    config.commit()
    assert_bgp_commands('bgp bestpath as-path multipath-relax as-set')

    config.delete('delete vrf name NVYRBGP protocols bgp parameters bestpath as-path')
    config.commit()
    assert_bgp_commands(absent=('bgp bestpath as-path multipath-relax as-set',))


def test_parameter_bestpath_bandwidth_missing_default(config):
    """Apply bestpath bandwidth missing default and verify its removal in FRR."""
    config.set('set vrf name NVYRBGP protocols bgp parameters bestpath bandwidth default-weight-for-missing')
    config.commit()
    assert_bgp_commands('bgp bestpath bandwidth default-weight-for-missing')

    config.delete('delete vrf name NVYRBGP protocols bgp parameters bestpath bandwidth')
    config.commit()
    assert_bgp_commands(absent=('bgp bestpath bandwidth default-weight-for-missing',))


def test_suppression_delay_requires_enable(config):
    """Reject suppression delay requires enable before applying BGP."""
    config.set('set vrf name NVYRBGP protocols bgp parameters suppress-fib-pending-delay 2000')
    with assert_raises(CommitError, match='requires suppress-fib-pending enable'):
        config.commit()


def test_startup_med_requires_time(config):
    """Reject startup med requires time before applying BGP."""
    config.set('set vrf name NVYRBGP protocols bgp parameters max-med on-startup med 500')
    with assert_raises(CommitError, match='requires time'):
        config.commit()


def test_as_set_requires_multipath(config):
    """Reject as set requires multipath before applying BGP."""
    config.set('set vrf name NVYRBGP protocols bgp parameters bestpath as-path multipath-relax-as-set enable')
    with assert_raises(CommitError, match='requires multipath-relax enable'):
        config.commit()


def test_confederation_peers_require_identifier(config):
    """Reject confederation peers require identifier before applying BGP."""
    config.set('set vrf name NVYRBGP protocols bgp parameters confederation peers 65001')
    with assert_raises(CommitError, match='require identifier'):
        config.commit()


def test_confederation_peer_is_not_local_as(config):
    """Reject confederation peer is not local as before applying BGP."""
    config.set('set vrf name NVYRBGP protocols bgp parameters confederation identifier 64512 peers 65000')
    with assert_raises(CommitError, match='cannot contain local-as'):
        config.commit()


def test_dynamic_listener_requires_family(config):
    """Reject dynamic listener requires family before applying BGP."""
    config.set('set vrf name NVYRBGP protocols bgp peer-group DYNAMIC remote-as 65001')
    config.set('set vrf name NVYRBGP protocols bgp parameters listen range 192.0.2.0/24 peer-group DYNAMIC')
    with assert_raises(CommitError, match='requires an active address-family'):
        config.commit()


def test_route_map_timer_is_daemon_wide(config):
    """Reject route map timer is daemon wide before applying BGP."""
    config.set('set vrf name NVYRBGP protocols bgp parameters route-map delay-timer 10')
    with assert_raises(CommitError, match='daemon-wide'):
        config.commit()
