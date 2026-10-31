"""Validate static-routing CLI translation into installed FRR configuration."""

import json

import pytest

# Let pytest establish package imports and load conftest before importing helpers.
if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.tree import lookup
from nvyr.config_session import CommitError
from nvyr.errors import RouterError
from nvyr.helpers.process import cmd
from nvyr.op_scripts import static
from smoketests.assertions import (
    assert_no_static_configuration,
    assert_equal, assert_false, assert_in, assert_not_in, assert_raises, assert_config_names_unused,
    assert_no_static_routes, assert_static_route_unconfigured, assert_static_route_configured,
    assert_frr_routes, assert_frr_route_absent, assert_kernel_route,
    assert_kernel_route_absent, assert_static_instance_empty,
    assert_kernel_multipath_weights,
    assert_operational_output,
)
from smoketests.support import prepared_test


def clear_static(config, resources):
    """Withdraw test routes before deleting any supporting link or VRF."""
    config.discard()
    running_config = config.get_config()
    static_config = lookup(running_config, ('protocols', 'static'), None)
    changed = False

    if static_config is not None:
        config.delete('delete protocols static')
        changed = True

    vrf_static = lookup(running_config, ('vrf', 'name', 'NVYRSMOKE', 'protocols', 'static'), None)
    if resources['vrf'] and vrf_static is not None:
        config.delete('delete vrf name NVYRSMOKE protocols static')
        changed = True

    if changed:
        config.commit()


def standup(config, resources):
    """Reserve unused test resources and provide connected next-hop networks."""
    running = config.get_config()
    # Even references to an absent interface/VRF can block its later deletion.
    assert_config_names_unused(running, 'dum997', 'NVYRSMOKE')
    links = json.loads(cmd(['ip', '-j', '-d', 'link', 'show']))
    for link in links:
        assert_not_in(link['ifname'], ('dum997', 'NVYRSMOKE'), msg='Smoketest link name is already in use')
        table = link.get('linkinfo', {}).get('info_data', {}).get('table')
        assert_false(table == 41001, msg='Smoketest VRF table 41001 is already in use')

    configured_vrfs = lookup(running, ('vrf', 'name'), {})
    assert_not_in('NVYRSMOKE', configured_vrfs)
    assert_not_in('dum997', lookup(running, ('interfaces', 'dummy'), {}))
    for vrf in configured_vrfs.values():
        assert_false(str(vrf.get('table')) == '41001', msg='Smoketest table is already configured')

    # Read all tables rather than querying a possibly nonexistent table directly.
    for family in ('-4', '-6'):
        routes = json.loads(cmd(['ip', family, '-j', 'route', 'show', 'table', 'all']))
        for route in routes:
            assert_false(str(route.get('table')) == '41001', msg='Smoketest table contains existing routes')

    resources['prepared'] = True
    clear_static(config, resources)
    assert_no_static_routes('192.0.2.0/24', '2001:db8:100::/64')
    assert_kernel_route_absent('198.18.97.0/24')
    assert_kernel_route_absent('2001:db8:97::/64')

    # Use the CLI/configd lifecycle for the supporting interface as well as routes.
    # Track ownership before committing so cleanup also handles partial commits.
    resources['dummy'] = True
    config.set('set interfaces dummy dum997 address 198.18.97.1/24')
    config.set('set interfaces dummy dum997 address 2001:db8:97::1/64')
    config.set('set interfaces dummy dum997 address fe80::97:1/64')
    config.commit()


def cleanup(config, resources):
    """Attempt every owned-resource cleanup; report failures to the global restore."""
    if not resources['prepared']:
        return

    errors = []
    try:
        clear_static(config, resources)
        assert_no_static_routes('192.0.2.0/24', '2001:db8:100::/64')
        running = config.get_config()
        if resources['vrf'] and lookup(running, ('vrf', 'name', 'NVYRSMOKE'), None) is not None:
            assert_kernel_route_absent('192.0.2.0/24', vrf='NVYRSMOKE')
            assert_kernel_route_absent('2001:db8:100::/64', vrf='NVYRSMOKE')
    except Exception as error:
        errors.append(f'route cleanup: {error}')

    # Removing our dummy through configd removes its addresses and connected routes.
    if resources['dummy']:
        try:
            config.discard()
            running = config.get_config()
            if lookup(running, ('interfaces', 'dummy', 'dum997'), None) is not None:
                config.delete('delete interfaces dummy dum997')
                config.commit()
        except Exception as error:
            errors.append(f'dummy cleanup: {error}')

    if resources['vrf']:
        try:
            config.discard()
            running = config.get_config()
            if lookup(running, ('vrf', 'name', 'NVYRSMOKE'), None) is not None:
                config.delete('delete vrf name NVYRSMOKE')
                config.commit()
        except Exception as error:
            errors.append(f'VRF cleanup: {error}')

    if errors:
        raise RuntimeError('\n'.join(errors))


def create_test_vrf(config, resources):
    """Create the reserved VRF through configd, tracking even a partial commit."""
    if resources['vrf']:
        return
    config.set('set vrf name NVYRSMOKE table 41001')
    resources['vrf'] = True
    config.commit()


@pytest.fixture(scope='module')
def static_suite(config, request):
    """Keep the next-hop interface and optional VRF across independent route cases."""
    def stop(message):
        """Stop further tests if local cleanup cannot establish a clean baseline."""
        request.session.shouldstop = message

    resources = {'prepared': False, 'dummy': False, 'vrf': False}

    def prepare(session):
        """Bind the module resource inventory to the shared lifecycle."""
        standup(session, resources)

    def restore(session):
        """Release only resources claimed by this module."""
        cleanup(session, resources)

    with prepared_test(config, prepare, restore, stop=stop):
        yield resources


@pytest.fixture(autouse=True)
def static_environment(config, request, static_suite):
    """Withdraw only test routes between cases; retain the supporting topology."""
    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, lambda session: None,
                       lambda session: clear_static(session, static_suite), stop=stop):
        yield static_suite


def test_ipv4_blackhole(config):
    """An IPv4 blackhole becomes an exact FRR static-route directive."""
    config.set('set protocols static route 192.0.2.0/24 blackhole')
    config.commit()

    assert_static_route_configured('192.0.2.0/24', 'blackhole')


def test_ipv6_reject(config):
    """An IPv6 reject route becomes an exact FRR static-route directive."""
    config.set('set protocols static route6 2001:db8:100::/64 reject')
    config.commit()

    assert_static_route_configured('2001:db8:100::/64', 'reject')


def test_disable_and_reenable(config):
    """Prefix disable withdraws forwarding while retaining the editable route."""
    # Install the route.
    config.set('set protocols static route 192.0.2.0/24 blackhole')
    config.commit()

    assert_static_route_configured('192.0.2.0/24', 'blackhole')

    # Disable the route without deleting its configuration.
    config.set('set protocols static route 192.0.2.0/24 disable')
    config.commit()

    running_config = config.get_config()
    route = lookup(running_config, ('protocols', 'static', 'route', '192.0.2.0/24'))

    assert_in('disable', route)
    assert_static_route_unconfigured('192.0.2.0/24', 'blackhole')

    # Re-enable the route.
    config.delete('delete protocols static route 192.0.2.0/24 disable')
    config.commit()

    assert_static_route_configured('192.0.2.0/24', 'blackhole')


def test_ipv4_reject(config):
    """IPv4 reject must use an unreachable route rather than a silent blackhole."""
    config.set('set protocols static route 192.0.2.0/24 reject')
    config.commit()

    assert_static_route_configured('192.0.2.0/24', 'reject')


def test_ipv6_blackhole(config):
    """IPv6 silent discard must be installed independently of IPv4 support."""
    config.set('set protocols static route6 2001:db8:100::/64 blackhole')
    config.commit()

    assert_static_route_configured('2001:db8:100::/64', 'blackhole')


def test_ipv4_next_hop(config):
    """A connected IPv4 gateway resolves through the test dummy interface."""
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 198.18.97.2')


def test_ipv6_next_hop(config):
    """A global IPv6 gateway resolves using the test interface's connected route."""
    config.set('set protocols static route6 2001:db8:100::/64 next-hop 2001:db8:97::2')
    config.commit()

    assert_frr_routes('ipv6 route 2001:db8:100::/64 2001:db8:97::2')


def test_interface_only_routes(config):
    """Both address families support direct interface paths without gateways."""
    config.set('set protocols static route 192.0.2.0/24 interface dum997')
    config.set('set protocols static route6 2001:db8:100::/64 interface dum997')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 dum997', 'ipv6 route 2001:db8:100::/64 dum997')


def test_gateway_interface_binding(config):
    """Gateway/interface pairs remain explicit in FRR and use the selected link."""
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 interface dum997')
    config.set('set protocols static route6 2001:db8:100::/64 next-hop 2001:db8:97::2 interface dum997')
    config.commit()

    assert_frr_routes(
        'ip route 192.0.2.0/24 198.18.97.2 dum997',
        'ipv6 route 2001:db8:100::/64 2001:db8:97::2 dum997',
    )


def test_onlink_gateways(config):
    """Onlink permits off-subnet gateways only through an explicitly bound link."""
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.98.2 interface dum997')
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.98.2 onlink')
    config.set('set protocols static route6 2001:db8:100::/64 next-hop 2001:db8:98::2 interface dum997')
    config.set('set protocols static route6 2001:db8:100::/64 next-hop 2001:db8:98::2 onlink')
    config.commit()

    assert_frr_routes(
        'ip route 192.0.2.0/24 198.18.98.2 dum997 onlink',
        'ipv6 route 2001:db8:100::/64 2001:db8:98::2 dum997 onlink',
    )


def test_link_local_and_ipv4_over_ipv6(config):
    """A scoped link-local gateway supports IPv6 and RFC 5549 IPv4 routes."""
    config.set('set protocols static route 192.0.2.0/24 next-hop fe80::97:2 interface dum997')
    config.set('set protocols static route6 2001:db8:100::/64 next-hop fe80::97:2 interface dum997')
    config.commit()

    assert_frr_routes(
        'ip route 192.0.2.0/24 fe80::97:2 dum997',
        'ipv6 route 2001:db8:100::/64 fe80::97:2 dum997',
    )


def test_ipv4_multipath_and_next_hop_disable(config):
    """Disabling one ECMP member withdraws only that member; enabling restores it."""
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2')
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.3')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 198.18.97.2', 'ip route 192.0.2.0/24 198.18.97.3')

    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 disable')
    config.commit()

    assert_frr_route_absent('ip route 192.0.2.0/24 198.18.97.2')

    config.delete('delete protocols static route 192.0.2.0/24 next-hop 198.18.97.2 disable')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 198.18.97.2', 'ip route 192.0.2.0/24 198.18.97.3')


def test_ipv6_weighted_multipath(config):
    """Independent IPv6 next hops retain their configured relative weights."""
    config.set('set protocols static route6 2001:db8:100::/64 next-hop 2001:db8:97::2 weight 2')
    config.set('set protocols static route6 2001:db8:100::/64 next-hop 2001:db8:97::3 weight 3')
    config.commit()

    assert_frr_routes(
        'ipv6 route 2001:db8:100::/64 2001:db8:97::2 weight 2',
        'ipv6 route 2001:db8:100::/64 2001:db8:97::3 weight 3',
    )


def test_distance_selection_and_fallback(config):
    """Distance and disabled paths translate independently of FRR route selection."""
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 distance 10')
    config.set('set protocols static route 192.0.2.0/24 blackhole distance 200')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 198.18.97.2 10', 'ip route 192.0.2.0/24 blackhole 200')

    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 disable')
    config.commit()

    assert_frr_route_absent('ip route 192.0.2.0/24 198.18.97.2 10')
    assert_frr_routes('ip route 192.0.2.0/24 blackhole 200')


    config.delete('delete protocols static route 192.0.2.0/24 next-hop 198.18.97.2 disable')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 198.18.97.2 10', 'ip route 192.0.2.0/24 blackhole 200')


def test_metric_selection_and_tag_update(config):
    """Gateway metric and tag changes replace the corresponding FRR directives."""
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 metric 20')
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 tag 123')
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.3 metric 40')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 198.18.97.2 tag 123 metric 20')

    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 metric 60')
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 tag 456')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 198.18.97.2 tag 456 metric 60')
    assert_frr_route_absent('ip route 192.0.2.0/24 198.18.97.2 tag 123 metric 20')


def test_interface_path_options_and_disable(config):
    """Interface paths support preferences, tags, weights, and individual disable."""
    config.set('set protocols static route 192.0.2.0/24 interface dum997 distance 10')
    config.set('set protocols static route 192.0.2.0/24 interface dum997 metric 20')
    config.set('set protocols static route 192.0.2.0/24 interface dum997 tag 123')
    config.set('set protocols static route 192.0.2.0/24 interface dum997 weight 2')
    config.set('set protocols static route 192.0.2.0/24 reject distance 200')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 dum997 tag 123 10 metric 20 weight 2')

    config.set('set protocols static route 192.0.2.0/24 interface dum997 disable')
    config.commit()

    assert_frr_route_absent('ip route 192.0.2.0/24 dum997 tag 123 10 metric 20 weight 2')
    assert_frr_routes('ip route 192.0.2.0/24 reject 200')

    assert_frr_route_absent('ip route 192.0.2.0/24 dum997 tag 123 10 metric 20 weight 2')

    config.delete('delete protocols static route 192.0.2.0/24 interface dum997 disable')
    config.commit()


def test_discard_path_options_and_disable(config):
    """Disabled discard alternatives are omitted; switching actions replaces the FIB entry."""
    config.set('set protocols static route 192.0.2.0/24 blackhole distance 10')
    config.set('set protocols static route 192.0.2.0/24 blackhole metric 20')
    config.set('set protocols static route 192.0.2.0/24 blackhole tag 123')
    config.set('set protocols static route 192.0.2.0/24 reject distance 30')
    config.set('set protocols static route 192.0.2.0/24 reject metric 40')
    config.set('set protocols static route 192.0.2.0/24 reject tag 456')
    config.set('set protocols static route 192.0.2.0/24 reject disable')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 blackhole tag 123 10 metric 20')
    assert_frr_route_absent('ip route 192.0.2.0/24 reject tag 456 30 metric 40')

    config.set('set protocols static route 192.0.2.0/24 blackhole disable')
    config.delete('delete protocols static route 192.0.2.0/24 reject disable')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 reject tag 456 30 metric 40')
    assert_frr_route_absent('ip route 192.0.2.0/24 blackhole tag 123 10 metric 20')


def test_descriptions_and_implicit_defaults(config):
    """Descriptions remain in nVyR, while default distance/metric stay implicit."""
    config.set('set protocols static route 192.0.2.0/24 description "Test destination"')
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 description "Primary gateway"')
    config.commit()

    route = lookup(config.get_config(), ('protocols', 'static', 'route', '192.0.2.0/24'))
    assert_equal(route['description'], 'Test destination')
    assert_equal(route['next-hop']['198.18.97.2'], {'description': 'Primary gateway'})
    assert_frr_routes('ip route 192.0.2.0/24 198.18.97.2')


def test_ipv6_prefix_disable(config):
    """Disabling an IPv6 prefix withdraws all of its otherwise enabled paths."""
    config.set('set protocols static route6 2001:db8:100::/64 next-hop 2001:db8:97::2')
    config.commit()

    assert_frr_routes('ipv6 route 2001:db8:100::/64 2001:db8:97::2')

    config.set('set protocols static route6 2001:db8:100::/64 disable')
    config.commit()
    assert_static_route_unconfigured('2001:db8:100::/64', '2001:db8:97::2')

    config.delete('delete protocols static route6 2001:db8:100::/64 disable')
    config.commit()

    assert_frr_routes('ipv6 route 2001:db8:100::/64 2001:db8:97::2')


def test_source_specific_routes(config):
    """A source-specific route can coexist with a destination-only IPv6 route."""
    config.set('set protocols static route6 2001:db8:100::/64 blackhole')
    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 next-hop 2001:db8:97::2')
    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:300::/64 interface dum997')
    config.commit()

    assert_frr_routes(
        'ipv6 route 2001:db8:100::/64 blackhole',
        'ipv6 route 2001:db8:100::/64 from 2001:db8:200::/64 2001:db8:97::2',
        'ipv6 route 2001:db8:100::/64 from 2001:db8:300::/64 dum997',
    )


def test_source_specific_disable_and_delete(config):
    """Source-group disable and deletion leave sibling source routes installed."""
    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 blackhole')
    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:300::/64 reject')
    config.commit()

    assert_frr_routes('ipv6 route 2001:db8:100::/64 from 2001:db8:200::/64 blackhole',
                      'ipv6 route 2001:db8:100::/64 from 2001:db8:300::/64 reject')


    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 disable')
    config.commit()

    assert_frr_routes('ipv6 route 2001:db8:100::/64 from 2001:db8:300::/64 reject')

    assert_frr_route_absent('ipv6 route 2001:db8:100::/64 from 2001:db8:200::/64 blackhole')

    config.delete('delete protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 disable')
    config.commit()

    assert_frr_routes('ipv6 route 2001:db8:100::/64 from 2001:db8:200::/64 blackhole')

    config.delete('delete protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64')
    config.commit()

    assert_frr_route_absent('ipv6 route 2001:db8:100::/64 from 2001:db8:200::/64 blackhole')


def test_named_vrf_isolation(config, static_environment):
    """Identical prefixes in default and named VRFs keep independent actions."""
    create_test_vrf(config, static_environment)
    config.set('set protocols static route 192.0.2.0/24 blackhole')
    config.set('set vrf name NVYRSMOKE protocols static route 192.0.2.0/24 reject')
    config.set('set vrf name NVYRSMOKE protocols static route6 2001:db8:100::/64 blackhole')
    config.commit()

    assert_static_route_configured('192.0.2.0/24', 'blackhole')
    assert_frr_routes('ip route 192.0.2.0/24 reject', 'ipv6 route 2001:db8:100::/64 blackhole', vrf='NVYRSMOKE')

    # Removing the VRF's routes must leave its protocol instance and default routes.
    config.delete('delete vrf name NVYRSMOKE protocols static')
    config.commit()

    assert_static_instance_empty('NVYRSMOKE')
    assert_static_route_configured('192.0.2.0/24', 'blackhole')


def test_next_hop_vrf_resolution(config, static_environment):
    """Named-VRF routes can resolve both address families through the default VRF."""
    create_test_vrf(config, static_environment)
    config.set('set vrf name NVYRSMOKE protocols static route 192.0.2.0/24 next-hop 198.18.97.2 vrf default')
    config.set('set vrf name NVYRSMOKE protocols static route6 2001:db8:100::/64 next-hop 2001:db8:97::2 vrf default')
    config.commit()

    assert_frr_routes(
        'ip route 192.0.2.0/24 198.18.97.2 nexthop-vrf default',
        'ipv6 route 2001:db8:100::/64 2001:db8:97::2 nexthop-vrf default',
        vrf='NVYRSMOKE',
    )


def test_delete_last_route_and_recreate(config):
    """Deleting the last route leaves a reusable empty static protocol instance."""
    config.set('set protocols static route 192.0.2.0/24 blackhole')
    config.commit()
    assert_static_route_configured('192.0.2.0/24', 'blackhole')

    config.delete('delete protocols static')
    config.commit()

    assert_no_static_configuration()
    assert_static_instance_empty()

    config.set('set protocols static route 192.0.2.0/24 reject')
    config.commit()
    assert_static_route_configured('192.0.2.0/24', 'reject')


def test_failed_commit_preserves_existing_routes(config):
    """A bad next hop rejects the whole static owner without withdrawing good routes."""
    config.set('set protocols static route 192.0.2.0/24 blackhole')
    config.commit()
    original = config.get_config()

    config.delete('delete protocols static route 192.0.2.0/24 blackhole')
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.1')

    with assert_raises(CommitError, match='assigned to the local system'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_static_route_configured('192.0.2.0/24', 'blackhole')
    config.discard()


def test_ipv4_weighted_multipath(config):
    """IPv4 ECMP must preserve relative weights when installing both next hops."""
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 weight 2')
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.3 weight 3')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 198.18.97.2 weight 2', 'ip route 192.0.2.0/24 198.18.97.3 weight 3')


def test_next_hop_deletion(config):
    """Deleting one gateway preserves its sibling in the installed FRR configuration."""
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2')
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.3')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 198.18.97.2', 'ip route 192.0.2.0/24 198.18.97.3')

    config.delete('delete protocols static route 192.0.2.0/24 next-hop 198.18.97.2')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 198.18.97.3')

    assert_frr_route_absent('ip route 192.0.2.0/24 198.18.97.2')


def test_disabled_prefix_allows_inactive_paths(config):
    """A disabled prefix may retain paths that are not valid until enabled."""
    config.set('set protocols static route6 2001:db8:100::/64 disable')
    config.set('set protocols static route6 2001:db8:100::/64 next-hop fe80::97:2')
    config.commit()
    assert_no_static_configuration()

    config.delete('delete protocols static route6 2001:db8:100::/64 disable')
    with assert_raises(CommitError, match='link-local next hop requires an interface'):
        config.commit()

    # Correct the candidate and verify that the previously disabled route can install.
    config.set('set protocols static route6 2001:db8:100::/64 next-hop fe80::97:2 interface dum997')
    config.commit()

    assert_frr_routes('ipv6 route 2001:db8:100::/64 fe80::97:2 dum997')


def test_source_specific_path_options(config):
    """Source-specific paths share distance, metric, tag, weight, and disable behavior."""
    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 description "Source group"')
    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 next-hop 2001:db8:97::2 distance 10')
    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 next-hop 2001:db8:97::2 metric 20')
    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 next-hop 2001:db8:97::2 tag 123')
    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 next-hop 2001:db8:97::2 weight 2')
    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 reject distance 200')
    config.commit()

    assert_frr_routes('ipv6 route 2001:db8:100::/64 from 2001:db8:200::/64 2001:db8:97::2 tag 123 10 metric 20 weight 2')

    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 next-hop 2001:db8:97::2 disable')
    config.commit()

    config.set('set protocols static route6 2001:db8:100::/64 disable')
    config.commit()
    assert_no_static_configuration()


def test_vrf_source_specific_route(config, static_environment):
    """A source-specific route in a named VRF must not leak into the main table."""
    create_test_vrf(config, static_environment)
    config.set('set vrf name NVYRSMOKE protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 reject')
    config.commit()

    assert_frr_routes('ipv6 route 2001:db8:100::/64 from 2001:db8:200::/64 reject', vrf='NVYRSMOKE')


def test_next_hop_vrf_local_address_rejected(config, static_environment):
    """Local-address validation uses the next-hop VRF rather than the route VRF."""
    create_test_vrf(config, static_environment)
    config.set('set vrf name NVYRSMOKE protocols static route 192.0.2.0/24 next-hop 198.18.97.1 vrf default')

    with assert_raises(CommitError, match='local system in VRF default'):
        config.commit()

    config.discard()


def test_interface_dependency_blocks_deletion(config):
    """An interface referenced by a static route cannot be removed underneath it."""
    config.set('set protocols static route 192.0.2.0/24 interface dum997')
    config.commit()

    assert_frr_routes('ip route 192.0.2.0/24 dum997')
    original = config.get_config(source='candidate')

    with assert_raises(RouterError, match='referenc'):
        config.delete('delete interfaces dummy dum997')

    assert_equal(config.get_config(source='candidate'), original)


def test_invalid_route_commit_empty_prefix(config):
    """Reject empty prefix while preserving the running routes."""
    original = config.get_config()
    config.set('set protocols static route 192.0.2.0/24')

    with assert_raises(CommitError, match='at least one enabled'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_invalid_route_commit_disabled_gateway(config):
    """Reject disabled gateway while preserving the running routes."""
    original = config.get_config()
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 disable')

    with assert_raises(CommitError, match='at least one enabled'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_invalid_route_commit_disabled_interface(config):
    """Reject disabled interface while preserving the running routes."""
    original = config.get_config()
    config.set('set protocols static route 192.0.2.0/24 interface dum997 disable')

    with assert_raises(CommitError, match='at least one enabled'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_invalid_route_commit_disabled_blackhole(config):
    """Reject disabled blackhole while preserving the running routes."""
    original = config.get_config()
    config.set('set protocols static route 192.0.2.0/24 blackhole disable')

    with assert_raises(CommitError, match='at least one enabled'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_invalid_route_commit_disabled_reject(config):
    """Reject disabled reject while preserving the running routes."""
    original = config.get_config()
    config.set('set protocols static route 192.0.2.0/24 reject disable')

    with assert_raises(CommitError, match='at least one enabled'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_invalid_route_commit_onlink_without_interface(config):
    """Reject onlink without interface while preserving the running routes."""
    original = config.get_config()
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 onlink')

    with assert_raises(CommitError, match='onlink requires an interface'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_invalid_route_commit_unscoped_link_local(config):
    """Reject unscoped link local while preserving the running routes."""
    original = config.get_config()
    config.set('set protocols static route6 2001:db8:100::/64 next-hop fe80::97:2')

    with assert_raises(CommitError, match='link-local next hop requires an interface'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_invalid_route_commit_local_ipv4(config):
    """Reject local IPv4 while preserving the running routes."""
    original = config.get_config()
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.1')

    with assert_raises(CommitError, match='assigned to the local system'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_invalid_route_commit_local_ipv6(config):
    """Reject local IPv6 while preserving the running routes."""
    original = config.get_config()
    config.set('set protocols static route6 2001:db8:100::/64 next-hop 2001:db8:97::1')

    with assert_raises(CommitError, match='assigned to the local system'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_invalid_route_reserved_interface(config):
    """Reject discard keywords used as interface identifiers at CLI entry."""
    with assert_raises(RouterError, match='reserved by FRR'):
        config.set('set protocols static route 192.0.2.0/24 interface Null0')


def test_invalid_route6_reserved_gateway_interface(config):
    """Gateway interface values receive the same entry validation as path tags."""
    with assert_raises(RouterError, match='reserved by FRR'):
        config.set('set protocols static route6 2001:db8:100::/64 next-hop fe80::1 interface reject')


def test_invalid_source_specific_reserved_interface(config):
    """Source-specific paths also reject FRR's discard identifiers at entry."""
    with assert_raises(RouterError, match='reserved by FRR'):
        config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64 interface blackhole')


def test_invalid_route_commit_empty_source_group(config):
    """Reject empty source group while preserving the running routes."""
    original = config.get_config()
    config.set('set protocols static route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64')

    with assert_raises(CommitError, match='at least one enabled'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_conflicting_paths_discard_conflict(config):
    """Reject discard conflict before applying static routes."""
    original = config.get_config()
    config.set('set protocols static route 192.0.2.0/24 blackhole')
    config.set('set protocols static route 192.0.2.0/24 reject distance 10')

    with assert_raises(CommitError, match='mutually exclusive'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_conflicting_paths_gateway_discard_preference(config):
    """Reject gateway discard preference before applying static routes."""
    original = config.get_config()
    config.set('set protocols static route 192.0.2.0/24 blackhole')
    config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2')

    with assert_raises(CommitError, match='cannot share distance'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_conflicting_paths_interface_discard_preference(config):
    """Reject interface discard preference before applying static routes."""
    original = config.get_config()
    config.set('set protocols static route 192.0.2.0/24 reject metric 10')
    config.set('set protocols static route 192.0.2.0/24 interface dum997 metric 10')

    with assert_raises(CommitError, match='cannot share distance'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_conflicting_paths_duplicate_gateway(config):
    """Reject duplicate gateway before applying static routes."""
    original = config.get_config()
    config.set('set protocols static route6 2001:db8:100::/64 next-hop 2001:db8:97::2')
    config.set('set protocols static route6 2001:db8:100::/64 next-hop 2001:0db8:97::2')

    with assert_raises(CommitError, match='duplicates another enabled'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_conflicting_paths_duplicate_source(config):
    """Reject duplicate source before applying static routes."""
    original = config.get_config()
    config.set('set protocols static route6 2001:db8:100::/64 blackhole')
    config.set('set protocols static route6 2001:db8:100::/64 source-specific from ::/0 reject')

    with assert_raises(CommitError, match='duplicates another destination/source'):
        config.commit()

    assert_equal(config.get_config(), original)
    assert_no_static_configuration()
    config.discard()


def test_schema_rejects_invalid_values_host_bits(config):
    """Reject host bits during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.1/24 blackhole')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_ipv4_prefix_length(config):
    """Reject IPv4 prefix length during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.0/33 blackhole')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_ipv6_prefix_length(config):
    """Reject IPv6 prefix length during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route6 2001:db8:100::/129 reject')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_gateway_family(config):
    """Reject gateway family during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route6 2001:db8:100::/64 next-hop 198.18.97.2')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_invalid_gateway(config):
    """Reject invalid gateway during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.0/24 next-hop 999.1.1.1')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_distance_low(config):
    """Reject distance low during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 distance 0')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_distance_high(config):
    """Reject distance high during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 distance 256')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_metric_low(config):
    """Reject metric low during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 metric -1')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_metric_high(config):
    """Reject metric high during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 metric 4294967296')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_tag_low(config):
    """Reject tag low during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 tag 0')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_tag_high(config):
    """Reject tag high during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 tag 4294967296')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_weight_low(config):
    """Reject weight low during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 weight 0')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_weight_high(config):
    """Reject weight high during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 weight 65536')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_interface_name(config):
    """Reject interface name during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 interface bad/name')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_vrf_name(config):
    """Reject vrf name during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route 192.0.2.0/24 next-hop 198.18.97.2 vrf bad/name')

    assert_equal(config.get_config(source='candidate'), original)


def test_schema_rejects_invalid_values_source_family(config):
    """Reject source family during insertion without changing the candidate."""
    original = config.get_config(source='candidate')

    with assert_raises(RouterError):
        config.set('set protocols static route6 2001:db8:100::/64 source-specific from 192.0.2.0/24 reject')

    assert_equal(config.get_config(source='candidate'), original)
