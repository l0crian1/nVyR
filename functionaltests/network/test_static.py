"""Static FIB behavior on the same persistent routing/firewall scenario.

Compatible prefixes are installed together, with one shared next-hop link and
VRF. Mutation tests own distinct destinations. The last-route deletion and empty
instance cases explicitly replace the static subtree, retaining all interfaces.
CLI-only rejection tests remain in smoketests/test_static.py, not duplicated here.
"""

import json
import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.tree import lookup
from nvyr.config_session import CommitError
from nvyr.errors import RouterError
from nvyr.helpers.process import cmd
from nvyr.op_scripts import static
from smoketests.assertions import (
    assert_equal, assert_in, assert_not_in, assert_raises, assert_no_static_routes,
    assert_route_absent, assert_route_present, assert_frr_routes, assert_frr_route_absent,
    assert_kernel_route, assert_kernel_route_absent, assert_static_instance_empty,
    assert_kernel_multipath_weights, assert_operational_output,
)


def test_opmode_ipv4_routes(config):
    """Expose IPv4 route text and native JSON through the operational wrapper."""
    # Installed once by configs/network-static.conf.
    assert_route_present('198.19.128.0/24', 'blackhole')

    assert_operational_output('show ip route 198.19.128.0/24', '198.19.128.0/24')

    assert_in('198.19.128.0/24', static.show('show ip route'))
    assert_in('198.19.128.0/24', cmd(['static.nvyr.op', 'show', 'show ip route 198.19.128.0/24']))
    assert_in('198.19.128.0/24', static.show('show ip route 198.19.128.0/24 longer-prefixes static'))
    assert_in('198.19.128.0/24', static.show('show static routes'))
    routes = json.loads(static.show('show ip route', raw=True))
    assert_in('198.19.128.0/24', routes)
    status = json.loads(static.show('show static routes vrf default', raw=True))
    assert_in('198.19.128.0/24', [route['prefix'] for route in status['default']['routes']])


def test_opmode_ipv4_route_selectors(config):
    """Route origin filters exclude static routes, while tag selects the configured route."""
    # Installed once by configs/network-static.conf.

    assert_operational_output('show ip route tag 195', '198.19.129.0/24')
    assert_not_in('198.19.129.0/24', json.loads(static.show('show ip route tag 196', raw=True)))
    assert_in('198.18.97.0/24', json.loads(static.show('show ip route connected', raw=True)))
    assert_in('198.18.97.1/32', json.loads(static.show('show ip route local', raw=True)))
    assert_not_in('198.19.129.0/24', json.loads(static.show('show ip route bgp', raw=True)))
    assert_not_in('198.19.129.0/24', json.loads(static.show('show ip route kernel', raw=True)))


def test_opmode_ipv6_routes(config):
    """Expose IPv6 route text and native JSON through the operational wrapper."""
    # Installed once by configs/network-static.conf.
    assert_route_present('2001:db8:502::/64', 'blackhole')

    assert_operational_output('show ipv6 route 2001:db8:502::/64', '2001:db8:502::/64')

    assert_in('2001:db8:502::/64', static.show('show ipv6 route'))
    assert_in('2001:db8:502::/64', cmd(['static.nvyr.op', 'show', 'show ipv6 route 2001:db8:502::/64']))
    assert_in('2001:db8:502::/64', static.show('show ipv6 route 2001:db8:502::/64 longer-prefixes static'))
    assert_in('2001:db8:502::/64', static.show('show static routes'))
    routes = json.loads(static.show('show ipv6 route', raw=True))
    assert_in('2001:db8:502::/64', routes)
    status = json.loads(static.show('show static routes vrf default', raw=True))
    assert_in('2001:db8:502::/64', [route['prefix'] for route in status['default']['routes']])


def test_opmode_ipv6_route_selectors(config):
    """IPv6 supports the same origin and tag filters without changing FRR ordering."""
    # Installed once by configs/network-static.conf.

    assert_operational_output('show ipv6 route tag 195', '2001:db8:503::/64')
    assert_not_in('2001:db8:503::/64', json.loads(static.show('show ipv6 route tag 196', raw=True)))
    assert_in('2001:db8:97::/64', json.loads(static.show('show ipv6 route connected', raw=True)))
    assert_in('2001:db8:97::1/128', json.loads(static.show('show ipv6 route local', raw=True)))
    assert_not_in('2001:db8:503::/64', json.loads(static.show('show ipv6 route bgp', raw=True)))
    assert_not_in('2001:db8:503::/64', json.loads(static.show('show ipv6 route kernel', raw=True)))


def test_ipv4_blackhole(config):
    """An IPv4 blackhole must appear in FRR and discard in the kernel."""
    # Installed once by configs/network-static.conf.

    assert_route_present('198.19.132.0/24', 'blackhole')


def test_ipv6_reject(config):
    """An IPv6 reject route must install as an unreachable kernel route."""
    # Installed once by configs/network-static.conf.

    assert_route_present('2001:db8:505::/64', 'reject')


def test_disable_and_reenable(config):
    """Prefix disable withdraws forwarding while retaining the editable route."""
    # Installed once by configs/network-static.conf.

    assert_route_present('198.19.134.0/24', 'blackhole')

    # Disable the route without deleting its configuration.
    config.set('set protocols static route 198.19.134.0/24 disable')
    config.commit()

    running_config = config.get_config()
    route = lookup(running_config, ('protocols', 'static', 'route', '198.19.134.0/24'))

    assert_in('disable', route)
    assert_route_absent('198.19.134.0/24', 'blackhole')

    # Re-enable the route.
    config.delete('delete protocols static route 198.19.134.0/24 disable')
    config.commit()

    assert_route_present('198.19.134.0/24', 'blackhole')


def test_ipv4_reject(config):
    """IPv4 reject must use an unreachable route rather than a silent blackhole."""
    # Installed once by configs/network-static.conf.

    assert_route_present('198.19.135.0/24', 'reject')


def test_ipv6_blackhole(config):
    """IPv6 silent discard must be installed independently of IPv4 support."""
    # Installed once by configs/network-static.conf.

    assert_route_present('2001:db8:508::/64', 'blackhole')


def test_ipv4_next_hop(config):
    """A connected IPv4 gateway resolves through the test dummy interface."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes('ip route 198.19.137.0/24 198.18.97.2')
    assert_kernel_route('198.19.137.0/24', 'via 198.18.97.2', 'dev dum997')


def test_ipv6_next_hop(config):
    """A global IPv6 gateway resolves using the test interface's connected route."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes('ipv6 route 2001:db8:510::/64 2001:db8:97::2')
    assert_kernel_route('2001:db8:510::/64', 'via 2001:db8:97::2', 'dev dum997')


def test_interface_only_routes(config):
    """Both address families support direct interface paths without gateways."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes('ip route 198.19.139.0/24 dum997', 'ipv6 route 2001:db8:511::/64 dum997')
    assert_kernel_route('198.19.139.0/24', 'dev dum997', absent=('via ',))
    assert_kernel_route('2001:db8:511::/64', 'dev dum997', absent=('via ',))


def test_gateway_interface_binding(config):
    """Gateway/interface pairs remain explicit in FRR and use the selected link."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes(
        'ip route 198.19.140.0/24 198.18.97.2 dum997',
        'ipv6 route 2001:db8:512::/64 2001:db8:97::2 dum997',
    )
    assert_kernel_route('198.19.140.0/24', 'via 198.18.97.2', 'dev dum997')
    assert_kernel_route('2001:db8:512::/64', 'via 2001:db8:97::2', 'dev dum997')


def test_onlink_gateways(config):
    """Onlink permits off-subnet gateways only through an explicitly bound link."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes(
        'ip route 198.19.141.0/24 198.18.98.2 dum997 onlink',
        'ipv6 route 2001:db8:513::/64 2001:db8:98::2 dum997 onlink',
    )
    assert_kernel_route('198.19.141.0/24', 'via 198.18.98.2', 'dev dum997', 'onlink')
    assert_kernel_route('2001:db8:513::/64', 'via 2001:db8:98::2', 'dev dum997', 'onlink')


def test_link_local_and_ipv4_over_ipv6(config):
    """A scoped link-local gateway supports IPv6 and RFC 5549 IPv4 routes."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes(
        'ip route 198.19.142.0/24 fe80::97:2 dum997',
        'ipv6 route 2001:db8:514::/64 fe80::97:2 dum997',
    )
    assert_kernel_route('198.19.142.0/24', 'via inet6 fe80::97:2', 'dev dum997')
    assert_kernel_route('2001:db8:514::/64', 'via fe80::97:2', 'dev dum997')


def test_ipv4_multipath_and_next_hop_disable(config):
    """Disabling one ECMP member withdraws only that member; enabling restores it."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes('ip route 198.19.143.0/24 198.18.97.2', 'ip route 198.19.143.0/24 198.18.97.3')
    assert_kernel_route('198.19.143.0/24', 'via 198.18.97.2', 'via 198.18.97.3')

    config.set('set protocols static route 198.19.143.0/24 next-hop 198.18.97.2 disable')
    config.commit()

    assert_frr_route_absent('ip route 198.19.143.0/24 198.18.97.2')
    assert_kernel_route('198.19.143.0/24', 'via 198.18.97.3', absent=('via 198.18.97.2',))

    config.delete('delete protocols static route 198.19.143.0/24 next-hop 198.18.97.2 disable')
    config.commit()

    assert_kernel_route('198.19.143.0/24', 'via 198.18.97.2', 'via 198.18.97.3')


def test_ipv6_weighted_multipath(config):
    """Independent IPv6 next hops retain their configured relative weights."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes(
        'ipv6 route 2001:db8:516::/64 2001:db8:97::2 weight 2',
        'ipv6 route 2001:db8:516::/64 2001:db8:97::3 weight 3',
    )
    assert_kernel_multipath_weights('2001:db8:516::/64', {
        ('2001:db8:97::2', 'dum997'): 2,
        ('2001:db8:97::3', 'dum997'): 3,
    })


def test_distance_selection_and_fallback(config):
    """A preferred gateway yields to the higher-distance discard when disabled."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes('ip route 198.19.145.0/24 198.18.97.2 10', 'ip route 198.19.145.0/24 blackhole 200')
    assert_kernel_route('198.19.145.0/24', 'via 198.18.97.2', absent=('blackhole',))

    config.set('set protocols static route 198.19.145.0/24 next-hop 198.18.97.2 disable')
    config.commit()

    assert_kernel_route('198.19.145.0/24', 'blackhole', absent=('via ',))

    config.delete('delete protocols static route 198.19.145.0/24 next-hop 198.18.97.2 disable')
    config.commit()

    assert_kernel_route('198.19.145.0/24', 'via 198.18.97.2', absent=('blackhole',))


def test_metric_selection_and_tag_update(config):
    """At equal distance, the lower metric wins; tag/metric updates reach FRR."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes('ip route 198.19.146.0/24 198.18.97.2 tag 123 metric 20')
    assert_kernel_route('198.19.146.0/24', 'via 198.18.97.2', absent=('via 198.18.97.3',))

    config.set('set protocols static route 198.19.146.0/24 next-hop 198.18.97.2 metric 60')
    config.set('set protocols static route 198.19.146.0/24 next-hop 198.18.97.2 tag 456')
    config.commit()

    assert_frr_routes('ip route 198.19.146.0/24 198.18.97.2 tag 456 metric 60')
    assert_frr_route_absent('ip route 198.19.146.0/24 198.18.97.2 tag 123 metric 20')
    assert_kernel_route('198.19.146.0/24', 'via 198.18.97.3', absent=('via 198.18.97.2',))


def test_interface_path_options_and_disable(config):
    """Interface paths support preferences, tags, weights, and individual disable."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes('ip route 198.19.147.0/24 dum997 tag 123 10 metric 20 weight 2')
    assert_kernel_route('198.19.147.0/24', 'dev dum997', absent=('unreachable',))

    config.set('set protocols static route 198.19.147.0/24 interface dum997 disable')
    config.commit()

    assert_frr_route_absent('ip route 198.19.147.0/24 dum997 tag 123 10 metric 20 weight 2')
    assert_kernel_route('198.19.147.0/24', 'unreachable', absent=('dev dum997',))

    config.delete('delete protocols static route 198.19.147.0/24 interface dum997 disable')
    config.commit()

    assert_kernel_route('198.19.147.0/24', 'dev dum997', absent=('unreachable',))


def test_discard_path_options_and_disable(config):
    """Disabled discard alternatives are omitted; switching actions replaces the FIB entry."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes('ip route 198.19.148.0/24 blackhole tag 123 10 metric 20')
    assert_frr_route_absent('ip route 198.19.148.0/24 reject tag 456 30 metric 40')
    assert_kernel_route('198.19.148.0/24', 'blackhole')

    config.set('set protocols static route 198.19.148.0/24 blackhole disable')
    config.delete('delete protocols static route 198.19.148.0/24 reject disable')
    config.commit()

    assert_frr_routes('ip route 198.19.148.0/24 reject tag 456 30 metric 40')
    assert_frr_route_absent('ip route 198.19.148.0/24 blackhole tag 123 10 metric 20')
    assert_kernel_route('198.19.148.0/24', 'unreachable', absent=('blackhole',))


def test_descriptions_and_implicit_defaults(config):
    """Descriptions remain in nVyR, while default distance/metric stay implicit."""
    # Installed once by configs/network-static.conf.

    route = lookup(config.get_config(), ('protocols', 'static', 'route', '198.19.149.0/24'))
    assert_equal(route['description'], 'Test destination')
    assert_equal(route['next-hop']['198.18.97.2'], {'description': 'Primary gateway'})
    assert_frr_routes('ip route 198.19.149.0/24 198.18.97.2')
    assert_kernel_route('198.19.149.0/24', 'via 198.18.97.2')


def test_ipv6_prefix_disable(config):
    """Disabling an IPv6 prefix withdraws all of its otherwise enabled paths."""
    # Installed once by configs/network-static.conf.
    assert_kernel_route('2001:db8:522::/64', 'via 2001:db8:97::2')

    config.set('set protocols static route6 2001:db8:522::/64 disable')
    config.commit()
    assert_route_absent('2001:db8:522::/64', '2001:db8:97::2')

    config.delete('delete protocols static route6 2001:db8:522::/64 disable')
    config.commit()
    assert_kernel_route('2001:db8:522::/64', 'via 2001:db8:97::2')


def test_source_specific_routes(config):
    """A source-specific route can coexist with a destination-only IPv6 route."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes(
        'ipv6 route 2001:db8:523::/64 blackhole',
        'ipv6 route 2001:db8:523::/64 from 2001:db8:200::/64 2001:db8:97::2',
        'ipv6 route 2001:db8:523::/64 from 2001:db8:300::/64 dum997',
    )
    assert_kernel_route('2001:db8:523::/64', 'via 2001:db8:97::2', source='2001:db8:200::/64')
    assert_kernel_route('2001:db8:523::/64', 'dev dum997', source='2001:db8:300::/64')


def test_source_specific_disable_and_delete(config):
    """Source-group disable and deletion leave sibling source routes installed."""
    # Installed once by configs/network-static.conf.

    assert_kernel_route('2001:db8:524::/64', 'blackhole', source='2001:db8:200::/64')
    assert_kernel_route('2001:db8:524::/64', 'unreachable', source='2001:db8:300::/64')

    config.set('set protocols static route6 2001:db8:524::/64 source-specific from 2001:db8:200::/64 disable')
    config.commit()

    assert_frr_route_absent('ipv6 route 2001:db8:524::/64 from 2001:db8:200::/64 blackhole')
    assert_kernel_route_absent('2001:db8:524::/64', source='2001:db8:200::/64')
    assert_kernel_route('2001:db8:524::/64', 'unreachable', source='2001:db8:300::/64')

    config.delete('delete protocols static route6 2001:db8:524::/64 source-specific from 2001:db8:200::/64 disable')
    config.commit()
    assert_kernel_route('2001:db8:524::/64', 'blackhole', source='2001:db8:200::/64')

    config.delete('delete protocols static route6 2001:db8:524::/64 source-specific from 2001:db8:200::/64')
    config.commit()
    assert_kernel_route_absent('2001:db8:524::/64', source='2001:db8:200::/64')


@pytest.mark.exclusive_static
def test_named_vrf_isolation(config):
    """Identical prefixes in default and named VRFs keep independent actions."""
    config.set('set protocols static route 192.0.2.0/24 blackhole')
    config.set('set vrf name NVYRSMOKE protocols static route 192.0.2.0/24 reject')
    config.set('set vrf name NVYRSMOKE protocols static route6 2001:db8:100::/64 blackhole')
    config.commit()

    assert_route_present('192.0.2.0/24', 'blackhole')
    assert_frr_routes('ip route 192.0.2.0/24 reject', 'ipv6 route 2001:db8:100::/64 blackhole', vrf='NVYRSMOKE')
    assert_kernel_route('192.0.2.0/24', 'unreachable', vrf='NVYRSMOKE')
    assert_kernel_route('2001:db8:100::/64', 'blackhole', vrf='NVYRSMOKE')

    # Removing the VRF's routes must leave its protocol instance and default routes.
    config.delete('delete vrf name NVYRSMOKE protocols static')
    config.commit()

    assert_kernel_route_absent('192.0.2.0/24', vrf='NVYRSMOKE')
    assert_kernel_route_absent('2001:db8:100::/64', vrf='NVYRSMOKE')
    assert_static_instance_empty('NVYRSMOKE')
    assert_route_present('192.0.2.0/24', 'blackhole')


def test_next_hop_vrf_resolution(config):
    """Named-VRF routes can resolve both address families through the default VRF."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes(
        'ip route 198.19.154.0/24 198.18.97.2 nexthop-vrf default',
        'ipv6 route 2001:db8:526::/64 2001:db8:97::2 nexthop-vrf default',
        vrf='NVYRSMOKE',
    )
    assert_kernel_route('198.19.154.0/24', 'via 198.18.97.2', 'dev dum997', vrf='NVYRSMOKE')
    assert_kernel_route('2001:db8:526::/64', 'via 2001:db8:97::2', 'dev dum997', vrf='NVYRSMOKE')
    assert_kernel_route_absent('198.19.154.0/24')
    assert_kernel_route_absent('2001:db8:526::/64')


@pytest.mark.exclusive_static
def test_delete_last_route_and_recreate(config):
    """Deleting the last route leaves a reusable empty static protocol instance."""
    config.set('set protocols static route 192.0.2.0/24 blackhole')
    config.commit()
    assert_route_present('192.0.2.0/24', 'blackhole')

    config.delete('delete protocols static')
    config.commit()

    assert_no_static_routes('192.0.2.0/24')
    assert_static_instance_empty()

    config.set('set protocols static route 192.0.2.0/24 reject')
    config.commit()
    assert_route_present('192.0.2.0/24', 'reject')


@pytest.mark.exclusive_static
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
    assert_route_present('192.0.2.0/24', 'blackhole')
    config.discard()


def test_ipv4_weighted_multipath(config):
    """IPv4 ECMP must preserve relative weights when installing both next hops."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes('ip route 198.19.157.0/24 198.18.97.2 weight 2', 'ip route 198.19.157.0/24 198.18.97.3 weight 3')
    assert_kernel_multipath_weights('198.19.157.0/24', {
        ('198.18.97.2', 'dum997'): 2,
        ('198.18.97.3', 'dum997'): 3,
    })


def test_next_hop_deletion(config):
    """Deleting one gateway preserves its sibling without leaving stale kernel state."""
    # Installed once by configs/network-static.conf.
    assert_kernel_route('198.19.158.0/24', 'via 198.18.97.2', 'via 198.18.97.3')

    config.delete('delete protocols static route 198.19.158.0/24 next-hop 198.18.97.2')
    config.commit()

    assert_frr_route_absent('ip route 198.19.158.0/24 198.18.97.2')
    assert_kernel_route('198.19.158.0/24', 'via 198.18.97.3', absent=('via 198.18.97.2',))


def test_disabled_prefix_allows_inactive_paths(config):
    """A disabled prefix may retain paths that are not valid until enabled."""
    # Installed once by configs/network-static.conf.
    assert_frr_route_absent('ipv6 route 2001:db8:531::/64 fe80::97:2')
    assert_kernel_route_absent('2001:db8:531::/64')

    config.delete('delete protocols static route6 2001:db8:531::/64 disable')
    with assert_raises(CommitError, match='link-local next hop requires an interface'):
        config.commit()

    # Correct the candidate and verify that the previously disabled route can install.
    config.set('set protocols static route6 2001:db8:531::/64 next-hop fe80::97:2 interface dum997')
    config.commit()
    assert_kernel_route('2001:db8:531::/64', 'via fe80::97:2', 'dev dum997')


def test_source_specific_path_options(config):
    """Source-specific paths share distance, metric, tag, weight, and disable behavior."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes('ipv6 route 2001:db8:532::/64 from 2001:db8:200::/64 2001:db8:97::2 tag 123 10 metric 20 weight 2')
    assert_kernel_route('2001:db8:532::/64', 'via 2001:db8:97::2', source='2001:db8:200::/64')

    config.set('set protocols static route6 2001:db8:532::/64 source-specific from 2001:db8:200::/64 next-hop 2001:db8:97::2 disable')
    config.commit()
    assert_kernel_route('2001:db8:532::/64', 'unreachable', source='2001:db8:200::/64')

    config.set('set protocols static route6 2001:db8:532::/64 disable')
    config.commit()
    assert_frr_route_absent('ipv6 route 2001:db8:532::/64 from 2001:db8:200::/64 reject 200')
    assert_frr_route_absent('ipv6 route 2001:db8:532::/64 from 2001:db8:200::/64 2001:db8:97::2 tag 123 10 metric 20 weight 2')
    assert_kernel_route_absent('2001:db8:532::/64', source='2001:db8:200::/64')


def test_vrf_source_specific_route(config):
    """A source-specific route in a named VRF must not leak into the main table."""
    # Installed once by configs/network-static.conf.

    assert_frr_routes('ipv6 route 2001:db8:533::/64 from 2001:db8:200::/64 reject', vrf='NVYRSMOKE')
    assert_kernel_route('2001:db8:533::/64', 'unreachable', vrf='NVYRSMOKE', source='2001:db8:200::/64')
    assert_kernel_route_absent('2001:db8:533::/64')
