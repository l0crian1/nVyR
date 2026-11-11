"""Dual-stack IS-IS adjacency, policy, routing and forwarding on shared links.

Compatible IS-IS settings are installed once in the routed-network scenario.
Dedicated destinations distinguish IS-IS from BGP/OSPF/RIP. Policy edits and
adjacency resets restore in place; no case recreates the shared interfaces/VRFs.
"""

import pytest

from nvyr.helpers.process import cmd
from smoketests.assertions import assert_kernel_route, assert_kernel_route_absent
from smoketests.support import wait_for


@pytest.mark.parametrize('prefix', ['198.19.94.1/32', '2001:db8:94::1/128'])
def test_learned_routes_and_forwarding(prefix):
    assert_kernel_route(prefix, 'dev veth42061', vrf='NVYRLEFT')
    family = 'ip' if ':' not in prefix else 'ipv6'
    assert prefix in cmd(['vtysh', '-c', f'show {family} route vrf NVYRLEFT isis'])
    cmd(['ip', 'vrf', 'exec', 'NVYRLEFT', 'ping', '-c', '2', '-W', '2', prefix.split('/')[0]])


@pytest.mark.parametrize('prefix', ['198.19.95.0/24', '2001:db8:95::/64'])
def test_static_redistribution(prefix):
    assert_kernel_route(prefix, 'dev veth42061', vrf='NVYRLEFT')


@pytest.mark.parametrize('prefix', ['198.19.94.2/32', '2001:db8:94::2/128'])
def test_filtered_connected_prefixes(prefix):
    assert_kernel_route_absent(prefix, vrf='NVYRLEFT')


def test_route_map_update_withdraws_both_families(config):
    config.set('set policy prefix-list ipv4 RNISIS rule 10 action deny')
    config.set('set policy prefix-list ipv6 RNISIS rule 10 action deny')
    config.commit()
    assert_kernel_route_absent('198.19.94.1/32', vrf='NVYRLEFT')
    assert_kernel_route_absent('2001:db8:94::1/128', vrf='NVYRLEFT')
    assert_kernel_route('198.19.95.0/24', 'dev veth42061', vrf='NVYRLEFT')
    assert_kernel_route('198.19.90.1/32', 'proto ospf', vrf='NVYRLEFT')


def test_scoped_adjacency_reset_recovers():
    cmd(['isis.nvyr.op', 'clear', 'clear isis vrf NVYRLEFT neighbor'])
    wait_for(lambda: cmd(['isis.nvyr.op', 'show', 'show isis vrf NVYRLEFT neighbor']),
             lambda output: 'Up' in output, description='IS-IS adjacency after reset', timeout=20)
    assert_kernel_route('198.19.94.1/32', 'dev veth42061', vrf='NVYRLEFT')
    assert_kernel_route('2001:db8:94::1/128', 'dev veth42061', vrf='NVYRLEFT')


def test_conditional_and_always_default_origination(config):
    for family, prefix, route in [('ipv4-unicast', '0.0.0.0/0', 'route'),
                                   ('ipv6-unicast', '::/0', 'route6')]:
        config.set(f'set vrf name NVYRRIGHT protocols static {route} {prefix} blackhole')
        config.set(f'set vrf name NVYRRIGHT protocols isis address-family {family} level level-2 default-originate metric 40')
    config.commit()

    for prefix in ('0.0.0.0/0', '::/0'):
        assert_kernel_route(prefix, 'dev veth42061', vrf='NVYRLEFT')

    config.delete('delete vrf name NVYRRIGHT protocols static route 0.0.0.0/0')
    config.delete('delete vrf name NVYRRIGHT protocols static route6 ::/0')
    config.commit()

    for prefix in ('0.0.0.0/0', '::/0'):
        assert_kernel_route_absent(prefix, vrf='NVYRLEFT')

    for family in ('ipv4-unicast', 'ipv6-unicast'):
        config.set(f'set vrf name NVYRRIGHT protocols isis address-family {family} level level-2 default-originate always')
    config.commit()

    for prefix in ('0.0.0.0/0', '::/0'):
        assert_kernel_route(prefix, 'dev veth42061', vrf='NVYRLEFT')
