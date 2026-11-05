"""Authenticated RIP, RIPng, filtered redistribution, forwarding and withdrawal.

All compatible routes and policies are installed once with the routed-network
scenario. These destinations are not advertised by BGP or OSPF. Deleting shared
VRFs/links is incompatible; the deliberate policy mutation is restored in place.
"""

import pytest

from nvyr.helpers.process import cmd
from smoketests.assertions import assert_kernel_route, assert_kernel_route_absent


@pytest.mark.parametrize('prefix', ['198.19.92.1/32', '2001:db8:92::1/128'])
def test_filtered_connected_routes_and_forwarding(prefix):
    assert_kernel_route(prefix, 'dev veth42061', vrf='NVYRLEFT')
    family, protocol = ('ip', 'rip') if ':' not in prefix else ('ipv6', 'ripng')
    output = cmd(['vtysh', '-c', f'show {family} route vrf NVYRLEFT {protocol}'])
    assert prefix in output
    cmd(['ip', 'vrf', 'exec', 'NVYRLEFT', 'ping', '-c', '2', '-W', '2', prefix.split('/')[0]])


@pytest.mark.parametrize('prefix', ['198.19.93.0/24', '2001:db8:93::/64'])
def test_static_redistribution(prefix):
    assert_kernel_route(prefix, 'dev veth42061', vrf='NVYRLEFT')


@pytest.mark.parametrize('prefix', ['198.19.92.2/32', '2001:db8:92::2/128'])
def test_unselected_connected_routes_are_not_advertised(prefix):
    assert_kernel_route_absent(prefix, vrf='NVYRLEFT')


def test_policy_withdrawal_preserves_other_protocols(config):
    config.set('set policy prefix-list ipv4 RNRIP rule 10 action deny')
    config.set('set policy prefix-list ipv6 RNRIP rule 10 action deny')
    config.commit()
    # An inbound deny can also discard a poisoned update; allow the configured
    # twelve-second route timeout to expire before declaring withdrawal failed.
    assert_kernel_route_absent('198.19.92.1/32', vrf='NVYRLEFT', timeout=20)
    assert_kernel_route_absent('2001:db8:92::1/128', vrf='NVYRLEFT', timeout=20)
    assert_kernel_route('198.19.93.0/24', 'dev veth42061', vrf='NVYRLEFT')
    assert_kernel_route('2001:db8:93::/64', 'dev veth42061', vrf='NVYRLEFT')
    assert_kernel_route('198.19.90.1/32', 'proto ospf', vrf='NVYRLEFT')
