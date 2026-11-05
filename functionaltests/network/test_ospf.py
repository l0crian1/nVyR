"""Authenticated OSPFv2/v3 adjacency, route exchange, redistribution and withdrawal.

Uses the existing routed-network VRFs and transit, with dedicated OSPF destinations.
Deleting shared links/VRFs or changing BGP probe routes is incompatible. Only the
withdrawal case changes configuration; all other cases observe the shared baseline.
"""

import pytest

from nvyr.helpers.process import cmd
from smoketests.assertions import assert_kernel_route, assert_kernel_route_absent
from smoketests.support import wait_for


@pytest.mark.parametrize('family', ['ip', 'ipv6'])
def test_authenticated_neighbors(family):
    native = 'ospf' if family == 'ip' else 'ospf6'
    wait_for(lambda: cmd(['vtysh', '-c', f'show {family} {native} vrf NVYRLEFT neighbor']),
             lambda output: '198.18.60.2' in output and 'Full' in output,
             description=f'{native} authenticated neighbor', timeout=20)


@pytest.mark.parametrize('prefix', ['198.19.90.1/32', '2001:db8:90::1/128'])
def test_internal_routes(prefix):
    # Linux uses RTPROT_OSPF for both OSPF versions.
    assert_kernel_route(prefix, 'proto ospf', vrf='NVYRLEFT')
    address = prefix.split('/')[0]
    cmd(['ip', 'vrf', 'exec', 'NVYRLEFT', 'ping', '-c', '2', '-W', '2', address])


@pytest.mark.parametrize('prefix', ['198.19.91.0/24', '2001:db8:91::/64'])
def test_filtered_redistribution(prefix):
    assert_kernel_route(prefix, 'proto ospf', vrf='NVYRLEFT')


def test_redistribution_policy_withdrawal(config):
    config.set('set policy prefix-list ipv4 RNOSPF rule 10 action deny')
    config.set('set policy prefix-list ipv6 RNOSPF rule 10 action deny')
    config.commit()

    assert_kernel_route_absent('198.19.91.0/24', vrf='NVYRLEFT')
    assert_kernel_route_absent('2001:db8:91::/64', vrf='NVYRLEFT')
    assert_kernel_route('198.19.90.1/32', 'proto ospf', vrf='NVYRLEFT')
    assert_kernel_route('2001:db8:90::1/128', 'proto ospf', vrf='NVYRLEFT')
