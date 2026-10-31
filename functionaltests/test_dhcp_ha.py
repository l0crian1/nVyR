"""Kea HA: concurrent IPv4/IPv6 allocations, replication, exhaustion and takeover.

One fabric and four peers are created once: active-active in the default routing
domain, active-passive inside VRFs. Both families run concurrently. Packet tests
use generated nVyR configuration and real Kea hooks. These private namespaces
cannot share the routed scenario's single DHCP server because HA needs two
servers on the same client link. No management interface or host firewall changes.
"""

import ipaddress
import subprocess
import time

import pytest

from functionaltests.kea_ha import Topology


@pytest.fixture(scope='module')
def ha(tmp_path_factory):
    topology = Topology(tmp_path_factory.mktemp('kea-ha'))
    try:
        topology.prepare()
        yield topology
    finally:
        topology.close()


def assert_unique(grants):
    owners = {}
    for grant in grants:
        address = grant['address']
        previous = owners.setdefault(address, grant['client'])
        assert previous == grant['client'], f'Duplicate lease: {address} granted to {previous} and {grant["client"]}'


def assert_replicated(ha, family, subnet, grants):
    left = ha.control(family, subnet, 1, f'lease{family}-get-all')['arguments']['leases']
    right = ha.control(family, subnet, 2, f'lease{family}-get-all')['arguments']['leases']
    identity = 'hw-address' if family == 4 else 'duid'
    left = {lease['ip-address']: lease[identity] for lease in left}
    right = {lease['ip-address']: lease[identity] for lease in right}
    assert left == right
    assert {grant['address'] for grant in grants} <= left.keys()


def test_ipv4_active_active_concurrent_exhaustion(ha):
    grants = ha.clients(4, 2, 100)
    assert len(grants) == 20
    assert_unique(grants)
    assert {grant['server'] for grant in grants} == {'192.0.2.1', '192.0.2.2'}
    assert_replicated(ha, 4, 2, grants)


def test_ipv6_active_active_concurrent_exhaustion(ha):
    grants = ha.clients(6, 2, 100)
    assert len(grants) == 20
    assert_unique(grants)
    assert {grant['server'] for grant in grants} == {'2001:db8:2::1', '2001:db8:2::2'}
    assert_replicated(ha, 6, 2, grants)


def test_ipv4_active_passive_vrf_allocations(ha):
    grants = ha.clients(4, 3, 4)
    assert len(grants) == 4
    assert_unique(grants)
    assert {grant['server'] for grant in grants} == {'192.0.3.1'}
    assert_replicated(ha, 4, 3, grants)


def test_ipv6_active_passive_vrf_allocations(ha):
    grants = ha.clients(6, 3, 4)
    assert len(grants) == 4
    assert_unique(grants)
    assert {grant['server'] for grant in grants} == {'2001:db8:3::1'}
    assert_replicated(ha, 6, 3, grants)


def test_both_families_takeover_and_return_to_service(ha):
    """Maintenance uses Kea's real HA transitions and preserves replicated leases."""
    for family in (4, 6):
        ha.control(family, 3, 2, 'ha-maintenance-start')
    ha.wait_states({(4, 3, 2): 'partner-in-maintenance', (6, 3, 2): 'partner-in-maintenance'})
    try:
        for family in (4, 6):
            grants = ha.clients(family, 3, 4, offset=100)
            assert len(grants) == 4
            assert_unique(grants)
            assert all(int(ipaddress.ip_address(grant['server'])) & 255 == 2 for grant in grants)
            assert_replicated(ha, family, 3, grants)
    finally:
        for family in (4, 6):
            ha.control(family, 3, 2, 'ha-maintenance-cancel')
    ha.wait_states({(4, 3, 1): 'hot-standby', (4, 3, 2): 'hot-standby',
                    (6, 3, 1): 'hot-standby', (6, 3, 2): 'hot-standby'})


def test_active_active_partner_failure_and_lease_resynchronization(ha):
    """Use default failure timers; both families fail over during the same outage."""
    stopped = [ha.servers[family, 2, 2] for family in (4, 6)]
    for server in stopped:
        server['process'].terminate()
    for server in stopped:
        server['process'].wait(timeout=10)

    try:
        deadline = time.monotonic() + 100
        states = {}
        while time.monotonic() < deadline:
            for family in (4, 6):
                # Kea requires evidence of clients going unanswered, not merely
                # lost heartbeats. secs/elapsed-time models their retransmissions.
                ha.clients(family, 2, 100, seconds=20)
                states[family] = ha.state(family, 2, 1)
            if all(state == 'partner-down' for state in states.values()):
                break
        assert states == {4: 'partner-down', 6: 'partner-down'}

        for family in (4, 6):
            grants = ha.clients(family, 2, 100, seconds=20)
            assert len(grants) == 20
            assert_unique(grants)
            assert all(int(ipaddress.ip_address(grant['server'])) & 255 == 1 for grant in grants)
    finally:
        for server in stopped:
            server['process'] = subprocess.Popen(server['command'], env=server['env'],
                                                  stdout=server['output'], stderr=subprocess.STDOUT)

    ha.wait_states({(4, 2, 1): 'load-balancing', (4, 2, 2): 'load-balancing',
                    (6, 2, 1): 'load-balancing', (6, 2, 2): 'load-balancing'})
    assert_replicated(ha, 4, 2, [])
    assert_replicated(ha, 6, 2, [])
