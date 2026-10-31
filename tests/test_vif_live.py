"""Real VLAN lifecycle and tagged packets in a disposable network namespace."""

from copy import deepcopy
import os
import subprocess

import pytest

from nvyr.errors import RouterError
from nvyr.helpers.link_manager import Manager
from nvyr.helpers.netlink import Kernel
from tests.test_netlink import Leases
from tests.test_netlink_live import isolated, run, wait_for, ProcessDHCP

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETLINK_TEST') != '1',
                                reason='requires isolated privileged Netlink container')


@pytest.fixture
def topology(tmp_path, isolated):
    """Two VLANs share a veth transport and use separate routing domains."""
    kernel = Kernel()
    manager = Manager(kernel, Leases(), tmp_path)
    manager.replace('vrf', {'VIFBLUE': {'kind': 'vrf', 'attributes': {'table': 190}},
                            'VIFRED': {'kind': 'vrf', 'attributes': {'table': 191}}})
    links = {
        'veth90': {'kind': 'virtual-ethernet', 'attributes': {'peer-name': 'veth91', 'mtu': 9000}},
        'veth91': {'kind': 'virtual-ethernet', 'attributes': {'peer-name': 'veth90', 'mtu': 9000}},
        'veth90.10': {'kind': 'vlan', 'attributes': {'parent': 'veth90', 'vlan': 10, 'vrf': 'VIFBLUE'}},
        'veth91.10': {'kind': 'vlan', 'attributes': {'parent': 'veth91', 'vlan': 10, 'vrf': 'VIFRED'}},
    }
    try:
        manager.replace('virtual-ethernet', links)
        yield manager, kernel, links
    finally:
        manager.replace('virtual-ethernet', {}, recovery=True)
        manager.replace('vrf', {}, recovery=True)
        kernel.close()


def test_tagged_ipv4_packets(topology):
    """IPv4 crosses the VLAN, without a local-route shortcut between addresses."""
    manager, kernel, links = topology
    links['veth90.10']['addresses'] = ['192.0.2.0/31']
    links['veth91.10']['addresses'] = ['192.0.2.1/31']
    manager.replace('virtual-ethernet', links)
    run('ip', 'vrf', 'exec', 'VIFBLUE', 'ping', '-c', '1', '-W', '2', '192.0.2.1')
    assert kernel.device('veth90.10')['attributes']['mtu'] == 9000


def test_tagged_ipv6_packets(topology):
    """IPv6 neighbor discovery and echo packets use the tagged interfaces."""
    manager, _, links = topology
    links['veth90.10']['addresses'] = ['2001:db8:90::/127']
    links['veth91.10']['addresses'] = ['2001:db8:90::1/127']
    manager.replace('virtual-ethernet', links)
    run('ip', 'vrf', 'exec', 'VIFBLUE', 'ping', '-6', '-c', '1', '-W', '2', '2001:db8:90::1')


def test_vlan_update_and_parent_mtu_preserve_indices(topology):
    """Overrides, removal, and parent MTU changes never recreate existing links."""
    manager, kernel, links = topology
    indices = {name: kernel.device(name)['index'] for name in links}
    links['veth90.10']['attributes'].update(mtu=1400, description='VLAN test', **{'link-group': 10})
    manager.replace('virtual-ethernet', links)
    assert kernel.device('veth90.10')['attributes']['mtu'] == 1400

    del links['veth90.10']['attributes']['mtu']
    links['veth90']['attributes']['mtu'] = 1600
    manager.replace('virtual-ethernet', links)
    assert kernel.device('veth90.10')['attributes']['mtu'] == 1600
    assert {name: kernel.device(name)['index'] for name in links} == indices


def test_vlan_failure_restores_parent_and_children(topology):
    """An invalid child MTU compensates prior parent changes in the transaction."""
    manager, kernel, links = topology
    broken = deepcopy(links)
    broken['veth90']['attributes']['description'] = 'must roll back'
    broken['veth90.10']['attributes']['mtu'] = 9500
    with pytest.raises(RouterError, match='previous configuration restored'):
        manager.replace('virtual-ethernet', broken)
    assert kernel.device('veth90')['attributes']['description'] == ''
    assert kernel.device('veth90.10')['attributes']['mtu'] == 9000


def test_vlan_disable_mac_and_reenable(topology):
    """Child MAC/state changes keep the parent up and preserve both identities."""
    manager, kernel, links = topology
    parent_index = kernel.device('veth90')['index']
    child_index = kernel.device('veth90.10')['index']
    links['veth90.10']['addresses'] = ['192.0.2.0/31']
    links['veth90.10']['attributes']['mac'] = '02:00:00:00:90:10'
    manager.replace('virtual-ethernet', links)
    assert kernel.device('veth90.10')['attributes']['mac'] == '02:00:00:00:90:10'

    links['veth90.10']['disabled'] = True
    manager.replace('virtual-ethernet', links)
    assert not kernel.device('veth90.10')['up']
    assert '192.0.2.0/31' not in kernel.addresses('veth90.10')
    assert kernel.device('veth90')['up']

    links['veth90.10']['disabled'] = False
    manager.replace('virtual-ethernet', links)
    assert '192.0.2.0/31' in kernel.addresses('veth90.10')
    assert kernel.device('veth90.10')['index'] == child_index
    assert kernel.device('veth90')['index'] == parent_index


def test_parent_loss_recreates_pair_and_vlans(topology):
    """Audit recovery restores paired parents before either dependent VLAN."""
    manager, kernel, links = topology
    original = kernel.device('veth90.10')['index']
    run('ip', 'link', 'del', 'veth91')
    manager.reconcile()
    assert all(kernel.device(name) is not None for name in links)
    assert kernel.device('veth90.10')['index'] != original
    assert not manager.failures


def test_all_children_removed_before_paired_parent(topology):
    """Deleting a pair cannot implicitly remove a child before its cleanup runs."""
    manager, kernel, _ = topology
    removed = []
    original = kernel.ipr.link

    def record(operation, **arguments):
        if operation == 'del':
            removed.append(arguments['index'])
        return original(operation, **arguments)

    children = {kernel.device(name)['index'] for name in ('veth90.10', 'veth91.10')}
    kernel.ipr.link = record
    manager.replace('virtual-ethernet', {})
    assert set(removed[:2]) == children
    assert kernel.device('veth90') is None
    assert not manager.state['pending']


def test_ethernet_vlan_dhcp_lease_and_cleanup(tmp_path, isolated):
    """An Ethernet-owned VLAN obtains a real tagged lease and releases its client."""
    kernel = Kernel()
    client = ProcessDHCP(tmp_path / 'runtime')
    manager = Manager(kernel, client, tmp_path / 'state')
    namespace = 'nvyr-vif-dhcp'
    server = None
    run('ip', 'netns', 'add', namespace)
    run('ip', 'link', 'add', 'eth97', 'type', 'veth', 'peer', 'name', 'vifpeer97')
    run('ip', 'link', 'set', 'vifpeer97', 'netns', namespace)

    try:
        run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
        run('ip', '-n', namespace, 'link', 'set', 'vifpeer97', 'up')
        run('ip', '-n', namespace, 'link', 'add', 'link', 'vifpeer97', 'name', 'server.10', 'type', 'vlan', 'id', '10')
        run('ip', '-n', namespace, 'address', 'add', '198.18.0.1/24', 'dev', 'server.10')
        run('ip', '-n', namespace, 'link', 'set', 'server.10', 'up')
        with open(tmp_path / 'server.log', 'w') as log:
            server = subprocess.Popen([
                'ip', 'netns', 'exec', namespace, 'dnsmasq', '--keep-in-foreground', '--port=0',
                '--interface=server.10', '--bind-interfaces', '--dhcp-authoritative',
                '--dhcp-range=198.18.0.20,198.18.0.30,255.255.255.0,2m',
                f'--dhcp-leasefile={tmp_path / "leases"}',
            ], stdout=log, stderr=subprocess.STDOUT)

        links = {
            'eth97': {'kind': 'ethernet'},
            'eth97.10': {'kind': 'vlan', 'dhcp4': True, 'attributes': {'parent': 'eth97', 'vlan': 10}},
        }
        manager.replace('ethernet', links)
        parent_index = kernel.device('eth97')['index']
        wait_for(lambda: client.lease('eth97.10', kernel.device('eth97.10')['index']) is not None,
                 reconcile=manager.reconcile)
        manager.reconcile()
        assert any(address.startswith('198.18.0.') for address in kernel.addresses('eth97.10'))
        assert not any(address.startswith('198.18.0.') for address in kernel.addresses('eth97'))

        # Removing only the child must stop its client and preserve the parent.
        manager.replace('ethernet', {'eth97': links['eth97']})
        assert kernel.device('eth97.10') is None
        assert kernel.device('eth97')['index'] == parent_index
        assert client.process is None
    finally:
        manager.replace('ethernet', {}, recovery=True)
        client.stop('eth97.10')
        if server is not None:
            server.terminate()
            server.wait(timeout=10)
        run('ip', 'link', 'del', 'eth97')
        run('ip', 'netns', 'del', namespace)
        kernel.close()


def test_missing_physical_parent_waits_for_hotplug(tmp_path, isolated):
    """Boot recovery retains VLAN intent while a physical parent is absent."""
    kernel = Kernel()
    manager = Manager(kernel, Leases(), tmp_path)
    links = {
        'eth97': {'kind': 'ethernet'},
        'eth97.10': {'kind': 'vlan', 'attributes': {'parent': 'eth97', 'vlan': 10}},
    }
    manager.replace('ethernet', links, recovery=True)
    assert kernel.device('eth97.10') is None
    run('ip', 'link', 'add', 'eth97', 'type', 'veth', 'peer', 'name', 'vifpeer97')
    try:
        manager.reconcile()
        assert kernel.device('eth97.10')['up']
        assert not manager.failures
    finally:
        manager.replace('ethernet', {}, recovery=True)
        run('ip', 'link', 'del', 'eth97')
        kernel.close()
