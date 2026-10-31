"""Native bridge regression tests, only in an isolated privileged container."""

from copy import deepcopy
import json
import os

import pytest

from nvyr.config_scripts.interface_bridge import generate
from nvyr.errors import RouterError
from nvyr.helpers.link_manager import Manager
from nvyr.helpers.netlink import Kernel
from nvyr.helpers.bridge_netlink import bridge_data, vlan_inventory
from tests.test_netlink import Leases
from tests.test_netlink_live import isolated, run

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETLINK_TEST') != '1',
                                reason='requires isolated privileged Netlink container')


@pytest.fixture
def topology(tmp_path, isolated):
    kernel = Kernel()
    manager = Manager(kernel, Leases(), tmp_path)
    ports = {'dum90': {'kind': 'dummy'}, 'dum91': {'kind': 'dummy'}}
    manager.replace('dummy', ports)
    values = {'br90': {'member': {'interface': {'dum90': {}, 'dum91': {}}}}}
    try:
        manager.replace('bridge', generate({'bridges': values}, None))
        yield manager, kernel, values
    finally:
        manager.replace('bridge', {}, recovery=True)
        manager.replace('dummy', {}, recovery=True)
        kernel.close()


def test_creation_update_audit_and_delete(topology):
    """Port audits retain bridge ownership, and attribute updates retain ifindices."""
    manager, kernel, values = topology
    index = kernel.device('br90')['index']
    assert kernel.device('dum90')['attributes']['vrf'] == index
    manager.reconcile()
    assert not manager.failures
    assert kernel.device('dum90')['attributes']['vrf'] == index
    values['br90']['description'] = 'Native bridge test'
    manager.replace('bridge', generate({'bridges': values}, None))
    assert kernel.device('br90')['index'] == index
    assert kernel.device('br90')['attributes']['description'] == 'Native bridge test'


def test_restart_and_external_bridge_loss(topology):
    """Persisted ownership survives restart and recreation reattaches existing ports."""
    manager, kernel, values = topology
    bridge_index = kernel.device('br90')['index']
    port_index = kernel.device('dum90')['index']
    restarted = Manager(kernel, manager.dhcp, manager.path.parent)
    restarted.reconcile()
    assert not restarted.failures
    assert kernel.device('br90')['index'] == bridge_index

    run('ip', 'link', 'del', 'br90')
    kernel.refresh('br90')
    kernel.refresh('dum90')
    kernel.refresh('dum91')
    manager.reconcile()
    assert not manager.failures
    assert kernel.device('br90')['index'] != bridge_index
    assert kernel.device('dum90')['index'] == port_index
    assert kernel.device('dum90')['attributes']['vrf'] == kernel.device('br90')['index']


def test_bridge_dhcp_client_intent(topology):
    """The common lease manager starts and stops DHCP on the bridge, never its ports."""
    manager, kernel, values = topology
    values['br90']['address'] = ['dhcp']
    manager.replace('bridge', generate({'bridges': values}, None))
    assert set(manager.dhcp.clients) == {'br90'}
    assert manager.dhcp.clients['br90'][0] == kernel.device('br90')['index']

    del values['br90']['address']
    manager.replace('bridge', generate({'bridges': values}, None))
    assert not manager.dhcp.clients


def test_vlan_zero_access_trunk_and_removal(topology):
    """Default-PVID zero removes implicit VLAN 1 on the bridge and every port."""
    manager, kernel, values = topology
    bridge = values['br90']
    bridge.update({'vlan-filtering': {}, 'default-pvid': '0'})
    bridge['member']['interface']['dum90']['vlan'] = {'10': {'pvid': {}, 'untagged': {}}}
    bridge['member']['interface']['dum91']['vlan'] = {'10': {}, '20': {}}
    manager.replace('bridge', generate({'bridges': values}, None))
    assert vlan_inventory('br90') == {}
    assert vlan_inventory('dum90') == {10: (True, True)}
    assert vlan_inventory('dum91') == {10: (False, False), 20: (False, False)}
    del bridge['member']['interface']['dum91']['vlan']['20']
    manager.replace('bridge', generate({'bridges': values}, None))
    assert vlan_inventory('dum91') == {10: (False, False)}


def test_static_forwarding_and_multicast(topology):
    """Static forwarding and MDB entries are reconciled without disturbing dynamic entries."""
    manager, kernel, values = topology
    values['br90']['static-mac'] = {'02:00:00:00:90:01': {'interface': 'dum90'}}
    values['br90']['multicast'] = {'static-group': {'TV': {'address': '239.90.0.1', 'interface': ['dum90']}}}
    manager.replace('bridge', generate({'bridges': values}, None))
    entries = json.loads(run('bridge', '-j', 'fdb', 'show', 'br', 'br90'))
    assert any(entry['mac'] == '02:00:00:00:90:01' and entry['state'] == 'static' for entry in entries)
    assert '239.90.0.1' in run('bridge', '-j', 'mdb', 'show', 'dev', 'br90')
    del values['br90']['static-mac']
    del values['br90']['multicast']
    manager.replace('bridge', generate({'bridges': values}, None))
    assert '02:00:00:00:90:01' not in run('bridge', '-j', 'fdb', 'show', 'br', 'br90')
    assert '239.90.0.1' not in run('bridge', '-j', 'mdb', 'show', 'dev', 'br90')


def test_stp_port_settings_and_reset(topology):
    """STP flags, flooding and isolation apply and return to their defaults."""
    manager, kernel, values = topology
    values['br90']['spanning-tree'] = {'priority': '4096'}
    values['br90']['member']['interface']['dum90'] = {
        'spanning-tree': {'cost': '500', 'bpdu-guard': {}, 'root-guard': {}},
        'hairpin': {}, 'isolated': {}, 'flood': {'unknown-unicast': {'disable': {}}}}
    manager.replace('bridge', generate({'bridges': values}, None))
    assert bridge_data('br90')['stp_state'] == 1
    port = json.loads(run('bridge', '-d', '-j', 'link', 'show', 'dev', 'dum90'))[0]
    assert port['cost'] == 500 and port['guard'] and port['root_block'] and port['hairpin']
    assert port['isolated'] and not port['flood']
    del values['br90']['spanning-tree']
    values['br90']['member']['interface']['dum90'] = {}
    manager.replace('bridge', generate({'bridges': values}, None))
    port = json.loads(run('bridge', '-d', '-j', 'link', 'show', 'dev', 'dum90'))[0]
    assert not port['guard'] and not port['isolated'] and port['flood']


def test_failed_apply_rolls_back(topology):
    """A rejected native change restores attributes and previous port memberships."""
    manager, kernel, values = topology
    broken = deepcopy(values)
    broken['br90']['description'] = 'must roll back'
    broken['br90']['mtu'] = '1'
    with pytest.raises(RouterError, match='previous configuration restored'):
        manager.replace('bridge', generate({'bridges': broken}, None))
    assert kernel.device('br90')['attributes']['description'] == ''
    assert kernel.device('dum90')['attributes']['vrf'] == kernel.device('br90')['index']
