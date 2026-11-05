"""Static-neighbor schema, ownership, rollback and operational descriptions."""

from copy import deepcopy

import pytest

from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import interface_ip, interfaces
from nvyr.helpers.link_manager import Manager
from nvyr.op_scripts import neighbors
from tests.test_netlink import backend, spec
from tests.test_neighbor_dns_op import neighbor_data


OPTIONS = {
    'ip': {'arp-entry': {'192.0.2.2': {'mac-address': '02:00:00:00:00:02', 'description': 'Core'}}},
    'ipv6': {'neighbor': {'2001:db8::2': {'mac-address': '02:00:00:00:00:02'}}},
}


@pytest.mark.parametrize('family,node,address', [('ip', 'arp-entry', '192.0.2.2'),
                                               ('ipv6', 'neighbor', '2001:db8::2')])
@pytest.mark.parametrize('kind,name', [('ethernet', 'eth1'), ('dummy', 'dum1'),
                                     ('bridge', 'br1'), ('bond', 'bond1'),
                                     ('virtual-ethernet', 'veth1')])
def test_anchored_values(controller, engine, session, kind, name, family, node, address):
    controller.execute(f'set interfaces {kind} {name} {family} {node} {address} '
                       'mac-address 02:00:00:00:00:02 description "Core switch"', session)
    values = engine.view(session)['interfaces'][kind][name][family][node][address]
    assert values == {'mac-address': '02:00:00:00:00:02', 'description': 'Core switch'}


@pytest.mark.parametrize('options,message', [
    ({'ip': {'arp-entry': {'192.0.2.2': {'description': 'Missing MAC'}}}}, 'requires mac-address'),
    ({'ipv6': {'neighbor': {'2001:db8::2': {'mac-address': '02:00:00:00:00:02'},
                           '2001:db8:0::2': {'mac-address': '02:00:00:00:00:03'}}}}, 'duplicate neighbor'),
    ({'ipv6': {'disable': True, 'neighbor': {'2001:db8::2': {'mac-address': '02:00:00:00:00:02'}}}},
     'disable conflicts'),
])
def test_relationship_checks(options, message):
    with pytest.raises(ValidationError, match=message):
        interface_ip.normalize(options, kind='ethernet')


def test_copy_configuration_view():
    links = interfaces.settings({'eth1': OPTIONS})
    assert interface_ip.neighbors(links['eth1'].ip_options) == {
        '192.0.2.2': '02:00:00:00:00:02', '2001:db8::2': '02:00:00:00:00:02'}


def test_vlan_anchors_and_cli_validation(controller, engine, session):
    controller.execute('set interfaces ethernet eth1 vif 100 ipv6 neighbor fe80::2 '
                       'description "VLAN peer" mac-address 02:00:00:00:00:02', session)
    entries = engine.view(session)['interfaces']['ethernet']['eth1']['vif']['100']['ipv6']['neighbor']
    assert entries['fe80::2']['description'] == 'VLAN peer'
    for suffix in ('ip arp-entry 192.0.2.0/24', 'ipv6 neighbor 192.0.2.1',
                   'ip arp-entry 192.0.2.2 mac-address ff:ff:ff:ff:ff:ff'):
        with pytest.raises(ValidationError):
            controller.execute('set interfaces ethernet eth1 ' + suffix, session)


def test_same_address_on_distinct_interfaces(backend):
    backend.kernel.add('eth2')
    backend.replace('ethernet', {name: spec(**{'ip-options': deepcopy(OPTIONS)}) for name in ('eth1', 'eth2')})
    backend.replace('ethernet', {'eth2': spec(**{'ip-options': OPTIONS})})
    assert not backend.kernel.neighbors('eth1')
    assert set(backend.kernel.neighbors('eth2')) == {'192.0.2.2', '2001:db8::2'}


def test_owned_neighbor_lifecycle_and_metadata(backend):
    original = {'eth1': spec(**{'ip-options': deepcopy(OPTIONS)})}
    backend.kernel.neighbor_entries['eth1'] = {'192.0.2.99': ('02:00:00:00:00:99', 128)}
    backend.replace('ethernet', original)
    assert len(backend.kernel.neighbors('eth1')) == 3

    changed = deepcopy(original)
    changed['eth1']['ip-options']['ip']['arp-entry']['192.0.2.2']['description'] = 'New label'
    backend.kernel.neighbor_writes.clear()
    backend.replace('ethernet', changed)
    assert backend.kernel.neighbor_writes == []

    changed['eth1']['ip-options']['ip']['arp-entry']['192.0.2.2']['mac-address'] = '02:00:00:00:00:03'
    backend.replace('ethernet', changed)
    assert backend.kernel.neighbors('eth1')['192.0.2.2'] == ('02:00:00:00:00:03', 128)

    backend.kernel.neighbor_entries['eth1'].pop('2001:db8::2')
    backend.reconcile()
    assert '2001:db8::2' in backend.kernel.neighbors('eth1')

    backend.replace('ethernet', {'eth1': spec(disabled=True, **{'ip-options': OPTIONS})})
    assert set(backend.kernel.neighbors('eth1')) == {'192.0.2.99'}
    backend.replace('ethernet', original)
    backend.replace('ethernet', {})
    assert set(backend.kernel.neighbors('eth1')) == {'192.0.2.99'}


def test_partial_failure_rolls_back_and_restart_keeps_ownership(backend, monkeypatch):
    original = {'eth1': spec(**{'ip-options': deepcopy(OPTIONS)})}
    backend.replace('ethernet', original)
    changed = deepcopy(original)
    changed['eth1']['ip-options']['ip']['arp-entry']['192.0.2.3'] = {'mac-address': '02:00:00:00:00:03'}
    write = backend.kernel.neighbor

    def fail_after_write(operation, name, address, mac=None):
        write(operation, name, address, mac)
        if operation == 'replace' and address == '192.0.2.3':
            raise RouterError('Interrupted write')

    monkeypatch.setattr(backend.kernel, 'neighbor', fail_after_write)
    with pytest.raises(RouterError, match='previous configuration restored'):
        backend.replace('ethernet', changed)
    assert '192.0.2.3' not in backend.kernel.neighbors('eth1')

    restarted = Manager(backend.kernel, backend.dhcp, backend.path.parent, boot='first')
    restarted.replace('ethernet', {'eth1': spec()})
    assert not backend.kernel.neighbors('eth1')


def test_descriptions_are_scoped_and_canonical(neighbor_data, monkeypatch):
    configuration = {'interfaces': {'ethernet': {'eth0': {
        'ip': {'arp-entry': {'192.0.2.3': {'mac-address': '02:00:00:00:00:01', 'description': 'Core switch'}}}
    }}}}
    monkeypatch.setattr(neighbors, 'running_configuration', lambda: configuration)
    output = neighbors.show('show arp')
    assert 'Description' in output and 'Core switch' in output
