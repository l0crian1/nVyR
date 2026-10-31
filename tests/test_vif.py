"""VLAN schema, composed references and common parent-driver contracts."""

from types import SimpleNamespace

import pytest

from nvyr.errors import ValidationError
from nvyr.helpers import interfaces
from nvyr.helpers.netlink import VLAN, normalize
from nvyr.helpers.nftables_formatters import nft_interface_contexts
from nvyr.schema import Schema


def test_ethernet_vlan_plan_and_defaults(controller, engine, session, monkeypatch):
    """An anchored child shares its parent owner but inherits MTU at runtime."""
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    applied = []
    monkeypatch.setattr(interfaces.manager, 'replace', lambda owner, links, **kwargs: applied.append((owner, links)))
    controller.execute('set interfaces ethernet eth1 mtu 9000 vif 10 address dhcp description Users link-group 10', session)
    assert engine.commit(session)['results']['ethernet']['success']

    owner, links = applied[-1]
    assert owner == 'ethernet'
    assert links['eth1']['attributes']['mtu'] == 9000
    assert links['eth1.10'] == {
        'kind': 'vlan', 'addresses': [], 'dhcp4': True, 'disabled': False,
        'dhcp-options': {'default-route-distance': 210},
        'ip-options': {},
        'attributes': {'parent': 'eth1', 'vlan': 10, 'vrf': '', 'link-group': 10, 'description': 'Users'},
    }
    assert 'mtu' not in engine.running['interfaces']['ethernet']['eth1']['vif']['10']


def test_vlan_reference_identity_and_parent_deletion(controller, engine, session):
    """References protect the composed name, including deletion of an ancestor."""
    controller.execute('set interfaces virtual-ethernet veth0 peer-name veth1 vif 10', session)
    controller.execute('set interfaces virtual-ethernet veth1 peer-name veth0', session)
    controller.execute('set firewall ipv4 input filter rule 10 inbound-interface veth0.10 action accept', session)
    assert all(result['success'] for result in engine.commit(session)['results'].values())

    with pytest.raises(ValidationError, match='referenced'):
        controller.execute('delete interfaces virtual-ethernet veth0 vif 10', session)
    with pytest.raises(ValidationError, match='referenced'):
        controller.execute('delete interfaces virtual-ethernet veth0', session)

    controller.execute('delete firewall', session)
    controller.execute('delete interfaces virtual-ethernet', session)
    assert all(result['success'] for result in engine.commit(session)['results'].values())


def test_vlan_vrf_reapply_and_completion(controller, engine, session):
    """Candidate VIF names complete before creation and membership triggers firewall."""
    controller.execute('set vrf name BLUE table 101', session)
    controller.execute('set interfaces virtual-ethernet veth0 peer-name veth1 vif 10', session)
    controller.execute('set interfaces virtual-ethernet veth1 peer-name veth0', session)
    completion = controller.completion('set firewall ipv4 input filter rule 10 inbound-interface ', session, explicit=True)
    assert 'veth0.10' in dict(completion['candidates'])
    controller.execute('set firewall ipv4 input filter rule 10 inbound-interface veth0.10 action accept', session)
    assert all(result['success'] for result in engine.commit(session)['results'].values())

    controller.execute('set interfaces virtual-ethernet veth0 vif 10 vrf BLUE', session)
    result = engine.commit(session)
    assert list(result['results']) == ['vrf_conntrack', 'virtual-ethernet', 'firewall']
    assert all(item['success'] for item in result['results'].values())
    context = nft_interface_contexts(engine.running)
    assert 'veth0.10' in context['ipv4', 'input']['members']
    assert 'veth0' not in context['ipv4', 'input']['members']
    with pytest.raises(ValidationError, match='referenced'):
        controller.execute('delete vrf name BLUE', session)


@pytest.mark.parametrize('value', ['0', '4095', '-1', '1.5', '001'])
def test_invalid_vlan_ids(controller, session, value):
    """Reserved, noninteger and alias spellings fail before candidate insertion."""
    with pytest.raises(ValidationError):
        controller.execute(f'set interfaces ethernet eth1 vif {value}', session)


def test_vlan_name_and_mtu_validation():
    """Full names, child MTU and child VRF are verified independently of the parent."""
    with pytest.raises(ValidationError, match='interface name'):
        interfaces.verify_vifs({'veth12345678901': {'vif': {'4094': {}}}})
    with pytest.raises(ValidationError, match='MTU'):
        interfaces.verify_vifs({'eth0': {'mtu': '1500', 'vif': {'10': {'mtu': '9000'}}}})
    with pytest.raises(ValidationError, match='VRF'):
        interfaces.verify_membership({'eth0': {'vif': {'10': {'vrf': 'MISSING'}}}}, vrfs={}, bridge_members=set())


def test_vlan_driver_is_parent_type_independent():
    """A future bond or bridge can supply the same ordinary VLAN definition."""
    spec = {'kind': 'vlan', 'attributes': {'parent': 'bond0', 'vlan': 100}}
    assert normalize({'bond0.100': spec})['bond0.100']['kind'] == 'vlan'
    assert VLAN().dependencies(dict(spec, name='bond0.100')) == ('bond0',)
    with pytest.raises(ValidationError, match='cannot change'):
        VLAN().validate(dict(spec, name='bond0.100'), {}, dict(spec, attributes={'parent': 'bond1', 'vlan': 100}))


def test_equal_tags_on_different_parents_have_distinct_references(controller, engine, session):
    """Protect only the referenced parent/tag pair, including uncommitted children."""
    controller.execute('set interfaces virtual-ethernet veth0 peer-name veth1 vif 10', session)
    controller.execute('set interfaces virtual-ethernet veth1 peer-name veth0 vif 10', session)
    controller.execute('set firewall ipv4 input filter rule 10 inbound-interface veth0.10 action accept', session)
    controller.execute('delete interfaces virtual-ethernet veth1 vif 10', session)
    with pytest.raises(ValidationError, match='veth0.10'):
        controller.execute('delete interfaces virtual-ethernet veth0 vif 10', session)

    # Full-tree load validation uses the same identities as interactive deletion.
    configuration = engine.view(session)
    registrar = engine.dependencies
    assert ('interface', 'veth0.10', ('interfaces', 'virtual-ethernet', 'veth0', 'vif', '10')) in registrar.from_tree(configuration, 'dependency')
    assert engine.references(session, ['interfaces', 'virtual-ethernet', 'veth0', 'vif', '10']) == [
        ('firewall', 'ipv4', 'input', 'filter', 'rule', '10', 'inbound-interface', 'veth0.10'),
    ]


def test_dependency_format_rejects_unknown_placeholders():
    """Malformed identity declarations must fail when a schema is loaded."""
    with pytest.raises(ValueError, match='dependency-format'):
        Schema({'kind': 'node', 'children': {'bad': {
            'kind': 'tag_node', 'dependency': 'interface', 'dependency-format': '{unknown}',
        }}})
