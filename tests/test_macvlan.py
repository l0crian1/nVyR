"""MACVLAN configuration and operational CLI contracts."""

from types import SimpleNamespace

import pytest

from nvyr.config_scripts import interface_macvlan
from nvyr.config_session import CommitError
from nvyr.errors import ValidationError
from nvyr.helpers import interfaces, netlink
from nvyr.tree import ReadOnlyTree


def test_macvlan_on_bridge_vif_has_independent_commits(local_session, monkeypatch):
    applied = []

    def record(owner, links, **kwargs):
        applied.append((owner, set(links)))

    monkeypatch.setattr(interfaces.manager, 'replace', record)
    local_session.set('set interfaces bridge br0 vif 10')
    local_session.set('set interfaces macvlan macvlan0 source-interface br0.10')
    local_session.commit()
    assert applied == [('bridge', {'br0', 'br0.10'}), ('macvlan', {'macvlan0'})]

    applied.clear()
    local_session.delete('delete interfaces macvlan macvlan0')
    local_session.commit()
    assert applied == [('macvlan', set())]


def test_macvlan_dhcp_mac_and_pd(controller, engine, session):
    controller.execute('set interfaces ethernet eth0 vif 100', session)
    controller.execute('set interfaces dummy dum1', session)
    controller.execute('set interfaces macvlan macvlan1 source-interface eth0.100 mac 02:00:00:00:00:02', session)
    controller.execute('set interfaces macvlan macvlan1 address dhcp address dhcpv6', session)
    controller.execute('set interfaces macvlan macvlan1 dhcp-options host-name router', session)
    controller.execute('set interfaces macvlan macvlan1 dhcpv6-pd 1 length 56', session)
    controller.execute('set interfaces macvlan macvlan1 dhcpv6-pd 1 interface dum1 subnet-id 10 address 1', session)

    context = SimpleNamespace(effective=ReadOnlyTree(engine.schema.defaults(engine.view(session))))
    links = interface_macvlan.generate(interface_macvlan.get_config(context), context)
    child = netlink.normalize(links)['macvlan1']
    attrs = child['attributes']
    assert attrs['parent'] == 'eth0.100' and attrs['mode'] == 'vepa'
    assert attrs['mac'] == '02:00:00:00:00:02' and 'mtu' not in attrs
    assert child['dhcp4'] and child['dhcp-options']['host-name'] == 'router'
    assert child['dhcp6']['address']
    assert child['dhcp6']['requests']['1']['interface']['dum1'] == {'subnet-id': '10', 'address': '1'}


def test_opposing_stacks_are_rejected_before_apply(local_session):
    local_session.set('set interfaces dummy dum0')
    local_session.set('set interfaces macvlan macvlan1 source-interface dum0')
    local_session.set('set interfaces vxlan vxlan1 vni 101 source-interface macvlan1')
    local_session.commit()

    local_session.set('set interfaces vxlan vxlan0 vni 100')
    local_session.set('set interfaces macvlan macvlan0 source-interface vxlan0')
    with pytest.raises(CommitError, match='one MACVLAN/VXLAN stacking direction'):
        local_session.commit()
    running = local_session.get_config()['interfaces']
    assert set(running['macvlan']) == {'macvlan1'}
    assert set(running['vxlan']) == {'vxlan1'}


@pytest.mark.parametrize('parent', [None, 'macvlan1', 'br0.999'])
def test_macvlan_requires_parent_in_candidate(parent):
    profile = {'source-interface': parent} if parent else {}
    context = SimpleNamespace(effective={'interfaces': {'macvlan': {'macvlan1': profile}}}, recovery=False)
    with pytest.raises(ValidationError, match='source-interface'):
        interface_macvlan.verify(interface_macvlan.get_config(context), context)


def test_nested_macvlans_cannot_select_the_requested_kernel_parent():
    profiles = {'macvlan1': {'source-interface': 'eth0'}, 'macvlan2': {'source-interface': 'macvlan1'}}
    context = SimpleNamespace(effective={'interfaces': {'macvlan': profiles, 'ethernet': {'eth0': {}}}}, recovery=False)
    with pytest.raises(ValidationError, match='underlying link'):
        interface_macvlan.verify(interface_macvlan.get_config(context), context)


@pytest.mark.parametrize('suffix,args', [
    ('', []), (' macvlan1', ['--intf_name', 'macvlan1']),
    (' macvlan1 detail', ['--intf_name', 'macvlan1', '--detail']),
    (' statistics', ['--statistics']),
])
def test_macvlan_show_dispatch(controller, monkeypatch, suffix, args):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    controller.execute('show interfaces macvlan' + suffix)
    assert calls == [['interfaces.nvyr.op', 'show', '--intf_type', 'macvlan', *args]]
