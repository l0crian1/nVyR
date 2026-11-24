"""MACVLAN configuration and operational CLI contracts."""

from types import SimpleNamespace

import pytest

from nvyr.config_scripts import interface_bridge
from nvyr.errors import ValidationError
from nvyr.helpers import netlink
from nvyr.tree import ReadOnlyTree


def test_macvlan_dhcp_mac_and_pd(controller, engine, session):
    controller.execute('set interfaces ethernet eth0 vif 100', session)
    controller.execute('set interfaces dummy dum1', session)
    controller.execute('set interfaces macvlan macvlan1 source-interface eth0.100 mac 02:00:00:00:00:02', session)
    controller.execute('set interfaces macvlan macvlan1 address dhcp address dhcpv6', session)
    controller.execute('set interfaces macvlan macvlan1 dhcp-options host-name router', session)
    controller.execute('set interfaces macvlan macvlan1 dhcpv6-pd 1 length 56', session)
    controller.execute('set interfaces macvlan macvlan1 dhcpv6-pd 1 interface dum1 subnet-id 10 address 1', session)

    context = SimpleNamespace(effective=ReadOnlyTree(engine.schema.defaults(engine.view(session))))
    links = interface_bridge.generate(interface_bridge.get_config(context), context)
    child = netlink.normalize(links)['macvlan1']
    attrs = child['attributes']
    assert attrs['parent'] == 'eth0.100' and attrs['mode'] == 'vepa'
    assert attrs['mac'] == '02:00:00:00:00:02' and 'mtu' not in attrs
    assert child['dhcp4'] and child['dhcp-options']['host-name'] == 'router'
    assert child['dhcp6']['address']
    assert child['dhcp6']['requests']['1']['interface']['dum1'] == {'subnet-id': '10', 'address': '1'}


@pytest.mark.parametrize('parent', [None, 'macvlan1', 'br0.999'])
def test_macvlan_requires_parent_in_candidate(parent):
    profile = {'source-interface': parent} if parent else {}
    context = SimpleNamespace(effective={'interfaces': {'macvlan': {'macvlan1': profile}}}, recovery=False)
    with pytest.raises(ValidationError, match='source-interface'):
        interface_bridge.verify(interface_bridge.get_config(context), context)


def test_nested_macvlans_cannot_select_the_requested_kernel_parent():
    profiles = {'macvlan1': {'source-interface': 'eth0'}, 'macvlan2': {'source-interface': 'macvlan1'}}
    context = SimpleNamespace(effective={'interfaces': {'macvlan': profiles, 'ethernet': {'eth0': {}}}}, recovery=False)
    with pytest.raises(ValidationError, match='underlying link'):
        interface_bridge.verify(interface_bridge.get_config(context), context)


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
