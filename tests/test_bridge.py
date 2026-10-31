"""Bridge syntax, validation, dependencies and operational dispatch contracts."""

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nvyr.errors import ValidationError
from nvyr.helpers import bridge_config
from nvyr.config_scripts import interface_bridge
from nvyr.tree import ReadOnlyTree


def context(values):
    return SimpleNamespace(effective={'interfaces': {'bridge': values, 'dummy': {'dum1': {}, 'dum2': {}}}},
                           recovery=False)


def test_anchored_bridge_vlan_and_member_configuration(controller, engine, session):
    controller.execute('set interfaces dummy dum1', session)
    controller.execute('set interfaces bridge br0 vlan-filtering default-pvid 0 member interface dum1 vlan 10 pvid untagged', session)
    result = engine.commit(session)
    assert all(item['success'] for item in result['results'].values()), str(result['results'])
    bridge = engine.running['interfaces']['bridge']['br0']
    assert bridge['member']['interface']['dum1']['vlan']['10'] == {'pvid': True, 'untagged': True}


def test_empty_spanning_tree_enables_and_deletion_disables(controller, engine, session):
    controller.execute('set interfaces bridge br0 spanning-tree', session)
    assert engine.commit(session)['results']['bridge']['success']
    assert bridge_config.bridge_options(engine.running['interfaces']['bridge']['br0'])['stp_state'] == 1
    controller.execute('delete interfaces bridge br0 spanning-tree', session)
    assert engine.commit(session)['results']['bridge']['success']
    assert bridge_config.bridge_options(engine.running['interfaces']['bridge']['br0'])['stp_state'] == 0


def test_member_dependency_protects_deletion(controller, engine, session):
    controller.execute('set interfaces dummy dum1', session)
    controller.execute('set interfaces bridge br0 member interface dum1', session)
    assert all(item['success'] for item in engine.commit(session)['results'].values())
    with pytest.raises(ValidationError, match='referenced'):
        controller.execute('delete interfaces dummy dum1', session)


@pytest.mark.parametrize(('settings', 'message'), [
    ({'member': {'interface': {'dum9': {}}}}, 'must be configured'),
    ({'member': {'interface': {'br0': {}}}}, 'itself'),
    ({'member': {'interface': {'dum1': {'backup-interface': 'dum2'}}}}, 'different member'),
    ({'member': {'interface': {'dum1': {'backup-interface': 'dum2'}, 'dum2': {'backup-interface': 'dum1'}}}}, 'cycle'),
    ({'vlan': {'10': {'local': {}}}}, 'require vlan-filtering'),
    ({'vlan-filtering': {}, 'member': {'interface': {'dum1': {'vlan': {'10': {'pvid': {}}, '20': {'pvid': {}}}}}}}, 'only one'),
    ({'vlan-statistics-per-port': {}}, 'requires vlan-statistics'),
    ({'spanning-tree': {'max-age': '40s'}}, 'STP requires'),
    ({'multicast': {'query-interval': '10s'}}, 'query-response-interval'),
    ({'member': {'interface': {'dum1': {'neighbor-vlan-suppression': {}}}}}, 'requires neighbor-suppression'),
    ({'static-mac': {'02:00:00:00:00:01': {}}}, 'is required'),
    ({'static-mac': {'02:00:00:00:00:01': {'interface': 'dum1'}}}, 'must be a bridge member'),
    ({'multicast': {'static-group': {'TV': {}}}}, 'address and interface'),
    ({'vlan-filtering': {}, 'vlan-protocol': '802.1ad', 'vif': {'10': {}}}, '802.1Q VIFs'),
])
def test_verification_rejects_inconsistent_bridge(settings, message):
    values = {'br0': settings}
    run = context(values)
    with pytest.raises(ValidationError, match=message):
        interface_bridge.verify(interface_bridge.get_config(run), run)


def test_duplicate_members_and_l3_rejected():
    values = {'br0': {'member': {'interface': {'dum1': {}}}},
              'br1': {'member': {'interface': {'dum1': {}}}}}
    run = context(values)
    with pytest.raises(ValidationError, match='already belongs'):
        interface_bridge.verify(interface_bridge.get_config(run), run)
    del values['br1']
    run = context(values)
    run.effective['interfaces']['dummy']['dum1']['address'] = ['192.0.2.1/24']
    with pytest.raises(ValidationError, match='cannot have addresses'):
        interface_bridge.verify(interface_bridge.get_config(run), run)


def test_default_pvid_and_explicit_vlan_one():
    assert bridge_config.vlan_memberships({}) == {1: (True, True)}
    assert bridge_config.vlan_memberships({'default-pvid': '0'}) == {}
    assert bridge_config.vlan_memberships({'vlan': {'10': {'pvid': {}}}}) == {10: (True, False)}
    assert bridge_config.vlan_memberships({'default-pvid': '0', 'vlan': {'1': {}}}) == {1: (False, False)}


def test_bridge_vifs_are_native_children():
    run = context({'br0': {'vif': {'10': {'address': ['192.0.2.1/24']}}}})
    links = interface_bridge.generate(interface_bridge.get_config(run), run)
    assert links['br0']['kind'] == 'bridge'
    assert links['br0.10']['attributes']['parent'] == 'br0'
    assert bridge_config.vlan_memberships(links['br0']['attributes']['bridge'], local=True)[10] == (False, False)


def test_ruleless_bridge_is_valid():
    run = context({'br0': {}})
    interface_bridge.verify(interface_bridge.get_config(run), run)


def test_bridge_lifecycle_keeps_configuration_read_only(monkeypatch):
    run = context({'br0': {
        'vrf': 'BLUE',
        'member': {'interface': {'dum1': {}}},
        'vif': {'10': {'address': ['192.0.2.1/24'], 'vrf': 'BLUE'}},
    }})
    run.effective['vrf'] = {'name': {'BLUE': {'table': '100'}}}
    source = run.effective
    original = deepcopy(source)
    run.effective = ReadOnlyTree(source)
    configuration = interface_bridge.get_config(run)
    manager = SimpleNamespace(request=Mock(), replace=Mock())
    monkeypatch.setattr(interface_bridge.interfaces, 'manager', manager)

    # Later stages use the collected data, not another read of the configd context.
    stage_context = SimpleNamespace(recovery=True)
    with monkeypatch.context() as patch:
        patch.setattr(interface_bridge, 'generate', Mock(side_effect=AssertionError('verify called generate')))
        interface_bridge.verify(configuration, stage_context)
    manager.replace.assert_not_called()

    links = interface_bridge.generate(configuration, stage_context)
    assert json.loads(json.dumps(links)) == links
    manager.request.assert_called_once_with('validate', owner='bridge', links=links, recovery=True)

    before_apply = deepcopy(links)
    with monkeypatch.context() as patch:
        patch.setattr(interface_bridge, 'link_definitions', Mock(side_effect=AssertionError('apply formatted links')))
        interface_bridge.apply(links, stage_context)
    manager.replace.assert_called_once_with('bridge', links, recovery=True)
    assert links == before_apply
    assert source == original


@pytest.mark.parametrize('values', [
    {'br0': {'vrf': 'MISSING'}},
    {'br0': {'vif': {'10': {'vrf': 'MISSING'}}}},
])
def test_bridge_and_vif_require_configured_vrf(values):
    run = context(values)
    with pytest.raises(ValidationError, match='VRF.*not configured'):
        interface_bridge.verify(interface_bridge.get_config(run), run)


@pytest.mark.parametrize(('group', 'source'), [
    ('239.1.1.1', '2001:db8::1'),
    ('ff3e::1', '192.0.2.1'),
])
def test_multicast_source_family_checked_in_verify(group, source):
    run = context({'br0': {
        'member': {'interface': {'dum1': {}}},
        'multicast': {'static-group': {'TV': {
            'address': group, 'source': source, 'interface': ['dum1'],
        }}},
    }})
    with pytest.raises(ValidationError, match='same family'):
        interface_bridge.verify(interface_bridge.get_config(run), run)


def test_bridge_native_validation_failure_propagates(monkeypatch):
    from nvyr.errors import RouterError

    run = context({'br0': {}})
    request = Mock(side_effect=RouterError('Interface br0 is not owned by bridge'))
    monkeypatch.setattr(interface_bridge.interfaces.manager, 'request', request)

    with pytest.raises(RouterError, match='not owned'):
        interface_bridge.verify(interface_bridge.get_config(run), run)


def test_multicast_default_retains_native_quarter_interval():
    from nvyr.helpers.bridge_netlink import native_value
    options = bridge_config.multicast_options({})
    assert native_value('mcast_startup_query_interval', options['mcast_startup_query_interval']) == 3125


@pytest.mark.parametrize('command', [
    'set interfaces bridge br0 member interface dum1 spanning-tree priority 64',
    'set interfaces bridge br0 member interface dum1 spanning-tree cost 65536',
    'set interfaces bridge br0 address dhcpv6',
    'set interfaces bridge br0 spanning-tree forward-delay 1s',
    'set interfaces bridge br0 spanning-tree max-age 5s',
    'set interfaces bridge br0 static-mac ff:ff:ff:ff:ff:ff interface dum1',
    'set interfaces bridge br0 static-mac 00:00:00:00:00:00 interface dum1',
    'set interfaces bridge br0 multicast static-group TV address 192.0.2.1',
    'set interfaces bridge br0 multicast static-group TV address 2001:db8::1',
    'set interfaces bridge br0 multicast static-group TV source 239.1.1.1',
    'set interfaces bridge br0 multicast static-group TV source ff3e::1',
    'set interfaces bridge br0 multicast static-group TV source 0.0.0.0',
    'set interfaces bridge br0 multicast static-group TV source ::',
])
def test_native_scalar_bounds_rejected(controller, session, command):
    with pytest.raises(ValidationError):
        controller.execute(command, session)


@pytest.mark.parametrize('command', [
    'set interfaces bridge br0 spanning-tree forward-delay 2s',
    'set interfaces bridge br0 spanning-tree forward-delay 30s',
    'set interfaces bridge br0 spanning-tree max-age 6s',
    'set interfaces bridge br0 spanning-tree max-age 40s',
    'set interfaces bridge br0 multicast static-group TV address 239.1.1.1',
    'set interfaces bridge br0 multicast static-group TV address ff3e::1',
    'set interfaces bridge br0 multicast static-group TV source 192.0.2.1',
    'set interfaces bridge br0 multicast static-group TV source 2001:db8::1',
])
def test_bridge_scalar_values_accepted(controller, session, command):
    controller.execute(command, session)


def test_operational_dispatch_native_paths(controller, session):
    from nvyr.schema import Schema
    schema = Schema.bundled('operational')
    for line in ('show interfaces bridge', 'show interfaces bridge br0',
                 'show interfaces bridge br0 member', 'show interfaces bridge br0 member dum1',
                 'show interfaces bridge br0 vlan', 'show interfaces bridge br0 mac',
                 'show interfaces bridge br0 spanning-tree', 'show interfaces bridge br0 multicast',
                 'clear interfaces bridge br0 learned-macs',
                 'clear interfaces bridge br0 learned-macs interface dum1',
                 'clear interfaces bridge br0 learned-macs vlan 10'):
        parsed = schema.operational(line.split())
        assert parsed


def test_bridge_completion_keeps_interface_subcommands(controller):
    """A new positional bridge branch coexists with optional typed interface views."""
    assert controller.completion('show interfaces bri')['replacement'] == 'bridge'
    assert controller.completion('show interfaces ethe')['replacement'] == 'ethernet'
    choices = dict(controller.completion('show interfaces bridge br0 ', explicit=True)['candidates'])
    assert {'member', 'vlan', 'mac', 'multicast', 'spanning-tree'} <= choices.keys()


def test_bridge_operational_arguments_and_clear_permission(controller, monkeypatch):
    """Native script arguments retain the selected bridge, port and VLAN at the boundary."""
    from nvyr.errors import RouterError
    from nvyr.helpers import access

    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    token = access.role.set('net-admin')
    try:
        controller.execute('show interfaces bridge br0 member dum1')
        assert calls[-1] == ['bridge.nvyr.op', 'show', '--bridge', 'br0', '--section', 'member', '--member', 'dum1']
        controller.execute('clear interfaces bridge br0 learned-macs vlan 10')
        assert calls[-1] == ['bridge.nvyr.op', 'clear', 'br0', '--vlan', '10']
    finally:
        access.role.reset(token)

    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError, match='requires net-admin'):
            controller.execute('clear interfaces bridge br0 learned-macs')
    finally:
        access.role.reset(token)
    assert len(calls) == 2
