from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nvyr.config_scripts import interface_ethernet as ethernet
from nvyr.errors import BusyError, RecoveryError, RouterError
from nvyr.helpers import interfaces
from nvyr.tree import ReadOnlyTree, lookup


@pytest.mark.parametrize('value', ['dhcp', '192.0.2.1', '192.0.2.1/24', '2001:db8::1', '2001:db8::1/64'])
def test_ethernet_address_forms(controller, session, value):
    controller.execute('set interfaces ethernet eth0 address ' + value, session)

    assert session.mutations[0].kind == 'add'


@pytest.mark.parametrize('value', ['192.0.2.999', '192.0.2.1/33', '2001:db8::1/129', 'dhcp6', 'fe80::1%eth0', 'bad'])
def test_invalid_ethernet_address(controller, session, value):
    with pytest.raises(RouterError):
        controller.execute('set interfaces ethernet eth0 address ' + value, session)

    assert not session.mutations


def test_interface_existence_helper_uses_current_namespace(monkeypatch):
    def index(name):
        if name == 'eth0':
            return 2

        raise OSError('not present')

    monkeypatch.setattr(interfaces.socket, 'if_nametoindex', index)

    assert interfaces.exists('eth0') and not interfaces.exists('absent')


def test_missing_interface_fails_verify_before_apply(controller, engine, session, monkeypatch):
    monkeypatch.setattr(interfaces, 'exists', lambda name: False)
    calls = []
    monkeypatch.setattr(interfaces.manager, 'replace', lambda *args, **kwargs: calls.append(args))
    controller.execute('set interfaces ethernet eth999 address dhcp', session)
    controller.execute('set system host-name independent', session)
    result = engine.commit(session)

    assert 'interfaces ethernet eth999: interface does not exist' in result['results']['ethernet']['error']
    assert result['results']['system']['success']
    assert [stage for _, stage, _ in engine.modules['ethernet'].calls][-2:] == ['get_config', 'verify']
    assert not calls and session.mutations


def test_real_script_plans_empty_up_multivalue_disable_and_delete(controller, engine, session, monkeypatch):
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    plans = []
    monkeypatch.setattr(interfaces.manager, 'replace', lambda owner, plan, **kw: plans.append((owner, plan)))
    controller.execute('set interfaces ethernet eth0', session)

    assert engine.commit(session)['results']['ethernet']['success']
    assert plans[-1][1]['eth0'] == {
        'kind': 'ethernet', 'addresses': [], 'dhcp4': False, 'disabled': False,
        'dhcp-options': {'default-route-distance': 210},
        'ip-options': {},
        'attributes': {'mtu': 1500, 'vrf': '', 'link-group': 0},
    }

    controller.execute('set interfaces ethernet eth0 address 192.0.2.1 address 2001:db8::1/64 address dhcp disable', session)

    assert engine.commit(session)['results']['ethernet']['success']

    link = plans[-1][1]['eth0']

    assert link == {
        'kind': 'ethernet', 'addresses': ['192.0.2.1/32', '2001:db8::1/64'],
        'dhcp4': True, 'disabled': True,
        'dhcp-options': {'default-route-distance': 210},
        'ip-options': {},
        'attributes': {'mtu': 1500, 'vrf': '', 'link-group': 0},
    }
    assert lookup(engine.running, ('interfaces', 'ethernet', 'eth0', 'address')) == ['192.0.2.1', '2001:db8::1/64', 'dhcp']

    controller.execute('delete interfaces ethernet eth0', session)

    assert engine.commit(session)['results']['ethernet']['success']
    assert plans[-1][1] == {}
    assert all(owner == 'ethernet' for owner, _ in plans)


def test_recovery_can_keep_profiles_for_temporarily_absent_interfaces(monkeypatch):
    monkeypatch.setattr(interfaces, 'exists', lambda name: False)
    configuration = ethernet.get_config(SimpleNamespace(effective={'interfaces': {'ethernet': {'eth0': {}}}}))
    ethernet.verify(configuration, SimpleNamespace(recovery=True))

    with pytest.raises(RouterError):
        ethernet.verify(configuration, SimpleNamespace(recovery=False))


def test_ethernet_lifecycle_uses_collected_config_and_preserves_vif_definitions(monkeypatch):
    source = {
        'interfaces': {'ethernet': {'eth1': {
            'mtu': '9000', 'address': ['192.0.2.1/24'],
            'vif': {'10': {'address': ['2001:db8::1/64'], 'vrf': 'BLUE', 'link-group': '10'}},
        }}},
        'vrf': {'name': {'BLUE': {'table': '100'}}},
    }
    original = deepcopy(source)
    configuration = ethernet.get_config(SimpleNamespace(effective=ReadOnlyTree(source)))
    stage_context = SimpleNamespace(recovery=False)
    manager = SimpleNamespace(request=Mock(), replace=Mock())
    monkeypatch.setattr(interfaces, 'manager', manager)
    monkeypatch.setattr(interfaces, 'exists', lambda name: name == 'eth1')
    named = Mock()
    monkeypatch.setattr(interfaces, 'require_named', named)

    # Verify must work from collected configuration without invoking another lifecycle stage.
    with monkeypatch.context() as patch:
        patch.setattr(ethernet, 'generate', Mock(side_effect=AssertionError('verify called generate')))
        ethernet.verify(configuration, stage_context)
    named.assert_called_once_with('eth1')
    manager.replace.assert_not_called()

    links = ethernet.generate(configuration, stage_context)
    assert json.loads(json.dumps(links)) == links
    assert links['eth1']['attributes']['mtu'] == 9000
    assert links['eth1.10']['attributes'] == {
        'parent': 'eth1', 'vlan': 10, 'vrf': 'BLUE', 'link-group': 10,
    }
    assert links['eth1.10']['addresses'] == ['2001:db8::1/64']
    manager.request.assert_called_once_with('validate', owner='ethernet', links=links, recovery=False)

    before_apply = deepcopy(links)
    with monkeypatch.context() as patch:
        patch.setattr(ethernet, 'link_definitions', Mock(side_effect=AssertionError('apply formatted links')))
        ethernet.apply(links, stage_context)
    manager.replace.assert_called_once_with('ethernet', links, recovery=False)
    assert links == before_apply
    assert source == original


def test_ethernet_uses_collected_bridge_membership():
    effective = {'interfaces': {
        'ethernet': {'eth1': {'address': ['192.0.2.1/24']}},
        'bridge': {'br0': {'member': {'interface': {'eth1': {}}}}},
    }}
    configuration = ethernet.get_config(SimpleNamespace(effective=effective))

    with pytest.raises(RouterError, match='bridge member cannot have'):
        ethernet.verify(configuration, SimpleNamespace(recovery=False))


def test_compensation_failure_keeps_engine_journal_and_blocks_commits(controller, engine, session, monkeypatch):
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)

    def fail(*args, **kwargs):
        raise RecoveryError('netlinkd rollback failed; restart configd to recover')

    monkeypatch.setattr(interfaces.manager, 'replace', fail)
    controller.execute('set interfaces ethernet eth0 address dhcp', session)

    with pytest.raises(RecoveryError, match='rollback failed'):
        engine.commit(session)

    assert engine.unhealthy and engine.store.read('transaction.json') is not None
    assert engine.running == {} and session.mutations

    with pytest.raises(BusyError, match='recovery'):
        engine.commit(session)
