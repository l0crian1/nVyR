"""Virtual Ethernet configuration and pair ownership contracts."""

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nvyr.config_scripts import interface_virtual_ethernet as virtual_ethernet
from nvyr.errors import ValidationError
from nvyr.helpers import interfaces
from nvyr.helpers.netlink import VirtualEthernet, normalize, virtual_mac
from nvyr.tree import ReadOnlyTree


def test_pair_creation_assigns_stable_addresses_to_both_ends():
    """Explicit addresses prevent udev from changing the captured MAC baseline."""
    calls = []
    kernel = SimpleNamespace(ipr=SimpleNamespace(link=lambda *args, **kwargs: calls.append((args, kwargs))))
    driver = VirtualEthernet()
    driver.create(kernel, {'name': 'veth90', 'attributes': {'peer-name': 'veth91'}})
    first = calls[0][1]

    assert first['address'] == virtual_mac('veth90')
    assert first['peer']['address'] == virtual_mac('veth91')
    assert first['address'] != first['peer']['address']
    assert int(first['address'].split(':')[0], 16) & 3 == 2
    assert int(first['peer']['address'].split(':')[0], 16) & 3 == 2

    # Reversing the initiating endpoint must preserve each interface's identity.
    driver.create(kernel, {'name': 'veth91', 'attributes': {'peer-name': 'veth90'}})
    second = calls[1][1]
    assert second['address'] == first['peer']['address']
    assert second['peer']['address'] == first['address']


def test_pair_commit_check_defaults_and_delete(controller, engine, session, monkeypatch):
    """Both endpoints share one owner and retain independent interface options."""
    applied = []
    monkeypatch.setattr(interfaces.manager, 'replace', lambda *args, **kwargs: applied.append(args))
    controller.execute('set interfaces virtual-ethernet veth0 peer-name veth1 address 192.0.2.0/31 link-group 10', session)
    controller.execute('set interfaces virtual-ethernet veth1 peer-name veth0 address 192.0.2.1/31 disable', session)

    assert engine.check(session)['results']['virtual-ethernet']['success']
    assert applied == []
    assert engine.commit(session)['results']['virtual-ethernet']['success']
    assert len(applied) == 1
    links = applied[0][1]
    assert links['veth0']['attributes'] == {'peer-name': 'veth1', 'mtu': 1500, 'vrf': '', 'link-group': 10}
    assert links['veth1']['disabled']
    assert 'mtu' not in engine.running['interfaces']['virtual-ethernet']['veth0']

    controller.execute('delete interfaces virtual-ethernet veth0', session)
    failed = engine.commit(session)['results']['virtual-ethernet']
    assert not failed['success'] and 'configure virtual-ethernet veth0' in failed['error']
    assert len(applied) == 1

    controller.execute('delete interfaces virtual-ethernet veth1', session)
    assert engine.commit(session)['results']['virtual-ethernet']['success']
    assert applied[-1] == ('virtual-ethernet', {})


@pytest.mark.parametrize('configuration,message', [
    ({'veth0': {}}, 'peer-name is required'),
    ({'veth0': {'peer-name': 'veth0'}}, 'own peer'),
    ({'veth0': {'peer-name': 'veth1'}}, 'configure virtual-ethernet veth1'),
    ({'veth0': {'peer-name': 'veth1'}, 'veth1': {'peer-name': 'veth2'}}, 'configure virtual-ethernet veth1'),
])
def test_pair_validation(configuration, message):
    """Incomplete or inconsistent pairs fail before contacting the daemon."""
    context = SimpleNamespace(effective={'interfaces': {'virtual-ethernet': configuration}},
                              previous={}, recovery=False)
    with pytest.raises(ValidationError, match=message):
        virtual_ethernet.verify(virtual_ethernet.get_config(context), context)


def test_pair_lifecycle_uses_collected_configuration(monkeypatch):
    endpoints = {
        'veth0': {'peer-name': 'veth1', 'mtu': '9000',
                  'vif': {'10': {'address': ['2001:db8::1/64'], 'vrf': 'BLUE'}}},
        'veth1': {'peer-name': 'veth0', 'address': ['192.0.2.1/24'], 'vrf': 'BLUE'},
    }
    source = {'interfaces': {'virtual-ethernet': endpoints},
              'vrf': {'name': {'BLUE': {'table': '100'}}}}
    previous = {'interfaces': {'virtual-ethernet': {
        'veth0': {'peer-name': 'veth1'}, 'veth1': {'peer-name': 'veth0'},
    }}}
    original = deepcopy(source)
    prior = deepcopy(previous)
    context = SimpleNamespace(effective=ReadOnlyTree(source), previous=ReadOnlyTree(previous))
    configuration = virtual_ethernet.get_config(context)
    stage_context = SimpleNamespace(recovery=True)
    manager = SimpleNamespace(request=Mock(), replace=Mock())
    monkeypatch.setattr(interfaces, 'manager', manager)

    with monkeypatch.context() as patch:
        patch.setattr(virtual_ethernet, 'generate', Mock(side_effect=AssertionError('verify called generate')))
        virtual_ethernet.verify(configuration, stage_context)
    manager.replace.assert_not_called()

    links = virtual_ethernet.generate(configuration, stage_context)
    assert json.loads(json.dumps(links)) == links
    assert links['veth0']['attributes']['peer-name'] == 'veth1'
    assert links['veth1']['attributes']['peer-name'] == 'veth0'
    assert links['veth0.10']['attributes'] == {
        'parent': 'veth0', 'vlan': 10, 'vrf': 'BLUE', 'link-group': 0,
    }
    assert links['veth0.10']['addresses'] == ['2001:db8::1/64']
    manager.request.assert_called_once_with('validate', owner='virtual-ethernet', links=links, recovery=True)

    before_apply = deepcopy(links)
    with monkeypatch.context() as patch:
        patch.setattr(virtual_ethernet, 'link_definitions', Mock(side_effect=AssertionError('apply formatted links')))
        virtual_ethernet.apply(links, stage_context)
    manager.replace.assert_called_once_with('virtual-ethernet', links, recovery=True)
    assert links == before_apply
    assert source == original
    assert previous == prior


def test_peer_change_uses_collected_previous_configuration():
    context = SimpleNamespace(
        effective={'interfaces': {'virtual-ethernet': {
            'veth0': {'peer-name': 'veth2'}, 'veth2': {'peer-name': 'veth0'},
        }}},
        previous={'interfaces': {'virtual-ethernet': {'veth0': {'peer-name': 'veth1'}}}},
    )
    configuration = virtual_ethernet.get_config(context)

    with pytest.raises(ValidationError, match='delete and commit the pair'):
        virtual_ethernet.verify(configuration, SimpleNamespace(recovery=False))


def test_pair_uses_collected_bridge_membership():
    context = SimpleNamespace(effective={'interfaces': {
        'virtual-ethernet': {
            'veth0': {'peer-name': 'veth1', 'address': ['192.0.2.1/24']},
            'veth1': {'peer-name': 'veth0'},
        },
        'bridge': {'br0': {'member': {'interface': {'veth0': {}}}}},
    }}, previous={})
    configuration = virtual_ethernet.get_config(context)

    with pytest.raises(ValidationError, match='bridge member cannot have'):
        virtual_ethernet.verify(configuration, SimpleNamespace(recovery=False))


def test_peer_change_requires_committed_deletion(controller, engine, session):
    """Replacing the peer cannot silently destroy a retained endpoint."""
    controller.execute('set interfaces virtual-ethernet veth0 peer-name veth1', session)
    controller.execute('set interfaces virtual-ethernet veth1 peer-name veth0', session)
    assert engine.commit(session)['results']['virtual-ethernet']['success']

    controller.execute('delete interfaces virtual-ethernet veth1', session)
    controller.execute('set interfaces virtual-ethernet veth0 peer-name veth2', session)
    controller.execute('set interfaces virtual-ethernet veth2 peer-name veth0', session)
    result = engine.commit(session)['results']['virtual-ethernet']
    assert not result['success'] and 'delete and commit the pair' in result['error']


def test_vrf_reapply_and_reference_protection(controller, engine, session):
    """Membership watches and deletion guards also recognize veth endpoints."""
    controller.execute('set vrf name BLUE table 100', session)
    controller.execute('set interfaces virtual-ethernet veth0 peer-name veth1', session)
    controller.execute('set interfaces virtual-ethernet veth1 peer-name veth0', session)
    controller.execute('set firewall ipv4 input filter rule 10 inbound-interface veth0 action accept', session)
    assert all(item['success'] for item in engine.commit(session)['results'].values())

    controller.execute('set interfaces virtual-ethernet veth0 vrf BLUE', session)
    result = engine.commit(session)
    assert list(result['results']) == ['vrf_conntrack', 'virtual-ethernet', 'firewall']
    assert all(item['success'] for item in result['results'].values())

    with pytest.raises(ValidationError, match='referenced'):
        controller.execute('delete interfaces virtual-ethernet veth0', session)


def test_daemon_normalization_rejects_incomplete_pairs():
    """Direct daemon clients must obey the same pair requirements as configd."""
    with pytest.raises(ValidationError, match='configure virtual-ethernet'):
        normalize({'veth0': {'kind': 'virtual-ethernet', 'attributes': {'peer-name': 'veth1'}}})


def test_peer_completion_and_invalid_names(controller, session):
    """Peer suggestions use the candidate and names obey Linux's length limit."""
    controller.execute('set interfaces virtual-ethernet veth1 peer-name veth0', session)
    result = controller.completion('set interfaces virtual-ethernet veth0 peer-name ', session, explicit=True)
    assert 'veth1' in dict(result['candidates'])

    with pytest.raises(ValidationError):
        controller.execute('set interfaces virtual-ethernet veth123456789012 peer-name veth0', session)
