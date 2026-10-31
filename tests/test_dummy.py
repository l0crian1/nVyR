"""Dummy lifecycle boundaries, collected dependencies and read-only native preflight."""

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nvyr.config_scripts import interface_dummy as dummy
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import dhcp_options, interface_ip, interfaces
from nvyr.tree import ReadOnlyTree


def context(values):
    return SimpleNamespace(effective={'interfaces': {'dummy': values}}, recovery=False)


def test_dummy_verify_uses_daemon_ownership_validation(monkeypatch):
    request = Mock(side_effect=RouterError('dum0 is owned by another owner'))
    monkeypatch.setattr(interfaces.manager, 'request', request)
    run = context({'dum0': {}})

    with pytest.raises(RouterError, match='owned by another'):
        dummy.verify(dummy.get_config(run), run)
    assert request.call_args.args == ('validate',)
    assert request.call_args.kwargs['owner'] == 'dummy'


def test_dummy_lifecycle_separates_verification_formatting_and_application(monkeypatch):
    run = context({'dum0': {
        'address': ['192.0.2.1/24', '2001:db8::1/64'], 'vrf': 'BLUE',
        'ip': {'arp-ignore': '2'},
        'ipv6': {'eui64': ['2001:db8:1::/64'], 'duplicate-address-detection': {'probes': '2'}},
        'dhcp-options': {'client-id': {'text': 'dummy-client'}, 'default-route-distance': '210'},
    }})
    run.effective['vrf'] = {'name': {'BLUE': {'table': '100'}}}
    source = run.effective
    original = deepcopy(source)
    run.effective = ReadOnlyTree(source)
    configuration = dummy.get_config(run)
    stage_context = SimpleNamespace(recovery=True)
    manager = SimpleNamespace(request=Mock(), replace=Mock())
    monkeypatch.setattr(interfaces, 'manager', manager)

    with monkeypatch.context() as patch:
        patch.setattr(dummy, 'generate', Mock(side_effect=AssertionError('verify called generate')))
        dummy.verify(configuration, stage_context)
    manager.replace.assert_not_called()

    with monkeypatch.context() as patch:
        patch.setattr(dhcp_options, 'verify', Mock(side_effect=AssertionError('generate verified DHCP')))
        patch.setattr(interface_ip, 'verify', Mock(side_effect=AssertionError('generate verified IP')))
        links = dummy.generate(configuration, stage_context)
    assert json.loads(json.dumps(links)) == links
    assert links['dum0']['attributes']['vrf'] == 'BLUE'
    assert links['dum0']['addresses'] == ['192.0.2.1/24', '2001:db8::1/64']
    assert links['dum0']['dhcp-options']['default-route-distance'] == 210
    manager.request.assert_called_once_with('validate', owner='dummy', links=links, recovery=True)

    before_apply = deepcopy(links)
    with monkeypatch.context() as patch:
        patch.setattr(dummy, 'link_definitions', Mock(side_effect=AssertionError('apply formatted links')))
        dummy.apply(links, stage_context)
    manager.replace.assert_called_once_with('dummy', links, recovery=True)
    assert links == before_apply
    assert source == original


@pytest.mark.parametrize(('values', 'message'), [
    ({'vrf': 'MISSING'}, 'VRF.*not configured'),
    ({'ipv6': {'no-ra-mtu': True}}, 'RA options require'),
    ({'ipv6': {'disable': True}, 'address': ['2001:db8::1/64']}, 'conflicts'),
    ({'ipv6': {'duplicate-address-detection': {'disable': True, 'probes': '2'}}}, 'conflicts'),
    ({'dhcp-options': {'client-id': {'text': 'a', 'hex': '00:01'}}}, 'exactly one'),
    ({'dhcp-options': {'host-name': 'edge', 'user-class': 'x' * 150,
                      'vendor-class-id': 'y' * 150}}, 'maximum 240'),
])
def test_dummy_rejects_relationship_errors_before_native_request(monkeypatch, values, message):
    run = context({'dum0': values})
    request = Mock()
    monkeypatch.setattr(interfaces.manager, 'request', request)

    with pytest.raises(ValidationError, match=message):
        dummy.verify(dummy.get_config(run), run)
    request.assert_not_called()


def test_dummy_collects_bridge_membership_for_verification():
    run = context({'dum0': {'ip': {'arp-ignore': '2'}}})
    run.effective['interfaces']['bridge'] = {'br0': {'member': {'interface': {'dum0': {}}}}}
    configuration = dummy.get_config(run)

    with pytest.raises(ValidationError, match='bridge member cannot have'):
        dummy.verify(configuration, SimpleNamespace(recovery=False))


def test_dummy_removal_submits_empty_owner(monkeypatch):
    run = context({})
    replace = Mock()
    monkeypatch.setattr(interfaces.manager, 'replace', replace)

    dummy.apply(dummy.generate(dummy.get_config(run), run), run)
    replace.assert_called_once_with('dummy', {}, recovery=False)
