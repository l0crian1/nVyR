"""Loopback schema, driver safety and configuration-script contracts."""

from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from nvyr.config_scripts import interface_loopback
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import interfaces
from nvyr.helpers.netlink import Loopback, normalize
from nvyr.helpers.reapply_schema import validate_reapply
from nvyr.tree import ReadOnlyTree


def test_loopback_anchor_and_allowed_settings(controller, session):
    controller.execute('set interfaces loopback lo address 192.0.2.1/32 description "Router identity"', session)
    controller.execute('set interfaces loopback lo address 2001:db8::1/128', session)
    choices = dict(controller.completion('set interfaces loopback lo ', session, explicit=True)['candidates'])
    assert {'address', 'description'} <= choices.keys()
    assert not {'disable', 'mtu', 'mac', 'vrf', 'vif', 'dhcp-options'} & choices.keys()


@pytest.mark.parametrize('suffix', ['lo1', 'eth0', 'lo address dhcp', 'lo disable',
                                  'lo mtu 1500', 'lo vrf BLUE', 'lo address invalid'])
def test_loopback_rejects_unsupported_configuration(controller, session, suffix):
    with pytest.raises(RouterError):
        controller.execute('set interfaces loopback ' + suffix, session)


def test_loopback_verify_and_apply_use_same_definitions(monkeypatch):
    calls = []
    context = SimpleNamespace(recovery=False)
    source = {'interfaces': {'loopback': {
        'lo': {'address': ['192.0.2.1/32'], 'description': 'Router identity'},
    }}}
    original = deepcopy(source)
    configuration = interface_loopback.get_config(SimpleNamespace(effective=ReadOnlyTree(source)))
    monkeypatch.setattr(interfaces, 'manager', interfaces.NetlinkManager())
    monkeypatch.setattr(interfaces.manager, 'request', lambda op, **args: calls.append((op, args)))

    with monkeypatch.context() as patch:
        patch.setattr(interface_loopback, 'generate', Mock(side_effect=AssertionError('verify called generate')))
        interface_loopback.verify(configuration, context)
    assert [operation for operation, arguments in calls] == ['validate']

    generated = interface_loopback.generate(configuration, context)
    before_apply = deepcopy(generated)
    with monkeypatch.context() as patch:
        patch.setattr(interface_loopback, 'link_definitions', Mock(side_effect=AssertionError('apply formatted links')))
        interface_loopback.apply(generated, context)

    assert [operation for operation, arguments in calls] == ['validate', 'replace']
    assert normalize(calls[0][1]['links']) == normalize(calls[1][1]['links'])
    assert generated['lo']['attributes'] == {'description': 'Router identity'}
    assert generated['lo']['addresses'] == ['192.0.2.1/32']
    assert json.loads(json.dumps(generated)) == generated
    assert generated == before_apply
    assert source == original


@pytest.mark.parametrize('definition', [
    {'kind': 'loopback', 'disabled': True},
    {'kind': 'loopback', 'dhcp4': True},
    {'kind': 'loopback', 'attributes': {'vrf': 'BLUE'}},
    {'kind': 'loopback', 'addresses': ['127.0.0.1/32']},
    {'kind': 'loopback', 'addresses': ['::1/64']},
])
def test_driver_rejects_dangerous_loopback_settings(definition):
    with pytest.raises(ValidationError):
        normalize({'lo': definition})


def test_driver_rejects_other_names_and_device_types():
    with pytest.raises(ValidationError, match='named lo'):
        normalize({'lo1': {'kind': 'loopback'}})
    assert Loopback().matches({'message': {'ifi_type': 772}})
    assert not Loopback().matches({'message': {'ifi_type': 1}})


def test_system_addresses_are_retained_and_deduplicated():
    specification = normalize({'lo': {'kind': 'loopback', 'addresses': ['127.0.0.1/8', '192.0.2.1/32']}})['lo']
    assert Loopback().addresses(specification) == ['127.0.0.1/8', '::1/128', '192.0.2.1/32']


def test_watches_allow_interface_types_without_vrf():
    """A heterogeneous provider family can watch fields absent from loopback."""
    root = {'children': {
        'ethernet': {'dependency': 'interface', 'children': {'vrf': {'kind': 'leaf_node'}}},
        'loopback': {'dependency': 'interface', 'children': {'address': {'kind': 'leaf_node'}}},
        'consumer': {'kind': 'leaf_node', 'script': {'name': 'firewall'},
                     'depends': 'interface', 'reapply-on-change': ['vrf']},
    }}
    validate_reapply(root)

    root['children']['consumer']['reapply-on-change'] = ['misspelled-vrf']
    with pytest.raises(ValueError, match='unknown reapply-on-change'):
        validate_reapply(root)


def test_loopback_reference_does_not_trigger_vrf_reapply(controller, session, engine):
    """An alias change on lo cannot affect a consumer watching VRF membership."""
    controller.execute('set interfaces loopback lo', session)
    controller.execute('set firewall ipv4 input filter rule 10 inbound-interface lo action accept', session)
    result = engine.commit(session)
    assert all(item['success'] for item in result['results'].values())

    controller.execute('set interfaces loopback lo description "Router identity"', session)
    assert set(engine.commit(session)['results']) == {'loopback'}

    with pytest.raises(ValidationError, match='referenced'):
        controller.execute('delete interfaces loopback lo', session)
