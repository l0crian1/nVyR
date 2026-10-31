"""Unicast schema and verification boundaries, separate from native daemon readback."""

from copy import deepcopy

import pytest

from nvyr.config_scripts import protocols_bgp as bgp
from nvyr.errors import RouterError, ValidationError
from tests.bgp_config import verify_bgp
from tests.test_bgp import context


def verify_peer(peer):
    verify_bgp({'default': {'local-as': '65000', 'neighbor': {'192.0.2.2': peer}}}, context())


def test_nested_local_as_terminal_path(controller, engine, session):
    controller.execute('set protocols bgp local-as 65000', session)
    controller.execute('set protocols bgp neighbor 192.0.2.2 remote-as external local-as number 65100', session)
    controller.execute('set protocols bgp neighbor 192.0.2.2 local-as no-prepend replace-as dual-as', session)
    result = engine.commit(session)
    assert result['results']['bgp']['success']
    rendered = bgp.generate({'instances': {'default': engine.running['protocols']['bgp']}}, None)['default'][0]
    assert 'neighbor 192.0.2.2 local-as 65100 no-prepend replace-as dual-as' in rendered


def test_local_as_modifiers_cannot_skip_parents(controller, session):
    with pytest.raises(RouterError):
        controller.execute('set protocols bgp neighbor 192.0.2.2 local-as replace-as', session)
    with pytest.raises(RouterError):
        controller.execute('set protocols bgp neighbor 192.0.2.2 local-as no-prepend dual-as', session)


def test_link_local_scope_is_required():
    configuration = {'default': {'local-as': '65000', 'neighbor': {'fe80::2': {'remote-as': '65001'}}}}
    with pytest.raises(ValidationError, match='requires interface'):
        verify_bgp(configuration, context())
    configuration['default']['neighbor']['fe80::2']['interface'] = 'eth1'
    verify_bgp(configuration, context())


def test_unnumbered_peer_identity():
    configuration = {'default': {'local-as': '65000', 'neighbor': {
        'eth1': {'remote-as': 'external', 'ipv6-only': {}, 'address-family': {'ipv6-unicast': {}}}}}}
    verify_bgp(configuration, context())
    assert 'neighbor eth1 interface v6only remote-as external' in bgp.generate({'instances': configuration}, None)['default'][0]


@pytest.mark.parametrize('peer, message', [
    ({'remote-as': '65001', 'local-as': {'no-prepend': {}}}, 'requires number'),
    ({'remote-as': 'internal', 'local-as': {'number': '65100'}}, 'external neighbor'),
    ({'remote-as': 'external', 'local-as': {'number': '65000'}}, 'must differ'),
    ({'remote-as': 'external', 'ipv6-only': {}}, 'interface neighbor'),
    ({'remote-as': 'external', 'role': {'strict': {}}}, 'requires type'),
    ({'remote-as': 'internal', 'role': {'type': 'peer'}}, 'external neighbor'),
    ({'remote-as': 'external', 'capability': {'strict-match': {}, 'override': {}}}, 'mutually exclusive'),
    ({'remote-as': 'external', 'capability': {'disable-negotiation': {}, 'dynamic': {}}}, 'cannot be combined'),
])
def test_peer_rejections(peer, message):
    with pytest.raises(ValidationError, match=message):
        verify_peer(peer)


@pytest.mark.parametrize('settings, message', [
    ({'disable': {}, 'weight': '20'}, 'cannot be combined'),
    ({'allowas-in': {}}, 'exactly one'),
    ({'allowas-in': {'count': '2', 'origin': {}}}, 'exactly one'),
    ({'remove-private-as': {'all': {}, 'replace': {}}}, 'all replace'),
    ({'soft-reconfiguration': {}}, 'requires inbound'),
    ({'maximum-prefix': {'threshold': '90'}}, 'requires limit'),
    ({'maximum-prefix': {'limit': '10', 'force': {}}}, 'requires soft-reconfiguration'),
    ({'maximum-prefix': {'limit': '10', 'restart': '1', 'warning-only': {}}}, 'mutually exclusive'),
    ({'conditional-advertisement': {'advertise-map': 'P'}}, 'exactly one'),
    ({'conditional-advertisement': {'advertise-map': 'P', 'exist-map': 'P', 'non-exist-map': 'P'}}, 'exactly one'),
    ({'addpath': {'transmit': {}}}, 'exactly one'),
    ({'addpath': {'transmit': {'all': {}, 'best-selected': '2'}}}, 'exactly one'),
    ({'addpath': {'disable-receive': {}, 'receive-limit': '4'}}, 'mutually exclusive'),
    ({'attribute-unchanged': {}}, 'requires as-path'),
    ({'as-path-list': {'import': 'MISSING'}}, 'not configured'),
    ({'unsuppress-map': 'MISSING'}, 'not configured'),
])
def test_family_rejections(settings, message):
    with pytest.raises(ValidationError, match=message):
        verify_peer({'remote-as': 'external', 'address-family': {'ipv4-unicast': settings}})


def test_deactivation_replaces_inherited_family_settings():
    group = {'remote-as': 'external', 'address-family': {'ipv4-unicast': {'weight': '100'}}}
    peer = {'address-family': {'ipv4-unicast': {'disable': {}}}}
    original = deepcopy(group)
    merged = bgp.inherited(group, peer)
    assert merged['address-family']['ipv4-unicast'] == {'disable': {}}
    assert group == original


def test_deactivation_does_not_hide_conflicting_member_settings():
    group = {'remote-as': 'external', 'address-family': {'ipv4-unicast': {'weight': '100'}}}
    peer = {'peer-group': 'PEERS', 'address-family': {'ipv4-unicast': {'disable': {}, 'weight': '200'}}}
    configuration = {'default': {'local-as': '65000', 'peer-group': {'PEERS': group},
                                 'neighbor': {'192.0.2.2': peer}}}

    with pytest.raises(ValidationError, match='disable cannot be combined'):
        verify_bgp(configuration, context())


def test_new_policy_dependencies(controller, engine, session):
    controller.execute('set policy as-path-list ASIMPORT rule 10 action permit regex ".*"', session)
    controller.execute('set protocols bgp local-as 65000 neighbor 192.0.2.2 remote-as 65001', session)
    controller.execute('set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast as-path-list import ASIMPORT', session)
    assert engine.commit(session)['results']['bgp']['success']
    with pytest.raises(ValidationError, match='referenc'):
        controller.execute('delete policy as-path-list ASIMPORT', session)
