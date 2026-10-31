"""BGP schema, verification, ownership and rollback contracts."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import protocols_bgp as bgp
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import frr_bgp, frr_reload, validators
from tests.bgp_config import verify_bgp
from tests.test_frr_reload import Backend


def context(policies=None):
    return SimpleNamespace(effective={'policy': policies or {}}, check_only=True, report=lambda message: None)


def test_default_and_vrf_share_one_apply(controller, engine, session, monkeypatch):
    calls = []
    monkeypatch.setattr(frr_reload, 'manager', SimpleNamespace(apply=lambda *args, **kwargs: calls.append(args)))
    controller.execute('set protocols bgp local-as 65000 parameters router-id 192.0.2.1', session)
    controller.execute('set protocols bgp neighbor 192.0.2.2 remote-as 65000 address-family ipv4-unicast', session)
    controller.execute('set vrf name BLUE table 101', session)
    controller.execute('set vrf name BLUE protocols bgp local-as 65001 parameters router-id 192.0.2.10', session)
    controller.execute('set vrf name BLUE protocols bgp neighbor 2001:db8::2 remote-as 65001 address-family ipv6-unicast', session)
    result = engine.commit(session)

    assert result['results']['bgp']['success']
    assert len(calls) == 1
    assert set(calls[0][1]) == {'default', 'BLUE'}
    assert 'address-family ipv6 unicast' in calls[0][1]['BLUE'][0]
    assert 'no neighbor 2001:db8::2 activate' in calls[0][1]['BLUE'][0]

    calls.clear()
    controller.execute('delete vrf name BLUE', session)
    result = engine.commit(session)
    assert result['results']['bgp']['success']
    assert len(calls) == 1 and set(calls[0][1]) == {'default'}


def test_update_source_and_policy_dependencies(controller, session):
    controller.execute('set interfaces dummy dum9', session)
    controller.execute('set policy route-map IMPORT rule 10 action permit', session)
    controller.execute('set protocols bgp local-as 65000', session)
    controller.execute('set protocols bgp neighbor 192.0.2.2 remote-as 65001 update-source dum9', session)
    controller.execute('set protocols bgp neighbor 192.0.2.2 address-family ipv4-unicast route-map import IMPORT export IMPORT', session)
    with pytest.raises(RouterError, match='referenc'):
        controller.execute('delete interfaces dummy dum9', session)
    with pytest.raises(RouterError, match='referenc'):
        controller.execute('delete policy route-map IMPORT', session)


@pytest.mark.parametrize('family', ['ipv4-unicast', 'ipv6-unicast'])
@pytest.mark.parametrize('vrf', ['default', 'BLUE'])
@pytest.mark.parametrize('peer', ['neighbor 192.0.2.2', 'peer-group TRANSIT'])
def test_route_map_directions_render_native_frr(controller, engine, session, monkeypatch, family, vrf, peer):
    """Both CLI directions retain their meaning across peers, families and routing instances."""
    calls = []
    monkeypatch.setattr(frr_reload, 'manager', SimpleNamespace(apply=lambda *args, **kwargs: calls.append(args)))
    controller.execute('set policy route-map IMPORT rule 10 action permit', session)
    controller.execute('set policy route-map EXPORT rule 10 action permit', session)
    root = 'protocols bgp'
    if vrf != 'default':
        controller.execute('set vrf name BLUE table 101', session)
        root = 'vrf name BLUE protocols bgp'
    controller.execute(f'set {root} local-as 65000 parameters ebgp-requires-policy enable', session)
    controller.execute(f'set {root} {peer} remote-as 65001', session)
    if peer.startswith('peer-group'):
        controller.execute(f'set {root} neighbor 192.0.2.2 peer-group TRANSIT', session)

    path = f'{root} {peer} address-family {family} route-map'
    choices = dict(controller.completion(f'set {path} ', session, explicit=True)['candidates'])
    assert {'import', 'export'} <= choices.keys()
    assert not {'in', 'out'} & choices.keys()
    controller.execute(f'set {path} import IMPORT export EXPORT', session)
    result = engine.commit(session)

    assert result['results']['bgp']['success']
    native = calls[-1][1][vrf][0]
    name = peer.split()[1]
    assert f'neighbor {name} route-map IMPORT in' in native
    assert f'neighbor {name} route-map EXPORT out' in native


@pytest.mark.parametrize('configured, missing', [('import', 'export'), ('export', 'import')])
def test_route_map_policy_enforcement_checks_each_direction(configured, missing):
    """A route-map in one direction cannot satisfy opt-in policy enforcement for the other."""
    settings = {'route-map': {configured: 'POLICY'}}
    instance = {
        'local-as': '65000',
        'parameters': {'ebgp-requires-policy': 'enable'},
        'neighbor': {'192.0.2.2': {
            'remote-as': '65001', 'address-family': {'ipv4-unicast': settings},
        }},
    }
    with pytest.raises(ValidationError, match=f'explicit {missing} policy'):
        verify_bgp({'default': instance}, context({'route-map': {'POLICY': {}}}))


@pytest.mark.parametrize('command', [
    'set protocols bgp local-as 0',
    'set protocols bgp local-as 4294967296',
    'set protocols bgp parameters router-id 0.0.0.0',
    'set protocols bgp parameters router-id 224.0.0.1',
    'set protocols bgp neighbor 224.0.0.1 remote-as 65000',
    'set protocols bgp neighbor fe80::1%eth0 remote-as 65000',
    'set protocols bgp neighbor 192.0.2.2 update-source "lo\nend"',
    'set protocols bgp neighbor 192.0.2.2 ttl-security hops 255',
    'set protocols bgp neighbor 192.0.2.2 timers connect 0',
    'set protocols bgp neighbor 192.0.2.2 address-family ipv6-unicast send-community all',
    'set protocols bgp address-family ipv6-unicast network 192.0.2.0/24',
    'set protocols bgp address-family ipv4-unicast maximum-paths ebgp 257',
])
def test_schema_rejects_invalid_values(controller, session, command):
    with pytest.raises(RouterError):
        controller.execute(command, session)


@pytest.mark.parametrize('command', [
    'set protocols bgp parameters timers holdtime 1',
    'set protocols bgp parameters timers holdtime 2',
    'set protocols bgp neighbor 192.0.2.2 timers holdtime 1',
    'set protocols bgp peer-group PEERS timers holdtime 2',
    'set vrf name BLUE protocols bgp parameters timers holdtime 1',
    'set protocols bgp parameters minimum-holdtime 180',
    'set vrf name BLUE protocols bgp parameters minimum-holdtime 180',
    'set protocols bgp neighbor 192.0.2.2 password " leading"',
    'set protocols bgp peer-group PEERS password "trailing "',
    'set vrf name BLUE protocols bgp neighbor 192.0.2.2 password "two  spaces"',
])
def test_standalone_restrictions_fail_at_entry(controller, session, command):
    with pytest.raises(ValidationError):
        controller.execute(command, session)

    assert not session.mutations


@pytest.mark.parametrize('settings', [
    {'parameters': {'timers': {'holdtime': '2'}}},
    {'parameters': {'minimum-holdtime': '180'}},
    {'neighbor': {'192.0.2.2': {'remote-as': '65001', 'password': 'two  spaces'}}},
])
def test_loaded_configuration_checks_standalone_restrictions(settings):
    from nvyr.schema import Schema

    with pytest.raises(ValidationError):
        Schema.bundled().validate_configuration({'protocols': {'bgp': {'local-as': '65000', **settings}}})


def test_allowed_timer_boundaries_and_password_spacing(controller, session):
    controller.execute('set protocols bgp parameters timers holdtime 0', session)
    controller.execute('set protocols bgp neighbor 192.0.2.2 timers holdtime 3', session)
    controller.execute('set protocols bgp peer-group PEERS timers holdtime 65535', session)
    controller.execute('set protocols bgp parameters minimum-holdtime 179', session)
    controller.execute('set protocols bgp parameters minimum-holdtime 181', session)
    controller.execute('set protocols bgp neighbor 192.0.2.2 password "two words"', session)


@pytest.mark.parametrize('options, message', [
    ({}, 'remote-as is required'),
    ({'remote-as': '65000', 'ebgp-multihop': '2'}, 'external neighbor'),
    ({'remote-as': '65001', 'ebgp-multihop': '2', 'ttl-security': {'hops': '1'}}, 'mutually exclusive'),
    ({'remote-as': '65001', 'ttl-security': {}}, 'requires hops'),
    ({'remote-as': '65000', 'timers': {'keepalive': '60', 'holdtime': '90'}}, 'one third'),
    ({'remote-as': '65000', 'timers': {'keepalive': '0', 'holdtime': '90'}}, 'one third'),
    ({'remote-as': '65000', 'update-source': '2001:db8::1'}, 'address family'),
    ({'remote-as': '65001', 'address-family': {'ipv4-unicast': {}}}, 'explicit import policy'),
    ({'peer-group': 'MISSING'}, 'not configured'),
    ({'remote-as': '65001', 'shutdown': {}, 'address-family': {'ipv4-unicast': {'route-reflector-client': {}}}}, 'internal neighbor'),
])
def test_peer_verification(options, message):
    with pytest.raises(ValidationError, match=message):
        verify_bgp({'default': {'local-as': '65000', 'parameters': {'ebgp-requires-policy': 'enable'}, 'neighbor': {'192.0.2.2': options}}}, context())


def test_peer_group_inheritance_and_scoping():
    group = {'remote-as': '65001', 'update-source': '192.0.2.1', 'address-family': {
        'ipv4-unicast': {'route-map': {'import': 'POLICY', 'export': 'POLICY'}}}}
    instance = {'local-as': '65000', 'peer-group': {'TRANSIT': group},
                'neighbor': {'192.0.2.2': {'peer-group': 'TRANSIT'}}}
    before = deepcopy(instance)
    policies = {'route-map': {'POLICY': {'rule': {'10': {'action': 'permit'}}}}}
    verify_bgp({'default': instance}, context(policies))
    assert instance == before

    with pytest.raises(ValidationError, match='not configured'):
        verify_bgp({'default': instance, 'BLUE': {'local-as': '65000', 'neighbor': {
            '192.0.2.2': {'peer-group': 'TRANSIT'}}}}, context(policies))

    instance['neighbor']['192.0.2.2']['remote-as'] = '65002'
    with pytest.raises(ValidationError, match='conflicts'):
        verify_bgp({'default': instance}, context(policies))


def test_peer_group_community_override_rejected():
    instance = {'local-as': '65000', 'peer-group': {'INTERNAL': {
        'remote-as': '65000', 'address-family': {'ipv4-unicast': {'send-community': ['standard']}}}},
        'neighbor': {'192.0.2.2': {'peer-group': 'INTERNAL', 'address-family': {
            'ipv4-unicast': {'send-community': ['extended']}}}}}
    with pytest.raises(ValidationError, match='cannot override'):
        verify_bgp({'default': instance}, context())

    instance['peer-group']['INTERNAL']['address-family']['ipv4-unicast']['send-community'] = ['standard', 'extended']
    verify_bgp({'default': instance}, context())


def test_password_whitespace_is_not_silently_changed(controller, session):
    with pytest.raises(ValidationError, match='whitespace'):
        controller.execute('set protocols bgp neighbor 192.0.2.2 password "two  spaces"', session)

    assert not session.mutations


def test_neighbor_timers_inherit_the_peer_group_before_instance():
    instance = {'local-as': '65000', 'parameters': {'timers': {'keepalive': '30', 'holdtime': '90'}},
                'peer-group': {'INTERNAL': {'remote-as': '65000', 'timers': {'keepalive': '10', 'holdtime': '30'}}},
                'neighbor': {'192.0.2.2': {'peer-group': 'INTERNAL', 'timers': {'keepalive': '5'}}}}
    verify_bgp({'default': instance}, context())
    assert 'neighbor 192.0.2.2 timers 5 30' in bgp.generate({'instances': {'default': instance}}, None)['default'][0]


def test_missing_local_as_and_duplicate_neighbors():
    with pytest.raises(ValidationError, match='local-as'):
        verify_bgp({'default': {}}, context())
    with pytest.raises(ValidationError, match='duplicate'):
        verify_bgp({'default': {'local-as': '65000', 'neighbor': {
            '2001:db8::1': {'remote-as': '65000'},
            '2001:db8:0::1': {'remote-as': '65000'}}}}, context())


def test_all_policy_references_are_checked():
    with pytest.raises(ValidationError, match='MISSING'):
        verify_bgp({'default': {'local-as': '65000', 'address-family': {
            'ipv6-unicast': {'network': {'2001:db8::/32': {'route-map': 'MISSING'}}}}}}, context())
    settings = {'access-list': {'in': 'A'}, 'prefix-list': {'in': 'P'}}
    with pytest.raises(ValidationError, match='mutually exclusive'):
        verify_bgp({'default': {'local-as': '65000', 'neighbor': {'192.0.2.2': {
            'remote-as': '65000', 'address-family': {'ipv4-unicast': settings}}}}}, context())


def test_source_accepts_interface_or_address():
    assert validators.bgp_update_source('eth0.10')
    assert validators.bgp_update_source('192.0.2.1')
    assert validators.bgp_update_source('2001:db8::1')
    assert not validators.bgp_update_source('300.0.0.1')
    assert not validators.bgp_update_source('lo;end')


def test_adapter_preserves_static_policy_and_other_vrf():
    before = ('ip route 192.0.2.0/24 blackhole\nroute-map KEEP permit 10\n set metric 1\nexit\n'
              'router bgp 65002 vrf KEEP\n bgp router-id 192.0.2.2\nexit\nend\n')
    desired = bgp.generate({'instances': {'default': {'local-as': '65000'}}}, None)
    result = frr_bgp.adapter.replace(before, desired)
    assert before.replace('end\n', '') in result
    assert frr_bgp.adapter.select(result, desired) == desired


def test_bgp_rollback_and_restart_recovery(tmp_path):
    manager = Backend(tmp_path / 'stage')
    desired = bgp.generate({'instances': {'default': {'local-as': '65000'}}}, None)
    manager.apply('bgp', desired, tmp_path, adapter=frr_bgp.adapter)
    manager.failures = 1
    changed = bgp.generate({'instances': {'default': {'local-as': '65001'}}}, None)
    with pytest.raises(RouterError, match='previous configuration restored'):
        manager.apply('bgp', changed, tmp_path, adapter=frr_bgp.adapter)
    assert frr_bgp.adapter.select(manager.running, desired) == desired

    manager.crash = True
    with pytest.raises(SystemExit):
        manager.apply('bgp', changed, tmp_path, adapter=frr_bgp.adapter)
    manager.crash = False
    manager.apply('bgp', desired, tmp_path, adapter=frr_bgp.adapter, recovery=True)
    assert frr_bgp.adapter.select(manager.running, desired) == desired
