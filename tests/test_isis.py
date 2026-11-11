"""IS-IS schema, ownership, verification and operational command contracts."""

from types import SimpleNamespace

import pytest

from nvyr.config_scripts import protocols_isis
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import frr_isis, frr_reload
from nvyr.helpers.validators import isis_net
from nvyr.op_scripts import isis


@pytest.mark.parametrize('value,valid', [
    ('49.0001.0000.0000.0001.00', True), ('49.0000.0000.0001.00', True),
    ('49.0001.0000.0000.0001.01', False), ('49.0000.0001.00', False),
    ('49.0001.GGGG.0000.0001.00', False), ('49.0001.0000.0000.0001.00\n', False),
])
def test_net_validation(value, valid):
    assert isis_net(value) is valid


def test_global_and_vrf_lifecycle(controller, engine, session, monkeypatch):
    calls = []
    monkeypatch.setattr(frr_reload, 'manager', SimpleNamespace(apply=lambda *args, **kwargs: calls.append(args)))
    controller.execute('set protocols isis net 49.0001.0000.0000.0001.00 options level level-2', session)
    controller.execute('set protocols isis interface dum1 address-family ipv4-unicast address-family ipv6-unicast network point-to-point', session)
    controller.execute('set vrf name BLUE table 101', session)
    controller.execute('set vrf name BLUE protocols isis net 49.0001.0000.0000.0002.00', session)
    result = engine.commit(session)
    assert result['results']['isis']['success'], result
    assert set(calls[0][1]) == {'router isis nvyr', 'router isis nvyr vrf BLUE', 'interface dum1'}


@pytest.mark.parametrize('extra,match', [
    ({'net': []}, 'NET'),
    ({'net': [f'49.{area:04d}.0000.0000.0001.00' for area in range(4)]}, 'three NET'),
    ({'options': {'level': 'level-1'}, 'address-family': {'ipv4-unicast': {'level': {'level-2': {'redistribute': {'static': {}}}}}}}, 'routing level'),
    ({'net': ['49.0001.0000.0000.0001.00', '49.0002.0000.0000.0002.00']}, 'system ID'),
    ({'interface': {'dum1': {}}}, 'address-family'),
    ({'level': {'level-1': {'authentication': {'mode': 'md5'}}}}, 'password'),
    ({'level': {'level-2': {'timers': {'lsp-refresh': '1000'}}}}, 'LSP refresh'),
    ({'level': {'level-1': {'fast-reroute': {'tiebreaker': {'1': {}}}}}}, 'type'),
    ({'spf': {'delay': {'initial': '50'}}}, 'requires'),
    ({'options': {'metric-style': 'narrow'}, 'topology': {'ipv6-unicast': {}}}, 'wide'),
    ({'address-family': {'ipv4-unicast': {'level': {'level-1': {'redistribute': {'static': {'route-map': 'MISSING'}}}}}}}, 'route-map'),
    ({'interface': {'dum1': {'address-family': ['ipv4-unicast'], 'topology': {'ipv6-unicast': {}}}}}, 'topology'),
])
def test_cross_node_validation(extra, match):
    settings = {'net': ['49.0001.0000.0000.0001.00'], **extra}
    with pytest.raises(ValidationError, match=match):
        protocols_isis.verify({'instances': {'default': settings}, 'interfaces': {}, 'policies': {}}, None)


def test_interface_vrf_and_ipv6_consistency():
    settings = {'net': ['49.0001.0000.0000.0001.00'], 'interface': {'dum1': {'address-family': ['ipv6-unicast']}}}
    for interface in [{'vrf': 'BLUE'}, {'ipv6': {'disable': True}}]:
        with pytest.raises(ValidationError):
            protocols_isis.verify({'instances': {'default': settings}, 'interfaces': {'dum1': interface}, 'policies': {}}, None)


def test_adapter_preserves_other_protocols_and_foreign_instances():
    original = 'interface dum1\n ip ospf cost 5\n ip router isis nvyr\n isis metric level-1 20\nexit\nrouter isis foreign\n net 49.0001.0000.0000.0009.00\nexit\nend\n'
    changed = frr_isis.adapter.replace(original, {'interface dum1': [], 'router isis nvyr': []})
    assert 'ip ospf cost 5' in changed
    assert 'router isis foreign' in changed
    assert 'isis metric' not in changed
    assert 'ip router isis' not in changed


@pytest.mark.parametrize('line,native', [
    ('show isis', 'show isis summary'),
    ('show isis vrf level', 'show isis vrf level summary'),
    ('show isis interface level', 'show isis interface level'),
    ('show isis interface spf-delay', 'show isis interface spf-delay'),
    ('show isis vrf BLUE', 'show isis vrf BLUE summary'),
    ('show isis route level level-2 backup json', 'show isis route level-2 backup json'),
    ('show isis interface eth2', 'show isis interface eth2'),
    ('show isis database detail 0000.0000.0001.00-00 json', 'show isis database detail 0000.0000.0001.00-00 json'),
    ('show isis spf-delay', 'show isis spf-delay-ietf'),
    ('clear isis neighbor', 'clear isis vrf default neighbor'),
    ('clear isis vrf BLUE neighbor 0000.0000.0001', 'clear isis vrf BLUE neighbor 0000.0000.0001'),
])
def test_operational_translation(line, native):
    assert isis.native_words(line, line.split()[0]) == native.split()


@pytest.mark.parametrize('tail', ['interface dum1 level level-1 metric 16777216', 'level level-3', 'net invalid'])
def test_cli_rejects_invalid_values(controller, session, tail):
    with pytest.raises(RouterError):
        controller.execute('set protocols isis ' + tail, session)


@pytest.mark.parametrize('protocol,af', [('bgp', 'ipv4-unicast'), ('bgp', 'ipv6-unicast'), ('ospf', None), ('ospfv3', None), ('rip', None), ('ripng', None)])
def test_other_protocols_accept_isis_source(controller, session, protocol, af):
    base = 'set protocols ' + protocol + (' address-family ' + af if af else '')
    controller.execute(base + ' redistribute isis metric 5', session)


def test_routed_network_configuration_validates(local_session):
    from functionaltests.routed_network import commands

    for command in commands():
        local_session.set(command)
    candidate = local_session.get_config(source='candidate')
    context = SimpleNamespace(effective=candidate, scripts={'isis': {'vrf': ['NVYRLEFT', 'NVYRRIGHT']}})
    configuration = protocols_isis.get_config(context)
    protocols_isis.verify(configuration, context)
    desired = protocols_isis.generate(configuration, context)
    assert 'router isis nvyr vrf NVYRLEFT' in desired
    assert 'router isis nvyr vrf NVYRRIGHT' in desired


def test_acceptance_configuration_validates(local_session):
    from acceptance.baseline import commands

    options = {'ethernet': 'eth5', 'image': 'alpine', 'assets': 'boot-12345678-1234-1234-1234-123456789012'}
    for filename, number, command in commands(options):
        local_session.set(command)
    candidate = local_session.get_config(source='candidate')
    context = SimpleNamespace(effective=candidate, scripts={'isis': {'vrf': ['default', 'BOOTLEFT']}})
    configuration = protocols_isis.get_config(context)
    protocols_isis.verify(configuration, context)
    desired = protocols_isis.generate(configuration, context)
    assert 'router isis nvyr' in desired
    assert 'router isis nvyr vrf BOOTLEFT' in desired
