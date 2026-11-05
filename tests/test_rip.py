"""RIP schema, reference validation, ownership and operational scope contracts.

Native translation is exercised separately against disposable FRR. Packet and
route tests share the routed-network scenario rather than rebuilding links here.
"""

from types import SimpleNamespace

import pytest

from nvyr.config_scripts import protocols_rip
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import frr_reload, frr_rip
from nvyr.op_scripts import rip


@pytest.mark.parametrize('protocol', ['rip', 'ripng'])
def test_default_and_vrf_pipeline(controller, engine, session, monkeypatch, protocol):
    calls = []
    monkeypatch.setattr(frr_reload, 'manager', SimpleNamespace(apply=lambda *args, **kwargs: calls.append(args)))
    controller.execute(f'set protocols {protocol} interface dum1 passive', session)
    controller.execute(f'set protocols {protocol} maximum-paths 4 timers update 10', session)
    controller.execute('set vrf name BLUE table 101', session)
    controller.execute(f'set vrf name BLUE protocols {protocol} default-information originate', session)
    result = engine.commit(session)
    assert result['results'][protocol]['success'], result
    assert len(calls) == 1
    assert set(calls[0][1]) == {f'router {protocol}', f'router {protocol} vrf BLUE'}
    assert 'timers basic 10 180 120' in calls[0][1][f'router {protocol}'][0]


@pytest.mark.parametrize('protocol', ['rip', 'ripng'])
@pytest.mark.parametrize('tail', ['maximum-paths 256', 'offset-list in metric 17', 'route wrong'])
def test_entry_validation(controller, session, protocol, tail):
    with pytest.raises(RouterError):
        controller.execute(f'set protocols {protocol} {tail}', session)


@pytest.mark.parametrize('settings,match', [
    ({'offset-list': {'in': {'metric': '1'}}}, 'access-list and metric'),
    ({'redistribute': {'static': {'route-map': 'MISSING'}}}, 'route-map'),
    ({'source-distance': {'192.0.2.0/24': {}}}, 'distance is required'),
    ({'interface': {'dum1': {'split-horizon': {'disable': True, 'poisoned-reverse': True}}}}, 'mutually exclusive'),
    ({'interface': {'dum1': {'authentication': {'mode': 'text'}}}}, 'exactly one'),
    ({'interface': {'dum1': {'authentication': {'mode': 'text', 'password': 'test', 'md5-auth-length': 'rfc'}}}}, 'requires mode md5'),
    ({'interface': {'dum1': {'authentication': {'mode': 'md5', 'key-chain': 'MISSING'}}}}, 'key-chain'),
])
def test_cross_node_validation(settings, match):
    with pytest.raises(ValidationError, match=match):
        protocols_rip.verify({'protocol': 'rip', 'instances': {'default': settings},
                              'policies': {}, 'interfaces': {}}, None)


def test_interface_membership_validation():
    with pytest.raises(ValidationError, match='belongs to VRF BLUE'):
        protocols_rip.verify({'protocol': 'rip', 'instances': {'default': {'interface': {'dum1': {}}}},
                              'policies': {}, 'interfaces': {'dum1': {'vrf': 'BLUE'}}}, None)


def test_shared_interface_and_protocol_ownership():
    original = ('interface dum1\n description Keep\n ip ospf cost 5\n ip rip v2-broadcast\n'
                ' ipv6 ripng split-horizon poisoned-reverse\nexit\nrouter bgp 65000\nexit\nend\n')
    adapter = frr_rip.adapters['rip']
    desired = adapter.desired('interface dum1\n ip rip send version 2\nexit\n')
    output = adapter.replace(original, desired)
    assert 'v2-broadcast' not in output
    assert 'ip ospf cost 5' in output
    assert 'ipv6 ripng split-horizon poisoned-reverse' in output
    assert 'router bgp 65000' in output
    assert adapter.select(output, desired) == desired


@pytest.mark.parametrize('line,native', [
    ('show ip rip vrf BLUE status', ['show', 'ip', 'rip', 'vrf', 'BLUE', 'status']),
    ('show ipv6 ripng', ['show', 'ipv6', 'ripng']),
    ('clear rip', ['clear', 'ip', 'rip', 'vrf', 'default']),
    ('clear ripng vrf BLUE', ['clear', 'ipv6', 'ripng', 'vrf', 'BLUE']),
    ('clear rip all', ['clear', 'ip', 'rip']),
])
def test_operational_scope(line, native):
    assert rip.native_words(line, line.split()[0]) == native


@pytest.mark.parametrize('tail', ['version 2', 'neighbor 192.0.2.1', 'distance 120',
                                'interface dum1 authentication mode md5', 'passive-default'])
def test_ripng_does_not_offer_ipv4_only_commands(controller, session, tail):
    with pytest.raises(RouterError):
        controller.execute('set protocols ripng ' + tail, session)


def test_routed_network_rip_configuration_validates(local_session):
    from functionaltests.routed_network import commands

    # Install the shared topology/configuration once; inspect RIP before unrelated
    # service apply stages, which require the live test harness.
    for command in commands():
        local_session.set(command)
    candidate = local_session.get_config(source='candidate')
    for protocol in ('rip', 'ripng'):
        context = SimpleNamespace(owner=protocol, effective=candidate,
                                  scripts={protocol: {'vrf': ['NVYRLEFT', 'NVYRRIGHT']}})
        configuration = protocols_rip.get_config(context)
        protocols_rip.verify(configuration, context)
        desired = protocols_rip.generate(configuration, context)
        assert f'router {protocol} vrf NVYRLEFT' in desired
        assert f'router {protocol} vrf NVYRRIGHT' in desired
