"""VXLAN CLI scope, native ownership and validation."""

from types import SimpleNamespace

import pytest

from nvyr.config_scripts import interface_bridge
from nvyr.errors import ParseError, ValidationError
from nvyr.helpers import vxlan, vxlan_config
from nvyr.tree import ReadOnlyTree


def context(profile):
    return SimpleNamespace(effective=ReadOnlyTree({'interfaces': {
        'vxlan': {'vxlan1': profile}, 'dummy': {'dum0': {}},
        'bridge': {'br0': {'vlan-filtering': {}, 'member': {'interface': {'vxlan1': {}, 'dum0': {}}}}},
    }}), recovery=False)


@pytest.mark.parametrize('values,message', [
    ({}, 'either vni or external'),
    ({'vni': '0', 'external': {}}, 'either vni or external'),
    ({'external': {}, 'flood-vtep': ['192.0.2.1']}, 'external mode'),
    ({'vni': '10', 'multicast-group': '239.1.1.1'}, 'source-interface'),
    ({'vni': '10', 'source-address': '192.0.2.1', 'remote': '2001:db8::2'}, 'single underlay'),
    ({'vni': '10', 'remote': '239.1.1.1'}, 'invalid remote'),
    ({'vni': '10', 'static-mac': {'02:00:00:00:00:01': {}}}, 'remote is required'),
    ({'vni': '10', 'source-port': {'minimum': '4000'}}, 'minimum <= maximum'),
    ({'external': {'vlan': {'3': {'vni': '9'}, '5': {'vni': '9'}}}}, 'own VNI'),
    ({'external': {'vni-filter': {}, 'vlan': {'3': {'vni': '0'}}}}, 'nonzero VNI'),
])
def test_preflight(values, message):
    with pytest.raises(ValidationError, match=message):
        vxlan_config.verify_interface('vxlan1', values, {'dum0'}, {'vxlan1'})


def test_mapping_owned_only_by_external_port():
    ctx = context({'external': {'vlan': {'10': {'vni': '900'}}}})
    members = interface_bridge.get_config(ctx)['bridges']['br0']['member']['interface']
    assert members == {'vxlan1': {'vlan': {'10': {}}, 'vxlan-mappings': {'10': '900'}}, 'dum0': {}}
    assert not ctx.effective['interfaces']['bridge']['br0']['member']['interface']['vxlan1']


def test_configuration_anchors_and_scope(controller, engine, session):
    controller.execute('set interfaces vxlan vxlan5 external vlan 30 vni 123', session)
    assert engine.view(session)['interfaces']['vxlan']['vxlan5']['external']['vlan']['30']['vni'] == '123'
    with pytest.raises(ParseError, match='vni'):
        controller.execute('set interfaces bridge br0 member interface dum0 vlan 30 vni 123', session)


def test_unrelated_routed_tunnel_edit_leaves_bridge_ports_alone(local_session):
    local_session.set('set interfaces dummy dum0')
    local_session.set('set interfaces bridge br0 member interface dum0')
    local_session.set('set interfaces vxlan vxlan1 vni 101')
    local_session.commit()

    local_session.set('set interfaces vxlan vxlan1 ttl 64')
    results = local_session.commit()['results']
    assert 'vxlan' in results
    assert 'bridge' not in results and 'bridge-ports' not in results


def test_kernel_creation_only_changes():
    before = vxlan.settings({'vni': '0', 'ttl': '64'})
    for profile, reason in [({'vni': '1'}, 'id'), ({'vni': '0', 'ttl': 'inherit'}, 'ttl inherit'),
                            ({'vni': '0', 'destination-port': '4789'}, 'dstport')]:
        assert vxlan.immutable_change(before, vxlan.settings(profile)) == reason
    assert vxlan.immutable_change(before, vxlan.settings({'vni': '0', 'ttl': '1', 'tos': 'inherit'})) is None


@pytest.mark.parametrize('suffix,arguments', [
    ('', []), (' vxlan7', ['--interface', 'vxlan7']),
    (' vxlan7 fdb', ['--interface', 'vxlan7', '--section', 'fdb']),
    (' vxlan7 vni', ['--interface', 'vxlan7', '--section', 'vni']),
])
def test_operational_dispatch(controller, monkeypatch, suffix, arguments):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    controller.execute('show interfaces vxlan' + suffix)
    assert calls == [['vxlan.nvyr.op', 'show', *arguments]]
