"""OSPF ownership, cross-node validation, and CLI contracts; no packet tests."""

from types import SimpleNamespace

import pytest

from nvyr.config_scripts import protocols_ospf, protocols_ospfv3, policy
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import frr_ospf, frr_policy, frr_reload, validators
from nvyr.op_scripts import ospf


@pytest.mark.parametrize('protocol,module', [('ospf', protocols_ospf), ('ospfv3', protocols_ospfv3)])
def test_default_and_vrf_pipeline(controller, engine, session, monkeypatch, protocol, module):
    calls = []
    monkeypatch.setattr(frr_reload, 'manager', SimpleNamespace(apply=lambda *args, **kwargs: calls.append(args)))
    controller.execute(f'set protocols {protocol} options router-id 192.0.2.1', session)
    controller.execute(f'set protocols {protocol} interface dum1 area 0 passive', session)
    controller.execute('set vrf name BLUE table 101', session)
    controller.execute(f'set vrf name BLUE protocols {protocol} options router-id 192.0.2.2', session)
    result = engine.commit(session)

    assert result['results'][protocol]['success'], result
    assert len(calls) == 1
    native = 'ospf6' if protocol == 'ospfv3' else 'ospf'
    assert set(calls[0][1]) == {f'router {native}', f'router {native} vrf BLUE', 'interface dum1'}


@pytest.mark.parametrize('module', [protocols_ospf, protocols_ospfv3])
def test_area_aliases_and_backbone_type_are_rejected(module):
    for areas in ({'1': {}, '0.0.0.1': {}}, {'0': {'stub': {}}}, {'1': {'stub': {}, 'nssa': {}}}):
        with pytest.raises(ValidationError):
            module.verify({'instances': {'default': {'area': areas}}, 'interfaces': {}, 'policies': {}}, None)


@pytest.mark.parametrize('module', [protocols_ospf, protocols_ospfv3])
def test_interface_cannot_cross_vrf(module):
    configuration = {'instances': {'BLUE': {'interface': {'dum1': {'area': '0'}}}},
                     'interfaces': {'dum1': {'vrf': 'RED'}}, 'policies': {}}
    with pytest.raises(ValidationError, match='belongs to VRF RED'):
        module.verify(configuration, None)


def test_interface_replacement_preserves_other_owners():
    original = 'interface dum1\n description Keep\n ip ospf cost 5\n ipv6 ospf6 cost 7\nexit\nrouter bgp 65000\nexit\nend\n'
    desired = frr_ospf.ipv4.desired('interface dum1\n ip ospf cost 9\nexit\n')
    result = frr_ospf.ipv4.replace(original, desired)

    assert ' ip ospf cost 5' not in result
    assert ' ip ospf cost 9' in result
    assert ' ipv6 ospf6 cost 7' in result
    assert ' description Keep' in result
    assert 'router bgp 65000\nexit' in result
    assert frr_ospf.ipv4.select(result, desired) == desired


def test_keychain_preserves_nested_key_associations():
    desired = policy.generate({'key-chain': {'AUTH': {'key': {
        '2': {'secret': 'second', 'algorithm': 'hmac-sha-256'},
        '1': {'secret': 'first', 'algorithm': 'md5',
              'accept-lifetime': {'start': '2026-01-01T00:00:00', 'infinite': {}}},
    }}}}, None)
    block = desired['key chain AUTH'][0]
    assert block.index(' key 1') < block.index(' key 2')
    assert 'key-string first\n exit\n key 2' in block
    assert frr_policy.adapter.select(block, desired) == desired
    assert frr_policy.adapter.replace(block, {'key chain AUTH': []}) == 'end\n'


@pytest.mark.parametrize('value,valid', [('0', True), ('4294967295', True), ('0.0.0.1', True),
                                       ('4294967296', False), ('1.2.3.999', False), ('-1', False)])
def test_area_validator(value, valid):
    assert validators.ospf_area(value) is valid


@pytest.mark.parametrize('line,native', [
    ('show ip ospf vrf BLUE interface dum1', ['show', 'ip', 'ospf', 'vrf', 'BLUE', 'interface', 'dum1']),
    ('show ipv6 ospf neighbor 192.0.2.2', ['show', 'ipv6', 'ospf6', 'neighbor', '192.0.2.2']),
    ('clear ipv6 ospf vrf BLUE process', ['clear', 'ipv6', 'ospf6', 'process', 'vrf', 'BLUE']),
])
def test_operational_family_translation(line, native):
    assert ospf.native_words(line, line.split()[0]) == native


@pytest.mark.parametrize('tail', [
    'instance 1', 'options lsa-refresh 600', 'options maxage-delay 60',
    'area 1 virtual-link 192.0.2.2',
    'interface dum1 address 192.0.2.1 authentication plaintext secret',
])
def test_deferred_options_are_not_exposed(controller, session, tail):
    with pytest.raises(RouterError):
        controller.execute('set protocols ospf ' + tail, session)
