"""VPN schema, cross-field verification and canonical FRR readback contracts."""

import pytest

from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import frr_bgp, validators
from tests.bgp_config import verify_bgp
from tests.test_bgp import context


@pytest.mark.parametrize('value,valid', [
    ('65000:4294967295', True), ('65536:65535', True), ('192.0.2.1:65535', True),
    ('4294967295:1', True), ('65536:65536', False), ('192.0.2.1:65536', False),
    ('4294967296:1', False), ('65000:-1', False), ('2001:db8::1:1', False),
])
def test_rd_rt_encoding_limits(value, valid):
    assert bool(validators.bgp_rd_rt(value)) is valid


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_vpn_schema_and_individual_targets(controller, engine, session, family):
    controller.execute('set protocols bgp local-as 65000', session)
    controller.execute(f'set protocols bgp neighbor 192.0.2.2 remote-as 65000 shutdown address-family {family}-vpn accept-own', session)
    controller.execute('set vrf name BLUE table 100', session)
    controller.execute('set vrf name BLUE protocols bgp local-as 65000', session)
    root = f'set vrf name BLUE protocols bgp address-family {family}-unicast vpn'
    controller.execute(root + ' import export route-distinguisher 65000:1 label auto', session)
    controller.execute(root + ' route-target both 65000:1 both 65000:2', session)
    result = engine.commit(session)
    assert result['results']['bgp']['success'], result
    vpn = engine.running['vrf']['name']['BLUE']['protocols']['bgp']['address-family'][family + '-unicast']['vpn']
    assert set(vpn['route-target']['both']) == {'65000:1', '65000:2'}
    with pytest.raises(RouterError):
        controller.execute(f'set vrf name BLUE protocols bgp address-family {family}-vpn', session)


@pytest.mark.parametrize('vpn,error', [
    ({'import': {}}, 'import requires'),
    ({'export': {}}, 'route-distinguisher and label'),
    ({'export': {}, 'route-distinguisher': '65000:1', 'label': 'auto'}, 'export route-target'),
    ({'allocation-mode': 'per-nexthop', 'label': '16000'}, 'requires label auto'),
])
def test_incomplete_vpn_rejected(vpn, error):
    with pytest.raises(ValidationError, match=error):
        verify_bgp({'default': {'local-as': '65000', 'address-family': {'ipv4-unicast': {'vpn': vpn}}}}, context())


def test_route_target_readback_equivalence():
    prefix = 'router bgp 65000\n address-family ipv4 unicast\n'
    separate = prefix + '  rt vpn import 65000:2 65000:1\n  rt vpn export 65000:1 65000:2\n exit-address-family\nexit\n'
    both = prefix + '  rt vpn both 65000:1 65000:2\n exit-address-family\nexit\n'
    assert frr_bgp.adapter.desired(separate) == frr_bgp.adapter.desired(both)


def test_extended_community_schema_and_references(controller, engine, session):
    controller.execute('set policy extended-community-list standard VPN rule 10 action permit route-target 65000:1 route-target 65000:2 site-of-origin 192.0.2.1:1', session)
    controller.execute('set policy route-map IMPORT rule 10 action permit match extended-community-list VPN any', session)
    controller.execute('set policy route-map EXPORT rule 10 action permit set extended-community route-target 65000:1', session)
    result = engine.commit(session)
    assert result['results']['policy']['success'], result
    with pytest.raises(RouterError, match='referenc'):
        controller.execute('delete policy extended-community-list standard VPN', session)

    controller.execute('set protocols bgp local-as 65000 address-family ipv4-unicast vpn route-map import MISSING', session)
    result = engine.commit(session)
    assert 'MISSING' in result['results']['bgp']['error']
