"""LU syntax, shared-table conflicts and policy validation without native daemons."""

import pytest

from nvyr.config_scripts import protocols_bgp as bgp
from nvyr.errors import RouterError, ValidationError
from tests.bgp_config import verify_bgp
from tests.test_bgp import context


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_lu_schema_and_shared_origination(controller, engine, session, family):
    controller.execute('set protocols bgp local-as 65000', session)
    controller.execute('set protocols bgp parameters labeled-unicast explicit-null both', session)
    controller.execute(f'set protocols bgp peer-group LU remote-as external address-family {family}-labeled-unicast next-hop-self force', session)
    controller.execute('set protocols bgp neighbor 192.0.2.2 peer-group LU', session)
    controller.execute(f'set protocols bgp address-family {family}-labeled-unicast maximum-paths ebgp 4 ibgp 2', session)
    result = engine.commit(session)
    assert result['results']['bgp']['success']
    rendered = bgp.generate({'instances': {'default': engine.running['protocols']['bgp']}}, None)['default'][0]
    assert f'address-family {family} labeled-unicast' in rendered
    assert 'neighbor LU activate' in rendered
    assert 'bgp labeled-unicast explicit-null' in rendered
    with pytest.raises(RouterError):
        controller.execute(f'set protocols bgp address-family {family}-labeled-unicast network 192.0.2.0/24', session)
    with pytest.raises(RouterError):
        controller.execute(f'set vrf name BLUE protocols bgp neighbor 192.0.2.2 address-family {family}-labeled-unicast', session)


def test_shared_addpath_transmit_conflict():
    peer = {'remote-as': '65001', 'address-family': {
        'ipv4-unicast': {'addpath': {'transmit': {'all': {}}}},
        'ipv4-labeled-unicast': {'addpath': {'transmit': {'best-selected': '2'}}}}}
    with pytest.raises(ValidationError, match='same AddPath transmit strategy'):
        verify_bgp({'default': {'local-as': '65000', 'neighbor': {'192.0.2.2': peer}}}, context())


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_lu_missing_policy_is_rejected(family):
    peer = {'remote-as': '65001', 'address-family': {
        family + '-labeled-unicast': {'prefix-list': {'in': 'MISSING'}}}}
    with pytest.raises(ValidationError, match='not configured'):
        verify_bgp({'default': {'local-as': '65000', 'neighbor': {'192.0.2.2': peer}}}, context())
