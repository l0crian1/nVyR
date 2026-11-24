"""EVPN CLI scope, policy dependencies and nested FRR configuration ownership."""

from pathlib import Path

import pytest

from nvyr.config_scripts import evpn_vni, protocols_bgp
from nvyr.errors import RouterError, ValidationError


def test_evpn_scopes_and_commit(controller, engine, session):
    commands = [
        'set protocols bgp local-as 65000 address-family l2vpn-evpn advertise-all-vni',
        'set protocols bgp neighbor 192.0.2.2 remote-as 65000 address-family l2vpn-evpn',
        'set protocols bgp address-family l2vpn-evpn vni 10010 route-target both 65000:1 route-target both 65000:2',
        'set vrf name BLUE table 501',
        'set vrf name BLUE vni 50000',
        'set vrf name BLUE protocols bgp local-as 65000 address-family l2vpn-evpn advertise ipv4-unicast route-map EXPORT',
        'set policy access-list mac HOSTS rule 10 action permit address 02:00:00:00:00:01',
        'set policy route-map FILTER rule 10 action deny match mac access-list HOSTS',
        'set policy route-map FILTER rule 20 action permit match evpn route-type 2',
        'set policy route-map EXPORT rule 10 action permit']
    for command in commands:
        controller.execute(command, session)

    result = engine.commit(session)
    for owner in ('bgp', 'policy', 'evpn-vni'):
        assert result['results'][owner]['success'], result

    with pytest.raises(RouterError, match='referenc'):
        controller.execute('delete policy access-list mac HOSTS', session)
    for command in [
        'set vrf name BLUE protocols bgp address-family l2vpn-evpn advertise-all-vni',
        'set protocols bgp address-family l2vpn-evpn advertise ipv4-unicast',
        'set vrf name BLUE protocols bgp neighbor 192.0.2.2 address-family l2vpn-evpn']:
        with pytest.raises(RouterError):
            controller.execute(command, session)


def test_zebra_binding_keeps_other_vrf_commands():
    current = 'vrf BLUE\n vni 50000\n ip route 192.0.2.0/24 Null0\nexit-vrf\nvrf RED\n vni 42\nexit-vrf\nend\n'
    replaced = evpn_vni.adapter.replace(current, {'BLUE': []})
    assert replaced == current.replace(' vni 50000\n', '')
    assert evpn_vni.adapter.select(replaced, ['BLUE', 'RED']) == {'BLUE': [], 'RED': [' vni 42']}
    with pytest.raises(ValidationError, match='share L3VNI'):
        evpn_vni.verify({'BLUE': {'42': {}}, 'RED': {'42': {}}}, None)
    with pytest.raises(ValidationError, match='exactly one'):
        evpn_vni.verify({'BLUE': {'42': {}, '43': {}}}, None)


def test_documented_leaf_configuration(controller, engine, session):
    document = Path(__file__).resolve().parents[1] / 'docs/users/evpn.md'
    for line in document.read_text().splitlines():
        if line.startswith('set '):
            controller.execute(line, session)
    result = engine.commit(session)
    assert all(entry['success'] for entry in result['results'].values()), result


@pytest.mark.parametrize('values', [
    {'advertise-default-gw': {}}, {'advertise-svi-ip': {}},
    {'vni': {'10010': {'route-target': {'both': ['65000:10']}}}}])
def test_local_vtep_settings_require_advertising_vnis(values):
    with pytest.raises(ValidationError, match='requires advertise-all-vni'):
        protocols_bgp.verify_evpn(values, 'EVPN')
