"""Self-peering validation uses canonical addresses and the peer's routing domain."""

import ipaddress
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import protocols_bgp as bgp
from nvyr.errors import ValidationError
from nvyr.tree import ReadOnlyTree
from tests.bgp_config import verify_bgp


def context(configuration=None, *, check_only=False):
    return SimpleNamespace(effective=configuration or {}, check_only=check_only, report=lambda message: None)


def test_get_config_gathers_dependencies_for_later_stages(monkeypatch):
    effective = ReadOnlyTree({
        'protocols': {'bgp': {'local-as': '65000'}},
        'vrf': {'name': {
            'BLUE': {'protocols': {'bgp': {'local-as': '65001', 'neighbor': {
                '192.0.2.2': {'remote-as': '65002', 'address-family': {'ipv4-unicast': {
                    'route-map': {'import': 'IMPORT'}}}}}}}},
            'UNREGISTERED': {'protocols': {'bgp': {'local-as': '65003'}}},
        }},
        'policy': {'route-map': {'IMPORT': {'rule': {'10': {'action': 'permit'}}}}},
        'interfaces': {'dummy': {'dum9': {'vrf': 'BLUE', 'address': ['192.0.2.1/24']}}},
    })
    gathered = bgp.get_config(SimpleNamespace(effective=effective, scripts={'bgp': {'vrf': ('BLUE',)}}))
    assert set(gathered['instances']) == {'default', 'BLUE'}
    assert 'IMPORT' in gathered['policies']['route-map']
    assert gathered['interfaces']['dum9']['vrf'] == 'BLUE'

    def unexpected_inventory(*args, **kwargs):
        pytest.fail('later stages must use the gathered configuration inventory')

    monkeypatch.setattr(bgp.interfaces, 'configured', unexpected_inventory)
    later_context = SimpleNamespace(check_only=True, report=lambda message: None)
    bgp.verify(gathered, later_context)
    assert set(bgp.generate(gathered, later_context)) == {'default', 'BLUE'}


def test_get_config_skips_interface_inventory_without_neighbors(monkeypatch):
    def unexpected_inventory(*args, **kwargs):
        pytest.fail('instances without neighbors do not need an address inventory')

    monkeypatch.setattr(bgp.interfaces, 'configured', unexpected_inventory)
    gathered = bgp.get_config(SimpleNamespace(
        effective={'protocols': {'bgp': {'local-as': '65000'}}}, scripts={},
    ))

    assert gathered['interfaces'] == {}


@pytest.mark.parametrize('address', ['192.0.2.1', '2001:db8::1'])
def test_live_address_rejected_in_own_vrf(monkeypatch, address):
    queries = []

    def inventory(*, vrf):
        queries.append(vrf)
        return {ipaddress.ip_address(address)}

    monkeypatch.setattr(bgp, 'local_addresses', inventory)
    configuration = {'BLUE': {'local-as': '65000', 'neighbor': {address: {'remote-as': '65000'}}}}
    with pytest.raises(ValidationError, match='local system in VRF BLUE'):
        verify_bgp(configuration, context())
    assert queries == ['BLUE']


def test_inventory_queried_once_for_each_populated_vrf(monkeypatch):
    queries = []

    def inventory(*, vrf):
        queries.append(vrf)
        return set()

    monkeypatch.setattr(bgp, 'local_addresses', inventory)
    peers = {'192.0.2.1': {'remote-as': '65000'}, '192.0.2.2': {'remote-as': '65000'}}
    verify_bgp({'BLUE': {'local-as': '65000', 'neighbor': peers},
                'default': {'local-as': '65000', 'neighbor': peers},
                'EMPTY': {'local-as': '65000'}}, context())
    assert queries == ['default', 'BLUE']


def test_check_only_uses_proposed_vif_addresses_without_host_queries(monkeypatch):
    def inventory(**kwargs):
        pytest.fail('commit check must not require the proposed VRF to exist yet')

    monkeypatch.setattr(bgp, 'local_addresses', inventory)
    effective = {'interfaces': {'ethernet': {'eth1': {'vif': {'10': {
        'vrf': 'BLUE', 'address': ['2001:db8::1/64', 'dhcp']}}}}}}
    configuration = {'BLUE': {'local-as': '65000', 'neighbor': {'2001:db8:0:0::1': {'remote-as': '65000'}}}}
    with pytest.raises(ValidationError, match='local system in VRF BLUE'):
        verify_bgp(configuration, context(effective, check_only=True))


@pytest.mark.parametrize('owner, peer_vrf', [('default', 'BLUE'), ('BLUE', 'default'), ('BLUE', 'RED')])
def test_address_in_other_vrf_is_not_self_peering(owner, peer_vrf):
    profile = {'address': ['192.0.2.1/32']}
    if owner != 'default':
        profile['vrf'] = owner
    effective = {'interfaces': {'dummy': {'dum0': profile}}}
    verify_bgp({peer_vrf: {'local-as': '65000', 'neighbor': {'192.0.2.1': {'remote-as': '65000'}}}}, context(effective, check_only=True))


def test_disabled_peer_still_cannot_use_local_address():
    effective = {'interfaces': {'dummy': {'dum0': {'address': ['192.0.2.1/32']}}}}
    with pytest.raises(ValidationError, match='local system in VRF default'):
        verify_bgp({'default': {'local-as': '65000', 'neighbor': {
            '192.0.2.1': {'remote-as': '65000', 'shutdown': {}}}}}, context(effective, check_only=True))


def test_live_lookup_errors_are_not_ignored(monkeypatch):
    def inventory(**kwargs):
        raise ValidationError('inventory unavailable')

    monkeypatch.setattr(bgp, 'local_addresses', inventory)
    with pytest.raises(ValidationError, match='inventory unavailable'):
        verify_bgp({'default': {'local-as': '65000', 'neighbor': {
            '192.0.2.1': {'remote-as': '65000'}}}}, context())
