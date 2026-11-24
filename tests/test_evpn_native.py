"""Exercise EVPN reload and deletion on the packaged FRR in an isolated namespace."""

from copy import deepcopy
import os

import pytest

from nvyr.config_scripts import evpn_vni, policy
from nvyr.helpers import frr_policy
from tests.test_bgp_lu_native import apply, native, run


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_EVPN_NATIVE') != '1', reason='requires disposable FRR')


def test_evpn_policy_reload(native):
    manager, state = native
    maps = {'access-list': {'mac': {'HOSTS': {'rule': {
        '10': {'action': 'permit', 'address': '02:00:00:00:01:02'}, '20': {'action': 'deny', 'any': {}}}}}},
        'route-map': {'FILTER': {'rule': {
            '10': {'action': 'deny', 'match': {'evpn': {'default-route': {}}}},
            '20': {'action': 'permit', 'match': {'evpn': {'vni': '10010', 'route-type': '2',
                                                        'route-distinguisher': '65000:10'},
                                                'mac': {'access-list': 'HOSTS'}}},
            '30': {'action': 'permit', 'set': {'evpn': {'gateway-ip': {'ipv4': '192.0.2.1'}}}},
            '40': {'action': 'permit', 'set': {'evpn': {'gateway-ip': {'ipv6': '2001:db8::1'}}}}}}}}
    policy.verify(maps, None)
    for configuration in (maps, {}):
        manager.apply('policy', policy.generate(configuration, None), state,
                      adapter=frr_policy.adapter, daemons=('bgpd',))


def test_two_l2vnis_and_tenant_reload(native):
    manager, state = native
    namespace = manager.directory.name
    run('ip', '-n', namespace, 'link', 'add', 'BLUE', 'type', 'vrf', 'table', '501')
    run('ip', '-n', namespace, 'link', 'set', 'BLUE', 'up')
    manager.apply('evpn-vni', evpn_vni.generate({'BLUE': {'50000': {}}}, None), state,
                  adapter=evpn_vni.adapter, daemons=('zebra',))

    af = 'l2vpn-evpn'
    settings = {'advertise-all-vni': {}, 'enable-resolve-overlay-index': {}, 'auto-route-target': {'rfc8365-compatible': {}},
                'duplicate-address-detection': {'max-moves': '8', 'time': '90', 'freeze': 'permanent'},
                'vni': {'10010': {'route-distinguisher': '192.0.2.1:10',
                                  'route-target': {'both': ['65000:10', '65000:20']}, 'advertise-svi-ip': {}},
                        '10020': {'route-distinguisher': '192.0.2.1:20', 'flooding': 'disable',
                                  'advertise-default-gw': {}, 'advertise-subnet': {}}}}
    tenant = {'route-distinguisher': '192.0.2.1:500', 'route-target': {'both': ['65000:500', '65000:501']},
              'advertise': {'ipv4-unicast': {'gateway-ip': {}}, 'ipv6-unicast': {}},
              'default-originate': {'ipv4': {}, 'ipv6': {}}}
    config = {'default': {'local-as': '65000', 'address-family': {af: settings},
                          'peer-group': {'LEAF': {'remote-as': '65000', 'address-family': {af: {'route-reflector-client': {}}}}}},
              'BLUE': {'local-as': '65000', 'address-family': {af: tenant}}}
    apply(native, config)
    for options in ({'prefix-routes-only': {}}, {}):
        desired = evpn_vni.generate({'BLUE': {'50000': options}}, None)
        manager.apply('evpn-vni', desired, state, adapter=evpn_vni.adapter, daemons=('zebra',))
        assert evpn_vni.adapter.select(manager.snapshot(), desired) == desired
    updated = deepcopy(config)
    policies = updated['default']['address-family'][af]['vni']
    del policies['10010']
    policies['10020']['route-target'] = {'import': ['65001:22']}
    apply(native, updated)
    apply(native, {})
    manager.apply('evpn-vni', {}, state, adapter=evpn_vni.adapter, daemons=('zebra',))
