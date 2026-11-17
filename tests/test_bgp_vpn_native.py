"""VPN and extended-community native readback in one isolated FRR instance.

No packet validation here; shared routed tests own customer forwarding. These
checks require the packaged FRR and never configure the host routing instance.
"""

from copy import deepcopy
import os

import pytest

from nvyr.config_scripts import policy
from nvyr.helpers import frr_policy
from tests.test_bgp_lu_native import native, apply, run


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_VPN_NATIVE') != '1', reason='requires disposable FRR')


@pytest.fixture(scope='module')
def vpn_vrf(native):
    manager, _ = native
    namespace = manager.directory.name
    run('ip', '-n', namespace, 'link', 'add', 'VPNTEST', 'type', 'vrf', 'table', '1099')
    run('ip', '-n', namespace, 'link', 'set', 'VPNTEST', 'up')
    yield native
    run('ip', '-n', namespace, 'link', 'del', 'VPNTEST')


@pytest.mark.parametrize('family', ['ipv4-unicast', 'ipv6-unicast'])
def test_vrf_vpn_settings(vpn_vrf, family):
    manager, state = vpn_vrf
    maps = {'route-map': {name: {'rule': {'10': {'action': 'permit'}}} for name in ('VPN-IN', 'VPN-OUT')}}
    manager.apply('policy', policy.generate(maps, None), state, adapter=frr_policy.adapter, daemons=('bgpd',))
    vpn = {'import': {}, 'export': {}, 'route-distinguisher': '65000:100', 'label': 'auto',
           'route-target': {'both': ['65000:20', '65000:100', '192.0.2.1:1']},
           'route-map': {'import': 'VPN-IN', 'export': 'VPN-OUT'}}
    instances = {'default': {'local-as': '65000'}, 'VPNTEST': {'local-as': '65000', 'address-family': {family: {'vpn': vpn}}}}
    apply(vpn_vrf, instances)
    vpn['allocation-mode'] = 'per-nexthop'
    vpn['next-hop'] = '192.0.2.1' if family == 'ipv4-unicast' else '2001:db8::1'
    apply(vpn_vrf, instances)
    vpn.pop('allocation-mode')
    vpn.pop('next-hop')
    vpn['label'] = '16000'
    apply(vpn_vrf, instances)
    instances['VPNTEST']['address-family'][family].pop('vpn')
    apply(vpn_vrf, instances)
    apply(vpn_vrf, {})
    manager.apply('policy', {}, state, adapter=frr_policy.adapter, daemons=('bgpd',))


def test_vpn_policy_readback(native):
    manager, state = native
    configuration = {
        'extended-community-list': {
            'standard': {'VPN-RT': {'rule': {'10': {'action': 'permit', 'route-target': ['65000:100', '65000:200'],
                                                   'site-of-origin': ['192.0.2.1:1']}}}},
            'expanded': {'VPN-REGEX': {'rule': {'10': {'action': 'permit', 'regex': 'RT:65000:.*'}}}},
        },
        'route-map': {'VPN-POLICY': {'rule': {'10': {
            'action': 'permit',
            'match': {'extended-community-list': {'VPN-RT': {'any': {}}}, 'extended-community-limit': '10'},
            'set': {'extended-community': {'route-target': ['65000:100', '65000:200'], 'site-of-origin': '192.0.2.1:1'}},
        }}}},
    }
    desired = policy.generate(configuration, None)
    manager.apply('policy', desired, state, adapter=frr_policy.adapter, daemons=('bgpd',))
    assert frr_policy.adapter.select(manager.snapshot(), desired) == desired
    assert '65000:100' in manager.run(['vtysh', '-c', 'show bgp extcommunity-list VPN-RT detail'])
    configuration['route-map']['VPN-POLICY']['rule']['10']['set'] = {'extended-community-delete': 'VPN-RT'}
    desired = policy.generate(configuration, None)
    manager.apply('policy', desired, state, adapter=frr_policy.adapter, daemons=('bgpd',))
    configuration['route-map']['VPN-POLICY']['rule']['10']['set'] = {'extended-community': {'none': {}}}
    desired = policy.generate(configuration, None)
    manager.apply('policy', desired, state, adapter=frr_policy.adapter, daemons=('bgpd',))
    manager.apply('policy', {}, state, adapter=frr_policy.adapter, daemons=('bgpd',))


@pytest.mark.parametrize('family', ['ipv4-vpn', 'ipv6-vpn'])
@pytest.mark.parametrize('settings', [
    {'next-hop-self': {'force': {}}, 'route-reflector-client': {}, 'accept-own': {}},
    {'soft-reconfiguration': {'inbound': {}}, 'maximum-prefix': {'limit': '200', 'warning-only': {}},
     'maximum-prefix-out': '300', 'weight': '75'},
    {'addpath': {'transmit': {'best-selected': '2'}, 'receive-limit': '4'}, 'send-community': ['extended']},
    {'site-of-origin': '65000:2', 'attribute-unchanged': {'as-path': {}, 'next-hop': {}, 'med': {}}},
])
def test_vpn_peer_settings(native, family, settings):
    instance = {'local-as': '65000', 'parameters': {'default': {'ipv4-unicast': {'disable': {}}}},
                'peer-group': {'VPN': {'remote-as': '65000', 'address-family': {family: deepcopy(settings)}}},
                'neighbor': {'192.0.2.2': {'peer-group': 'VPN', 'shutdown': {}}}}
    apply(native, {'default': instance})
    manager, _ = native
    version = family.split('-')[0]
    for suffix in ('summary', 'rd all', 'rd 65000:100', 'rd 65000:100 ' + ('192.0.2.0/24' if version == 'ipv4' else '2001:db8::/32')):
        manager.run(['vtysh', '-c', f'show bgp {version} vpn {suffix}'])
    manager.run(['vtysh', '-c', f'clear bgp {version} vpn 192.0.2.2 soft out'])
    manager.run(['vtysh', '-c', 'show bgp mplsvpn-nh-label-bind detail'])
    instance['peer-group']['VPN']['address-family'][family] = {}
    apply(native, {'default': instance})
    apply(native, {})


@pytest.mark.parametrize('family,prefix', [('ipv4-vpn', '192.0.2.0/24'), ('ipv6-vpn', '2001:db8:100::/64')])
def test_vpn_network_and_retention(native, family, prefix):
    instance = {'local-as': '65000', 'address-family': {family: {
        'disable-retain-route-target-all': {}, 'network': {prefix: {'route-distinguisher': {
            '65000:100': {'label': '16000'}, '192.0.2.1:100': {'label': '16001'}}}}}}}
    for asn in ('65000', '65000', '65001'):
        # Exercise both same-AS and changed-AS revival after the VPN RIB existed.
        instance['local-as'] = asn
        instance['parameters'] = {
            'labeled-unicast': {'explicit-null': 'both'},
            'router-id': '192.0.2.10', 'timers': {'keepalive': '10', 'holdtime': '30'},
            'fast-external-failover': 'disable', 'hard-administrative-reset': 'disable',
            'client-to-client': {'reflection': 'disable'},
            'bestpath': {'compare-routerid': 'enable', 'med': {'confed': 'enable', 'missing-as-worst': 'enable'}},
        }
        instance['address-family']['ipv4-unicast'] = {
            'distance': {'external': '30', 'internal': '210', 'local': '220'}}
        instance['address-family']['ipv6-unicast'] = {
            'distance': {'external': '30', 'internal': '210', 'local': '220'},
            'next-hop': {'prefer-global': {}}}
        apply(native, {'default': instance})
        shortened = deepcopy(instance)
        shortened['address-family'][family]['network'][prefix]['route-distinguisher'].pop('65000:100')
        apply(native, {'default': shortened})
        apply(native, {})
        # Revival must not inherit any deleted process or AF settings.
        apply(native, {'default': {'local-as': asn}})
        apply(native, {})
