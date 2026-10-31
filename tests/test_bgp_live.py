"""Opt-in BGP reconciliation and route exchange against disposable FRR 10.7.1."""

from copy import deepcopy
import json
import os
from pathlib import Path
import time

import pytest

from nvyr.config_scripts import protocols_bgp as bgp, policy
from nvyr.errors import RouterError
from nvyr.helpers import frr_bgp, frr_policy, frr_reload


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_BGP_TEST') != '1', reason='requires disposable FRR daemons')


def run(*args):
    return frr_reload.run(list(args))


def wait_for(predicate):
    deadline = time.monotonic() + 20
    while not predicate():
        assert time.monotonic() < deadline, 'BGP peers/routes did not converge'
        time.sleep(0.1)


def apply(native, configuration):
    manager, state = native
    desired = bgp.generate({'instances': configuration}, None)
    manager.apply('bgp', desired, state, adapter=frr_bgp.adapter, daemons=('bgpd', 'zebra'))
    assert frr_bgp.adapter.select(manager.snapshot(), desired) == desired
    return desired


@pytest.fixture
def native(tmp_path):
    assert Path('/.dockerenv').exists(), 'native tests must not run on a shared router'
    manager = frr_reload.Manager()
    policies = {'route-map': {'BGP_TEST': {'rule': {'10': {'action': 'permit'}}}}}
    manager.apply('policy', policy.generate(policies, None), tmp_path, adapter=frr_policy.adapter)
    try:
        yield manager, tmp_path
    finally:
        manager = frr_reload.Manager()
        manager.apply('bgp', {}, tmp_path, adapter=frr_bgp.adapter, recovery=True)
        manager.apply('policy', {}, tmp_path, adapter=frr_policy.adapter, recovery=True)


def test_all_neighbor_and_instance_attributes(native):
    settings = {'route-map': {'import': 'BGP_TEST', 'export': 'BGP_TEST'}, 'next-hop-self': {},
                'default-originate': {'route-map': 'BGP_TEST'}, 'maximum-prefix': {'limit': '100'},
                'send-community': ['standard']}
    instance = {'local-as': '65000', 'parameters': {'router-id': '192.0.2.1', 'shutdown': 'enable',
                'log-neighbor-changes': 'enable', 'bestpath': {'as-path': {'multipath-relax': 'enable'}},
                'timers': {'keepalive': '10', 'holdtime': '30'}}, 'description': 'metadata', 'neighbor': {'192.0.2.2': {
                    'remote-as': '65001', 'description': 'Test neighbor', 'password': 'test-secret',
                    'shutdown': {}, 'passive': {}, 'update-source': 'lo', 'ebgp-multihop': '2',
                    'timers': {'keepalive': '3', 'holdtime': '9', 'connect': '10'},
                    'address-family': {'ipv4-unicast': settings, 'ipv6-unicast': settings}}}}
    configuration = {'default': instance}
    apply(native, configuration)
    peer = instance['neighbor']['192.0.2.2']
    del peer['ebgp-multihop']
    peer['ttl-security'] = {'hops': '2'}
    peer['update-source'] = '192.0.2.1'
    apply(native, configuration)
    apply(native, {'default': {'local-as': '65000'}})
    apply(native, {})


def test_peer_groups_overrides_and_removal(native):
    group = {'remote-as': '65000', 'timers': {'keepalive': '10', 'holdtime': '30'},
             'address-family': {'ipv4-unicast': {'next-hop-self': {}, 'send-community': ['standard', 'extended']}}}
    instance = {'local-as': '65000', 'peer-group': {'PEERS': group}, 'neighbor': {
        '192.0.2.2': {'peer-group': 'PEERS', 'remote-as': '65000', 'timers': {'keepalive': '5'},
                     'description': 'Individual member', 'update-source': '192.0.2.1', 'address-family': {
            'ipv4-unicast': {'next-hop-self': {}, 'send-community': ['standard']}}},
        '192.0.2.3': {'peer-group': 'PEERS'}}}
    apply(native, {'default': instance})
    del instance['neighbor']['192.0.2.2']
    apply(native, {'default': instance})
    apply(native, {})


def test_group_policy_and_member_filter_override(native):
    manager, state = native
    policies = {'prefix-list': {'ipv4': {
        'BGP_GROUP': {'rule': {'10': {'action': 'permit', 'prefix': '192.0.2.0/24'}}},
        'BGP_MEMBER': {'rule': {'10': {'action': 'permit', 'prefix': '198.51.100.0/24'}}},
    }}}
    manager.apply('policy', policy.generate(policies, None), state, adapter=frr_policy.adapter)
    instance = {'local-as': '65000', 'peer-group': {'PEERS': {
        'remote-as': '65000', 'address-family': {'ipv4-unicast': {'prefix-list': {'in': 'BGP_GROUP'}}}}},
        'neighbor': {'192.0.2.2': {'peer-group': 'PEERS', 'address-family': {
            'ipv4-unicast': {'prefix-list': {'in': 'BGP_MEMBER'}}}}}}
    apply(native, {'default': instance})
    del instance['neighbor']['192.0.2.2']['address-family']['ipv4-unicast']['prefix-list']
    apply(native, {'default': instance})


def test_networks_redistribution_aggregates_and_multipath(native):
    instance = {'local-as': '65000', 'address-family': {
        'ipv4-unicast': {'network': {'192.0.2.0/24': {'route-map': 'BGP_TEST'}},
                         'redistribute': {'connected': {}, 'static': {'route-map': 'BGP_TEST'}},
                         'aggregate-address': {'192.0.0.0/16': {'as-set': {}, 'summary-only': {}}},
                         'maximum-paths': {'ebgp': '256', 'ibgp': '4'}},
        'ipv6-unicast': {'network': {'2001:db8::/64': {}},
                         'redistribute': {'connected': {'route-map': 'BGP_TEST'}, 'static': {}},
                         'aggregate-address': {'2001:db8::/32': {'summary-only': {}}},
                         'maximum-paths': {'ebgp': '2', 'ibgp': '1'}}}}
    apply(native, {'default': instance})
    apply(native, {'default': {'local-as': '65000'}})


def test_reflector_and_disabled_timers(native):
    instance = {'local-as': '65000', 'parameters': {'timers': {'keepalive': '0', 'holdtime': '0'}}, 'neighbor': {
        '2001:db8::2': {'remote-as': '65000', 'update-source': '2001:db8::1', 'timers': {'keepalive': '0', 'holdtime': '0'},
                        'address-family': {'ipv6-unicast': {'route-reflector-client': {}}}}}}
    apply(native, {'default': instance})


def test_explicit_native_defaults(native):
    """FRR may suppress explicit defaults without changing their effective value."""
    instance = {'local-as': '65000', 'parameters': {'timers': {'keepalive': '60', 'holdtime': '180'}}, 'neighbor': {
        '192.0.2.2': {'remote-as': '65001', 'ebgp-multihop': '1',
                     'timers': {'keepalive': '60', 'holdtime': '180', 'connect': '30'}}}}
    apply(native, {'default': instance})


@pytest.mark.parametrize('selection', [
    ['standard'], ['extended'], ['large'], ['standard', 'extended'],
    ['extended', 'large'], ['standard', 'large'], ['standard', 'extended', 'large'],
])
def test_native_community_selection(native, selection):
    instance = {'local-as': '65000', 'neighbor': {'192.0.2.2': {
        'remote-as': '65000', 'address-family': {'ipv4-unicast': {'send-community': selection}}}}}
    apply(native, {'default': instance})
    del instance['neighbor']['192.0.2.2']['address-family']['ipv4-unicast']['send-community']
    apply(native, {'default': instance})


def test_local_as_change_and_lost_reply_rollback(native):
    manager, state = native
    before = apply(native, {'default': {'local-as': '65000', 'parameters': {'router-id': '192.0.2.1'}}})
    original_reload = manager.reload

    def lost_reply(target):
        original_reload(target)
        manager.reload = original_reload
        raise RouterError('lost successful reply')

    manager.reload = lost_reply
    with pytest.raises(RouterError, match='previous configuration restored'):
        apply(native, {'default': {'local-as': '65001', 'parameters': {'router-id': '192.0.2.10'}}})
    assert frr_bgp.adapter.select(manager.snapshot(), before) == before
    apply(native, {'default': {'local-as': '65001'}})


@pytest.fixture
def peer_link(native):
    run('ip', 'link', 'add', 'BGPSource', 'type', 'vrf', 'table', '504')
    run('ip', 'link', 'set', 'BGPSource', 'up')
    run('ip', 'link', 'add', 'BGPPeer', 'type', 'vrf', 'table', '503')
    run('ip', 'link', 'set', 'BGPPeer', 'up')
    run('ip', 'link', 'add', 'bgpa', 'type', 'veth', 'peer', 'name', 'bgpb')
    run('ip', 'link', 'set', 'bgpb', 'master', 'BGPPeer')
    run('ip', 'link', 'set', 'bgpa', 'master', 'BGPSource')
    run('ip', 'address', 'add', '198.18.0.1/30', 'dev', 'bgpa')
    run('ip', 'address', 'add', '198.18.0.2/30', 'dev', 'bgpb')
    run('ip', '-6', 'address', 'add', '2001:db8:ffff::1/64', 'dev', 'bgpa', 'nodad')
    run('ip', '-6', 'address', 'add', '2001:db8:ffff::2/64', 'dev', 'bgpb', 'nodad')
    run('ip', 'link', 'set', 'bgpa', 'up')
    run('ip', 'link', 'set', 'bgpb', 'up')
    run('ip', 'link', 'add', 'bgporigin', 'type', 'dummy')
    run('ip', 'link', 'set', 'bgporigin', 'master', 'BGPSource')
    run('ip', 'address', 'add', '203.0.113.1/24', 'dev', 'bgporigin')
    run('ip', '-6', 'address', 'add', '2001:db8:100::1/64', 'dev', 'bgporigin', 'nodad')
    run('ip', 'link', 'set', 'bgporigin', 'up')
    try:
        yield native
    finally:
        apply(native, {})
        run('ip', 'link', 'del', 'bgpa')
        run('ip', 'link', 'del', 'bgporigin')
        run('ip', 'link', 'del', 'BGPPeer')
        run('ip', 'link', 'del', 'BGPSource')


def test_ipv4_peer_exchange_and_withdrawal(peer_link):
    """Real eBGP exchanges a connected prefix between independent named VRFs."""
    filtering = {'route-map': {'import': 'BGP_TEST', 'export': 'BGP_TEST'}}
    configuration = {
        'BGPSource': {'local-as': '65000', 'parameters': {'router-id': '192.0.2.1'}, 'neighbor': {
            '198.18.0.2': {'remote-as': '65001', 'timers': {'connect': '1'}, 'address-family': {'ipv4-unicast': filtering}}},
            'address-family': {'ipv4-unicast': {'network': {'203.0.113.0/24': {}}}}},
        'BGPPeer': {'local-as': '65001', 'parameters': {'router-id': '192.0.2.2'}, 'neighbor': {
            '198.18.0.1': {'remote-as': '65000', 'timers': {'connect': '1'}, 'address-family': {'ipv4-unicast': filtering}}}},
    }
    apply(peer_link, configuration)

    def received():
        data = json.loads(run('vtysh', '-c', 'show bgp vrf BGPPeer ipv4 unicast 203.0.113.0/24 json'))
        return any(path.get('valid') and path.get('aspath', {}).get('string') == '65000' for path in data.get('paths', []))

    wait_for(received)
    wait_for(lambda: any(route.get('protocol') == 'bgp' for route in json.loads(
        run('ip', '-j', 'route', 'show', 'table', '503', '203.0.113.0/24'))))
    del configuration['BGPSource']['address-family']
    apply(peer_link, configuration)
    wait_for(lambda: not received())
    wait_for(lambda: not json.loads(run('ip', '-j', 'route', 'show', 'table', '503', '203.0.113.0/24')))


def test_ipv6_peer_exchange_and_withdrawal(peer_link):
    """IPv6 transport and NLRI work independently of IPv4 activation."""
    filtering = {'route-map': {'import': 'BGP_TEST', 'export': 'BGP_TEST'}}
    configuration = {
        'BGPSource': {'local-as': '65000', 'parameters': {'router-id': '192.0.2.1'}, 'neighbor': {
            '2001:db8:ffff::2': {'remote-as': '65001', 'timers': {'connect': '1'}, 'address-family': {'ipv6-unicast': filtering}}},
            'address-family': {'ipv6-unicast': {'network': {'2001:db8:100::/64': {}}}}},
        'BGPPeer': {'local-as': '65001', 'parameters': {'router-id': '192.0.2.2'}, 'neighbor': {
            '2001:db8:ffff::1': {'remote-as': '65000', 'timers': {'connect': '1'}, 'address-family': {'ipv6-unicast': filtering}}}},
    }
    apply(peer_link, configuration)

    def received():
        data = json.loads(run('vtysh', '-c', 'show bgp vrf BGPPeer ipv6 unicast 2001:db8:100::/64 json'))
        return any(path.get('valid') and path.get('aspath', {}).get('string') == '65000' for path in data.get('paths', []))

    wait_for(received)
    wait_for(lambda: any(route.get('protocol') == 'bgp' for route in json.loads(
        run('ip', '-6', '-j', 'route', 'show', 'table', '503', '2001:db8:100::/64'))))
    del configuration['BGPSource']['address-family']
    apply(peer_link, configuration)
    wait_for(lambda: not received())
    wait_for(lambda: not json.loads(run('ip', '-6', '-j', 'route', 'show', 'table', '503', '2001:db8:100::/64')))
