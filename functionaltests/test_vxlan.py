"""An independent Linux VTEP exercises nVyR fixed and multi-VNI forwarding."""

import json

import pytest

from functionaltests.native_network import native_namespace
from nvyr.helpers.process import cmd, rc_cmd
from smoketests.support import configuration_case


def peer(namespace, *args):
    return cmd(['ip', 'netns', 'exec', namespace, *args])


@pytest.fixture(scope='module')
def underlay(native_namespace):
    host, remote = 'vx-test-u', 'vx-test-peer'
    cmd(['ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', remote, 'netns', native_namespace])
    try:
        for ns, name, suffix in ((None, host, 1), (native_namespace, remote, 2)):
            ip = ['ip', '-n', ns] if ns else ['ip']
            cmd([*ip, 'link', 'set', name, 'up'])
            cmd([*ip, 'address', 'add', f'198.18.251.{suffix}/30', 'dev', name])
            cmd([*ip, 'address', 'add', f'2001:db8:251::{suffix}/64', 'dev', name, 'nodad'])
        yield native_namespace
    finally:
        cmd(['ip', 'link', 'del', host])


@pytest.fixture(autouse=True)
def restore(config, request, underlay):
    with configuration_case(config, request, config.get_config()):
        yield


def ping_both(namespace, subnet):
    args = ['ping', '-n', '-c', '1', '-W', '2']
    cmd([*args, subnet + '.2'])
    peer(namespace, *args, subnet + '.1')


def peer_tunnel(namespace, name, vni, local, remote, subnet):
    peer(namespace, 'ip', 'link', 'add', name, 'type', 'vxlan', 'id', str(vni), 'dstport', '4789',
         'local', local, 'remote', remote)
    peer(namespace, 'ip', 'link', 'set', name, 'up')
    peer(namespace, 'ip', 'address', 'add', subnet + '.2/24', 'dev', name)


@pytest.mark.parametrize('family', [4, 6])
def test_fixed_vni(config, underlay, family):
    prefix = '198.18.251.' if family == 4 else '2001:db8:251::'
    path = 'interfaces vxlan vxlan491'
    subnet = '198.18.248'
    peer_tunnel(underlay, 'fixed', 1491, prefix + '2', prefix + '1', subnet)
    try:
        peer(underlay, 'ip', 'address', 'add', '2001:db8:248::2/64', 'dev', 'fixed', 'nodad')
        config.set(f'set {path} vni 1491 source-address {prefix}1 destination-port 4789')
        config.set(f'set {path} address {subnet}.1/24 flood-vtep {prefix}2')
        config.set(f'set {path} address 2001:db8:248::1/64')
        config.commit()
        ping_both(underlay, subnet)
        cmd(['ping', '-6', '-n', '-c', '1', '-W', '2', '2001:db8:248::2'])
        peer(underlay, 'ping', '-6', '-n', '-c', '1', '-W', '2', '2001:db8:248::1')
        fdb = json.loads(cmd(['vxlan.nvyr.op', 'show', '--interface', 'vxlan491', '--section', 'fdb', '--raw']))
        assert any(row['mac'] == '00:00:00:00:00:00' and row['dst'] == prefix + '2' for row in fdb)

        before = json.loads(cmd(['ip', '-j', 'link', 'show', 'vxlan491']))[0]['ifindex']
        config.set(f'set {path} remote {prefix}2 ttl 33 tos 16')
        config.delete(f'delete {path} flood-vtep {prefix}2')
        config.commit()
        device = json.loads(cmd(['vxlan.nvyr.op', 'show', '--interface', 'vxlan491', '--raw']))[0]
        assert device['ifindex'] == before
        assert device['linkinfo']['info_data']['ttl'] == 33
        assert int(device['linkinfo']['info_data']['tos'], 16) == 16
        ping_both(underlay, subnet)
    finally:
        peer(underlay, 'ip', 'link', 'del', 'fixed')


def test_external_two_vnis(config, underlay):
    local, remote = '198.18.251.1', '198.18.251.2'
    path = 'interfaces vxlan vxlan492'
    bridge = 'interfaces bridge br492'
    config.set(f'set {path} source-address {local} destination-port 4789 external vni-filter')
    config.set(f'set {bridge} vlan-filtering default-pvid 0 member interface vxlan492')
    for vid in (10, 11):
        vni = 12000 + vid
        config.set(f'set {path} external vlan {vid} vni {vni}')
        config.set(f'set {bridge} vif {vid} address 198.19.{vid}.1/24')
        peer_tunnel(underlay, f'peer{vid}', vni, remote, local, f'198.19.{vid}')
    config.commit()

    for vid in (10, 11):
        # Stand in for a controller installing the per-VNI flood destination.
        cmd(['bridge', 'fdb', 'append', '00:00:00:00:00:00', 'dev', 'vxlan492',
             'self', 'dst', remote, 'src_vni', str(12000 + vid)])
        ping_both(underlay, f'198.19.{vid}')

    def view():
        return json.loads(cmd(['vxlan.nvyr.op', 'show', '--interface', 'vxlan492', '--section', 'vni', '--raw']))

    assert view() == [{'vlan': vid, 'vni': 12000 + vid, 'admitted': True} for vid in (10, 11)]
    entries = json.loads(cmd(['bridge.nvyr.op', 'show', '--bridge', 'br492', '--section', 'vlan', '--raw']))
    mapped = next(row['vlans'] for row in entries if row['ifname'] == 'vxlan492')
    assert [(row['vlan'], row['vni']) for row in mapped] == [(10, 12010), (11, 12011)]

    config.delete(f'delete {path} external vlan 10')
    config.commit()
    assert view() == [{'vlan': 11, 'vni': 12011, 'admitted': True}]
    assert rc_cmd(['ping', '-n', '-c', '1', '-W', '1', '198.19.10.2'])[0] == 1
    ping_both(underlay, '198.19.11')


def test_multicast_with_bridge_underlay_and_overlay(config, underlay):
    """Commit both bridges at once, then pass traffic to a multicast VTEP."""
    config.set('set interfaces virtual-ethernet veth4930 peer-name veth4931')
    config.set('set interfaces virtual-ethernet veth4931 peer-name veth4930')
    config.set('set interfaces bridge br493 address 198.18.249.1/30 member interface veth4930')
    config.set('set interfaces vxlan vxlan493 vni 1493 source-interface br493 source-address 198.18.249.1')
    config.set('set interfaces vxlan vxlan493 multicast-group 239.19.24.93 destination-port 4789')
    config.set('set interfaces bridge br494 mtu 1450 address 198.19.249.1/24 member interface vxlan493')
    config.commit()

    cmd(['ip', 'link', 'add', 'link', 'veth4931', 'name', 'vx-mc-u', 'netns', underlay,
         'type', 'macvlan', 'mode', 'bridge'])
    peer(underlay, 'ip', 'link', 'set', 'vx-mc-u', 'up')
    peer(underlay, 'ip', 'address', 'add', '198.18.249.2/30', 'dev', 'vx-mc-u')
    peer(underlay, 'ip', 'link', 'add', 'vx-mc-peer', 'type', 'vxlan', 'id', '1493', 'dstport', '4789',
         'local', '198.18.249.2', 'group', '239.19.24.93', 'dev', 'vx-mc-u')
    peer(underlay, 'ip', 'link', 'set', 'vx-mc-peer', 'up')
    peer(underlay, 'ip', 'address', 'add', '198.19.249.2/24', 'dev', 'vx-mc-peer')
    ping_both(underlay, '198.19.249')

    mac = json.loads(peer(underlay, 'ip', '-j', 'link', 'show', 'vx-mc-peer'))[0]['address']
    config.set('set interfaces vxlan vxlan493 learning disable')
    config.set(f'set interfaces vxlan vxlan493 static-mac {mac} remote 198.18.249.2')
    config.commit()
    def static_destinations():
        rows = json.loads(cmd(['vxlan.nvyr.op', 'show', '--interface', 'vxlan493', '--section', 'fdb', '--raw']))
        return {(row['mac'], row.get('dst')) for row in rows if row.get('state') == 'permanent'}

    assert (mac, '198.18.249.2') in static_destinations()
    ping_both(underlay, '198.19.249')
    config.delete(f'delete interfaces vxlan vxlan493 static-mac {mac}')
    config.commit()
    assert (mac, '198.18.249.2') not in static_destinations()
