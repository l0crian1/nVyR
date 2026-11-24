"""Two single-homed VTEPs, one stretched segment and two routed tenant subnets."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile
import time

from functionaltests.mpls_peer import processes
from nvyr.config_scripts import evpn_vni, policy, protocols_bgp
from nvyr.helpers import frr_bgp, frr_policy
from nvyr.helpers.process import cmd


def ip(ns, *words):
    return cmd(['ip', '-n', ns, *words])


def run(ns, *words):
    return cmd(['ip', 'netns', 'exec', ns, *words])


def underlay_vrf(ns, side):
    local = f'192.0.2.{side}'
    ip(ns, 'addr', 'add', local + '/30', 'dev', 'underlay')
    ip(ns, 'link', 'set', 'underlay', 'up')
    ip(ns, 'link', 'add', 'BLUE', 'type', 'vrf', 'table', '501')
    ip(ns, 'link', 'set', 'BLUE', 'up')
    return local


def setup_leaf(ns, side, *, local=None):
    if local is None:
        local = underlay_vrf(ns, side)
    else:
        ip(ns, 'link', 'add', 'BLUE', 'type', 'vrf', 'table', '501')
        ip(ns, 'link', 'set', 'BLUE', 'up')
    ip(ns, 'link', 'add', 'br0', 'type', 'bridge', 'vlan_filtering', '1', 'vlan_default_pvid', '0')
    ip(ns, 'link', 'set', 'br0', 'up')
    ip(ns, 'link', 'add', 'vx0', 'type', 'vxlan', 'external', 'local', local, 'dstport', '4789', 'nolearning')
    ip(ns, 'link', 'set', 'vx0', 'master', 'br0')
    ip(ns, 'link', 'set', 'vx0', 'up')
    run(ns, 'bridge', 'link', 'set', 'dev', 'vx0', 'learning', 'off', 'vlan_tunnel', 'on')
    for vlan, vni in [('10', '10010'), ('4000', '50000')]:
        run(ns, 'bridge', 'vlan', 'add', 'dev', 'vx0', 'vid', vlan)
        run(ns, 'bridge', 'vlan', 'add', 'dev', 'vx0', 'vid', vlan, 'tunnel_info', 'id', vni)
    run(ns, 'bridge', 'vlan', 'add', 'dev', 'br0', 'vid', '10', 'self')
    ip(ns, 'link', 'add', 'link', 'br0', 'name', 'gateway', 'type', 'vlan', 'id', '10')
    ip(ns, 'link', 'set', 'gateway', 'master', 'BLUE')
    ip(ns, 'link', 'set', 'gateway', 'address', '02:00:00:00:10:01', 'up')
    ip(ns, 'addr', 'add', '10.10.10.1/24', 'dev', 'gateway')
    ip(ns, 'addr', 'add', '2001:db8:10::1/64', 'dev', 'gateway', 'nodad')
    run(ns, 'bridge', 'vlan', 'add', 'dev', 'br0', 'vid', '4000', 'self')
    ip(ns, 'link', 'add', 'link', 'br0', 'name', 'l3svi', 'type', 'vlan', 'id', '4000')
    ip(ns, 'link', 'set', 'l3svi', 'master', 'BLUE')
    ip(ns, 'link', 'set', 'l3svi', 'addrgenmode', 'none')
    ip(ns, 'link', 'set', 'l3svi', 'address', f'02:00:00:00:50:0{side}', 'up')
    run(ns, 'sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')


def attach_host(leaf, host, side, *, routed):
    port = 'customer' if routed else 'access'
    ip(leaf, 'link', 'add', port, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', host)
    if routed:
        ip(leaf, 'link', 'set', port, 'master', 'BLUE')
        subnet, number = side, 10
        ip(leaf, 'addr', 'add', f'10.10.{subnet}.1/24', 'dev', port)
        ip(leaf, 'addr', 'add', f'2001:db8:{subnet}::1/64', 'dev', port, 'nodad')
    else:
        subnet, number = 10, side + 10
        ip(leaf, 'link', 'set', port, 'master', 'br0')
        run(leaf, 'bridge', 'vlan', 'add', 'dev', port, 'vid', '10', 'pvid', 'untagged')
    ip(leaf, 'link', 'set', port, 'up')
    if not routed:
        ip(host, 'link', 'set', 'eth0', 'address', f'02:00:00:10:00:0{side}')
    ip(host, 'link', 'set', 'eth0', 'up')
    ip(host, 'addr', 'add', f'10.10.{subnet}.{number}/24', 'dev', 'eth0')
    ip(host, 'addr', 'add', f'2001:db8:{subnet}::{number}/64', 'dev', 'eth0', 'nodad')
    ip(host, 'route', 'add', 'default', 'via', f'10.10.{subnet}.1')
    ip(host, '-6', 'route', 'add', 'default', 'via', f'2001:db8:{subnet}::1')


def configuration(side, *, peers=None):
    af = 'l2vpn-evpn'
    if peers is None:
        peers = {f'192.0.2.{3 - side}': {'remote-as': '65000', 'address-family': {af: {}}}}
    segment = {'route-distinguisher': f'192.0.2.{side}:10', 'route-target': {'both': ['65000:10']}}
    overlay = {'advertise-all-vni': {}, 'vni': {'10010': segment}}
    tenant = {'route-target': {'both': ['65000:500']},
              'advertise': {'ipv4-unicast': {'route-map': 'EXPORT4'}, 'ipv6-unicast': {}}}
    instances = {
        'default': {'local-as': '65000', 'parameters': {'router-id': f'192.0.2.{side}'},
                    'neighbor': peers,
                    'address-family': {af: overlay}},
        'BLUE': {'local-as': '65000', 'address-family': {af: tenant,
                 'ipv4-unicast': {'network': {f'10.10.{side}.0/24': {}}},
                 'ipv6-unicast': {'network': {f'2001:db8:{side}::/64': {}}}}}}
    settings = {'prefix-list': {'ipv4': {'LOCAL': {'rule': {'10': {
        'action': 'permit', 'prefix': f'10.10.{side}.0/24'}}}}},
        'route-map': {'EXPORT4': {'rule': {'10': {'action': 'permit', 'match': {'ipv4': {'prefix-list': 'LOCAL'}}}}}}}
    settings['access-list'] = {'mac': {'HOST2': {'rule': {
        '10': {'action': 'permit', 'address': '02:00:00:10:00:02'}}}}}
    settings['route-map']['FILTER-HOST'] = {'rule': {
        '10': {'action': 'deny', 'match': {'evpn': {'route-type': '2', 'vni': '10010',
                                                 'route-distinguisher': '192.0.2.2:10'},
                                         'mac': {'access-list': 'HOST2'}}},
        '20': {'action': 'permit'}}}
    native = evpn_vni.adapter.replace('', evpn_vni.generate({'BLUE': {'50000': {}}}, None))
    native = frr_policy.adapter.replace(native, policy.generate(settings, None))
    return frr_bgp.adapter.replace(native, protocols_bgp.generate({'instances': instances}, None))


def wait_for_route(leaf, directory, family, network, *, present=True):
    deadline = time.monotonic() + 40
    while True:
        routes = json.loads(ip(leaf, family, '-j', 'route', 'show', 'vrf', 'BLUE', 'exact', network))
        if bool(routes) == present:
            return
        assert time.monotonic() < deadline, (leaf, network, cmd([
            'vtysh', '--vty_socket', str(directory / leaf), '-c', 'show bgp l2vpn evpn route']))
        time.sleep(.25)


def test_dual_stack_l2_and_l3_forwarding():
    prefix = f'ev{os.getpid()}'
    leaves = [prefix + name for name in ('a', 'b')]
    layer2 = [leaf + 'l' for leaf in leaves]
    routed = [leaf + 'r' for leaf in leaves]
    with ExitStack() as cleanup:
        directory = Path(cleanup.enter_context(tempfile.TemporaryDirectory()))
        directory.chmod(0o755)
        for ns in [*leaves, *layer2, *routed]:
            cmd(['ip', 'netns', 'add', ns])
            cleanup.callback(cmd, ['ip', 'netns', 'del', ns])
            ip(ns, 'link', 'set', 'lo', 'up')
        ip(leaves[0], 'link', 'add', 'underlay', 'type', 'veth', 'peer', 'name', 'underlay', 'netns', leaves[1])
        for i, leaf in enumerate(leaves):
            setup_leaf(leaf, i + 1)
            attach_host(leaf, layer2[i], i + 1, routed=False)
            attach_host(leaf, routed[i], i + 1, routed=True)
            cleanup.enter_context(processes(directory / leaf, leaf, configuration(i + 1), daemons=('mgmtd', 'zebra', 'bgpd')))

        for i, leaf in enumerate(leaves):
            remote = 2 - i
            # Kernel routes in the tenant VRF confirm Type 5 import and nexthop programming.
            for family, network in [('-4', f'10.10.{remote}.0/24'), ('-6', f'2001:db8:{remote}::/64')]:
                wait_for_route(leaf, directory, family, network)

            for host, addresses in [(layer2[i], (f'10.10.10.{remote + 10}', f'2001:db8:10::{remote + 10}')),
                                    (routed[i], (f'10.10.{remote}.10', f'2001:db8:{remote}::10'))]:
                for address in addresses:
                    run(host, 'ping', '-n', '-c', '2', '-w', '5', address)

            for address in (f'10.10.{remote}.10', f'2001:db8:{remote}::10'):
                run(layer2[i], 'ping', '-n', '-c', '2', '-w', '5', address)

            remote_mac = json.loads(ip(layer2[1 - i], '-j', 'link', 'show', 'eth0'))[0]['address']
            fdb = json.loads(run(leaf, 'bridge', '-j', 'fdb', 'show', 'dev', 'vx0'))
            assert any(entry['mac'] == remote_mac and entry.get('dst') == f'192.0.2.{remote}' for entry in fdb), fdb

        # Withdraw only the IPv4 Type 5 export; IPv6 stays usable over the same L3VNI.
        peer_cli = ['vtysh', '--vty_socket', str(directory / leaves[1]), '-c', 'configure terminal',
                    '-c', 'router bgp 65000 vrf BLUE', '-c', 'address-family l2vpn evpn']
        cmd([*peer_cli, '-c', 'no advertise ipv4 unicast'])
        wait_for_route(leaves[0], directory, '-4', '10.10.2.0/24', present=False)
        run(routed[0], 'ping', '-n', '-c', '1', '-w', '3', '2001:db8:2::10')
        cmd([*peer_cli, '-c', 'advertise ipv4 unicast route-map EXPORT4'])
        wait_for_route(leaves[0], directory, '-4', '10.10.2.0/24')
        run(routed[0], 'ping', '-n', '-c', '1', '-w', '3', '10.10.2.10')

        # Observe the remote entry itself; unknown-unicast flooding can still deliver a ping.
        evpn_cli = ['vtysh', '--vty_socket', str(directory / leaves[1]), '-c', 'configure terminal',
                    '-c', 'router bgp 65000', '-c', 'address-family l2vpn evpn']
        for operation, expected in [('', False), ('no ', True)]:
            cmd([*evpn_cli, '-c', operation + 'neighbor 192.0.2.1 route-map FILTER-HOST out'])
            cmd(['vtysh', '--vty_socket', str(directory / leaves[1]), '-c', 'clear bgp l2vpn evpn 192.0.2.1 soft out'])
            deadline = time.monotonic() + 30
            while True:
                entries = json.loads(run(leaves[0], 'bridge', '-j', 'fdb', 'show', 'dev', 'vx0'))
                found = any(entry['mac'] == '02:00:00:10:00:02' and entry.get('dst') == '192.0.2.2' for entry in entries)
                if found == expected:
                    break
                assert time.monotonic() < deadline, entries
                time.sleep(.25)


def gateway_leaf(ns, side):
    local = underlay_vrf(ns, side)
    # FRR's gateway-IP model uses traditional bridges for both the shared L2VNI and L3VNI.
    for bridge, tunnel, vni in [('lan', 'vx30', '10030'), ('transit', 'vx50', '50000')]:
        ip(ns, 'link', 'add', bridge, 'type', 'bridge')
        ip(ns, 'link', 'set', bridge, 'master', 'BLUE')
        if bridge == 'transit':
            ip(ns, 'link', 'set', bridge, 'addrgenmode', 'none')
        ip(ns, 'link', 'set', bridge, 'address', f'02:00:00:{vni[:2]}:00:0{side}', 'up')
        ip(ns, 'link', 'add', tunnel, 'type', 'vxlan', 'id', vni, 'local', local, 'dstport', '4789', 'nolearning')
        ip(ns, 'link', 'set', tunnel, 'master', bridge)
        ip(ns, 'link', 'set', tunnel, 'up')
        run(ns, 'bridge', 'link', 'set', 'dev', tunnel, 'learning', 'off')
    ip(ns, 'addr', 'add', f'10.30.0.{side}/24', 'dev', 'lan')
    ip(ns, 'addr', 'add', f'2001:db8:30::{side}/64', 'dev', 'lan', 'nodad')


def gateway_configuration(side):
    af = 'l2vpn-evpn'
    local = f'192.0.2.{side}'
    peer = f'192.0.2.{3 - side}'
    settings = {'advertise-all-vni': {}, 'enable-resolve-overlay-index': {}}
    fabric = {'local-as': '65000', 'parameters': {'router-id': local}, 'address-family': {af: settings},
              'neighbor': {peer: {'remote-as': '65000', 'address-family': {af: {}}}}}
    tenant = {'local-as': '65000', 'parameters': {'router-id': local}}
    if side == 2:
        tenant['neighbor'] = {'10.30.0.99': {'remote-as': '65000', 'address-family': {'ipv4-unicast': {}}},
                              '2001:db8:30::99': {'remote-as': '65000', 'address-family': {'ipv4-unicast': {'disable': {}},
                                                                                        'ipv6-unicast': {}}}}
        tenant['address-family'] = {af: {'advertise': {'ipv4-unicast': {'gateway-ip': {}},
                                                       'ipv6-unicast': {'gateway-ip': {}}}}}
    native = evpn_vni.adapter.replace('', evpn_vni.generate({'BLUE': {'50000': {'prefix-routes-only': {}}}}, None))
    if side == 2:
        gateways = {'ipv4': '10.30.0.99', 'ipv6': '2001:db8:30::99'}
        rules = {'10': {'action': 'permit', 'match': {'evpn': {'route-type': '5'}},
                        'set': {'evpn': {'gateway-ip': gateways}}}, '20': {'action': 'permit'}}
        native = frr_policy.adapter.replace(native, policy.generate({'route-map': {'GATEWAY': {'rule': rules}}}, None))
    return frr_bgp.adapter.replace(native, protocols_bgp.generate({'instances': {'default': fabric, 'BLUE': tenant}}, None))


def test_recursive_gateway_ip():
    prefix = f'gw{os.getpid()}'
    left, right, host = [prefix + name for name in ('a', 'b', 'c')]
    with ExitStack() as cleanup:
        directory = Path(cleanup.enter_context(tempfile.TemporaryDirectory()))
        directory.chmod(0o755)
        for ns in (left, right, host):
            cmd(['ip', 'netns', 'add', ns])
            cleanup.callback(cmd, ['ip', 'netns', 'del', ns])
            ip(ns, 'link', 'set', 'lo', 'up')
        ip(left, 'link', 'add', 'underlay', 'type', 'veth', 'peer', 'name', 'underlay', 'netns', right)
        for side, leaf in enumerate((left, right), start=1):
            gateway_leaf(leaf, side)
            cleanup.enter_context(processes(directory / leaf, leaf, gateway_configuration(side), daemons=('mgmtd', 'zebra', 'bgpd')))

        ip(right, 'link', 'add', 'customer', 'type', 'veth', 'peer', 'name', 'eth0', 'netns', host)
        ip(right, 'link', 'set', 'customer', 'master', 'lan')
        ip(right, 'link', 'set', 'customer', 'up')
        ip(host, 'link', 'set', 'eth0', 'up')
        ip(host, 'addr', 'add', '10.30.0.99/24', 'dev', 'eth0')
        ip(host, 'addr', 'add', '2001:db8:30::99/64', 'dev', 'eth0', 'nodad')
        ip(host, 'addr', 'add', '198.51.100.99/32', 'dev', 'lo')
        ip(host, 'addr', 'add', '2001:db8:99::99/128', 'dev', 'lo', 'nodad')
        customer = {'default': {'local-as': '65000', 'parameters': {'router-id': '10.30.0.99'},
                                'neighbor': {'10.30.0.2': {'remote-as': '65000', 'address-family': {'ipv4-unicast': {}}},
                                             '2001:db8:30::2': {'remote-as': '65000', 'address-family': {
                                                 'ipv4-unicast': {'disable': {}}, 'ipv6-unicast': {}}}},
                                'address-family': {'ipv4-unicast': {'network': {'198.51.100.99/32': {}}},
                                                   'ipv6-unicast': {'network': {'2001:db8:99::99/128': {}}}}}}
        native = frr_bgp.adapter.replace('', protocols_bgp.generate({'instances': customer}, None))
        cleanup.enter_context(processes(directory / host, host, native, daemons=('mgmtd', 'zebra', 'bgpd')))

        destinations = [('-4', '10.30.0.99', '198.51.100.99/32'),
                        ('-6', '2001:db8:30::99', '2001:db8:99::99/128')]
        verify_gateway_paths(left, directory, destinations)

        # Withdraw before switching to explicit outbound route-map gateways.
        cli = ['vtysh', '--vty_socket', str(directory / right), '-c', 'configure terminal']
        tenant = [*cli, '-c', 'router bgp 65000 vrf BLUE', '-c', 'address-family l2vpn evpn']
        cmd([*tenant, '-c', 'no advertise ipv4 unicast', '-c', 'no advertise ipv6 unicast'])
        for family, _, network in destinations:
            wait_for_route(left, directory, family, network, present=False)
        cmd([*cli, '-c', 'router bgp 65000', '-c', 'address-family l2vpn evpn',
             '-c', 'neighbor 192.0.2.1 route-map GATEWAY out'])
        cmd([*tenant, '-c', 'advertise ipv4 unicast', '-c', 'advertise ipv6 unicast'])
        verify_gateway_paths(left, directory, destinations)


def verify_gateway_paths(leaf, directory, destinations):
    for family, gateway, network in destinations:
        wait_for_route(leaf, directory, family, network)
        address = network.split('/')[0]
        nexthop = json.loads(ip(leaf, family, '-j', 'route', 'get', address, 'vrf', 'BLUE'))[0]
        assert (nexthop.get('gateway'), nexthop['dev']) == (gateway, 'lan'), nexthop
        run(leaf, 'ip', 'vrf', 'exec', 'BLUE', 'ping', '-n', '-c', '2', '-w', '5', address)
