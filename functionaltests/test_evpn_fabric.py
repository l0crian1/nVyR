"""Single-homed EVPN over a routed underlay, with a spine reflecting three leaves."""

from contextlib import ExitStack
import json
import os
from pathlib import Path
import tempfile

import pytest

from functionaltests.mpls_peer import processes
from functionaltests.test_evpn import attach_host, configuration, ip, run, setup_leaf, wait_for_route
from nvyr.config_scripts import protocols_bgp
from nvyr.helpers import frr_bgp
from nvyr.helpers.process import cmd
from smoketests.support import wait_for


def bgp_peer(local, *, client=False):
    options = {'route-reflector-client': {}} if client else {}
    return {'remote-as': '65000', 'update-source': local, 'address-family': {'l2vpn-evpn': options}}


def underlay(spine, leaves, ipv6):
    """One routed point-to-point link per leaf. All BGP and VTEP addresses are loopbacks."""
    run(spine, 'sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
    family, hostlen = ('-6', 128) if ipv6 else ('-4', 32)
    flags = ['nodad'] if ipv6 else []
    routers = [spine, *leaves]
    local = {ns: f'2001:db8:ffff::{i}' if ipv6 else f'198.51.100.{i}' for i, ns in enumerate(routers, 1)}
    for ns in routers:
        ip(ns, family, 'addr', 'add', f'{local[ns]}/{hostlen}', 'dev', 'lo', *flags)

    for i, leaf in enumerate(leaves, 1):
        spine_port = f'leaf{i}'
        ip(spine, 'link', 'add', spine_port, 'type', 'veth', 'peer', 'name', 'underlay', 'netns', leaf)
        if ipv6:
            gateway, endpoint, length = f'2001:db8:{i}:ff::1', f'2001:db8:{i}:ff::2', 64
        else:
            gateway, endpoint, length = f'192.0.2.{4*i+1}', f'192.0.2.{4*i+2}', 30
        for ns, port, address in [(spine, spine_port, gateway), (leaf, 'underlay', endpoint)]:
            ip(ns, 'link', 'set', port, 'up')
            ip(ns, family, 'addr', 'add', f'{address}/{length}', 'dev', port, *flags)
        ip(spine, family, 'route', 'add', f'{local[leaf]}/{hostlen}', 'via', endpoint)
        for remote in routers:
            if remote != leaf:
                ip(leaf, family, 'route', 'add', f'{local[remote]}/{hostlen}', 'via', gateway)
    return local


def show(directory, node, line):
    return cmd(['vtysh', '--vty_socket', str(directory / node), '-c', line])


def verify_remote_host(directory, observer, mac, vtep, reflector):
    # Unknown-unicast flooding can deliver a ping while the remote MAC is missing.
    def destinations():
        entries = json.loads(run(observer, 'bridge', '-j', 'fdb', 'show', 'dev', 'vx0'))
        return {row['dst'] for row in entries if row['mac'] == mac and 'dst' in row}

    wait_for(destinations, lambda values: values == {vtep}, description=f'{mac} installed toward {vtep}', timeout=30)
    # The MAC-only path and both MAC/IP routes must come through the reflector
    # with the originating leaf as next hop, including after the move.
    for command in (f'show bgp vni 10010 type 2 mac {mac}',
                    f'show bgp l2vpn evpn route vni 10010 mac {mac} ip 10.10.10.11',
                    f'show bgp l2vpn evpn route vni 10010 mac {mac} ip 2001:db8:10::11'):
        def selected():
            route = json.loads(show(directory, observer, command + ' json'))
            return [(path['peer']['peerId'], hop['ip'])
                    for group in route.get('paths', []) for path in group
                    if path.get('bestpath', {}).get('overall')
                    for hop in path['nexthops'] if hop.get('used')]

        wait_for(selected, lambda paths: paths == [(reflector, vtep)],
                 description=f'{command} via {vtep}', timeout=30)


@pytest.mark.parametrize('ipv6', [False, True], ids=['ipv4-vteps', 'ipv6-vteps'])
def test_reflection_forwarding_and_mac_move(ipv6):
    prefix = f'ef{os.getpid()}'
    spine = prefix + 's'
    leaves = [prefix + suffix for suffix in 'abc']
    first, second, observer = leaves
    mobile, station = prefix + 'm', prefix + 'h'
    west, east = prefix + 'w', prefix + 'e'

    with ExitStack() as cleanup:
        directory = Path(cleanup.enter_context(tempfile.TemporaryDirectory()))
        directory.chmod(0o755)
        for ns in [spine, *leaves, mobile, station, west, east]:
            cmd(['ip', 'netns', 'add', ns])
            cleanup.callback(cmd, ['ip', 'netns', 'del', ns])
            ip(ns, 'link', 'set', 'lo', 'up')
        local = underlay(spine, leaves, ipv6)
        peers = {local[leaf]: bgp_peer(local[spine], client=True) for leaf in leaves}
        rr = {'default': {'local-as': '65000', 'parameters': {'router-id': '192.0.2.254'}, 'neighbor': peers}}
        config = frr_bgp.adapter.replace('', protocols_bgp.generate({'instances': rr}, None))
        daemons = ('mgmtd', 'zebra', 'bgpd')
        cleanup.enter_context(processes(directory / spine, spine, config, daemons=daemons))

        for i, leaf in enumerate(leaves, 1):
            setup_leaf(leaf, i, local=local[leaf])
            if leaf == first:
                attach_host(leaf, mobile, i, routed=False)
                attach_host(leaf, west, i, routed=True)
            elif leaf == observer:
                attach_host(leaf, station, i, routed=False)
                attach_host(leaf, east, i, routed=True)
            config = configuration(i, peers={local[spine]: bgp_peer(local[leaf])})
            cleanup.enter_context(processes(directory / leaf, leaf, config, daemons=daemons))

        # Only the reflector peers with the leaves. The kernel imports the remote Type 5s.
        for family, subnet, address in [('-4', '10.10.1.0/24', '10.10.1.10'),
                                        ('-6', '2001:db8:1::/64', '2001:db8:1::10')]:
            wait_for_route(observer, directory, family, subnet)
            run(east, 'ping', '-n', '-c', '2', '-w', '5', address)

        flood = json.loads(run(observer, 'bridge', '-j', 'fdb', 'show', 'dev', 'vx0'))
        destinations = {row.get('dst') for row in flood if row['mac'] == '00:00:00:00:00:00'}
        assert {local[first], local[second]} <= destinations
        assert local[spine] not in destinations
        assert not json.loads(ip(spine, '-j', 'link', 'show', 'type', 'vxlan'))

        mac = '02:00:00:10:00:01'
        for origin in [first, second]:
            if origin == second:
                # Move the access port itself. The host retains its NIC, MAC and both IPs.
                ip(first, 'link', 'set', 'access', 'nomaster')
                ip(first, 'link', 'set', 'access', 'netns', second)
                ip(second, 'link', 'set', 'access', 'master', 'br0')
                run(second, 'bridge', 'vlan', 'add', 'dev', 'access', 'vid', '10', 'pvid', 'untagged')
                ip(second, 'link', 'set', 'access', 'up')
            for address in ('10.10.10.1', '2001:db8:10::1', '10.10.10.13', '2001:db8:10::13'):
                run(mobile, 'ping', '-n', '-c', '2', '-w', '5', address)
            verify_remote_host(directory, observer, mac, local[origin], local[spine])
            for address in ('10.10.10.11', '2001:db8:10::11'):
                run(station, 'ping', '-n', '-c', '2', '-w', '5', address)
