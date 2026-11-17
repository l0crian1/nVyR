"""Conflicting route next hops and AllowedIPs on a shared WireGuard interface.

Uses the existing two peers and right-side FRR daemon; no per-test topology.
The shared configuration fixture restores route, peer-prefix and BGP edits.
The outage case restores its native peer's link, addresses and return route.
Incompatible with removing the
NVYRLEFT VRF, its WireGuard interface or the native routed-peer BGP process.
"""
from contextlib import contextmanager
import json
import subprocess

import pytest

from nvyr.helpers.process import cmd, rc_cmd
from smoketests.support import wait_for


CASES = (
    (4, 'route', '10.0.0.0/8', '10.0.0.0/24', '10.1.0.0/24',
     '198.18.77.2', '198.18.77.6', '198.18.77.1', '10.1.0.2', '10.0.0.2', '10.0.0.88'),
    (6, 'route6', 'fd42:100::/48', 'fd42:100:0:1::/64', 'fd42:100:0:2::/64',
     '2001:db8:77::2', '2001:db8:77::6', '2001:db8:77::1',
     'fd42:100:0:2::2', 'fd42:100:0:1::2', 'fd42:100:0:1::88'),
)


def configure_routes(config, case):
    family, route, broad, specific, outside, first, second, *_ = case
    root = f'vrf name NVYRLEFT protocols static {route}'
    config.delete(f'delete {root} {specific}')
    config.delete(f'delete {root} {outside}')
    config.set(f'set {root} {broad} next-hop {first} interface wg42076')
    config.set(f'set {root} {specific} next-hop {second} interface wg42076')
    config.commit()
    return root


def expect_route(family, destination, gateway, *, protocol='static'):
    # FRR installs routes asynchronously; an initially missing route is a pending observation.
    _, output = wait_for(lambda: rc_cmd(['ip', f'-{family}', '-j', 'route', 'get',
                                        destination, 'vrf', 'NVYRLEFT']),
                         lambda result: result[0] == 0 and json.loads(result[1])[0].get('gateway') == gateway,
                         timeout=15, description=f'{destination} next hop {gateway}')
    routes = json.loads(output)
    assert routes[0]['dev'] == 'wg42076', routes
    _, output = wait_for(lambda: rc_cmd(['ip', f'-{family}', '-j', 'route', 'get', 'fibmatch',
                                        destination, 'vrf', 'NVYRLEFT']),
                         lambda result: result[0] == 0 and json.loads(result[1])[0].get('protocol') == protocol,
                         timeout=15, description=f'{destination} selected {protocol} route')
    installed = json.loads(output)
    print(f"IPv{family} FIB: {installed[0]['dst']} via {gateway} dev wg42076 ({protocol})")


@contextmanager
def capture_packet(namespace, interface, expression):
    process = subprocess.Popen(['ip', 'netns', 'exec', namespace, 'tcpdump', '-l', '-nn', '-v',
                                '-i', interface, '-c', '1', expression],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert 'listening on' in process.stderr.readline()
        yield
        output, error = process.communicate(timeout=5)
        assert process.returncode == 0 and output.strip(), (output, error)
        print(f'Captured on {namespace}/{interface}: {output.strip()}')
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)


def traffic(family, destination, *, specific=True, succeeds=True):
    namespace = 'nvyr-routed-left' if specific else 'nvyr-routed-right'
    interface = 'wg77' if specific else 'wg76'
    protocol = 'icmp and icmp[0] = 8' if family == 4 else 'icmp6 and ip6[40] = 128'
    with capture_packet(namespace, interface, f'{protocol} and dst host {destination}'):
        status, output = rc_cmd(['ping', f'-{family}', '-n', '-I', 'NVYRLEFT',
                                 '-c', '2', '-i', '0.2', '-W', '1', destination])
        if succeeds:
            assert status == 0 and ', 0% packet loss' in output, output
        else:
            assert status == 1 and '100% packet loss' in output, output
    print(f'IPv{family} {destination}: ' + ('2/2 replies' if succeeds else '0/2 replies, expected conflict'))


@pytest.mark.parametrize('case', CASES, ids=('ipv4', 'ipv6'))
def test_overlapping_routes_and_specific_route_withdrawal(config, case):
    family, _, _, specific, _, first, second, _, outside, inside, _ = case
    root = configure_routes(config, case)
    expect_route(family, outside, first)
    traffic(family, outside, specific=False)
    expect_route(family, inside, second)
    traffic(family, inside)

    config.delete(f'delete {root} {specific}')
    config.commit()
    expect_route(family, inside, first)
    # Removing the specific route does not remove the specific WireGuard peer lookup.
    traffic(family, inside)


@pytest.mark.parametrize('case', CASES, ids=('ipv4', 'ipv6'))
def test_competing_route_distances_do_not_override_allowedips(config, case):
    family, _, _, specific, _, first, second, _, _, inside, _ = case
    root = configure_routes(config, case)
    config.set(f'set {root} {specific} next-hop {first} interface wg42076')
    config.set(f'set {root} {specific} next-hop {first} distance 10')
    config.set(f'set {root} {specific} next-hop {second} distance 200')
    config.commit()
    expect_route(family, inside, first)
    traffic(family, inside)

    config.delete(f'delete {root} {specific} next-hop {first}')
    config.commit()
    expect_route(family, inside, second)
    traffic(family, inside)


@pytest.mark.parametrize('case', CASES, ids=('ipv4', 'ipv6'))
def test_conflicting_next_hop_loses_traffic_until_allowedips_matches(config, case):
    family, _, _, specific, _, first, _, _, _, _, conflict = case
    root = configure_routes(config, case)
    config.delete(f'delete {root} {specific}')
    config.set(f'set {root} {specific} next-hop {first} interface wg42076')
    config.commit()
    expect_route(family, conflict, first)
    # The destination exists only on the broad peer, but encryption selects the specific peer.
    traffic(family, conflict, succeeds=False)

    config.delete(f'delete interfaces wireguard wg42076 peer specific allowed-ips {specific}')
    config.commit()
    expect_route(family, conflict, first)
    traffic(family, conflict, specific=False)


@pytest.mark.parametrize('case', CASES, ids=('ipv4', 'ipv6'))
def test_unavailable_specific_peer_does_not_fall_back_to_broad_peer(config, case):
    family, _, _, specific, _, first, _, _, _, inside, _ = case
    root = configure_routes(config, case)
    config.delete(f'delete {root} {specific}')
    config.commit()
    expect_route(family, inside, first)
    traffic(family, inside)

    cmd(['ip', '-n', 'nvyr-routed-left', 'link', 'set', 'wg77', 'down'])
    try:
        # FIB fallback does not make WireGuard try another peer when its selected peer is down.
        with capture_packet('nvyr-routed-left', 'veth42074', 'udp dst port 52077'):
            status, output = rc_cmd(['ping', f'-{family}', '-n', '-I', 'NVYRLEFT',
                                     '-c', '2', '-i', '0.2', '-W', '1', inside])
            assert status == 1 and '100% packet loss' in output, output
        print(f'IPv{family}: specific peer down, 0/2 replies despite route via broad peer')
    finally:
        cmd(['ip', '-n', 'nvyr-routed-left', 'link', 'set', 'wg77', 'up'])
        # This native peer has no configuration manager: link-down removes its IPv6 addresses/routes.
        for address in ('2001:db8:77::6/128', 'fd42:100:0:1::2/128', 'fd42:100:0:2::99/128'):
            cmd(['ip', '-n', 'nvyr-routed-left', '-6', 'address', 'replace', address,
                 'dev', 'wg77', 'nodad'])
        cmd(['ip', '-n', 'nvyr-routed-left', '-6', 'route', 'replace', '2001:db8:77::1/128',
             'dev', 'wg77'])

    wait_for(lambda: rc_cmd(['ping', f'-{family}', '-n', '-I', 'NVYRLEFT', '-c', '1', '-W', '1', inside]),
             lambda result: result[0] == 0, timeout=20, description='specific peer recovery')
    traffic(family, inside)


def peer_commands(directory, commands):
    args = ['vtysh', '--vty_socket', str(directory), '-c', 'configure terminal', '-c', 'router bgp 65072']
    for command in commands:
        args.extend(['-c', command])
    cmd(args)


@pytest.mark.parametrize('case', CASES, ids=('ipv4', 'ipv6'))
def test_bgp_route_over_tunnel_does_not_override_allowedips(config, routed_peer, case):
    family, _, _, specific, _, first, _, local, _, inside, conflict = case
    root = configure_routes(config, case)
    config.delete(f'delete {root} {specific}')
    neighbor = f'vrf name NVYRLEFT protocols bgp neighbor {first}'
    config.set(f'set {neighbor} remote-as 65072 timers connect 1')
    config.set(f'set {neighbor} address-family ipv{family}-unicast route-map import RNCALL')
    config.commit()
    advertised = False
    try:
        peer_commands(routed_peer, [f'neighbor {local} remote-as 65061',
                      f'neighbor {local} timers connect 1', f'address-family ipv{family} unicast',
                      f'neighbor {local} activate', f'network {specific}'])
        advertised = True
        wait_for(lambda: json.loads(cmd(['vtysh', '-c', f'show bgp vrf NVYRLEFT neighbors {first} json'])),
                 lambda data: data.get(first, {}).get('bgpState') == 'Established',
                 timeout=30, description=f'IPv{family} BGP session over WireGuard')
        expect_route(family, inside, first, protocol='bgp')
        traffic(family, inside)
        traffic(family, conflict, succeeds=False)

        peer_commands(routed_peer, [f'address-family ipv{family} unicast', f'no network {specific}'])
        advertised = False
        expect_route(family, inside, first, protocol='static')
        traffic(family, inside)
    finally:
        peer_commands(routed_peer, [f'no neighbor {local}'])
        if advertised:
            peer_commands(routed_peer, [f'address-family ipv{family} unicast', f'no network {specific}'])
