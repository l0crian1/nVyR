"""Opt-in DHCPv4 options on real udhcpc, dnsmasq, Netlink and FRR.

Run in a disposable privileged container with NVYR_NETLINK_TEST=1.
FRR tests additionally require NVYR_RELOAD_TEST=1, running FRR daemons,
and root membership in frrvty for the isolated peer's Zebra process.
"""

import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from nvyr.helpers.link_manager import Manager
from nvyr.helpers.netlink import Kernel
from nvyr.op_scripts import dhcp as dhcp_op
from tests.test_netlink_live import ProcessDHCP, isolated, run, wait_for

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETLINK_TEST') != '1',
                                reason='requires disposable privileged DHCP lab')


@pytest.fixture
def dhcp_lab(tmp_path, isolated):
    """An isolated LAN and VRF keep test default routes away from management."""
    name, peer, namespace, vrf = 'eth97', 'dhcppeer97', 'nvyr-dhcp-options', 'DHCPTEST'
    kernel = Kernel()
    client = ProcessDHCP(tmp_path / 'runtime')
    manager = Manager(kernel, client, tmp_path / 'state')
    server = None
    run('ip', 'netns', 'add', namespace)
    try:
        run('ip', 'link', 'add', vrf, 'type', 'vrf', 'table', '597')
        run('ip', 'link', 'set', vrf, 'up')
        run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', peer)
        run('ip', 'link', 'set', peer, 'netns', namespace)
        run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
        run('ip', '-n', namespace, 'address', 'add', '198.18.97.1/24', 'dev', peer)
        run('ip', '-n', namespace, 'link', 'set', peer, 'up')
        server_log = tmp_path / 'server.log'
        with server_log.open('w') as output:
            server = subprocess.Popen([
                'ip', 'netns', 'exec', namespace, 'dnsmasq', '--keep-in-foreground', '--port=0',
                f'--interface={peer}', '--bind-interfaces', '--dhcp-authoritative',
                '--dhcp-range=198.18.97.20,198.18.97.30,255.255.255.0,2m',
                '--dhcp-option=26,1400',
                '--dhcp-option=121,203.0.113.0/24,198.18.97.1,0.0.0.0/0,198.18.97.1',
                '--dhcp-host=id:00:57:41:4e,198.18.97.21',
                '--dhcp-host=id:01:02:00:00:00:00:01,198.18.97.22',
                '--dhcp-vendorclass=set:vendor,ISP-vendor',
                '--dhcp-userclass=set:customer,customer',
                '--dhcp-option=tag:vendor,tag:customer,6,192.0.2.53',
                f'--dhcp-leasefile={tmp_path / "leases"}', '--log-dhcp', '--log-facility=-'],
                stdout=output, stderr=subprocess.STDOUT)
        definition = {'kind': 'ethernet', 'dhcp4': True,
                      'attributes': {'vrf': vrf, 'mtu': 1500}, 'dhcp-options': {}}

        def apply(options):
            definition['dhcp-options'] = options
            manager.replace('ethernet', {name: definition})

        def acquired():
            return client.lease(name, kernel.device(name)['index']) is not None

        yield SimpleNamespace(name=name, namespace=namespace, vrf=vrf, client=client,
                              kernel=kernel, manager=manager, apply=apply, acquired=acquired,
                              server_log=server_log, directory=tmp_path)
    finally:
        client.stop(name)
        if server is not None:
            server.terminate()
            server.wait(timeout=5)
        subprocess.run(['ip', 'link', 'del', name], capture_output=True)
        subprocess.run(['ip', 'link', 'del', vrf], capture_output=True)
        subprocess.run(['ip', 'netns', 'del', namespace], capture_output=True)
        kernel.close()


def test_real_client_text_identity_hostname_and_classes(dhcp_lab):
    """The server recognizes text identity and both class options, not just argv."""
    lab = dhcp_lab
    lab.apply({'client-id': {'text': 'WAN'}, 'host-name': 'dhcp-edge',
               'vendor-class-id': 'ISP-vendor', 'user-class': 'customer'})
    wait_for(lab.acquired, reconcile=lab.manager.reconcile)
    lease = lab.client._read('leases', lab.name)
    assert lease['address'] == '198.18.97.21/24'
    assert lease['dns'] == ['192.0.2.53']
    assert 'dhcp-edge' in lab.server_log.read_text()


def test_real_client_operational_state_and_suppressed_route(dhcp_lab, monkeypatch):
    """Display an actual udhcpc lease and confirm route policy against the kernel VRF table."""
    lab = dhcp_lab
    lab.apply({})
    wait_for(lab.acquired, reconcile=lab.manager.reconcile)
    lab.manager.reconcile()
    monkeypatch.setattr(dhcp_op.manager, 'request', lambda operation: lab.manager.status())
    monkeypatch.setattr(dhcp_op.dhcp, 'DHCP', lambda: lab.client)
    monkeypatch.setattr(dhcp_op.services, 'unit_properties', lambda units: {
        units[0]: {'ActiveState': 'active', 'MainPID': str(lab.client.process.pid)}})

    record, = json.loads(dhcp_op.show(interface=lab.name, raw=True))
    assert record['state'] == 'Bound' and record['address_installed']
    assert record['server'] == '198.18.97.1'
    assert record['vrf'] == 'DHCPTEST'
    assert record['default_route'] == 'Installed'
    assert record['distance'] == 210
    assert record['duration'] > 0 and record['expires_in'] > 0

    lab.apply({'no-default-route': True})
    record, = json.loads(dhcp_op.show(interface=lab.name, raw=True))
    assert record['gateway'] == '198.18.97.1'
    assert record['default_route'] == 'Suppressed by no-default-route'


def test_real_client_hex_identity_restarts_negotiation(dhcp_lab):
    """Changing the complete client identifier obtains the other reservation."""
    lab = dhcp_lab
    lab.apply({'client-id': {'text': 'WAN'}})
    wait_for(lab.acquired, reconcile=lab.manager.reconcile)
    token = lab.client._read('clients', lab.name)['token']
    lab.apply({'client-id': {'hex': '01:02:00:00:00:00:01'}})
    wait_for(lab.acquired, reconcile=lab.manager.reconcile)
    assert lab.client._read('clients', lab.name)['token'] != token
    assert lab.client._read('leases', lab.name)['address'] == '198.18.97.22/24'


def test_real_dhcp_mtu_default_route_policy_and_restore(dhcp_lab):
    """Lease policy changes retain the client and restore the configured MTU."""
    lab = dhcp_lab
    lab.apply({'mtu': True})
    wait_for(lab.acquired, reconcile=lab.manager.reconcile)
    lab.manager.reconcile()
    assert lab.kernel.device(lab.name)['attributes']['mtu'] == 1400
    routes = lab.kernel.routes(lab.name)
    default = next(route for route in routes if route['dst'] == '0.0.0.0/0' and route['protocol'] == 16)
    assert default['metric'] >> 24 == 210
    pid = lab.client.process.pid

    lab.apply({'default-route-distance': 10})
    assert lab.client.process.pid == pid
    assert lab.kernel.device(lab.name)['attributes']['mtu'] == 1500
    default = next(route for route in lab.kernel.routes(lab.name) if route['dst'] == '0.0.0.0/0' and route['protocol'] == 16)
    assert default['metric'] >> 24 == 10

    lab.apply({'mtu': True, 'no-default-route': True})
    routes = [route for route in lab.kernel.routes(lab.name) if route['protocol'] == 16]
    assert [route['dst'] for route in routes] == ['203.0.113.0/24']
    assert lab.kernel.device(lab.name)['attributes']['mtu'] == 1400
    lab.manager.dhcp_control(lab.name, 'release')
    wait_for(lambda: not lab.acquired(), reconcile=lab.manager.reconcile)
    assert lab.kernel.device(lab.name)['attributes']['mtu'] == 1500


def vty(*commands):
    arguments = ['vtysh']
    for command in commands:
        arguments.extend(['-c', command])
    return run(*arguments)


@pytest.mark.skipif(os.environ.get('NVYR_RELOAD_TEST') != '1', reason='requires FRR daemons')
def test_real_dhcp_ad_competes_with_static_and_bgp(dhcp_lab):
    """Verify RIB selection, kernel forwarding and fallback at real AD boundaries."""
    lab = dhcp_lab
    lab.apply({})
    wait_for(lab.acquired, reconcile=lab.manager.reconcile)
    peer_config = lab.directory / 'bgpd.conf'
    peer_config.write_text('router bgp 65097\n bgp router-id 198.18.97.1\n'
                           ' no bgp ebgp-requires-policy\n no bgp network import-check\n'
                           ' neighbor 198.18.97.21 remote-as 65098\n'
                           ' neighbor 198.18.97.21 ebgp-multihop 2\n'
                           ' address-family ipv4 unicast\n  network 0.0.0.0/0\n exit-address-family\n')
    peer = None
    peer_zebra = None

    def selected(protocol, distance):
        routes = json.loads(vty('show ip route vrf DHCPTEST 0.0.0.0/0 json')).get('0.0.0.0/0', [])
        return any(route.get('selected') and route['protocol'] == protocol and route['distance'] == distance
                   for route in routes)

    def forwarding_protocol():
        route = json.loads(run('ip', '-j', 'route', 'get', '192.0.2.1', 'vrf', 'DHCPTEST', 'fibmatch'))[0]
        return route.get('protocol')

    try:
        wait_for(lambda: selected('kernel', 210))
        vty('configure terminal', 'ip route 0.0.0.0/0 198.18.97.2 vrf DHCPTEST')
        wait_for(lambda: selected('static', 1))
        wait_for(lambda: forwarding_protocol() == 'static')
        vty('configure terminal', 'no ip route 0.0.0.0/0 198.18.97.2 vrf DHCPTEST')
        wait_for(lambda: selected('kernel', 210))
        wait_for(lambda: forwarding_protocol() == 'dhcp')

        lab.apply({'client-id': {'text': 'WAN'}})
        wait_for(lab.acquired, reconcile=lab.manager.reconcile)
        vty('configure terminal', 'router bgp 65098 vrf DHCPTEST', 'bgp router-id 198.18.97.21',
            'no bgp ebgp-requires-policy', 'neighbor 198.18.97.1 remote-as 65097')
        socket_directory = lab.directory / 'bgp-sockets'
        socket_directory.mkdir()
        zebra_socket = socket_directory / 'zserv.api'
        with (lab.directory / 'zebra.log').open('w') as output:
            peer_zebra = subprocess.Popen(['ip', 'netns', 'exec', lab.namespace, '/usr/lib/frr/zebra',
                                          '-N', 'dhcp-options-peer', '-u', 'root', '-g', 'root', '-f', '/dev/null',
                                          '-z', str(zebra_socket), '--vty_socket', str(socket_directory),
                                          '-i', str(lab.directory / 'zebra.pid'), '-P', '0'],
                                         stdout=output, stderr=subprocess.STDOUT)
        wait_for(lambda: zebra_socket.exists() or peer_zebra.poll() is not None)
        assert peer_zebra.poll() is None, (lab.directory / 'zebra.log').read_text()
        with (lab.directory / 'bgpd.log').open('w') as output:
            peer = subprocess.Popen(['ip', 'netns', 'exec', lab.namespace, '/usr/lib/frr/bgpd',
                                     '-N', 'dhcp-options-peer', '-S', '-z', str(zebra_socket),
                                     '-f', str(peer_config), '--vty_socket', str(socket_directory),
                                     '-i', str(lab.directory / 'bgpd.pid'), '-P', '0'],
                                    stdout=output, stderr=subprocess.STDOUT)
        wait_for(lambda: selected('bgp', 20), timeout=60)
        wait_for(lambda: forwarding_protocol() == 'bgp')

        lab.apply({'client-id': {'text': 'WAN'}, 'default-route-distance': 10})
        wait_for(lambda: selected('kernel', 10))
        wait_for(lambda: forwarding_protocol() == 'dhcp')
        lab.apply({'client-id': {'text': 'WAN'}, 'default-route-distance': 100})
        wait_for(lambda: selected('bgp', 20))
        wait_for(lambda: forwarding_protocol() == 'bgp')
        vty('configure terminal', 'no router bgp 65098 vrf DHCPTEST')
        wait_for(lambda: selected('kernel', 100))
        wait_for(lambda: forwarding_protocol() == 'dhcp')
    finally:
        if peer is not None:
            peer.terminate()
            peer.wait(timeout=10)
        if peer_zebra is not None:
            peer_zebra.terminate()
            peer_zebra.wait(timeout=10)
        remaining = vty('show running-config')
        if 'router bgp 65098 vrf DHCPTEST' in remaining:
            vty('configure terminal', 'no router bgp 65098 vrf DHCPTEST')
        if 'ip route 0.0.0.0/0 198.18.97.2 vrf DHCPTEST' in remaining:
            vty('configure terminal', 'no ip route 0.0.0.0/0 198.18.97.2 vrf DHCPTEST')
