"""Verify local EVPN gateway forwarding across a move with the host's cached MAC."""

from contextlib import closing, contextmanager, ExitStack
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest
from pyroute2 import netns

from functionaltests.mpls_peer import processes
from functionaltests.test_evpn import attach_host, configuration, ip, run, setup_leaf, wait_for_route
from nvyr.config_scripts import interface_bridge
from nvyr.helpers import interface_ip
from nvyr.helpers.dhcp import DHCP
from nvyr.helpers.link_manager import Manager
from nvyr.helpers.netlink import Kernel
from nvyr.helpers.process import cmd
from nvyr.op_scripts import interfaces

GATEWAY_MAC = '02:00:00:00:10:01'


@contextmanager
def managed_links(namespace, directory):
    netns.pushns(namespace)
    try:
        with closing(Kernel()) as kernel:
            kernel.ip_controller = interface_ip.Controller(secret=directory / 'secret', profile=directory / 'sysctl.conf')
            yield Manager(kernel, DHCP(directory / 'dhcp'), directory / 'state')
    finally:
        netns.popns()


def configure_gateway(leaf, mode, directory):
    profile = {'source-interface': 'gateway', 'vrf': 'BLUE', 'mode': mode, 'mac': GATEWAY_MAC,
               'address': ['10.10.10.1/24', '2001:db8:10::1/64'],
               'ipv6': {'duplicate-address-detection': {'disable': True}}}
    context = SimpleNamespace(effective={'interfaces': {'macvlan': {'macvlan10': profile}}})
    links = interface_bridge.generate(interface_bridge.get_config(context), context)
    with managed_links(leaf, directory) as manager:
        manager.replace('bridge', links)
        state = json.loads(interfaces.show(raw=True, intf_name='macvlan10'))[0]
        assert state['link'] == 'gateway' and state['address'] == GATEWAY_MAC
        assert state['linkinfo']['info_data']['mode'] == mode

    run(leaf, 'bridge', 'fdb', 'replace', GATEWAY_MAC, 'dev', 'br0', 'self', 'local', 'vlan', '10')
    run(leaf, 'nft', 'add', 'table', 'netdev', 'probe')
    run(leaf, 'nft', 'add', 'chain', 'netdev', 'probe', 'gateway',
        '{ type filter hook ingress device macvlan10 priority 0; }')
    run(leaf, 'nft', 'add', 'counter', 'netdev', 'probe', 'routed')
    run(leaf, 'nft', 'add', 'rule', 'netdev', 'probe', 'gateway', 'ip', 'saddr', '10.10.10.11',
        'ip', 'daddr', '10.10.2.10', 'icmp', 'type', 'echo-request', 'counter', 'name', 'routed')


def received(leaf):
    data = json.loads(run(leaf, 'nft', '-j', 'list', 'counter', 'netdev', 'probe', 'routed'))
    return next(row['counter']['packets'] for row in data['nftables'] if 'counter' in row)


@pytest.mark.parametrize('mode', ['vepa', 'private'])
def test_gateway_stays_local_after_host_move(mode):
    prefix = f'mv{os.getpid()}'
    first, second, mobile, target = [prefix + suffix for suffix in 'abmt']
    with ExitStack() as cleanup:
        root = Path(cleanup.enter_context(TemporaryDirectory()))
        root.chmod(0o755)
        for name in (first, second, mobile, target):
            cmd(['ip', 'netns', 'add', name])
            cleanup.callback(cmd, ['ip', 'netns', 'del', name])
            ip(name, 'link', 'set', 'lo', 'up')
        ip(first, 'link', 'add', 'underlay', 'type', 'veth', 'peer', 'name', 'underlay', 'netns', second)
        for side, leaf in enumerate((first, second), 1):
            setup_leaf(leaf, side, shared_svi=False)
            configure_gateway(leaf, mode, root / (leaf + '-state'))
            cleanup.enter_context(processes(root / leaf, leaf, configuration(side),
                                            daemons=('mgmtd', 'zebra', 'bgpd')))
        attach_host(first, mobile, 1, routed=False)
        attach_host(second, target, 2, routed=True)
        wait_for_route(first, root, '-4', '10.10.2.0/24')
        wait_for_route(first, root, '-6', '2001:db8:2::/64')

        # Learn the real gateway MAC first, then pin it so re-resolution cannot mask a broken move.
        for address in ('10.10.10.1', '2001:db8:10::1'):
            run(mobile, 'ping', '-n', '-c', '1', '-w', '5', address)
            neighbor = json.loads(ip(mobile, '-j', 'neigh', 'show', 'to', address, 'dev', 'eth0'))[0]
            assert neighbor['lladdr'] == GATEWAY_MAC
            ip(mobile, 'neigh', 'replace', address, 'lladdr', GATEWAY_MAC, 'nud', 'permanent', 'dev', 'eth0')

        for origin, other in [(first, second), (second, first)]:
            if origin == second:
                ip(first, 'link', 'set', 'access', 'nomaster')
                ip(first, 'link', 'set', 'access', 'netns', second)
                ip(second, 'link', 'set', 'access', 'master', 'br0')
                run(second, 'bridge', 'vlan', 'add', 'dev', 'access', 'vid', '10', 'pvid', 'untagged')
                ip(second, 'link', 'set', 'access', 'up')
            for gateway in ('10.10.10.1', '2001:db8:10::1'):
                neighbor = json.loads(ip(mobile, '-j', 'neigh', 'show', 'to', gateway, 'dev', 'eth0'))[0]
                assert neighbor['lladdr'] == GATEWAY_MAC and 'PERMANENT' in neighbor['state']
            before, elsewhere = received(origin), received(other)
            for address in ('10.10.2.10', '2001:db8:2::10'):
                run(mobile, 'ping', '-n', '-c', '2', '-w', '5', address)
            assert received(origin) == before + 2
            assert received(other) == elsewhere


def test_macvlan_edit_and_removal(tmp_path):
    namespace = f'mv-edit{os.getpid()}'
    cmd(['ip', 'netns', 'add', namespace])
    try:
        ip(namespace, 'link', 'add', 'uplink', 'type', 'dummy')
        ip(namespace, 'link', 'set', 'uplink', 'mtu', '1450', 'up')
        profile = {'mode': 'vepa', 'source-interface': 'uplink'}
        context = SimpleNamespace(effective={'interfaces': {'macvlan': {'macvlan0': profile}}})

        def apply(manager):
            links = interface_bridge.generate(interface_bridge.get_config(context), context)
            manager.replace('bridge', links)
            return json.loads(interfaces.show(raw=True, intf_name='macvlan0', intf_type='macvlan'))[0]

        with managed_links(namespace, tmp_path) as manager:
            initial = apply(manager)
            assert initial['mtu'] == 1450 and initial['linkinfo']['info_data']['mode'] == 'vepa'
            profile.update(mode='private', mac=GATEWAY_MAC, mtu='1400', disable=True)
            edited = apply(manager)
            assert edited['ifindex'] == initial['ifindex'] and 'UP' not in edited['flags']
            assert edited['linkinfo']['info_data']['mode'] == 'private'
            assert edited['mtu'] == 1400 and edited['address'] == GATEWAY_MAC

            for key in ('mac', 'mtu', 'disable'):
                del profile[key]
            restored = apply(manager)
            assert restored['address'] == initial['address'] and restored['mtu'] == 1450
            assert restored['ifindex'] == initial['ifindex'] and 'UP' in restored['flags']

            manager.replace('bridge', {})
            assert manager.kernel.device('macvlan0') is None
            assert manager.kernel.device('uplink') is not None
    finally:
        cmd(['ip', 'netns', 'del', namespace])
