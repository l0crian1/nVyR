"""Verify local EVPN gateway forwarding across a move with the host's cached MAC."""

from contextlib import closing, contextmanager, ExitStack
from importlib.resources import files
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import pytest
from pyroute2 import netns

from functionaltests.mpls_peer import processes
from functionaltests.test_evpn import attach_host, configuration, ip, run, setup_leaf, wait_for_route
from nvyr.config_scripts import interface_bridge, interface_macvlan
from nvyr.controller import Controller
from nvyr.engine import Engine
from nvyr.helpers import interfaces as link_interfaces
from nvyr.helpers import interface_ip, vxlan
from nvyr.modules import registry
from nvyr.netlink_daemon import dispatch
from nvyr.schema import Schema
from nvyr.storage import Store
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
    links = interface_macvlan.generate(interface_macvlan.get_config(context), context)
    with managed_links(leaf, directory) as manager:
        manager.replace('macvlan', links)
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
        bridge = {'mtu': '1450', 'vif': {'10': {'mtu': '1450'}}}
        profile = {'mode': 'vepa', 'source-interface': 'br0.10'}
        context = SimpleNamespace(effective={'interfaces': {'bridge': {'br0': bridge},
                                                            'macvlan': {'macvlan0': profile}}})

        def apply(manager):
            links = interface_macvlan.generate(interface_macvlan.get_config(context), context)
            manager.replace('macvlan', links)
            return json.loads(interfaces.show(raw=True, intf_name='macvlan0', intf_type='macvlan'))[0]

        with managed_links(namespace, tmp_path) as manager:
            bridges = interface_bridge.generate(interface_bridge.get_config(context), context)
            manager.replace('bridge', bridges)
            initial = apply(manager)
            assert initial['link'] == 'br0.10'
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

            manager.replace('macvlan', {})
            assert manager.kernel.device('macvlan0') is None
            assert manager.kernel.device('br0.10') is not None
    finally:
        cmd(['ip', 'netns', 'del', namespace])


@pytest.mark.parametrize('stack', ['svi', 'macvlan-on-vxlan', 'vxlan-on-macvlan'])
def test_bridge_svi_overlay_commit_and_saved_replay(tmp_path, monkeypatch, stack):
    """Replay a saved overlay on fresh kernel devices and a fresh netlinkd journal."""
    root = json.loads(files('nvyr').joinpath('schemas/configuration.json').read_text())
    subtree = root['children']['interfaces']['children']
    kinds = ('ethernet', 'bond', 'virtual-ethernet', 'dummy', 'bridge', 'vxlan', 'macvlan')
    schema = Schema({'kind': 'node', 'children': {'interfaces': {
        'kind': 'node', 'children': {kind: subtree[kind] for kind in kinds}}}})
    store = Store(tmp_path / 'configd')

    macvlan_parent = 'vxlan9' if stack == 'macvlan-on-vxlan' else 'br0.10'
    vxlan_parent = 'macvlan0' if stack == 'vxlan-on-macvlan' else 'br0.10'

    for boot in ('initial', 'replay'):
        namespace = f'mv-{boot}-{os.getpid()}'
        cmd(['ip', 'netns', 'add', namespace])
        try:
            with managed_links(namespace, tmp_path / boot) as manager:
                def request(operation, **kwargs):
                    return dispatch(manager, dict(version=1, operation=operation, **kwargs))

                monkeypatch.setattr(link_interfaces.manager, 'request', request)
                engine = Engine(schema, registry(schema), store, boot_id=boot)
                assert not engine.startup_errors, engine.startup_errors
                session = engine.open('tester', 'console')
                cli = Controller(engine)
                if boot == 'initial':
                    if stack == 'macvlan-on-vxlan':
                        cli.execute('set interfaces vxlan vxlan9 vni 109 source-interface br0.10 destination-port 4790', session)
                    for line in (
                        'set interfaces bridge br0 vif 10 address 192.0.2.1/24',
                        f'set interfaces macvlan macvlan0 source-interface {macvlan_parent}',
                        f'set interfaces vxlan vxlan0 source-interface {vxlan_parent} external vlan 20 vni 12020',
                        'set interfaces bridge br1 vlan-filtering mtu 1450 member interface vxlan0',
                    ):
                        cli.execute(line, session)
                    result = engine.commit(session)
                    assert all(row['success'] for row in result['results'].values()), result
                    engine.save(session)

                claims = {'br0': 'bridge', 'br0.10': 'bridge', 'br1': 'bridge',
                          'vxlan0': 'vxlan', 'macvlan0': 'macvlan'}
                if stack == 'macvlan-on-vxlan':
                    claims['vxlan9'] = 'vxlan'
                assert manager.claims == claims
                assert manager.kernel.device('vxlan0')['attributes']['vrf'] == manager.kernel.device('br1')['index']
                assert vxlan.mappings('vxlan0') == {20: 12020}
                assert json.loads(cmd(['ip', '-j', 'link', 'show', 'macvlan0']))[0]['link'] == macvlan_parent
                native = json.loads(cmd(['ip', '-j', '-d', 'link', 'show', 'vxlan0']))[0]
                assert native['linkinfo']['info_data']['link'] == vxlan_parent

                if boot == 'replay':
                    cli.execute('set interfaces vxlan vxlan0 external vlan 20 vni 22020', session)
                    result = engine.commit(session)
                    assert all(row['success'] for row in result['results'].values()), result
                    assert vxlan.mappings('vxlan0') == {20: 22020}

                    engine.stage_configuration(session, {}, replace=True)
                    result = engine.commit(session)
                    assert all(row['success'] for row in result['results'].values()), result
                    assert not manager.claims and not manager.state['bridge-ports']
                    assert all(manager.kernel.device(name) is None for name in claims)
        finally:
            cmd(['ip', 'netns', 'del', namespace])
