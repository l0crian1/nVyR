"""Real kernel/DHCP tests: ONLY in a disposable privileged Docker container.

NVYR_NETLINK_TEST=1 PYTHONPATH=src pytest tests/test_netlink_live.py
Uses its own links, namespaces and daemon socket; no host networking/systemd needed.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from nvyr.errors import RouterError
from nvyr.helpers.dhcp import DHCP
from nvyr.helpers.dhcp_options import client_arguments
from nvyr.helpers.dns import Resolver
from nvyr.helpers.interfaces import NetlinkManager
from nvyr.helpers.link_manager import Manager
from nvyr.helpers.netlink import Kernel
from nvyr.storage import atomic_json

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETLINK_TEST') != '1',
                                reason='requires isolated privileged Netlink container')


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def wait_for(predicate, timeout=20, reconcile=lambda: None):
    deadline = time.monotonic() + timeout

    while True:
        reconcile()

        if predicate():
            return

        if time.monotonic() > deadline:
            raise AssertionError('Network state did not converge')

        time.sleep(.1)


def test_real_targeted_dumps_are_kernel_filtered(isolated):
    # No userspace filter: the response itself must exclude unrelated devices,
    # for both address families and DHCP routes.
    kernel = Kernel()
    created = []

    try:
        for number in (97, 98):
            name = f'dum{number}'
            run('ip', 'link', 'add', name, 'type', 'dummy')
            created.append(name)
            run('ip', 'link', 'set', name, 'up')
            run('ip', 'address', 'add', f'192.0.2.{number}/32', 'dev', name)
            run('ip', 'address', 'add', f'2001:db8::{number}/128', 'dev', name)
            run('ip', 'route', 'add', f'198.18.{number}.0/24', 'dev', name, 'proto', '16')

        index = kernel.device('dum97')['index']
        messages = kernel.address_dump(index)

        assert messages and all(m['index'] == index for m in messages)
        assert all(m['header']['flags'] & 0x20 for m in messages)  # NLM_F_DUMP_FILTERED

        with kernel.snapshot({'dum97'}):
            assert {'192.0.2.97/32', '2001:db8::97/128'} <= kernel.addresses('dum97').keys()
            assert [r['dst'] for r in kernel.routes('dum97') if r['protocol'] == 16] == ['198.18.97.0/24']
            assert set(kernel._addresses) == {index}
    finally:
        for name in created:
            run('ip', 'link', 'del', name)

        kernel.close()


@pytest.fixture
def isolated():
    assert Path('/.dockerenv').exists() and os.geteuid() == 0

    # Never use --network=host. Tests deliberately leave eth0 untouched.
    before = run('ip', '-j', 'address', 'show', 'dev', 'eth0')
    yield

    assert run('ip', '-j', 'address', 'show', 'dev', 'eth0') == before


@pytest.fixture
def daemon(tmp_path, isolated):
    path = tmp_path/'control.sock'
    processes = []

    def start():
        process = subprocess.Popen([sys.executable, '-m', 'nvyr.netlink_daemon', '--socket', str(path),
                                    '--state-dir', str(tmp_path/'state'), '--resolver-file', str(tmp_path/'resolv.conf')],
                                   stdout=open(tmp_path/'daemon.log', 'a'), stderr=subprocess.STDOUT)
        processes.append(process)
        wait_for(lambda: path.exists() or process.poll() is not None)

        assert process.poll() is None, (tmp_path/'daemon.log').read_text()

        return process

    process = start()
    yield NetlinkManager(path), process, start

    for item in processes:
        if item.poll() is None:
            item.terminate()
            item.wait(timeout=10)

    for name in ('dum98', 'eth98'):
        subprocess.run(['ip', 'link', 'del', name], capture_output=True)


def test_real_daemon_dummy_lifecycle_reconciliation_restart_and_errors(daemon):
    client, process, restart = daemon
    kernel = Kernel()

    try:
        definition = {'kind': 'dummy', 'attributes': {'mtu': 9000, 'mac': '02:11:22:33:44:98', 'description': 'Live dummy'},
                      'addresses': ['192.0.2.98/24', '2001:db8::98/64']}
        client.request('replace', owner='dummy', links={'dum98': definition})
        device = kernel.device('dum98')

        assert device['attributes']['mtu'] == 9000 and device['attributes']['description'] == 'Live dummy'
        assert device['up']
        assert set(kernel.addresses('dum98')) >= set(definition['addresses'])

        run('ip', 'link', 'set', 'dum98', 'down')
        wait_for(lambda: kernel.device('dum98')['up'])
        run('ip', 'link', 'del', 'dum98')
        wait_for(lambda: kernel.device('dum98') is not None)
        wait_for(lambda: set(kernel.addresses('dum98')) >= set(definition['addresses']))
        process.terminate()
        process.wait(timeout=10)
        restart()

        assert client.request('status')['owners']['dummy']['dum98']['attributes']['mtu'] == 9000

        # Valid at the wire boundary, rejected by the actual kernel. Compensation
        # must restore addresses/attributes and leave the daemon usable.
        bad = dict(definition, attributes={'mtu': 68})

        with pytest.raises(RouterError):
            client.request('replace', owner='dummy', links={'dum98': bad})

        assert kernel.device('dum98')['attributes']['mtu'] == 9000

        client.request('replace', owner='dummy', links={'dum98': dict(definition, disabled=True)})

        assert not kernel.device('dum98')['up'] and not kernel.addresses('dum98')

        client.request('replace', owner='dummy', links={})

        assert kernel.device('dum98') is None

        run('ip', 'link', 'add', 'dum98', 'type', 'dummy')

        with pytest.raises(RouterError, match='not owned'):
            client.request('replace', owner='dummy', links={'dum98': definition})
    finally:
        kernel.close()


def test_real_ethernet_static_attributes_routes_and_removal(daemon):
    client, _, _ = daemon
    kernel = Kernel()
    run('ip', 'link', 'add', 'eth98', 'type', 'veth', 'peer', 'name', 'nvyrpeer98')
    run('ip', 'link', 'set', 'nvyrpeer98', 'up')
    run('ip', 'link', 'set', 'eth98', 'mtu', '9000')

    try:
        baseline = kernel.device('eth98')['attributes']
        desired = {'kind': 'ethernet', 'attributes': {'mtu': 1500, 'description': 'Test port'},
                   'addresses': ['192.0.2.10/24', '192.0.2.11/24', '2001:db8::10/64']}
        client.request('replace', owner='ethernet', links={'eth98': desired})

        assert kernel.device('eth98')['up']
        assert set(kernel.addresses('eth98')) >= set(desired['addresses'])

        # MAC changes take the link down; any IPv6 addresses the kernel removes
        # during that transition must be reapplied before acknowledging success.
        desired['attributes']['mac'] = '02:11:22:33:44:97'
        client.request('replace', owner='ethernet', links={'eth98': desired})

        assert kernel.device('eth98')['attributes']['mac'] == desired['attributes']['mac']
        assert set(kernel.addresses('eth98')) >= set(desired['addresses'])

        run('ip', 'route', 'add', '203.0.113.0/24', 'dev', 'eth98', 'proto', '186')

        # Removing a primary address must retain a desired secondary in the same
        # prefix even when the kernel removes both on the primary delete.
        client.request('replace', owner='ethernet', links={'eth98': dict(desired, addresses=['192.0.2.11/24'])})

        assert '192.0.2.11/24' in kernel.addresses('eth98')
        assert any(route['protocol'] == 186 for route in kernel.routes('eth98'))

        client.request('replace', owner='ethernet', links={'eth98': dict(desired, disabled=True)})

        assert not kernel.device('eth98')['up'] and not kernel.addresses('eth98')

        client.request('replace', owner='ethernet', links={})

        assert kernel.device('eth98')['attributes'] == baseline
    finally:
        kernel.close()


def test_real_partial_bulk_delete_restores_cached_links(isolated, tmp_path, monkeypatch):
    kernel = Kernel()
    manager = Manager(kernel, DHCP(tmp_path/'runtime'), tmp_path/'state')
    links = {f'dum{900+i}': {'kind': 'dummy', 'addresses': [f'192.0.2.{i+1}/32']}
             for i in range(16)}
    original = kernel.delete_links

    def fail(devices):
        original(dict(list(devices.items())[:8]))
        raise RouterError('injected partial deletion')

    try:
        manager.replace('bulk-test', links)
        monkeypatch.setattr(kernel, 'delete_links', fail)

        with pytest.raises(RouterError, match='previous configuration restored'):
            manager.replace('bulk-test', {})

        assert not manager.state['pending']

        for name, definition in links.items():
            assert kernel.device(name)['up']
            assert set(definition['addresses']) <= kernel.addresses(name).keys()
    finally:
        monkeypatch.setattr(kernel, 'delete_links', original)
        manager.replace('bulk-test', {}, recovery=True)
        kernel.close()


def test_thousand_dual_stack_interfaces_over_rpc_and_targeted_recovery(daemon):
    client, _, _ = daemon
    kernel = Kernel()
    links = {f'dum{i+1000}': {'kind': 'dummy', 'addresses':
                            [f'198.18.{i//256}.{i%256}/32', f'2001:db8::{i+1:x}/128']}
             for i in range(1000)}

    try:
        # Uses the production 600-second client deadline and complete IPC path.
        client.request('replace', owner='scale', links=links)

        assert len(client.request('status')['owners']['scale']) == 1000
        assert set(kernel.addresses('dum1999')) >= set(links['dum1999']['addresses'])

        index = kernel.device('dum1500')['index']
        kernel.ipr.link('del', index=index)
        wait_for(lambda: kernel.device('dum1500') is not None)
        wait_for(lambda: set(kernel.addresses('dum1500')) >= set(links['dum1500']['addresses']))

        assert kernel.device('dum1500')['index'] != index
        assert kernel.device('dum1499')['up'] and kernel.device('dum1501')['up']
    finally:
        client.request('replace', owner='scale', links={})
        kernel.close()


def test_configd_commit_confirm_and_restart_use_real_daemon(daemon, tmp_path):
    from nvyr.protocol import Client

    backend, _, _ = daemon
    path = tmp_path/'configd.sock'
    startup = ('from nvyr.helpers import interfaces, nftables, ssh, frr_reload; '
               'frr_reload.manager.apply=lambda *a, **k: None; '
               'import logging; '
               'from nvyr.helpers import logging_runtime; '
               # Keep child-process failures in the captured test log, without a host logging service.
               'logging_runtime.configure_python=lambda name: logging.basicConfig(level=logging.INFO); '
               'logging_runtime.install=lambda *a, **k: None; '
               'logging_runtime.prepare_groups=lambda *a, **k: None; '
               'logging_runtime.cleanup=lambda *a, **k: None; '
               # This suite exercises real links, not firewall defaults in the container's kernel.
               'from contextlib import nullcontext; '
               'from nvyr.helpers import kernel_settings; '
               'kernel_settings.manager.transaction=lambda *a, **k: nullcontext(); '
               f'interfaces.manager = interfaces.NetlinkManager({backend.path!r}); '
               'nftables.manager.apply = lambda *args, **kwargs: None; '
               'ssh.manager.apply = lambda *args, **kwargs: None; '
               'from nvyr.helpers import accounts, system; '
               'accounts.manager.apply = lambda *args, **kwargs: None; '
               'system.apply_hostname = lambda *args, **kwargs: None; '
               'from nvyr.daemon import main; main()')

    def start():
        process = subprocess.Popen([sys.executable, '-c', startup, '--state', str(tmp_path/'configd-state'),
                                    '--socket', str(path)], stdout=open(tmp_path/'configd.log', 'a'), stderr=subprocess.STDOUT)
        wait_for(lambda: path.exists() or process.poll() is not None)

        assert process.poll() is None, (tmp_path/'configd.log').read_text()

        return process

    process, client, kernel = start(), None, Kernel()

    try:
        client = Client(path)
        client.request('open')
        client.request('execute', text='set vrf name BLUE table 100')
        client.request('execute', text='set vrf name RED table 256')
        client.request('execute', text='set interfaces dummy dum98 address 192.0.2.98/24')
        client.request('execute', text='set interfaces dummy dum98 vrf BLUE link-group 10')
        result = client.request('commit')

        assert result['results']['dummy']['success']
        assert '192.0.2.98/24' in kernel.addresses('dum98')
        assert kernel.device('dum98')['attributes']['vrf'] == kernel.device('BLUE')['index']

        client.request('execute', text='save')
        client.request('execute', text='set interfaces dummy dum98 disable')
        client.request('execute', text='set interfaces dummy dum98 vrf RED link-group 20')
        client.request('execute', text='commit-confirm 0.02', confirmation={'confirm_minutes': .02})

        assert not kernel.device('dum98')['up']
        assert kernel.device('dum98')['attributes']['vrf'] == kernel.device('RED')['index']

        wait_for(lambda: kernel.device('dum98')['up'])
        wait_for(lambda: '192.0.2.98/24' in kernel.addresses('dum98'))
        assert kernel.device('dum98')['attributes']['vrf'] == kernel.device('BLUE')['index']
        assert kernel.device('dum98')['attributes']['link-group'] == 10
        client.close()
        client = None
        process.terminate()
        process.wait(timeout=10)
        path.unlink(missing_ok=True)
        process = start()
        client = Client(path)
        client.request('open')

        assert '192.0.2.98/24' in kernel.addresses('dum98')
        assert kernel.device('dum98')['attributes']['vrf'] == kernel.device('BLUE')['index']

        client.request('execute', text='delete interfaces dummy dum98')
        result = client.request('commit')

        assert result['results']['dummy']['success']
        assert kernel.device('dum98') is None
        client.request('execute', text='delete vrf')
        assert client.request('commit')['results']['vrf']['success']
    finally:
        if client:
            client.close()

        process.terminate()
        process.wait(timeout=10)
        kernel.close()


class ProcessDHCP(DHCP):
    """Test the installed udhcpc binary without requiring systemd as container PID1.

Only service launch is replaced; production token/lease parsing and hooks run.
Clients remain separate processes when Manager is reconstructed.
"""

    def __init__(self, directory):
        super().__init__(directory, run=self.service)
        self.process = None
        self.hook = Path(directory)/'hook'
        self.hook.parent.mkdir(parents=True)
        self.hook.write_text(f'#!{sys.executable}\nfrom pathlib import Path\nfrom nvyr.helpers import dhcp\n'
                             f'dhcp.RUNTIME = Path({str(directory)!r})\ndhcp.hook_main()\n')
        self.hook.chmod(0o700)

    def service(self, args):
        if args[1] == 'kill':
            assert args[2] == '--kill-whom=main'
            self.process.send_signal(getattr(signal, args[3].removeprefix('--signal=')))
        elif args[1] == 'stop':
            if self.process is not None:
                self.process.terminate()
                self.process.wait(timeout=10)
                self.process = None
        elif self.process is None or self.process.poll() is not None:
            name = args[2].removeprefix('nvyr-dhcp4@').removesuffix('.service')
            data = self._read('clients', name)
            self.process = subprocess.Popen(client_arguments(name, data['options'], str(self.hook)),
                                            env=dict(os.environ, NVYR_DHCP_TOKEN=data['token'], NVYR_DHCP_INDEX=str(data['index'])),
                                            stdout=open(self.directory/'client.log', 'a'), stderr=subprocess.STDOUT)


def test_real_dhcp_vrf_attach_switch_detach_and_renew(tmp_path, isolated, monkeypatch):
    name, peer, namespace = 'eth97', 'nvyrpeer97', 'nvyr-dhcp-vrf'
    kernel, client, server = Kernel(), ProcessDHCP(tmp_path/'runtime'), None
    manager = Manager(kernel, client, tmp_path/'state')
    run('ip', 'netns', 'add', namespace)

    def assert_lease_routes(table):
        routes = [route for route in kernel.routes(name) if route['protocol'] == 16]
        assert {route['dst'] for route in routes} == {'0.0.0.0/0', '203.0.113.0/24'}
        assert all(route.get('table', 254) == table for route in routes)

    def renew():
        previous = client._read('leases', name)['expires']
        client.process.send_signal(signal.SIGUSR1)
        wait_for(lambda: client._read('leases', name).get('expires', 0) > previous,
                 reconcile=manager.reconcile)
        manager.reconcile()

    try:
        # A separate DHCP server supplies real leases without touching eth0.
        run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', peer)
        run('ip', 'link', 'set', peer, 'netns', namespace)
        run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
        run('ip', '-n', namespace, 'address', 'add', '198.18.0.1/24', 'dev', peer)
        run('ip', '-n', namespace, 'link', 'set', peer, 'up')
        server = subprocess.Popen([
            'ip', 'netns', 'exec', namespace, 'dnsmasq', '--keep-in-foreground', '--port=0',
            f'--interface={peer}', '--bind-interfaces', '--dhcp-authoritative',
            '--dhcp-range=198.18.0.20,198.18.0.30,255.255.255.0,2m',
            '--dhcp-option=121,203.0.113.0/24,198.18.0.1,0.0.0.0/0,198.18.0.1',
            f'--dhcp-leasefile={tmp_path/"server-leases"}'],
            stdout=open(tmp_path/'server.log', 'w'), stderr=subprocess.STDOUT)
        manager.replace('vrf', {'BLUE': {'kind': 'vrf', 'attributes': {'table': 100}},
                                'RED': {'kind': 'vrf', 'attributes': {'table': 256}}})
        desired = {name: {'kind': 'ethernet', 'dhcp4': True,
                          'attributes': {'vrf': ''}, 'addresses': ['2001:db8::20/64']}}
        manager.replace('ethernet', desired)
        wait_for(lambda: client.lease(name, kernel.device(name)['index']) is not None,
                 reconcile=manager.reconcile)
        manager.reconcile()
        assert_lease_routes(254)
        original_pid = client.process.pid

        # Existing leases are reapplied immediately; no bounce or renew is needed.
        desired[name]['attributes']['vrf'] = 'BLUE'
        manager.replace('ethernet', desired)
        assert_lease_routes(100)
        renew()
        assert_lease_routes(100)

        # A failed DHCP route write rolls membership and routes back together.
        original_route = kernel.route

        def fail_red_route(operation, interface, route):
            if operation == 'add' and route.get('table') == 256:
                raise OSError('injected DHCP route failure')

            return original_route(operation, interface, route)

        monkeypatch.setattr(kernel, 'route', fail_red_route)
        desired[name]['attributes']['vrf'] = 'RED'
        with pytest.raises(RouterError, match='previous configuration restored'):
            manager.replace('ethernet', desired)

        assert kernel.device(name)['attributes']['vrf'] == kernel.device('BLUE')['index']
        assert_lease_routes(100)
        monkeypatch.setattr(kernel, 'route', original_route)

        # Switching masters and returning to default leave no stale DHCP routes.
        desired[name]['attributes']['vrf'] = 'RED'
        manager.replace('ethernet', desired)
        assert_lease_routes(256)
        renew()
        assert_lease_routes(256)
        desired[name]['attributes']['vrf'] = ''
        manager.replace('ethernet', desired)
        assert_lease_routes(254)
        renew()
        assert_lease_routes(254)
        assert client.process.pid == original_pid
        assert '2001:db8::20/64' in kernel.addresses(name)

        # Acquiring a fresh lease while already inside a VRF uses the same path.
        manager.replace('ethernet', {})
        desired[name]['attributes']['vrf'] = 'BLUE'
        manager.replace('ethernet', desired)
        wait_for(lambda: client.lease(name, kernel.device(name)['index']) is not None,
                 reconcile=manager.reconcile)
        manager.reconcile()
        assert_lease_routes(100)
    finally:
        manager.replace('ethernet', {}, recovery=True)
        manager.replace('vrf', {}, recovery=True)
        client.stop(name)
        if server is not None:
            server.terminate()
            server.wait(timeout=5)

        subprocess.run(['ip', 'link', 'del', name], capture_output=True)
        subprocess.run(['ip', 'netns', 'del', namespace], capture_output=True)
        kernel.close()


def test_real_dhcp_acquire_renew_expire_release_and_manager_restart(tmp_path, isolated):
    name, peer, namespace = 'eth97', 'nvyrpeer97', 'nvyr-dhcp-test'
    kernel, client, server = Kernel(), ProcessDHCP(tmp_path/'runtime'), None
    run('ip', 'netns', 'add', namespace)

    try:
        run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', peer)
        run('ip', 'link', 'set', peer, 'netns', namespace)
        run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
        run('ip', '-n', namespace, 'address', 'add', '198.18.0.1/24', 'dev', peer)
        run('ip', '-n', namespace, 'link', 'set', peer, 'up')
        server = subprocess.Popen(['ip', 'netns', 'exec', namespace, 'dnsmasq', '--keep-in-foreground', '--port=0',
                                   f'--interface={peer}', '--bind-interfaces', '--dhcp-authoritative',
                                   '--dhcp-range=198.18.0.20,198.18.0.30,255.255.255.0,2m',
                                   '--dhcp-option=6,198.18.0.1,1.1.1.1',
                                   '--dhcp-option=121,203.0.113.0/24,198.18.0.1,0.0.0.0/0,198.18.0.1',
                                   f'--dhcp-leasefile={tmp_path/"server-leases"}', '--log-dhcp', '--log-facility=-'],
                                  stdout=open(tmp_path/'server.log', 'w'), stderr=subprocess.STDOUT)
        manager = Manager(kernel, client, tmp_path/'state')
        manager.resolver = Resolver(tmp_path/'state', manager.dns_servers, boot=manager.boot, path=tmp_path/'resolv.conf')
        manager.resolver.replace(['2606:4700:4700::1111', name])
        desired = {name: {'kind': 'ethernet', 'dhcp4': True, 'addresses': ['2001:db8::20/64']}}
        manager.replace('ethernet', desired)

        def acquired():
            return any(prefix.startswith('198.18.0.') for prefix in kernel.addresses(name))

        wait_for(acquired, reconcile=manager.reconcile)
        address = client._read('leases', name)['address']
        state = kernel.addresses(name)[address]
        remaining = int(client._read('leases', name)['expires'] - time.monotonic())

        assert abs(state['valid_lft'] - remaining) <= 2

        # Repeated maintenance must not replace the address or generate a new
        # RTM_NEWADDR event when the lease has not changed.
        index = kernel.device(name)['index']

        def stamp():
            return next(m.get_attr('IFA_CACHEINFO')['tstamp'] for m in kernel.address_dump(index)
                        if m.get_attr('IFA_ADDRESS') == address.split('/')[0])

        before = stamp()
        time.sleep(.1)
        manager.reconcile({name})

        assert stamp() == before

        wait_for(lambda: 'nameserver 198.18.0.1' in manager.resolver.path.read_text(), reconcile=manager.reconcile)

        assert 'nameserver 2606:4700:4700::1111' in manager.resolver.path.read_text()

        wait_for(lambda: len([r for r in kernel.routes(name) if r['protocol'] == 16]) == 2, reconcile=manager.reconcile)

        assert '2001:db8::20/64' in kernel.addresses(name)

        first_pid = client.process.pid
        first = client._read('leases', name)['expires']
        time.sleep(1)
        from nvyr.netlink_daemon import dispatch
        dispatch(manager, {'version': 1, 'operation': 'dhcp-renew', 'interface': name})
        wait_for(lambda: client._read('leases', name).get('expires', 0) > first, reconcile=manager.reconcile)
        manager = Manager(kernel, client, tmp_path/'state')
        manager.resolver = Resolver(tmp_path/'state', manager.dns_servers, boot=manager.boot, path=tmp_path/'resolv.conf')
        manager.replace('ethernet', desired, recovery=True)
        manager.reconcile()

        assert 'nameserver 198.18.0.1' in manager.resolver.path.read_text()
        assert client.process.pid == first_pid and acquired()

        # Release follows the real hook, removing only leased addresses/routes/DNS.
        dispatch(manager, {'version': 1, 'operation': 'dhcp-release', 'interface': name})
        wait_for(lambda: not acquired(), reconcile=manager.reconcile)
        assert not any(route['protocol'] == 16 for route in kernel.routes(name))
        assert 'nameserver 198.18.0.1' not in manager.resolver.path.read_text()
        assert '2001:db8::20/64' in kernel.addresses(name)
        assert client.process.pid == first_pid
        wait_for(lambda: 'DHCPRELEASE' in (tmp_path/'server.log').read_text())

        # Periodic service checks must not restart a deliberately released client.
        client.checked.clear()
        manager.reconcile()
        assert not acquired() and client.process.pid == first_pid
        dispatch(manager, {'version': 1, 'operation': 'dhcp-renew', 'interface': name})
        wait_for(acquired, reconcile=manager.reconcile)

        # Reproduce expiration without waiting two minutes; the real lease event
        # drives actual address and DHCP route deletion, leaving static IPv6.
        expired = client._read('leases', name)
        expired['expires'] = time.monotonic()-1
        atomic_json(client._path('leases', name), expired)
        manager.reconcile()

        assert not acquired() and not any(r['protocol'] == 16 for r in kernel.routes(name))
        assert 'nameserver 198.18.0.1' not in manager.resolver.path.read_text()
        assert '2001:db8::20/64' in kernel.addresses(name)

        client.process.send_signal(signal.SIGUSR1)
        wait_for(acquired, reconcile=manager.reconcile)
        manager.replace('ethernet', {})
        manager.reconcile()

        assert 'nameserver 198.18.0.1' not in manager.resolver.path.read_text()
        assert client.process is None and not kernel.addresses(name)

        wait_for(lambda: 'DHCPRELEASE' in (tmp_path/'server.log').read_text())
    finally:
        client.stop(name)

        if server is not None:
            server.terminate()
            server.wait(timeout=5)

        subprocess.run(['ip', 'link', 'del', name], capture_output=True)
        subprocess.run(['ip', 'netns', 'del', namespace], capture_output=True)
        kernel.close()
