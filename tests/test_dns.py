import json
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import system_dns
from nvyr.errors import RecoveryError, RouterError, ValidationError
from nvyr.helpers import dns, interfaces
from nvyr.helpers.dhcp import DHCP, lease_event
from nvyr.helpers.link_manager import Manager
from nvyr.netlink_daemon import Server, dispatch
from nvyr.schema import Schema
from nvyr.storage import atomic_json
from tests.test_netlink import Kernel, spec


@pytest.fixture
def backend(tmp_path):
    kernel = Kernel()

    for name in ('eth1', 'eth2'):
        kernel.add(name)

    manager = Manager(kernel, DHCP(tmp_path/'leases', run=lambda args: None), tmp_path/'state', boot='first')
    manager.resolver = dns.Resolver(manager.path.parent, manager.dns_servers, boot=manager.boot,
                                    path=tmp_path/'resolv.conf')
    manager.replace('ethernet', {name: spec(dhcp4=True) for name in ('eth1', 'eth2')})

    return manager


def lease(backend, name, addresses, **changes):
    client = backend.dhcp._read('clients', name)
    event = lease_event('bound', {'NVYR_DHCP_TOKEN': client['token'], 'NVYR_DHCP_INDEX': str(client['index']),
                                 'ip': '192.0.2.10', 'subnet': '255.255.255.0', 'lease': '60',
                                 'dns': ' '.join(addresses)})
    event.update(changes)
    atomic_json(backend.dhcp._path('leases', name), event)


def servers(backend):
    return [line.split()[1] for line in backend.resolver.path.read_text().splitlines() if line.startswith('nameserver ')]


def test_observation_tracks_published_servers_and_precedence(backend):
    lease(backend, 'eth1', ['1.1.1.1', '8.8.8.8'])
    lease(backend, 'eth2', ['9.9.9.9'])
    backend.resolver.replace(['eth1', '1.1.1.1'])

    result = dispatch(backend, {'version': 1, 'operation': 'dns-status'})
    assert result == {'servers': [
        {'server': '1.1.1.1', 'source': 'Static', 'interface': None},
        {'server': '8.8.8.8', 'source': 'DHCP', 'interface': 'eth1'},
    ], 'pending': False, 'error': None}

    # A fresh daemon reconstructs provenance from the published servers and valid leases.
    backend.resolver.published = None
    assert backend.resolver.observation()['servers'] == result['servers']

    lease(backend, 'eth1', ['8.8.8.8'], expires=time.monotonic() - 1)
    backend.reconcile()
    assert len(backend.resolver.observation()['servers']) == 1


def test_observation_does_not_claim_failed_publication_succeeded(backend, monkeypatch):
    lease(backend, 'eth1', ['8.8.8.8'])
    backend.resolver.replace(['eth1'])
    lease(backend, 'eth1', ['9.9.9.9'])

    def fail(*args, **kwargs):
        raise OSError('read-only filesystem')

    monkeypatch.setattr(dns, 'write', fail)
    backend.reconcile()
    result = dispatch(backend, {'version': 1, 'operation': 'dns-status'})
    assert result['servers'] == [{'server': '8.8.8.8', 'source': 'DHCP', 'interface': 'eth1'}]
    assert 'read-only filesystem' in result['error']


def test_aggregation_renewal_expiry_fencing_and_idempotence(backend):
    lease(backend, 'eth1', ['1.1.1.1', '8.8.8.8'])
    lease(backend, 'eth2', ['8.8.8.8', '9.9.9.9'])
    backend.resolver.replace(['eth1', '2606:4700:4700::1111', '1.1.1.1', 'eth2',
                              '2606:4700:4700:0:0:0:0:1111', 'eth99'])

    assert servers(backend) == ['2606:4700:4700::1111', '1.1.1.1', '8.8.8.8', '9.9.9.9']

    inode = backend.resolver.path.stat().st_ino
    backend.reconcile()

    assert backend.resolver.path.stat().st_ino == inode
    assert backend.resolver.path.stat().st_mode & 0o777 == 0o644

    lease(backend, 'eth1', ['4.4.4.4'])
    backend.reconcile()  # No DNS configuration operation or commit.

    assert servers(backend) == ['2606:4700:4700::1111', '1.1.1.1', '4.4.4.4', '8.8.8.8', '9.9.9.9']

    lease(backend, 'eth1', ['4.4.4.4'], expires=time.monotonic()-1)
    lease(backend, 'eth2', ['9.9.9.9'], token='obsolete-client')
    backend.reconcile()

    assert servers(backend) == ['2606:4700:4700::1111', '1.1.1.1']

    lease(backend, 'eth1', ['4.4.4.4'], event='deconfig')
    lease(backend, 'eth2', ['9.9.9.9'], index=999)
    backend.reconcile()

    assert servers(backend) == ['2606:4700:4700::1111', '1.1.1.1']


@pytest.mark.parametrize('change', ['unplug', 'remove', 'disable', 'no-dhcp', 'replace', 'pending'])
def test_unusable_interfaces_contribute_no_dns(backend, change):
    lease(backend, 'eth1', ['8.8.8.8'])
    backend.resolver.replace(['1.1.1.1', 'eth1'])

    assert servers(backend) == ['1.1.1.1', '8.8.8.8']

    if change == 'unplug':
        del backend.kernel.devices['eth1']
    elif change == 'replace':
        backend.kernel.add('eth1')
    elif change == 'pending':
        backend.state['pending']['ethernet'] = {'before': {}, 'after': {}}
    else:
        links = {'eth2': spec(dhcp4=True)}

        if change != 'remove':
            links['eth1'] = spec(dhcp4=change != 'no-dhcp', disabled=change == 'disable')

        backend.replace('ethernet', links)

    backend.reconcile()

    assert servers(backend) == ['1.1.1.1']


def test_restarts_new_boot_and_configuration_removal(backend):
    lease(backend, 'eth1', ['8.8.8.8'])
    backend.resolver.replace(['1.1.1.1', 'eth1'])
    restarted = Manager(backend.kernel, backend.dhcp, backend.path.parent, boot='first')
    restarted.resolver = dns.Resolver(backend.path.parent, restarted.dns_servers, boot='first', path=backend.resolver.path)
    restarted.reconcile()

    assert servers(restarted) == ['1.1.1.1', '8.8.8.8']

    restarted.resolver = dns.Resolver(backend.path.parent, restarted.dns_servers, boot='second', path=backend.resolver.path)
    restarted.resolver.reconcile()

    assert servers(restarted) == []  # Unsaved previous-boot intent is discarded.

    restarted.resolver.replace(['9.9.9.9'], recovery=True)

    assert servers(restarted) == ['9.9.9.9']

    restarted.resolver.replace([])

    assert servers(restarted) == []


def test_ipv6_learned_data_can_use_the_same_aggregator(tmp_path):
    resolver = dns.Resolver(tmp_path, lambda name: ['2001:db8::53', '2001:0db8::53'],
                            boot='first', path=tmp_path/'resolv.conf')
    resolver.replace(['eth1', '2001:db8::53'])

    assert resolver.path.read_text().count('nameserver 2001:db8::53') == 1


def test_write_failure_compensation_pending_recovery_and_async_retry(backend, monkeypatch):
    backend.resolver.replace(['1.1.1.1'])
    original = dns.write

    def reject(path, text, **kw):
        if '9.9.9.9' in text:
            raise OSError('read-only resolver directory')

        return original(path, text, **kw)

    monkeypatch.setattr(dns, 'write', reject)

    with pytest.raises(RouterError, match='previous configuration restored'):
        backend.resolver.replace(['9.9.9.9'])

    assert servers(backend) == ['1.1.1.1']
    assert 'pending' not in json.loads(backend.resolver.journal.read_text())

    with pytest.raises(RecoveryError, match='DNS recovery failed'):
        backend.resolver.replace(['9.9.9.9'], recovery=True)

    restarted = dns.Resolver(backend.path.parent, backend.dns_servers, boot='first', path=backend.resolver.path)

    with pytest.raises(RecoveryError, match='incomplete transaction'):
        restarted.replace([])

    restarted.reconcile()

    assert servers(backend) == ['1.1.1.1']

    monkeypatch.setattr(dns, 'write', original)
    restarted.replace(['1.1.1.1'], recovery=True)
    backend.resolver = restarted
    backend.resolver.replace(['eth1'])
    lease(backend, 'eth1', ['9.9.9.9'])
    monkeypatch.setattr(dns, 'write', reject)
    backend.reconcile()

    assert 'DNS:' in backend.error and servers(backend) == []

    monkeypatch.setattr(dns, 'write', original)
    backend.reconcile()

    assert backend.error is None and servers(backend) == ['9.9.9.9']


def test_cli_schema_lifecycle_and_independent_hostname_owner(controller, engine, session, monkeypatch):
    calls = []
    monkeypatch.setattr(interfaces, 'manager', SimpleNamespace(request=lambda *args, **kw: calls.append((args, kw))))

    for value in ('1.1.1.1', '2606:4700:4700::1111', 'eth0', 'eth1'):
        controller.execute('set system name-server ' + value, session)

    assert engine.commit(session)['results']['dns']['success']
    assert calls[-1] == (('replace-dns',), {'sources': ['1.1.1.1', '2606:4700:4700::1111', 'eth0', 'eth1'], 'recovery': False})
    assert engine.schema.owners['dns'][0] == ('system', 'name-server')

    controller.execute('set system host-name test', session)

    assert set(engine.commit(session)['results']) == {'system'}
    assert len(calls) == 1

    controller.execute('delete system name-server', session)

    assert engine.commit(session)['results']['dns']['success']
    assert calls[-1][1]['sources'] == []


@pytest.mark.parametrize('value', ['1.1.1.999', '1.1.1.1/32', '2001:db8::1/64', '../eth0', 'eth0\nnameserver 8.8.8.8', 'x'*16])
def test_invalid_dns_sources_are_rejected_by_schema(value):
    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration({'system': {'name-server': [value]}})


def test_dns_rpc_and_lost_response_are_recoverable(backend, tmp_path, monkeypatch):
    path = tmp_path/'control.sock'
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen()
    server = Server(backend, path)
    monkeypatch.setattr(server, 'authorized', lambda connection: True)
    client = interfaces.NetlinkManager(path)
    thread = threading.Thread(target=lambda: server.handle(listener.accept()[0]))
    thread.start()

    try:
        client.request('replace-dns', sources=['1.1.1.1'])
        thread.join(5)

        assert servers(backend) == ['1.1.1.1']

        def lost_reply():
            from nvyr.protocol import receive

            connection, _ = listener.accept()

            with connection:
                dispatch(backend, receive(connection))

        thread = threading.Thread(target=lost_reply)
        thread.start()

        with pytest.raises(RecoveryError, match='lost apply reply'):
            client.request('replace-dns', sources=['8.8.8.8'])

        thread.join(5)

        assert servers(backend) == ['8.8.8.8']

        for sources in (None, {}, [1]):
            with pytest.raises(ValidationError):
                dispatch(backend, {'version': 1, 'operation': 'replace-dns', 'sources': sources})
    finally:
        listener.close()


def test_event_loop_updates_dns_without_another_configuration_request(backend, tmp_path, monkeypatch):
    server = Server(backend, tmp_path/'event.sock')
    monkeypatch.setattr(server, 'authorized', lambda connection: True)
    ready = threading.Event()
    thread = threading.Thread(target=lambda: server.run(ready=ready.set))
    thread.start()

    def wait_for(expected):
        deadline = time.monotonic()+6

        while servers(backend) != expected:
            assert thread.is_alive() and time.monotonic() < deadline

            time.sleep(.05)

    try:
        assert ready.wait(5)

        client = interfaces.NetlinkManager(server.path)
        client.request('replace-dns', sources=['1.1.1.1', 'eth1'])
        lease(backend, 'eth1', ['8.8.8.8'])
        wait_for(['1.1.1.1', '8.8.8.8'])
        lease(backend, 'eth1', ['9.9.9.9'], event='renew')
        wait_for(['1.1.1.1', '9.9.9.9'])
        client.request('replace', owner='ethernet', links={})
        wait_for(['1.1.1.1'])
    finally:
        server.running = False
        thread.join(5)

        assert not thread.is_alive()


def test_configd_confirmed_rollback_save_restart_and_failed_apply(backend, tmp_path, monkeypatch):
    from nvyr.controller import Controller
    from nvyr.engine import Engine
    from tests.lifecycle import recorded_registry
    from nvyr.storage import Store

    def request(operation, **arguments):
        return dispatch(backend, dict(version=1, operation=operation, **arguments))

    monkeypatch.setattr(interfaces.manager, 'request', request)
    schema = Schema.bundled()
    now = [100.0]
    store = Store(tmp_path/'configd')
    engine = Engine(schema, recorded_registry(schema), store, clock=lambda: now[0])
    session = engine.open('test', 'console')
    cli = Controller(engine)
    cli.execute('set system name-server 1.1.1.1', session)

    assert engine.commit(session)['results']['dns']['success']

    engine.save(session)
    cli.execute('delete system name-server', session)
    cli.execute('set system name-server 9.9.9.9', session)
    engine.commit(session, minutes=1, confirmed_minutes=1)

    assert servers(backend) == ['9.9.9.9']

    now[0] = 161
    engine.tick()

    assert servers(backend) == ['1.1.1.1']

    Engine(schema, recorded_registry(schema), store)

    assert servers(backend) == ['1.1.1.1']
    assert store.read('boot.json')['system']['name-server'] == ['1.1.1.1']

    cli.execute('set system name-server 8.8.8.8', session)

    def fail(*args, **kwargs):
        raise OSError('resolver write failed')

    monkeypatch.setattr(dns, 'write', fail)

    assert not engine.commit(session)['results']['dns']['success']
    assert servers(backend) == ['1.1.1.1']
    assert engine.view(session)['system']['name-server'] == ['1.1.1.1', '8.8.8.8']


def test_journal_failure_after_publication_compensates(backend, monkeypatch):
    backend.resolver.replace(['1.1.1.1'])
    save = backend.resolver.save
    calls = 0

    def fail_once():
        nonlocal calls
        calls += 1

        if calls == 2:
            raise OSError('journal fsync failed')

        save()

    monkeypatch.setattr(backend.resolver, 'save', fail_once)

    with pytest.raises(RouterError, match='previous configuration restored'):
        backend.resolver.replace(['9.9.9.9'])

    assert servers(backend) == ['1.1.1.1']
    assert json.loads(backend.resolver.journal.read_text())['sources'] == ['1.1.1.1']
