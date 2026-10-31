from contextlib import nullcontext
from copy import deepcopy
import gc
import json
import socket
import threading
import time
import weakref
from types import SimpleNamespace

import pytest

from nvyr.errors import RecoveryError, RouterError, ValidationError
from nvyr.helpers.dhcp import DHCP, lease_event
from nvyr.helpers.interfaces import NetlinkManager
from nvyr.helpers.link_manager import Manager
from nvyr.helpers.netlink import LinkType, Dummy, NetlinkKey, LINK_KEYMAP, read_attributes, normalize, Kernel as RealKernel
from nvyr.netlink_daemon import Server, dispatch, Schedule, receive_events
from nvyr.protocol import encode, receive
from nvyr.storage import atomic_json
from nvyr.helpers.vrf_rules import reconcile as reconcile_vrf_rules
from tests.test_vrf_rules import RuleSocket, dump as rule_dump


class Message(dict):
    def get_attr(self, key):
        return self.get(key)


class Kernel:
    decode_link = staticmethod(RealKernel.decode_link)

    def __init__(self):
        self.devices, self.ips, self.routing = {}, {}, {}
        self.next_index = 1
        self.ipr = SimpleNamespace(link=self.link)
        self.rule_socket = RuleSocket()

    def vrf_rules(self):
        reconcile_vrf_rules(self.rule_socket, rule_dump)

    # This in-memory backend applies writes immediately and reads current state;
    # there is no cached dump or pending address batch to refresh or flush.
    def snapshot(self, names=None):
        return nullcontext()

    def refresh(self, name):
        pass

    def refresh_addresses(self):
        pass

    def flush_addresses(self, *, verify=True):
        pass

    def add(self, name, kind=''):
        self.next_index += 1
        self.devices[name] = {'index': self.next_index, 'kind': kind, 'up': False, 'carrier': True,
                              'attributes': {'mac': '02:00:00:00:00:01', 'mtu': 1500, 'description': '',
                                             'vrf': 0, 'link-group': 0}}

    def device(self, name):
        device = deepcopy(self.devices.get(name))
        if device:
            attrs = device['attributes']
            device['message'] = Message(IFLA_MTU=attrs['mtu'], IFLA_ADDRESS=attrs['mac'], IFLA_IFALIAS=attrs['description'])
            device['message'].update(IFLA_MASTER=attrs['vrf'], IFLA_GROUP=attrs['link-group'])

        return device

    def link(self, operation, **args):
        if operation == 'add':
            self.add(args['ifname'], args['kind'])
            return

        name = next(name for name, dev in self.devices.items() if dev['index'] == args['index'])

        if operation == 'del':
            del self.devices[name]
            self.ips.pop(name, None)
            self.routing.pop(name, None)
        else:
            for key, value in args.items():
                if key == 'index':
                    continue

                self.devices[name]['attributes'][{'address': 'mac', 'ifalias': 'description',
                                                 'master': 'vrf', 'group': 'link-group'}.get(key, key)] = value

    def state(self, name, up):
        self.devices[name]['up'] = up

    def delete_links(self, devices):
        for device in devices.values():
            self.link('del', index=device['index'])

    def ip_policy(self, name, options, globals):
        pass

    def ip_profile(self, owners, globals):
        return nullcontext()

    def set_addresses(self, name, desired, **kwargs):
        self.ips[name] = set(desired)

    def ready(self, name):
        return True

    def routes(self, name):
        return deepcopy(self.routing.get(name, []))

    def route(self, operation, name, route):
        if operation == 'del':
            self.routing[name].remove(route)
        else:
            self.routing.setdefault(name, []).append(route)


class Leases:
    def __init__(self):
        self.events, self.clients = {}, {}

    def start(self, name, index, mac, options=None):
        self.clients[name] = (index, mac)

    def stop(self, name):
        self.clients.pop(name, None)
        self.events.pop(name, None)

    def lease(self, name, index):
        return self.events.get(name)


@pytest.fixture
def backend(tmp_path):
    kernel = Kernel()
    kernel.add('eth1')

    return Manager(kernel, Leases(), tmp_path, boot='first')


def spec(kind='ethernet', **kwargs):
    return {'kind': kind, **kwargs}


def test_attributes_addresses_disabled_removal_and_original_baseline(backend):
    base = backend.kernel.device('eth1')['attributes']
    backend.replace('ethernet', {'eth1': spec(attributes={'mtu': 9000, 'description': 'uplink'}, addresses=['192.0.2.1/24'])})

    assert backend.kernel.devices['eth1']['up']
    assert backend.kernel.ips['eth1'] == {'192.0.2.1/24'}
    assert backend.kernel.devices['eth1']['attributes']['mtu'] == 9000

    restarted = Manager(backend.kernel, backend.dhcp, backend.path.parent, boot='first')
    restarted.replace('ethernet', {'eth1': spec(disabled=True, addresses=['192.0.2.1/24'])})

    assert not backend.kernel.devices['eth1']['up'] and not backend.kernel.ips['eth1']
    assert backend.kernel.devices['eth1']['attributes'] == base

    restarted.replace('ethernet', {})

    assert backend.kernel.device('eth1') is not None and not restarted.state['records']


def test_dummy_create_hotplug_recreate_delete_and_foreign_device(backend):
    backend.replace('dummy', {'dum1': spec('dummy')})

    assert backend.kernel.devices['dum1']['up']

    del backend.kernel.devices['dum1']
    backend.reconcile()

    assert backend.kernel.devices['dum1']['up']

    backend.replace('dummy', {})

    assert backend.kernel.device('dum1') is None

    backend.kernel.add('dum1', 'dummy')

    with pytest.raises(ValidationError, match='not owned'):
        backend.replace('dummy', {'dum1': spec('dummy')})


def test_missing_physical_recovery_and_hotplug(backend):
    with pytest.raises(ValidationError, match='does not exist'):
        backend.replace('ethernet', {'eth2': spec()})

    backend.replace('ethernet', {'eth2': spec(addresses=['192.0.2.2/24'])}, recovery=True)

    with pytest.raises(ValidationError, match='already claimed'):
        backend.replace('other', {'eth2': spec()}, recovery=True)

    backend.kernel.add('eth2')
    backend.reconcile()

    assert backend.kernel.ips['eth2'] == {'192.0.2.2/24'}
    assert not backend.kernel.devices['eth1']['up']


@pytest.mark.parametrize('interrupted', [False, True])
def test_partial_bulk_delete_preserves_intent_and_recovers(backend, monkeypatch, interrupted):
    links = {f'dum{i}': spec('dummy', addresses=[f'192.0.2.{i}/32']) for i in range(1, 5)}
    backend.replace('dummy', links)
    original = backend.kernel.delete_links

    def fail(devices):
        journal = json.loads(backend.path.read_text())

        assert journal['pending']['dummy']['after'] == {}
        assert set(journal['pending']['dummy']['before']) == links.keys()

        original(dict(list(devices.items())[:2]))
        raise KeyboardInterrupt() if interrupted else RouterError('delete failed')

    monkeypatch.setattr(backend.kernel, 'delete_links', fail)

    with pytest.raises(KeyboardInterrupt if interrupted else RouterError):
        backend.replace('dummy', {})

    restarted = Manager(backend.kernel, backend.dhcp, backend.path.parent, boot='first')

    assert bool(restarted.state['pending']) == interrupted

    if interrupted:
        # An unfinished owner is left for configd to recover, not the watchdog.
        restarted.reconcile()

        assert len(set(links) & backend.kernel.devices.keys()) == 2

        restarted.replace('dummy', links, recovery=True)

    assert not restarted.state['pending']

    for name, definition in links.items():
        assert backend.kernel.devices[name]['up']
        assert backend.kernel.ips[name] == set(definition['addresses'])

    monkeypatch.setattr(backend.kernel, 'delete_links', original)
    restarted.replace('dummy', {})

    assert not set(links) & backend.kernel.devices.keys()


def test_bulk_delete_preserves_reverse_dependency_order(backend, monkeypatch):
    class Dependent(Dummy):
        def dependencies(self, spec):
            return ('dum1',) if spec['name'] == 'dum2' else ()

    backend.types = dict(backend.types, dependent=Dependent())
    backend.replace('dependent', {name: spec('dependent') for name in ('dum1', 'dum2')})
    removed = []
    original = backend.kernel.link

    def link(operation, **args):
        if operation == 'del':
            removed.append(next(n for n, d in backend.kernel.devices.items() if d['index'] == args['index']))

        return original(operation, **args)

    monkeypatch.setattr(backend.kernel.ipr, 'link', link)
    monkeypatch.setattr(backend.kernel, 'delete_links', lambda devices: pytest.fail('dependent batch'))
    backend.replace('dependent', {})

    assert removed == ['dum2', 'dum1']


def test_delete_workers_join_on_failure_and_close_private_sockets(monkeypatch):
    from nvyr.helpers import netlink

    barrier = threading.Barrier(8)
    failed, release, done = threading.Event(), threading.Event(), threading.Event()
    opened, closed, errors = [], [], []

    class Worker:
        def __init__(self):
            self.ipr = SimpleNamespace(link=self.link)
            opened.append(self)

        def device(self, name):
            return {'index': int(name[3:]), 'kind': 'dummy'}

        def link(self, operation, index):
            barrier.wait(timeout=5)

            if index == 0:
                failed.set()
                raise RouterError('kernel refused deletion')

            assert release.wait(5)

        def close(self):
            closed.append(self)

    monkeypatch.setattr(netlink, 'Kernel', Worker)

    def delete():
        try:
            RealKernel.delete_links(None, {f'dum{i}': {'index': i, 'kind': 'dummy'} for i in range(8)})
        except Exception as error:
            errors.append(error)
        finally:
            done.set()

    thread = threading.Thread(target=delete)
    thread.start()

    try:
        assert failed.wait(5)
        assert not done.is_set()  # Failure cannot start rollback while peers run.
    finally:
        release.set()
        thread.join(5)

    assert done.is_set() and len(errors) == 1
    assert 'kernel refused' in str(errors[0])
    assert len(opened) == 8 and set(opened) == set(closed)


@pytest.mark.parametrize('current', [None, {'index': 22, 'kind': 'dummy'}, {'index': 21, 'kind': 'veth'}])
def test_delete_worker_rechecks_device_incarnation(monkeypatch, current):
    from nvyr.helpers import netlink

    closed = []
    monkeypatch.setattr(netlink, 'Kernel', lambda: SimpleNamespace(
        device=lambda name: current, close=lambda: closed.append(True),
        ipr=SimpleNamespace(link=lambda *a, **kw: pytest.fail('foreign device deleted'))))

    if current is None:
        RealKernel.delete_links(None, {'dum1': {'index': 21, 'kind': 'dummy'}})
    else:
        with pytest.raises(RouterError, match='replaced the owned device'):
            RealKernel.delete_links(None, {'dum1': {'index': 21, 'kind': 'dummy'}})

    assert closed == [True]


def test_compensation_and_unrecoverable_journal(backend, monkeypatch):
    backend.replace('ethernet', {'eth1': spec(addresses=['192.0.2.1/24'])})
    original = backend.kernel.set_addresses

    def fail(name, desired, **kw):
        original(name, desired, **kw)

        if '192.0.2.2/24' in desired:
            raise RouterError('kernel rejected change')

    monkeypatch.setattr(backend.kernel, 'set_addresses', fail)

    with pytest.raises(RouterError, match='previous configuration restored'):
        backend.replace('ethernet', {'eth1': spec(addresses=['192.0.2.2/24'])})

    assert backend.kernel.ips['eth1'] == {'192.0.2.1/24'}
    assert not backend.state['pending']

    def always_fail(*args, **kw):
        raise RouterError('kernel unavailable')

    monkeypatch.setattr(backend.kernel, 'set_addresses', always_fail)

    with pytest.raises(RecoveryError, match='rollback failed'):
        backend.replace('ethernet', {'eth1': spec()})

    restarted = Manager(backend.kernel, backend.dhcp, backend.path.parent, boot='first')

    assert restarted.state['pending']

    # Recovery of another owner must not clear this owner's interrupted journal.
    restarted.replace('dummy', {}, recovery=True)

    assert 'ethernet' in restarted.state['pending']

    monkeypatch.setattr(backend.kernel, 'set_addresses', original)
    restarted.replace('ethernet', {'eth1': spec()}, recovery=True)

    assert not restarted.state['pending']


def test_new_boot_does_not_replay_unsaved_config(backend):
    backend.replace('dummy', {'dum1': spec('dummy')})
    rebooted = Manager(Kernel(), Leases(), backend.path.parent, boot='second')
    rebooted.reconcile()

    assert not rebooted.state['owners'] and not rebooted.kernel.devices


def test_journal_write_failure_after_apply_remains_recovery_error(backend, monkeypatch):
    backend.replace('ethernet', {'eth1': spec()})
    original = backend.save
    calls = 0

    def fail_after_intent():
        nonlocal calls
        calls += 1

        if calls > 1:
            raise OSError('disk full')

        original()

    monkeypatch.setattr(backend, 'save', fail_after_intent)

    with pytest.raises(RecoveryError, match='rollback failed'):
        backend.replace('ethernet', {'eth1': spec(addresses=['192.0.2.1/24'])})

    assert json.loads(backend.path.read_text())['pending']['ethernet']


def test_unprivileged_peer_is_rejected():
    import struct

    connection = SimpleNamespace(getsockopt=lambda *args: struct.pack('3i', 123, 1000, 1000))

    assert not Server.authorized(connection)


def test_owner_and_device_incarnation_fences(backend):
    backend.replace('dummy', {'dum1': spec('dummy')})

    with pytest.raises(ValidationError, match='already claimed'):
        backend.replace('other', {'dum1': spec('dummy')})

    backend.kernel.add('dum1', 'dummy')  # Same name, different ifindex.

    with pytest.raises(ValidationError, match='not owned'):
        backend.validate('dummy', {'dum1': spec('dummy')})

    with pytest.raises(RouterError, match='refusing to delete'):
        backend.replace('dummy', {})

    assert backend.kernel.device('dum1')


def test_lease_addresses_and_route_ownership(backend):
    route = {'dst': '0.0.0.0/0', 'gateway': '192.0.2.254', 'metric': 1026, 'protocol': 16}
    foreign = dict(route, dst='203.0.113.0/24', protocol=186)
    backend.kernel.routing['eth1'] = [foreign]
    backend.dhcp.events['eth1'] = {'address': '192.0.2.10/24', 'routes': [route], 'expires': time.monotonic()+60}
    backend.replace('ethernet', {'eth1': spec(dhcp4=True, addresses=['2001:db8::1/64'])})

    assert backend.kernel.ips['eth1'] == {'192.0.2.10/24', '2001:db8::1/64'}
    assert backend.kernel.routing['eth1'] == [foreign, dict(route, metric=(210 << 24) | 1026)]

    backend.dhcp.events.clear()
    backend.reconcile()

    assert backend.kernel.ips['eth1'] == {'2001:db8::1/64'}
    assert backend.kernel.routing['eth1'] == [foreign]


def test_equivalent_static_address_does_not_get_dhcp_expiration(backend, monkeypatch):
    lease = {'address': '192.0.2.10/24', 'routes': [], 'expires': time.monotonic()+60}
    backend.dhcp.events['eth1'] = lease
    calls = []
    monkeypatch.setattr(backend.kernel, 'set_addresses', lambda *args, **kw: calls.append(kw))
    backend.replace('ethernet', {'eth1': spec(dhcp4=True, addresses=['192.0.2.10/255.255.255.0'])})

    assert calls[-1]['lease'] is None

    backend.replace('ethernet', {'eth1': spec(dhcp4=True, addresses=[])})

    assert calls[-1]['lease'] == lease


def test_driver_extension_and_dependency_order_without_protocol_changes(backend):
    created = []

    class Extension(Dummy):
        keymap = dict(LINK_KEYMAP, **{
            'parent': NetlinkKey('link', ('IFLA_LINK',)),
            'future-attribute': NetlinkKey('future', ('IFLA_LINKINFO', 'IFLA_INFO_DATA', 'FUTURE')),
        })

        def dependencies(self, spec):
            return [spec['attributes']['parent']] if 'parent' in spec.get('attributes', {}) else []

        def create(self, kernel, spec):
            created.append(spec['name'])
            super().create(kernel, spec)

        def snapshot(self, kernel, spec, device):
            return {'future-attribute': 99}

        def configure(self, kernel, spec, baseline):
            assert baseline['future-attribute'] == 99

    backend.types = dict(backend.types, extension=Extension())
    links = {'zparent': spec('extension'), 'achild': spec('extension', attributes={'parent': 'zparent', 'future-attribute': 42})}
    dispatch(backend, dict(version=1, operation='replace', owner='extension', links=links))

    assert created == ['zparent', 'achild']

    links['zparent']['attributes'] = {'parent': 'achild'}

    with pytest.raises(ValidationError, match='cyclic'):
        backend.validate('extension', links)


@pytest.mark.parametrize('value', [spec(kind='unknown'), spec(dhcp4='yes'), spec(addresses=[42]),
                                  spec(attributes=[]), spec(attributes={'unexpected': 1})])
def test_strict_boundary_validation(value):
    with pytest.raises(ValidationError):
        normalize({'eth1': value})


def test_no_duplicate_cli_value_validation():
    # Deliberately invalid CLI values: transport decoding must not grow a second
    # collection of value validators. Encoding/kernel errors still fail apply.
    attrs = {'mtu': 1, 'mac': 'not-a-mac', 'description': 'line\nbreak'}

    assert normalize({'eth1': spec(attributes=attrs)})['eth1']['attributes'] == attrs
    assert normalize({'eth1': spec(addresses=['invalid'])})['eth1']['addresses'] == ['invalid']


def test_keymap_extension_reads_batches_restores_and_avoids_flaps():
    message = Message(IFLA_MTU=1500, IFLA_ADDRESS='02:00:00:00:00:01',
                      IFLA_LINKINFO=Message(IFLA_INFO_DATA=Message(EXTRA=12)))

    class Extended(LinkType):
        keymap = dict(LINK_KEYMAP, extra=NetlinkKey('extra', ('IFLA_LINKINFO', 'IFLA_INFO_DATA', 'EXTRA')))

    driver = Extended()
    calls = []
    device = {'index': 2, 'up': True, 'message': message}
    kernel = SimpleNamespace(device=lambda name: device, state=lambda *args: calls.append(('state', args)),
                             ipr=SimpleNamespace(link=lambda *args, **kw: calls.append((args, kw))))
    original = driver.snapshot(kernel, {'name': 'eth1'}, device)

    assert original['extra'] == 12 and original['description'] == ''

    driver.configure(kernel, {'name': 'eth1', 'attributes': {'extra': 42, 'mtu': 9000}}, original)

    assert calls == [(('set',), {'index': 2, 'extra': 42, 'mtu': 9000})]

    message['IFLA_MTU'] = 9000
    message['IFLA_LINKINFO']['IFLA_INFO_DATA']['EXTRA'] = 42
    calls.clear()
    driver.configure(kernel, {'name': 'eth1', 'attributes': {'extra': 42, 'mtu': 9000}}, original)

    assert not calls  # No repeated kernel writes or link flaps.

    driver.configure(kernel, {'name': 'eth1', 'attributes': {}}, original)

    assert calls == [(('set',), {'index': 2, 'mtu': 1500, 'extra': 12})]

    calls.clear()
    driver.configure(kernel, {'name': 'eth1', 'attributes': {'mac': '02:11:22:33:44:55'}}, original)

    assert calls[0] == ('state', ('eth1', False))


def test_keymap_dispatches_to_mapped_netlink_operations():
    class Extended(LinkType):
        keymap = {'one': NetlinkKey('first', ('FIRST',)),
                  'two': NetlinkKey('second', ('SECOND',), operation='brport')}

    calls = []
    kernel = SimpleNamespace(device=lambda name: {'index': 4, 'up': False, 'message': Message(FIRST=0, SECOND=0)},
                             ipr=SimpleNamespace(link=lambda *args, **kw: calls.append(('link', args, kw)),
                                                 brport=lambda *args, **kw: calls.append(('brport', args, kw))))
    Extended().configure(kernel, {'name': 'test', 'attributes': {'one': 1, 'two': 2}}, {'one': 0, 'two': 0})

    assert calls == [('link', ('set',), {'index': 4, 'first': 1}), ('brport', ('set',), {'index': 4, 'second': 2})]


def test_dhcp_event_classless_routes_expiry_and_token_fence(tmp_path):
    env = {'NVYR_DHCP_TOKEN': 'generation', 'NVYR_DHCP_INDEX': '2', 'ip': '192.0.2.10',
           'subnet': '255.255.255.0', 'lease': '60', 'router': '192.0.2.1',
           'staticroutes': '198.51.100.0/24 192.0.2.254 0.0.0.0/0 192.0.2.253', 'dns': '192.0.2.53'}
    event = lease_event('bound', env)

    assert event['address'] == '192.0.2.10/24'
    assert event['routes'][1]['gateway'] == '192.0.2.253'
    assert not lease_event('renew', dict(env, staticroutes=''))['routes']

    calls = []
    client = DHCP(tmp_path, run=calls.append)
    client.start('eth1', 2, 'mac')
    data = client._read('clients', 'eth1')
    atomic_json(client._path('leases', 'eth1'), event)

    assert client.lease('eth1', 2) is None

    event['token'] = data['token']
    atomic_json(client._path('leases', 'eth1'), event)

    assert client.lease('eth1', 2) == event
    assert client.lease('eth1', 3) is None

    event['expires'] = time.monotonic()-1
    atomic_json(client._path('leases', 'eth1'), event)

    assert client.lease('eth1', 2) is None

    client.start('eth1', 2, 'different-mac')

    assert client._read('clients', 'eth1')['token'] != data['token']
    assert ['systemctl', 'stop', 'nvyr-dhcp4@eth1.service'] in calls


def test_client_entrypoint_passes_identity_and_custom_hook(tmp_path, monkeypatch):
    from nvyr.helpers import dhcp
    import os
    import sys

    monkeypatch.setattr(dhcp, 'RUNTIME', tmp_path)
    monkeypatch.setattr(sys, 'argv', ['nvyr-dhcp4', 'eth1'])
    monkeypatch.setattr(socket, 'if_nametoindex', lambda name: 2)
    monkeypatch.setattr(os, 'environ', dict(os.environ))
    atomic_json(tmp_path/'clients/eth1.json', {'index': 2, 'token': 'generation', 'options': {}})
    commands = []
    monkeypatch.setattr(os, 'execv', lambda *args: commands.append(args))
    dhcp.client_main()
    executable, args = commands[0]

    assert executable == '/usr/sbin/udhcpc' and '-R' in args and '-a' in args
    assert args[args.index('-s')+1] == '/usr/bin/nvyr-dhcp4-hook'
    assert os.environ['NVYR_DHCP_TOKEN'] == 'generation'

    monkeypatch.setattr(socket, 'if_nametoindex', lambda name: 3)

    with pytest.raises(RouterError, match='replaced'):
        dhcp.client_main()


def test_rpc_success_version_error_and_ambiguous_disconnect(backend, tmp_path, monkeypatch):
    path = tmp_path/'control.sock'
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(path))
    listener.listen()
    server = Server(backend, path)
    monkeypatch.setattr(server, 'authorized', lambda connection: True)
    client = NetlinkManager(path)

    def call(operation, **arguments):
        thread = threading.Thread(target=lambda: server.handle(listener.accept()[0]))
        thread.start()

        try:
            return client.request(operation, **arguments)
        finally:
            thread.join(5)

    try:
        call('replace', owner='dummy', links={'dum1': spec('dummy')})

        assert call('status')['owners']['dummy']

        with pytest.raises(RouterError, match='Unknown'):
            call('unexpected')

        def disconnect():
            connection, _ = listener.accept()

            with connection:
                receive(connection)

        thread = threading.Thread(target=disconnect)
        thread.start()

        with pytest.raises(RecoveryError, match='lost apply reply'):
            client.request('replace', owner='dummy', links={})

        thread.join(5)

        with pytest.raises(ValidationError, match='version'):
            dispatch(backend, {'version': 2})
    finally:
        listener.close()


def test_targeted_reconcile_does_not_touch_other_links_or_remove_siblings(backend, monkeypatch):
    backend.replace('dummy', {f'dum{i}': spec('dummy') for i in range(100)})
    calls = []
    original = backend.kernel.set_addresses

    def record(name, *args, **kwargs):
        calls.append(name)
        return original(name, *args, **kwargs)

    monkeypatch.setattr(backend.kernel, 'set_addresses', record)
    del backend.kernel.devices['dum50']
    backend.reconcile({'dum50'})

    assert calls == ['dum50']
    assert len(backend.state['records']) == 100
    assert all(backend.kernel.device(f'dum{i}')['up'] for i in range(100))


def test_deleted_links_leave_no_observations_or_persistent_records(backend):
    backend.replace('ethernet', {'eth1': spec()})
    backend.failures.update(eth1='unrelated error', DNS='resolver error')

    for batch in range(3):
        links = {f'dum{batch*100+i}': spec('dummy') for i in range(100)}
        backend.replace('dummy', links)

        assert set(backend.observed) == {'eth1'} | links.keys()

        backend.failures.update({name: 'old error' for name in links})
        backend.replace('dummy', {})

        assert set(backend.observed) == {'eth1'}
        assert set(backend.failures) == {'eth1', 'DNS'}
        assert set(backend.claims) == {'eth1'}
        assert set(backend.indices.values()) == {'eth1'}
        assert not backend.dependents and not backend.dhcp_names
        assert set(backend.state['records']) == {'eth1'}
        assert not backend.state['pending']
        assert json.loads(backend.path.read_text())['owners']['dummy'] == {}
        assert set(json.loads(backend.path.read_text())['records']) == {'eth1'}
        assert not backend.updates.read_bytes()


@pytest.mark.parametrize('cyclic', [False, True])
def test_dependency_sort_releases_input_without_cyclic_gc(backend, cyclic):
    class Links(dict):
        pass

    class Driver(Dummy):
        def dependencies(self, spec):
            return (spec['name'],) if cyclic else ()

    backend.types = dict(backend.types, example=Driver())
    links = Links(dum1=spec('example'))
    reference = weakref.ref(links)
    enabled = gc.isenabled()
    gc.disable()

    try:
        if cyclic:
            with pytest.raises(ValidationError, match='cyclic'):
                backend._ordered(links)
        else:
            assert backend._ordered(links) == ['dum1']

        del links

        assert reference() is None
    finally:
        if enabled:
            gc.enable()


def test_unhealthy_interface_does_not_block_other_recovery(backend):
    backend.replace('dummy', {'dum1': spec('dummy'), 'dum2': spec('dummy')})
    backend.kernel.add('dum1', 'dummy')  # A foreign incarnation must not be adopted.
    del backend.kernel.devices['dum2']
    backend.reconcile()

    assert set(backend.failures) == {'dum1'}
    assert backend.kernel.device('dum2')['up']

    backend.reconcile({'dum2'})

    assert 'dum1' in backend.error  # Unrelated success cannot hide a failure.

    del backend.kernel.devices['dum1']
    backend.reconcile({'dum1'})

    assert backend.error is None


def test_record_updates_replay_torn_tail_and_checkpoint_epoch(backend):
    backend.replace('dummy', {'dum1': spec('dummy')})
    checkpoint = json.loads(backend.path.read_text())
    del backend.kernel.devices['dum1']
    backend.reconcile({'dum1'})

    assert backend.updates.stat().st_size > 0
    assert json.loads(backend.path.read_text()) == checkpoint

    new_index = backend.state['records']['dum1']['index']

    with backend.updates.open('ab') as stream:
        stream.write(b'["interrupted')

    restarted = Manager(backend.kernel, backend.dhcp, backend.path.parent, boot='first')

    assert restarted.state['records']['dum1']['index'] == new_index
    assert backend.updates.read_bytes().endswith(b'\n')

    old_log = backend.updates.read_bytes()
    restarted.save()

    # Crash after publishing a checkpoint but before removing its previous log.
    backend.updates.write_bytes(old_log + (json.dumps([checkpoint['epoch'], 'dum1', None])+'\n').encode())
    again = Manager(backend.kernel, backend.dhcp, backend.path.parent, boot='first')

    assert again.state['records']['dum1']['index'] == new_index


@pytest.mark.parametrize('version,message', [(1, 'Unsupported netlinkd journal format'),
                                             (2, 'Missing netlinkd journal checkpoint ID')])
def test_invalid_journal_is_rejected_without_rewriting_state(backend, version, message):
    backend.replace('dummy', {'dum1': spec('dummy')})
    old = deepcopy(backend.state)
    old['format'] = version
    old.pop('epoch')
    old['pending']['dummy'] = {'before': old['owners']['dummy'], 'after': {}}
    atomic_json(backend.path, old)

    with pytest.raises(RouterError, match=message):
        Manager(backend.kernel, backend.dhcp, backend.path.parent, boot='first')

    assert json.loads(backend.path.read_text()) == old
    assert backend.kernel.device('dum1') is not None


def test_creation_uses_constant_number_of_full_journal_writes(backend, monkeypatch):
    calls, records = [], []
    original, original_record = backend.save, backend.save_record

    def save():
        calls.append(True)
        original()

    def save_record(name):
        records.append(name)
        original_record(name)

    monkeypatch.setattr(backend, 'save', save)
    monkeypatch.setattr(backend, 'save_record', save_record)
    backend.replace('dummy', {f'dum{i}': spec('dummy') for i in range(1000)})

    assert len(calls) == 2 and len(records) == 1000
    assert backend.updates.read_bytes() == b''


def test_kernel_snapshot_is_bulk_and_name_lookup_does_not_dump():
    calls = []
    messages = [Message(index=i+1, flags=1, IFLA_IFNAME=f'dum{i}', IFLA_MTU=1500,
                        IFLA_LINKINFO=Message(IFLA_INFO_KIND='dummy')) for i in range(1000)]

    def link(operation, **kwargs):
        calls.append(('link', operation, kwargs))
        return [messages[int(kwargs['ifname'][3:])]]

    def links():
        calls.append('links')
        return messages

    def addresses(**kwargs):
        calls.append('addresses')
        return []

    kernel = RealKernel.__new__(RealKernel)
    kernel._links = kernel._addresses = kernel._routes = None
    kernel.ipr = SimpleNamespace(get_links=links, get_addr=addresses, link=link)

    with kernel.snapshot():
        for i in range(1000):
            assert kernel.device(f'dum{i}')['index'] == i+1
            assert kernel.addresses(f'dum{i}') == {}
            assert kernel.ready(f'dum{i}')

    assert calls == ['links', 'addresses']

    kernel.device('dum500')

    assert calls[-1] == ('link', 'get', {'ifname': 'dum500'})
    assert kernel._links is None


def test_interrupted_inventory_is_retried_and_partial_results_discarded():
    from pyroute2.netlink.exceptions import NetlinkDumpInterrupted

    calls = []

    def dump():
        calls.append(True)
        yield 'partial' if len(calls) == 1 else 'complete'

        if len(calls) == 1:
            raise NetlinkDumpInterrupted()

    assert RealKernel.dump(dump) == ('complete',)
    assert len(calls) == 2

    def interrupted():
        raise NetlinkDumpInterrupted()

    with pytest.raises(RouterError, match='kept changing'):
        RealKernel.dump(interrupted)


def test_targeted_snapshot_filters_addresses_and_routes_in_kernel():
    calls = []
    message = Message(index=2, flags=1, IFLA_IFNAME='eth1', IFLA_MTU=1500)

    def link(operation, **kwargs):
        calls.append(('link', operation, kwargs))
        return [message]

    def addr(command, **kwargs):
        calls.append(('addr', command, kwargs))
        return []

    def route(command, **kwargs):
        calls.append(('route', command, kwargs))
        return []

    kernel = RealKernel.__new__(RealKernel)
    kernel._links = kernel._addresses = kernel._routes = None

    # No get_addr/get_links/get_routes: targeted work must never dump the host.
    kernel.ipr = SimpleNamespace(link=link, addr=addr, route=route)

    with kernel.snapshot({'eth1'}):
        assert kernel.addresses('eth1') == {}

        kernel.addresses('eth1', fresh=True)
        kernel.refresh('eth1')
        kernel.flush_addresses()

        assert kernel.routes('eth1') == []

    assert [call for call in calls if call[0] == 'addr'] == [
        ('addr', 'dump', {'index': 2, 'match': None})] * 3
    assert calls[-1] == ('route', 'dump', {'family': socket.AF_INET, 'table': 0, 'oif': 2, 'match': None})


def test_reconciliation_logging_is_quiet_until_debug_or_failure(backend, caplog, monkeypatch):
    import logging

    with caplog.at_level(logging.INFO):
        backend.replace('dummy', {'dum1': spec('dummy')})
        backend.reconcile()

    assert not caplog.records

    original = backend.kernel.set_addresses

    def fail(*args, **kwargs):
        raise OSError('injected kernel failure')

    monkeypatch.setattr(backend.kernel, 'set_addresses', fail)
    backend.reconcile()
    backend.reconcile()  # Audits must not repeatedly log the same failure.

    assert sum('reconciliation failed' in r.message for r in caplog.records) == 1

    monkeypatch.setattr(backend.kernel, 'set_addresses', original)

    with caplog.at_level(logging.DEBUG):
        backend.reconcile({'dum1'})

    assert 'reconciliation recovered' in caplog.text
    assert 'Reconcile targeted: 1 interfaces' in caplog.text
    assert 'Reconciliation finished' in caplog.text


def test_aged_bulk_snapshot_does_not_refresh_unchanged_dhcp_address(monkeypatch):
    monkeypatch.setattr('nvyr.helpers.netlink.time.monotonic', lambda: 100)
    kernel = RealKernel.__new__(RealKernel)
    kernel._addresses, kernel._expected = {}, {}
    reads = []

    def addresses(name, *, fresh=False):
        reads.append(fresh)
        return {'192.0.2.1/24': {'scope': 0, 'flags': 0, 'valid_lft': 30 if fresh else 40}}

    kernel.addresses = addresses

    # No ipr write interface: the expired snapshot must not cause a mutation.
    kernel.set_addresses('eth1', ['192.0.2.1/24'], lease={'address': '192.0.2.1/24', 'expires': 130})

    assert reads == [False, True]


def test_dhcp_and_static_address_lifetimes_use_netlink_cacheinfo(monkeypatch):
    monkeypatch.setattr('nvyr.helpers.netlink.time.monotonic', lambda: 100)
    kernel = RealKernel.__new__(RealKernel)
    kernel._addresses, kernel._expected = {}, {}
    kernel.addresses = lambda name: {}
    kernel.device = lambda name: {'index': 42}
    writes = []
    kernel.ipr = SimpleNamespace(addr=lambda operation, **kwargs: writes.append((operation, kwargs)))
    kernel.set_addresses('eth1', ['192.0.2.1/24', '2001:db8::1/64'],
                         lease={'address': '192.0.2.1/24', 'expires': 160})
    lifetimes = {args['address']: args['cacheinfo'] for _, args in writes}

    assert lifetimes == {'192.0.2.1': {'valid': 60, 'preferred': 60},
                         '2001:db8::1': {'valid': 0xffffffff, 'preferred': 0xffffffff}}


def link_event(backend, name, event='RTM_NEWLINK', **changes):
    device = backend.kernel.device(name)
    message = Message(device['message'], event=event, index=device['index'],
                      flags=(1 if device['up'] else 0) | (0x10000 if device['carrier'] else 0),
                      IFLA_IFNAME=name, IFLA_LINKINFO=Message(IFLA_INFO_KIND=device['kind']))
    message.update(changes)

    return message


def test_event_filter_ignores_noise_and_tracks_rename_address_and_dhcp_routes(backend):
    backend.replace('dummy', {'dum1': spec('dummy')})
    index = backend.kernel.device('dum1')['index']
    message = link_event(backend, 'dum1')

    assert backend.affected([message]) == set()  # Echo of our successful application.
    assert backend.affected([Message(message, IFLA_STATS64={'rx_packets': 42})]) == set()
    assert backend.affected([Message(message, IFLA_MTU=9000)]) == {'dum1'}
    assert backend.affected([Message(message, IFLA_IFNAME='renamed')]) == {'dum1'}
    assert backend.affected([Message(message, event='RTM_DELLINK')]) == {'dum1'}
    assert backend.affected([Message(event='RTM_DELADDR', index=index)]) == {'dum1'}
    assert not backend.affected([Message(event='RTM_NEWROUTE', proto=186, RTA_OIF=index)])
    assert backend.affected([Message(event='RTM_DELROUTE', proto=16, RTA_OIF=index)]) == {'dum1'}
    assert not backend.affected([Message(event='RTM_NEWADDR', index=99999)])


def test_idle_scheduler_coalesces_events_and_only_polls_dhcp(backend, monkeypatch):
    now = [100.0]
    monkeypatch.setattr('nvyr.netlink_daemon.time.monotonic', lambda: now[0])
    calls = []
    monkeypatch.setattr(backend, 'reconcile', lambda names=None: calls.append(names))
    scheduler = Schedule(now[0])
    scheduler.run(backend, now[0])

    assert calls == [None]

    calls.clear()

    for step in range(1, 119):
        now[0] = 100 + step/2
        scheduler.run(backend, now[0])

    assert not calls

    scheduler.notify({'dum1'}, now[0])
    deadline = scheduler.due
    scheduler.notify({'dum2'}, now[0]+.1)

    assert scheduler.due == deadline

    scheduler.run(backend, deadline)

    assert calls == [{'dum1', 'dum2'}]

    calls.clear()
    backend.dhcp_names = {'eth1'}
    scheduler.audit = 1000
    scheduler.run(backend, scheduler.maintenance)

    assert calls == [{'eth1'}]


@pytest.mark.parametrize('kind', ['overflow', 'truncated', 'overrun', 'decode'])
def test_notification_loss_requests_full_resync(backend, monkeypatch, kind):
    import errno

    monkeypatch.setattr('nvyr.netlink_daemon.time.monotonic', lambda: 10)
    scheduler = Schedule(0)
    scheduler.audit = 60

    def recv(size):
        if kind == 'overflow':
            raise OSError(errno.ENOBUFS, 'overflow')

        return b'data', [], socket.MSG_TRUNC if kind == 'truncated' else 0, (0, 0)

    def parse(data):
        if kind == 'decode':
            raise ValueError('malformed netlink')

        return [Message(header={'type': 4})]

    receive_events(SimpleNamespace(recvmsg=recv), SimpleNamespace(parse=parse), backend, scheduler)

    assert scheduler.audit == 10.2


def test_dad_waits_after_all_interfaces_are_configured(backend, monkeypatch):
    seen = []
    refreshed = False

    def refresh_addresses():
        nonlocal refreshed
        assert backend.kernel.device('dum1') and backend.kernel.device('dum2')
        refreshed = True
        seen.append('refresh')

    def ready(name):
        seen.append((name, refreshed))
        return refreshed

    monkeypatch.setattr(backend.kernel, 'refresh_addresses', refresh_addresses)
    monkeypatch.setattr(backend.kernel, 'ready', ready)
    backend.replace('dummy', {'dum1': spec('dummy'), 'dum2': spec('dummy')})

    assert seen == [('dum1', False), ('dum2', False), 'refresh', ('dum1', True), ('dum2', True)]
