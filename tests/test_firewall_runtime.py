"""Runtime cleanup validates full keys and never changes configured policy."""

from copy import deepcopy
import asyncio
import threading

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import firewall_runtime
from nvyr.op_scripts import firewall
from tests.test_login import as_role


@pytest.fixture
def runtime(engine, monkeypatch):
    engine.running['firewall'] = {'group': {
        'address-group': {
            'ipv4': {'BLOCKED': {'dynamic': {}}, 'STATIC': {'address': ['192.0.2.1']}},
            'ipv6': {'BLOCKED': {'dynamic': {}}},
        },
        'match-group': {
            'ipv4': {'FLOWS': {'dynamic': {}, 'match': {'source-address': True, 'destination-port': True}}},
            'ipv6': {'FLOWS': {'dynamic': {}, 'match': {'source-address': True, 'destination-port': True}}},
        },
    }}
    calls = []
    monkeypatch.setattr(firewall_runtime, 'rc_cmd', lambda argv: (calls.append(argv) or (0, '')))
    return calls


@pytest.mark.parametrize('family,address', [('ipv4', '192.0.2.1'), ('ipv6', '2001:db8::1')])
@pytest.mark.parametrize('kind,name', [('address-group', 'BLOCKED'), ('match-group', 'FLOWS')])
def test_cleanup_targets_one_key_or_one_set(controller, engine, session, runtime, family, address, kind, name):
    original = deepcopy(engine.running)
    pending = deepcopy(session.mutations)
    base = f'clear firewall group {kind} {family} {name}'
    member = address if kind == 'address-group' else f'destination-port 443 source-address {address}'

    result = firewall_runtime.clear(engine, controller.operational, base + ' member ' + member)
    native = f'{family}_{kind.replace("-", "_")}_{name}'
    key = address if kind == 'address-group' else address + ' . 443'
    assert runtime == [['nft', 'destroy', 'element', 'inet', 'nvyr_filter', native, '{', key, '}']]
    assert 'Learned member cleared' in result['text']

    result = firewall_runtime.clear(engine, controller.operational, base + ' learned')
    assert runtime[-1] == ['nft', 'flush', 'set', 'inet', 'nvyr_filter', native]
    assert 'Learned members cleared' in result['text']
    assert engine.running == original
    assert session.mutations == pending


@pytest.mark.parametrize('suffix', [
    'member', 'member source-address 192.0.2.1',
    'member source-address 192.0.2.1 destination-port 443 protocol tcp',
    'member source-address 192.0.2.1 destination-port 443 destination-port 80',
    'member source-address 192.0.2.0/24 destination-port 443',
    'member source-address 192.0.2.1 destination-port 80-443',
])
def test_incomplete_extra_repeated_or_broad_keys_cannot_delete(controller, engine, runtime, suffix):
    with pytest.raises(RouterError):
        firewall_runtime.clear(engine, controller.operational,
                               'clear firewall group match-group ipv4 FLOWS ' + suffix)
    assert not runtime


@pytest.mark.parametrize('line,message', [
    ('clear firewall group address-group ipv4 STATIC learned', 'not dynamic'),
    ('clear firewall group address-group ipv4 UNKNOWN learned', 'not configured'),
    ('clear firewall group address-group ipv4 BLOCKED member', 'exact learned member'),
    ('clear firewall group address-group ipv4 BLOCKED member 2001:db8::1', 'Invalid value'),
    ('clear firewall group address-group ipv4 BLOCKED member "192.0.2.1; flush ruleset"', 'Invalid value'),
    ('clear firewall quota TOTAL', 'Expected clear firewall group'),
    ('clear firewall group address-group ipv4 BLOCKED learned | count', 'without pipe'),
])
def test_bad_requests_do_not_touch_nftables(controller, engine, runtime, line, message):
    with pytest.raises(RouterError, match=message):
        firewall_runtime.clear(engine, controller.operational, line)
    assert not runtime


def test_existing_configured_members_are_never_flushed(controller, engine, runtime):
    engine.running['firewall']['group']['address-group']['ipv4']['BLOCKED']['address'] = ['192.0.2.1']
    with pytest.raises(RouterError, match='contains configured members'):
        firewall_runtime.clear(engine, controller.operational,
                               'clear firewall group address-group ipv4 BLOCKED learned')
    assert not runtime


@pytest.mark.parametrize('state', ['busy', 'unhealthy'])
def test_cleanup_refuses_commit_rollback_and_recovery(controller, engine, runtime, state):
    setattr(engine, state, True)
    with pytest.raises(RouterError, match='progress|recovery'):
        firewall_runtime.clear(engine, controller.operational,
                               'clear firewall group address-group ipv4 BLOCKED learned')
    assert not runtime


def test_cleanup_holds_engine_mutex_through_kernel_operation(controller, engine, runtime, monkeypatch):
    acquired = []

    def try_lock():
        locked = engine.mutex.acquire(blocking=False)
        acquired.append(locked)
        if locked:
            engine.mutex.release()

    def execute(argv):
        worker = threading.Thread(target=try_lock)
        worker.start()
        worker.join()
        return 0, ''

    monkeypatch.setattr(firewall_runtime, 'rc_cmd', execute)
    firewall_runtime.clear(engine, controller.operational,
                           'clear firewall group address-group ipv4 BLOCKED learned')
    assert acquired == [False]


@pytest.mark.parametrize('role', ['read-only', 'net-admin', 'sys-admin'])
def test_cli_and_direct_rpc_handler_enforce_role(controller, engine, runtime, monkeypatch, role):
    line = 'clear firewall group address-group ipv4 BLOCKED learned'
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    with as_role(role):
        if role == 'read-only':
            with pytest.raises(RouterError, match='net-admin'):
                controller.execute(line)
            with pytest.raises(RouterError, match='net-admin'):
                firewall_runtime.clear(engine, controller.operational, line)
            assert not runtime and not calls
        else:
            controller.execute(line)
            firewall_runtime.clear(engine, controller.operational, line)
            assert calls == [['firewall.nvyr.op', 'clear_group', line]]
            assert len(runtime) == 1


def test_completion_uses_running_group_names_and_only_its_fields(controller, engine, session, runtime):
    controller.execute('set firewall group address-group ipv4 PENDING dynamic', session)
    controller.execute('delete firewall group address-group ipv4 BLOCKED', session)
    for prefix, context in [('', None), ('run ', session)]:
        result = controller.completion(prefix + 'clear firewall group address-group ipv4 ', context, explicit=True)
        candidates = dict(result['candidates'])
        assert 'BLOCKED' in candidates
        assert 'PENDING' not in candidates and 'STATIC' not in candidates

        line = prefix + 'clear firewall group match-group ipv4 FLOWS member '
        result = controller.completion(line, context, explicit=True)
        candidates = dict(result['candidates'])
        assert 'source-address' in candidates and 'destination-port' in candidates
        assert 'protocol' not in candidates and 'connection' not in candidates
        assert '<Enter>' not in candidates

        result = controller.completion(line + 'source-address 192.0.2.1 des', context, tab=True)
        assert result['replacement'] == 'destination-port'
        result = controller.completion(line + 'source-address 192.0.2.1 destination-port 443 ', context, explicit=True)
        assert '<Enter>' in dict(result['candidates'])


def test_nested_connection_fields_and_exact_flag_byte(controller, engine, runtime):
    engine.running['firewall']['group']['match-group']['ipv4']['FLOWS']['match'] = {
        'connection': {'original': {'destination-address': True}},
        'tcp-flags': True,
    }
    line = ('clear firewall group match-group ipv4 FLOWS member '
            'connection original destination-address 192.0.2.1 tcp-flags syn and ack')
    firewall_runtime.clear(engine, controller.operational, line)
    assert runtime[-1][-2] == '18 . 192.0.2.1'

    candidates = dict(controller.completion(
        'clear firewall group match-group ipv4 FLOWS member connection original ', explicit=True)['candidates'])
    assert 'destination-address' in candidates and 'source-address' not in candidates


def test_native_failure_is_reported_without_success(controller, engine, runtime, monkeypatch):
    monkeypatch.setattr(firewall_runtime, 'rc_cmd', lambda argv: (1, 'No such file or directory'))
    with pytest.raises(RouterError, match='Cannot clear IPv4 address-group BLOCKED'):
        firewall_runtime.clear(engine, controller.operational,
                               'clear firewall group address-group ipv4 BLOCKED learned')


def test_op_script_delegates_and_closes_client(monkeypatch, capsys):
    calls = []

    class Client:
        def __init__(self, path):
            pass

        def request(self, operation, **arguments):
            calls.append((operation, arguments))
            return {'text': 'Learned members cleared.\n'}

        def close(self):
            calls.append('closed')

    monkeypatch.setattr(firewall, 'Client', Client)
    line = 'clear firewall group address-group ipv4 BLOCKED learned'
    firewall.clear_group(line)
    assert calls == [('clear-firewall-group', {'text': line}), 'closed']
    assert capsys.readouterr().out == 'Learned members cleared.\n'


@pytest.mark.parametrize('role', ['read-only', 'net-admin'])
def test_rpc_uses_authenticated_role_without_a_configuration_session(engine, runtime, tmp_path, role):
    from nvyr.daemon import Server
    from nvyr.protocol import Client

    engine.running['system'] = {'login': {'user': {'automation': {'role': role}}}}

    async def scenario():
        path = tmp_path / 'runtime.sock'
        server = Server(engine, identity=lambda writer: ('automation', 'test'))
        listener = await asyncio.start_unix_server(server.handle, path=str(path))
        client = Client(path)
        try:
            request = asyncio.to_thread(
                client.request, 'clear-firewall-group',
                text='clear firewall group address-group ipv4 BLOCKED learned')
            if role == 'read-only':
                with pytest.raises(RouterError, match='net-admin'):
                    await request
                assert not runtime
            else:
                result = await request
                assert 'Learned members cleared' in result['text']
                assert len(runtime) == 1
            assert not engine.sessions
        finally:
            client.close()
            listener.close()
            await listener.wait_closed()
            await asyncio.sleep(0)

    asyncio.run(scenario())
