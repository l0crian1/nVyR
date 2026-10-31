"""DNS-backed membership, failure recovery, schema and serialized manual updates."""

from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import dns.exception
import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import BusyError, RouterError
from nvyr.helpers import access, domain_groups, nftables
from nvyr.helpers.nftables_formatters import nft_singleton_group
from tests.test_geoip import context


def configuration(family='ipv4'):
    return {'firewall': {'group': {'domain-group': {family: {
        'SERVICES': {'domain': ['api.example.com'], 'lookup': {'rounds': '3'}}}}}}}


@pytest.fixture
def manager(tmp_path, monkeypatch):
    instance = domain_groups.Manager(tmp_path / 'domains')
    monkeypatch.setattr(domain_groups, 'manager', instance)
    return instance


@pytest.fixture
def loads(monkeypatch):
    calls = []
    monkeypatch.setattr(nftables.manager, 'apply', lambda text, *args, **kwargs: calls.append(text))
    return calls


def resolver(monkeypatch, answers):
    calls = []
    def resolve(name, kind, **options):
        calls.append((name, kind, options))
        values = answers.pop(0)
        if isinstance(values, Exception):
            raise values
        return [SimpleNamespace(address=value) for value in values]
    monkeypatch.setattr(domain_groups.dns.resolver, 'Resolver', lambda: SimpleNamespace(resolve=resolve))
    return calls


def test_back_to_back_rounds_union_all_answers(manager, monkeypatch):
    calls = resolver(monkeypatch, [['192.0.2.1'], ['192.0.2.1'], ['192.0.2.2', '192.0.2.1']])
    result = manager.resolve({'ipv4:api.example.com': 3}, {}, pytest.fail)
    assert result['ipv4:api.example.com']['addresses'] == ['192.0.2.1', '192.0.2.2']
    assert len(calls) == 3
    assert all(call[:2] == ('api.example.com.', 'A') for call in calls)


def test_ipv6_uses_aaaa_and_empty_success_removes_old_addresses(manager, monkeypatch):
    calls = resolver(monkeypatch, [['2001:db8::1'], []])
    first = manager.resolve({'ipv6:api.example.com': 1}, {}, pytest.fail)
    second = manager.resolve({'ipv6:api.example.com': 1}, first, pytest.fail)
    assert calls[0][1] == 'AAAA'
    assert second['ipv6:api.example.com']['addresses'] == []
    assert second['ipv6:api.example.com']['error'] is None


def test_failure_retains_cache_and_warns_without_repeating_timeouts(manager, monkeypatch):
    calls = resolver(monkeypatch, [dns.exception.Timeout()])
    messages = []
    result = manager.resolve({'ipv4:api.example.com': 10},
                             {'ipv4:api.example.com': {'addresses': ['192.0.2.1']}}, messages.append)
    assert result['ipv4:api.example.com']['addresses'] == ['192.0.2.1']
    assert len(calls) == 1 and 'Warning:' in messages[0]


def test_initial_failure_commits_empty_then_manual_update_populates(manager, monkeypatch, engine, loads, tmp_path):
    resolver(monkeypatch, [dns.exception.Timeout()])
    messages = []
    current = replace(context(configuration(), tmp_path), report=messages.append)
    firewall.apply(firewall.generate(current.effective, current), current)
    assert 'flush set inet nvyr_filter ipv4_domain_group_SERVICES' in loads[0]
    assert 'add element' not in loads[0] and messages
    engine.running = configuration()
    resolver(monkeypatch, [['192.0.2.1'], ['192.0.2.1'], ['192.0.2.2']])
    assert 'refreshed 1' in manager.update(engine)['text']
    assert '192.0.2.1, 192.0.2.2' in loads[-1]
    assert 'chain' not in loads[-1]


def test_reboot_uses_cache_and_never_contacts_dns(manager, monkeypatch, loads, tmp_path):
    manager.publish({'ipv4:api.example.com': {'addresses': ['192.0.2.1']}}, pytest.fail)
    monkeypatch.setattr(manager, 'resolve', lambda *args: pytest.fail('boot queried DNS'))
    current = context(configuration(), tmp_path, recovery=True)
    firewall.apply(firewall.generate(current.effective, current), current)
    assert '192.0.2.1' in loads[0]


def test_reboot_without_cache_warns_and_loads_empty(manager, monkeypatch, loads, tmp_path):
    monkeypatch.setattr(manager, 'resolve', lambda *args: pytest.fail('boot queried DNS'))
    messages = []
    current = replace(context(configuration(), tmp_path, recovery=True), report=messages.append)
    firewall.apply(firewall.generate(current.effective, current), current)
    assert 'flush set' in loads[0] and 'add element' not in loads[0]
    assert 'No cached DNS' in messages[0]


def test_manual_refresh_updates_including_parents_and_leaves_unchanged_sets(manager, monkeypatch, engine, loads):
    engine.running = configuration()
    engine.running['firewall']['group']['domain-group']['ipv4']['PARENT'] = {'include-group': ['SERVICES']}
    resolver(monkeypatch, [['192.0.2.1']] * 3)
    assert 'refreshed 2' in manager.update(engine, 'ipv4', 'SERVICES')['text']
    assert 'ipv4_domain_group_PARENT' in loads[0]
    resolver(monkeypatch, [['192.0.2.1']] * 3)
    assert 'refreshed 0' in manager.update(engine)['text']
    assert len(loads) == 1


def test_concurrent_commit_rejects_outdated_resolution(manager, monkeypatch, engine, loads):
    engine.running = configuration()
    def resolve(*args):
        engine.running['firewall']['group']['domain-group']['ipv4']['SERVICES']['domain'] = ['changed.example.com']
        return {'ipv4:api.example.com': {'addresses': ['192.0.2.1']}}
    monkeypatch.setattr(manager, 'resolve', resolve)
    with pytest.raises(BusyError, match='changed during'):
        manager.update(engine)
    assert not loads


def test_failed_native_update_keeps_cache(manager, monkeypatch, engine):
    engine.running = configuration()
    resolver(monkeypatch, [['192.0.2.1']] * 3)
    def fail(*args, **kwargs):
        raise RouterError('native failure')
    monkeypatch.setattr(nftables.manager, 'apply', fail)
    with pytest.raises(RouterError, match='native failure'):
        manager.update(engine)
    assert manager.read(pytest.fail) == {}


def test_busy_and_unauthorized_updates_do_not_query(manager, monkeypatch, engine):
    monkeypatch.setattr(manager, 'resolve', lambda *args: pytest.fail('unexpected lookup'))
    engine.busy = True
    with pytest.raises(BusyError):
        manager.update(engine)
    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError, match='Permission denied'):
            manager.update(engine)
    finally:
        access.role.reset(token)


def test_schema_anchors_references_negation_and_lookup_rounds(controller, session):
    controller.execute('set firewall group domain-group ipv4 SERVICES domain api.example.com domain cdn.example.com', session)
    controller.execute('set firewall group domain-group ipv4 SERVICES lookup rounds 5', session)
    controller.execute('set firewall ipv4 input filter rule 10 action accept source-domain-group not SERVICES', session)
    tree = controller.engine.view(session)
    firewall.verify(tree, None)
    assert 'SERVICES' in dict(controller.completion('set firewall ipv4 input filter rule 20 source-domain-group ', session)['candidates'])
    with pytest.raises(RouterError, match='referenced'):
        controller.execute('delete firewall group domain-group ipv4 SERVICES', session)
    for value in ('*.example.com', 'https://example.com', '192.0.2.1', 'bad..name'):
        with pytest.raises(RouterError):
            controller.execute('set firewall group domain-group ipv4 BAD domain ' + value, session)
    with pytest.raises(RouterError):
        controller.execute('set firewall group domain-group ipv4 SERVICES lookup rounds 0', session)


def test_verification_empty_group_cycles_and_duplicate_fields():
    tree = configuration()
    tree['firewall']['group']['domain-group']['ipv4']['SERVICES'] = {}
    with pytest.raises(RouterError, match='at least one domain'):
        firewall.verify(tree, None)
    tree['firewall']['group']['domain-group']['ipv4']['SERVICES'] = {'include-group': ['SERVICES']}
    with pytest.raises(RouterError, match='circular'):
        firewall.verify(tree, None)
    tree = configuration()
    tree['firewall']['group']['address-group'] = {'ipv4': {'A': {}}}
    tree['firewall']['ipv4'] = {'input': {'filter': {'rule': {'10': {
        'action': 'accept', 'source-domain-group': 'SERVICES', 'source-address-group': 'A'}}}}}
    with pytest.raises(RouterError, match='duplicates source-address'):
        firewall.verify(tree, None)


def test_dns_priority_before_firewall_and_after_interfaces(controller):
    schema = controller.engine.schema
    priorities = {name: spec[1] for name, spec in schema.owners.items()}
    assert priorities['dns'] < priorities['firewall']
    assert priorities['dns'] > priorities['bridge']


def test_domain_sets_have_tracking_and_no_dns_names():
    text = nft_singleton_group('domain-group', 'ipv6', 'SERVICES', {'domain': ['example.com']},
                               {'counter': True, 'last-used': True})
    assert 'type ipv6_addr' in text and 'counter;' in text and 'last;' in text
    assert 'example.com' not in text


@pytest.mark.parametrize('line,expected', [
    ('update firewall domain-group', ['domain_groups.nvyr.op', 'update']),
    ('update firewall domain-group ipv4', ['domain_groups.nvyr.op', 'update', '--family', 'ipv4']),
    ('update firewall domain-group ipv6 SERVICES', ['domain_groups.nvyr.op', 'update', '--family', 'ipv6', '--name', 'SERVICES']),
    ('show firewall domain-group ipv4 SERVICES', ['domain_groups.nvyr.op', 'show', '--family', 'ipv4', '--name', 'SERVICES']),
    ('show firewall group domain-group ipv6 SERVICES', ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind', 'domain-group', '--family', 'ipv6', '--group_name', 'SERVICES']),
])
def test_operational_selectors_preserve_family_and_name(controller, line, expected):
    from nvyr.helpers.process import operational_argv
    from nvyr.lexer import lex
    cursor = controller.operational.operational(lex(line))
    assert operational_argv(cursor.node['command'], lex(line), line,
                            omitted_positions=cursor.omitted_positions) == expected


@pytest.mark.parametrize('role', ['read-only', 'net-admin'])
def test_authenticated_domain_rpc(engine, manager, loads, monkeypatch, tmp_path, role):
    import asyncio
    from nvyr.daemon import Server
    from nvyr.protocol import Client

    engine.running = configuration()
    engine.running['system'] = {'login': {'user': {'automation': {'role': role}}}}
    resolver(monkeypatch, [['192.0.2.1']] * 3)

    async def scenario():
        path = tmp_path / 'domains.sock'
        server = Server(engine, identity=lambda writer: ('automation', 'test'))
        listener = await asyncio.start_unix_server(server.handle, path=str(path))
        client = Client(path)
        try:
            result = await asyncio.to_thread(client.request, 'domain-group-status')
            assert result['domains'][0]['domain'] == 'api.example.com'
            if role == 'read-only':
                with pytest.raises(RouterError, match='net-admin'):
                    await asyncio.to_thread(client.request, 'domain-group-update')
                assert not loads
            else:
                result = await asyncio.to_thread(client.request, 'domain-group-update', family='ipv4', name='SERVICES')
                assert 'refreshed 1' in result['text']
                assert len(loads) == 1
        finally:
            client.close()
            listener.close()
            await listener.wait_closed()
            await asyncio.sleep(0)
    asyncio.run(scenario())


def test_native_dns_cname_and_rotating_answers(manager, monkeypatch):
    """A real DNS client follows a CNAME answer and collects successive UDP responses."""
    import socketserver
    import threading
    import dns.message
    import dns.rrset

    requests = []
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            query = dns.message.from_wire(data)
            requests.append(query)
            response = dns.message.make_response(query)
            response.answer.append(dns.rrset.from_text('api.example.com.', 60, 'IN', 'CNAME', 'backend.example.com.'))
            response.answer.append(dns.rrset.from_text('backend.example.com.', 60, 'IN', 'A', f'192.0.2.{len(requests)}'))
            sock.sendto(response.to_wire(), self.client_address)

    server = socketserver.UDPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = dns.resolver.Resolver(configure=False)
    client.nameservers = ['127.0.0.1']
    client.port = server.server_address[1]
    monkeypatch.setattr(domain_groups.dns.resolver, 'Resolver', lambda: client)
    try:
        result = manager.resolve({'ipv4:api.example.com': 3}, {}, pytest.fail)
        assert result['ipv4:api.example.com']['addresses'] == ['192.0.2.1', '192.0.2.2', '192.0.2.3']
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_domain_and_geoip_membership_share_one_transaction(manager, monkeypatch, loads, tmp_path):
    from nvyr.helpers import geoip
    from tests.test_geoip import install
    geo = geoip.Manager(tmp_path / 'geoip')
    install(geo)
    monkeypatch.setattr(geoip, 'manager', geo)
    resolver(monkeypatch, [['192.0.2.1']] * 3)
    tree = configuration()
    tree['firewall']['group']['address-group'] = {'ipv4': {'USA': {'geoip': {'country': ['US']}}}}
    current = context(tree, tmp_path)
    firewall.apply(firewall.generate(current.effective, current), current)
    assert len(loads) == 1
    assert 'add element inet nvyr_filter ipv4_domain_group_SERVICES' in loads[0]
    assert 'add element inet nvyr_filter ipv4_address_group_USA' in loads[0]


def test_corrupt_cache_does_not_break_boot(manager, monkeypatch, loads, tmp_path):
    manager.directory.mkdir()
    (manager.directory / 'cache.json').write_text('{"ipv4:api.example.com": {"addresses": [123]}}')
    messages = []
    current = replace(context(configuration(), tmp_path, recovery=True), report=messages.append)
    firewall.apply(firewall.generate(current.effective, current), current)
    assert 'add element' not in loads[0]
    assert 'Cannot read domain-group cache' in messages[0]
