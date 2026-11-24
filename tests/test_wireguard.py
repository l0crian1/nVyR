"""WireGuard endpoint intent, DNS failure and native configuration boundaries.

Kernel application and traffic belong to smoketests and the routed suite.
"""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import interface_wireguard
from nvyr.errors import OperationalError, ValidationError
from nvyr.helpers import validators, wireguard
from nvyr.lexer import lex
from nvyr.helpers.process import operational_argv
from nvyr.op_scripts import wireguard as operations

KEY = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
OTHER = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='


def peer(endpoint=None):
    return {'public-key': OTHER, 'preshared-key': wireguard.ZERO_KEY, 'allowed-ips': ['10.0.0.0/8'],
            'persistent-keepalive': 0, 'endpoint': endpoint or {}, 'resolved': '192.0.2.1:51820'}


@pytest.mark.parametrize('key,valid', [(KEY, True), (wireguard.ZERO_KEY, False), ('a'*44, False),
                                      (KEY + '\n', False), (KEY[:-1] + 'A', False)])
def test_key_validation(key, valid):
    assert validators.wireguard_key(key) is valid


def test_roaming_survives_sync_and_endpoint_removal_clears_peer(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, 'DIRECTORY', tmp_path)
    endpoint = {'address': 'remote.example', 'port': '51820'}
    configured = {'private-key': KEY, 'listen-port': 0, 'firewall-mark': 0, 'peers': {'remote': peer(endpoint)}}
    native = {'private-key': '(none)', 'listen-port': 55555, 'peers': {OTHER: {'endpoint': '198.51.100.1:44444'}}}
    monkeypatch.setattr(wireguard, 'state', lambda name, **kwargs: native)
    commands, files = [], []

    def command(argv):
        commands.append(argv)
        if argv[1] == 'syncconf':
            files.append(wireguard.Path(argv[-1]).read_text())
        return ''

    monkeypatch.setattr(wireguard, 'cmd', command)
    wireguard.atomic_json(tmp_path / 'wg0.json', {'peers': {'remote': peer(endpoint)}})
    original = deepcopy(configured)
    wireguard.synchronize('wg0', configured)
    assert 'Endpoint = 198.51.100.1:44444' in files[-1]
    assert 'ListenPort = 55555' in files[-1]
    assert configured == original
    assert KEY not in (tmp_path / 'wg0.json').read_text()

    configured['peers']['remote']['endpoint'] = {}
    configured['peers']['remote']['resolved'] = None
    wireguard.synchronize('wg0', configured)
    assert ['wg', 'set', 'wg0', 'peer', OTHER, 'remove'] in commands
    assert 'Endpoint =' not in files[-1]
    assert not list(tmp_path.glob('wg-*'))


def test_dns_failure_is_warning_and_preserves_last_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, 'DIRECTORY', tmp_path)
    wireguard.atomic_json(tmp_path / 'wg0.json', {'peers': {'remote': {'resolved': '192.0.2.1:51820'}}})
    def fail(*args):
        raise OperationalError('DNS unavailable')
    monkeypatch.setattr(wireguard, 'resolve', fail)
    reports = []
    values = wireguard.prepare_endpoints('wg0', {'remote': peer({'address': 'new.example', 'port': '51820'})}, reports.append)
    assert values['remote']['resolved'] == '192.0.2.1:51820'
    assert 'DNS unavailable' in str(reports[0])


def test_dns_prefers_current_answer_and_shares_deadline(monkeypatch):
    calls = []
    class Resolver:
        def resolve(self, name, kind, **kwargs):
            calls.append((kind, kwargs))
            return ['192.0.2.1', '192.0.2.2'] if kind == 'A' else ['2001:db8::1']
    monkeypatch.setattr(wireguard.dns.resolver, 'Resolver', Resolver)
    assert wireguard.resolve({'address': 'a.example', 'port': '123'}, '192.0.2.2:123') == '192.0.2.2:123'
    assert [kind for kind, _ in calls] == ['A', 'AAAA']
    assert calls[1][1]['lifetime'] <= calls[0][1]['lifetime'] <= 3


def test_cross_peer_validation():
    values = {'wg0': {'private-key': KEY, 'peer': {
        'one': {'public-key': KEY, 'allowed-ips': ['10.0.0.0/8']},
        'two': {'public-key': OTHER, 'allowed-ips': ['10.0.0.0/8']}}}}
    configuration = {'interfaces': values, 'vrfs': {}, 'bridge_members': set(), 'bond_members': set()}
    with pytest.raises(ValidationError, match='also assigned'):
        interface_wireguard.verify(configuration, SimpleNamespace(recovery=False))


def test_refresh_skips_healthy_roaming_but_manual_refresh_resolves(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, 'DIRECTORY', tmp_path)
    endpoint = {'address': 'remote.example', 'port': '51820'}
    wireguard.atomic_json(tmp_path / 'wg0.json', {'peers': {'remote': peer(endpoint)}})
    monkeypatch.setattr(wireguard, 'state', lambda name: {'peers': {OTHER: {
        'handshake': wireguard.time.time(), 'endpoint': '198.51.100.1:55555'}}})
    calls = []
    monkeypatch.setattr(wireguard, 'resolve', lambda endpoint, current: '192.0.2.1:51820')
    monkeypatch.setattr(wireguard, 'cmd', lambda argv: calls.append(argv))

    assert 'recent handshake' in wireguard.refresh('wg0', scheduled=True)
    assert calls == []
    assert '192.0.2.1:51820' in wireguard.refresh('wg0', peer='remote')
    assert calls == [['wg', 'set', 'wg0', 'peer', OTHER, 'endpoint', '192.0.2.1:51820']]


def test_first_dns_failure_leaves_peer_without_endpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, 'DIRECTORY', tmp_path)
    def fail(*args):
        raise OperationalError('DNS unavailable')
    monkeypatch.setattr(wireguard, 'resolve', fail)
    reports = []
    prepared = wireguard.prepare_endpoints('wg0', {'remote': peer({'address': 'a.invalid', 'port': '123'})}, reports.append)
    assert prepared['remote']['resolved'] is None
    assert len(reports) == 1


def test_initial_resolution_retries_only_missing_endpoints(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, 'DIRECTORY', tmp_path)
    endpoint = {'address': 'remote.example', 'port': '51820'}
    values = {'failed': peer(endpoint), 'healthy': dict(peer(endpoint), **{'public-key': KEY})}
    wireguard.atomic_json(tmp_path / 'wg0.json', {'peers': values})
    native = {'peers': {OTHER: {'endpoint': None}, KEY: {'endpoint': None}}}
    monkeypatch.setattr(wireguard, 'state', lambda name: native)
    attempts = []
    def resolve(endpoint, current):
        attempts.append(current)
        if len(attempts) == 1:
            raise OperationalError('DNS unavailable')
        return '192.0.2.1:51820'
    def command(argv):
        native['peers'][argv[4]]['endpoint'] = argv[6]
    monkeypatch.setattr(wireguard, 'resolve', resolve)
    monkeypatch.setattr(wireguard, 'cmd', command)

    with pytest.raises(OperationalError, match='DNS unavailable'):
        wireguard.refresh('wg0', unresolved=True)
    assert native['peers'][KEY]['endpoint'] == '192.0.2.1:51820'
    wireguard.refresh('wg0', unresolved=True)
    assert len(attempts) == 3
    wireguard.refresh('wg0', unresolved=True)
    assert len(attempts) == 3


def test_recreation_retains_endpoint_obtained_after_generate(tmp_path, monkeypatch):
    monkeypatch.setattr(wireguard, 'DIRECTORY', tmp_path)
    endpoint = {'address': 'remote.example', 'port': '51820'}
    configured = {'private-key': KEY, 'listen-port': 0, 'firewall-mark': 0,
                  'peers': {'remote': dict(peer(endpoint), resolved=None)}}
    wireguard.atomic_json(tmp_path / 'wg0.json', {'peers': {'remote': peer(endpoint)}})
    monkeypatch.setattr(wireguard, 'state', lambda name, **kwargs: {'private-key': '(none)', 'listen-port': 0, 'peers': {}})
    rendered = []
    monkeypatch.setattr(wireguard, 'cmd', lambda argv: rendered.append(wireguard.Path(argv[-1]).read_text()))
    wireguard.synchronize('wg0', configured)
    assert 'Endpoint = 192.0.2.1:51820' in rendered[0]


def test_native_comparison_skips_unchanged_settings_but_detects_key_drift():
    settings = {'private-key': KEY, 'listen-port': 51820, 'firewall-mark': 1}
    peers = {'remote': peer()}
    live = {'private-key': KEY, 'listen-port': 51820, 'firewall-mark': '0x1', 'peers': {
        OTHER: {'endpoint': '192.0.2.1:51820', 'allowed-ips': ['10.0.0.0/8'],
                'preshared-key': wireguard.ZERO_KEY, 'keepalive': 0}}}
    assert wireguard.native_matches(settings, peers, live)
    live['peers'][OTHER]['preshared-key'] = KEY
    assert not wireguard.native_matches(settings, peers, live)
    live['peers'][OTHER]['preshared-key'] = wireguard.ZERO_KEY
    live['private-key'] = OTHER
    assert not wireguard.native_matches(settings, peers, live)


def test_missing_resolver_configuration_is_an_endpoint_failure(monkeypatch):
    def unavailable():
        raise wireguard.dns.resolver.NoResolverConfiguration()
    monkeypatch.setattr(wireguard.dns.resolver, 'Resolver', unavailable)
    with pytest.raises(OperationalError, match='DNS resolver unavailable'):
        wireguard.resolve({'address': 'remote.example', 'port': '51820'})


def test_masked_peer_detail_filters_by_original_name(monkeypatch):
    native = {'public-key': KEY, 'listen-port': 51820, 'firewall-mark': 0, 'peers': {OTHER: {
        'endpoint': '[2001:db8::10]:51820', 'allowed-ips': ['10.20.30.0/24'], 'handshake': 0,
        'received': 12, 'sent': 34, 'keepalive': 25, 'preshared': True}}}
    monkeypatch.setattr(wireguard, 'state', lambda name: native)
    monkeypatch.setattr(wireguard, 'manifest', lambda name: {'peers': {'branch': {'public-key': OTHER}}})
    output = operations.show(interface='wg0', peer='branch', detail=True, strip_private='partial')
    assert all(value not in output for value in (KEY, OTHER, 'branch', '2001:db8', '10.20'))
    assert '[x:x:x:x:x:x:0:10]:51820' in output and 'xxx.xxx.30.0/24' in output


def test_peer_completion_and_operational_binding(controller, engine, session):
    controller.execute(f'set interfaces wireguard wg0 private-key {KEY}', session)
    controller.execute(f'set interfaces wireguard wg0 peer branch public-key {OTHER}', session)
    engine.commit(session)
    for command in ('show wireguard wg0 peer ', 'update wireguard wg0 peer '):
        completions = controller.completion('run ' + command, session, explicit=True)
        assert 'branch' in dict(completions['candidates'])

    command = 'show wireguard wg0 peer branch detail'
    cursor = controller.operational.operational(lex(command))
    assert operational_argv(cursor.node['command'], lex(command), command) == [
        'wireguard.nvyr.op', 'show', '--interface', 'wg0', '--peer', 'branch', '--detail']
