"""Test live-suite isolation and assertions without executing host commands."""

from copy import deepcopy
import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nvyr.config_session import CommitError
from nvyr.helpers import interfaces
from nvyr.tree import lookup
from smoketests import assertions, firewall_support
from tests.test_static_smoketest import local_session


def test_ingress_sender_ignores_unrelated_interfaces_without_mac(monkeypatch):
    """PIM register links must not prevent a frame being sent through the test veths."""
    links = [
        {'ifname': 'pimreg', 'link_type': 'pimreg'},
        {'ifname': 'veth994', 'address': '02:00:00:00:00:01'},
        {'ifname': 'veth995', 'address': '02:00:00:00:00:02'},
    ]
    monkeypatch.setattr(firewall_support, 'cmd', lambda argv: json.dumps(links))
    frames = []

    class Sender:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def bind(self, address):
            assert address == ('veth994', 0)

        def send(self, frame):
            frames.append(frame)

    monkeypatch.setattr(firewall_support.socket, 'socket', lambda *args: Sender())

    firewall_support.send_ingress_udp()
    assert frames[0][:14] == bytes.fromhex('0200000000020200000000010800')

    firewall_support.send_ingress_udp(family='ipv6', vlan=100, priority=5)
    assert frames[1][:18] == bytes.fromhex('0200000000020200000000018100a06486dd')

    del links[2]['address']
    with pytest.raises(KeyError, match='address'):
        firewall_support.send_ingress_udp()
    assert len(frames) == 2


def test_live_feature_tests_are_explicit_functions():
    """Keep scenarios directly readable instead of rebuilding a parameterized test matrix."""
    directory = Path(__file__).resolve().parents[1] / 'smoketests'
    functional = directory.parent / 'functionaltests'
    paths = [directory / 'test_static.py', *directory.glob('test_firewall*.py'),
             *functional.glob('test_firewall*.py')]

    for path in paths:
        tree = ast.parse(path.read_text())
        functions = [
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')
        ]
        assert functions, path
        assert len({function.name for function in functions}) == len(functions)
        for function in functions:
            assert ast.get_docstring(function), function.name
            assert not function.decorator_list, function.name
            assert not any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(function)), function.name


class FakeSession:
    """Record mutations; only test-owned dummy deletion changes this tiny model."""

    def __init__(self, running):
        self.running = deepcopy(running)
        self.commands = []

    def get_config(self):
        return deepcopy(self.running)

    def discard(self):
        self.commands.append('discard')

    def commit(self):
        self.commands.append('commit')

    def set(self, command):
        self.commands.append(command)

    def delete(self, command):
        self.commands.append(command)
        if command in ('delete nat', 'delete firewall'):
            del self.running[command.split()[1]]
        else:
            del self.running['interfaces']['dummy'][command.split()[-1]]


@pytest.mark.parametrize('configuration,links', [
    ({'interfaces': {'dummy': {'dum998': {}}}}, '[]'),
    ({'firewall': {'reference': ['dum999']}}, '[]'),
    ({}, '[{"ifname": "dum998"}]'),
])
def test_preflight_collision_does_not_clear_firewall(monkeypatch, configuration, links):
    """A reserved name in configuration, references or the kernel stops before mutation."""
    config = FakeSession(configuration)
    resources = {'prepared': False, 'links': False}
    monkeypatch.setattr(firewall_support, 'cmd', lambda *args: links)

    with pytest.raises(AssertionError, match='already'):
        firewall_support.standup(config, resources)

    firewall_support.cleanup(config, resources)
    assert config.commands == []


def test_cleanup_discards_failure_and_releases_providers_after_consumers():
    """NAT and firewall disappear before owned links; eth0 and other dummies survive."""
    running = {
        'firewall': {'rule': 'test'},
        'nat': {'rule': 'test'},
        'interfaces': {
            'ethernet': {'eth0': {'address': ['dhcp']}},
            'dummy': {'dum998': {}, 'dum999': {}, 'dum1': {}},
        },
    }
    config = FakeSession(running)

    firewall_support.cleanup(config, {'prepared': True, 'links': True})

    assert config.commands == [
        'discard', 'delete nat', 'delete firewall', 'commit',
        'delete interfaces dummy dum998', 'delete interfaces dummy dum999', 'commit',
    ]
    assert config.running['interfaces']['ethernet'] == running['interfaces']['ethernet']
    assert config.running['interfaces']['dummy'] == {'dum1': {}}


def test_rule_assertions_cannot_borrow_fields_from_other_rules(monkeypatch):
    """Checking one rule must not accidentally pass because its neighbor has that match."""
    listing = '''
chain ipv4_input {
    ip saddr 192.0.2.1 accept comment "10|first"
    tcp dport 22 drop comment "100|neighbor"
}
'''
    monkeypatch.setattr(assertions, 'firewall_listing', lambda *args: listing)

    assertions.assert_firewall_rule('ipv4_input', 10, '192.0.2.1', absent=['drop'])
    with pytest.raises(AssertionError):
        assertions.assert_firewall_rule('ipv4_input', 10, 'tcp dport 22')
    with pytest.raises(AssertionError):
        assertions.assert_firewall_rule_absent('ipv4_input', 10)

    assertions.assert_firewall_rule_absent('ipv4_input', 1)


@pytest.mark.parametrize('changed', [False, True])
def test_rejected_commit_assertion_checks_installed_state(monkeypatch, changed):
    """An expected CommitError alone is insufficient if the transaction changed nftables."""
    class RejectedSession(FakeSession):
        def commit(self):
            raise CommitError({'results': {'firewall': {'success': False, 'error': 'invalid rule'}}})

    listings = iter(['original rules', 'changed rules' if changed else 'original rules'])
    monkeypatch.setattr(assertions, 'firewall_listing', lambda: next(listings))
    config = RejectedSession({'firewall': {}})

    if changed:
        with pytest.raises(AssertionError):
            assertions.assert_firewall_commit_rejected(config, 'invalid rule')
    else:
        assertions.assert_firewall_commit_rejected(config, 'invalid rule')


def test_nft_read_options_preserve_symbols_and_separate_state(monkeypatch):
    """Configuration comparisons suppress counters, while packet checks retain them."""
    commands = []

    def command(argv, **options):
        commands.append(argv)
        assert options == {'timeout': 10}
        return 'native output'

    monkeypatch.setattr(assertions, 'cmd', command)

    assertions.firewall_listing()
    assertions.firewall_listing('chain', 'ipv4_input', handles=True)
    assertions.firewall_listing('counter', 'counter_group_TOTAL', state=True)

    assert commands == [
        ['nft', '-s', 'list', 'table', 'inet', 'nvyr_filter'],
        ['nft', '-s', '-a', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_input'],
        ['nft', 'list', 'counter', 'inet', 'nvyr_filter', 'counter_group_TOTAL'],
    ]


@pytest.fixture
def firewall_baseline(local_session, monkeypatch):
    monkeypatch.setattr(firewall_support, 'cmd', lambda argv: '[]')
    resources = {'prepared': False, 'links': False}
    firewall_support.standup(local_session, resources)
    try:
        yield
    finally:
        firewall_support.cleanup(local_session, resources)


def test_rule_reset_does_not_reapply_interfaces(local_session, firewall_baseline, monkeypatch):
    local_session.set('set firewall ipv4 input filter rule 10 inbound-interface dum998 action accept')
    local_session.commit()
    applied = []
    monkeypatch.setattr(interfaces.manager, 'replace', lambda *args, **kwargs: applied.append(args))

    firewall_support.reset_firewall(local_session)

    assert applied == []
    running = local_session.get_config()
    assert 'firewall' not in running
    assert lookup(running, ('interfaces', 'dummy', 'dum998')) == {}
    assert lookup(running, ('interfaces', 'dummy', 'dum999')) == {}


def test_attribute_reset_keeps_both_links_and_optional_vrf(local_session, firewall_baseline, monkeypatch):
    local_session.set('set vrf name NVYRFWSMOKE table 41002')
    local_session.set('set interfaces dummy dum998 vrf NVYRFWSMOKE address 198.18.98.1/24 link-group 41002')
    local_session.set('set interfaces dummy dum999 mtu 1400 disable')
    local_session.commit()
    applied = []
    monkeypatch.setattr(interfaces.manager, 'replace', lambda *args, **kwargs: applied.append(args))

    firewall_support.reset_firewall(local_session)

    assert len(applied) == 1
    assert applied[0][0] == 'dummy'
    assert set(applied[0][1]) == {'dum998', 'dum999'}
    running = local_session.get_config()
    assert lookup(running, ('interfaces', 'dummy', 'dum998')) == {}
    assert lookup(running, ('interfaces', 'dummy', 'dum999')) == {}
    assert lookup(running, ('vrf', 'name', 'NVYRFWSMOKE', 'table')) == '41002'


def test_rejected_edits_and_empty_reset_need_no_commit(local_session, firewall_baseline, monkeypatch):
    local_session.set('set firewall ipv4 input filter rule 10')
    commits = []
    with monkeypatch.context() as patch:
        patch.setattr(local_session, 'commit', lambda: commits.append(True))
        firewall_support.reset_firewall(local_session)

    assert commits == []
    assert 'firewall' not in local_session.get_config(source='candidate')


def test_reset_failure_stops_remaining_cases(local_session, firewall_baseline, monkeypatch):
    request = SimpleNamespace(session=SimpleNamespace(shouldstop=False))
    fixture = firewall_support.firewall_environment.__wrapped__(local_session, request, {})
    next(fixture)

    def fail(session):
        raise RuntimeError('reset failed')

    with monkeypatch.context() as patch:
        patch.setattr(local_session, 'discard', lambda: fail(local_session))
        with pytest.raises(RuntimeError, match='reset failed'):
            next(fixture)
    assert 'cleanup failed' in request.session.shouldstop
