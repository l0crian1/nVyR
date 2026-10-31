"""Policy inspection preserves FRR syntax, raw capabilities and reset permissions."""

import pytest

from nvyr import opmode
from nvyr.errors import RouterError
from nvyr.helpers import access, vtysh
from nvyr.op_scripts import bgp, policy


@pytest.mark.parametrize('line', [
    'show route-map', 'show route-map IMPORT',
    'show ip access-list', 'show ip access-list ACL',
    'show ipv6 access-list', 'show ipv6 access-list ACL',
    'show ip prefix-list', 'show ipv6 prefix-list',
    'show ip prefix-list PREFIXES', 'show ipv6 prefix-list PREFIXES',
    'show ip prefix-list PREFIXES seq 4294967295', 'show ipv6 prefix-list PREFIXES seq 10',
    'show ip prefix-list summary', 'show ip prefix-list summary PREFIXES',
    'show ipv6 prefix-list summary', 'show ipv6 prefix-list summary PREFIXES',
    'show ip prefix-list detail', 'show ip prefix-list detail PREFIXES',
    'show ipv6 prefix-list detail', 'show ipv6 prefix-list detail PREFIXES',
    'show ip prefix-list PREFIXES 192.0.2.0/24',
    'show ip prefix-list PREFIXES 192.0.2.0/24 longer',
    'show ip prefix-list PREFIXES 192.0.2.0/24 first-match',
    'show ipv6 prefix-list PREFIXES 2001:db8::/32',
    'show ipv6 prefix-list PREFIXES 2001:db8::/32 longer',
    'show ipv6 prefix-list PREFIXES 2001:db8::/32 first-match',
    'show bgp as-path-access-list', 'show bgp as-path-access-list ASN_FILTER',
    'show ip as-path-access-list', 'show ip as-path-access-list ASN_FILTER',
])
def test_native_display_order(monkeypatch, line):
    calls = []
    monkeypatch.setattr(vtysh, 'show', lambda words, **kwargs: calls.append((words, kwargs)) or 'native output')

    assert policy.show(line) == 'native output'
    assert calls == [(tuple(line.split()), {'raw': False})]


@pytest.mark.parametrize('line', [
    'show bgp community-list', 'show bgp community-list COMMUNITY detail',
    'show bgp large-community-list', 'show bgp large-community-list LARGE detail',
])
def test_community_definitions_are_text_only(monkeypatch, line):
    calls = []
    monkeypatch.setattr(vtysh, 'show', lambda words, **kwargs: calls.append(words) or 'native output')

    assert bgp.show(line) == 'native output'
    with pytest.raises(RouterError, match='does not provide JSON'):
        bgp.show(line, raw=True)
    assert calls == [tuple(line.split())]


def test_abbreviations_pipes_and_run_preserve_order(monkeypatch):
    calls = []
    monkeypatch.setattr(vtysh, 'cmd', lambda argv: calls.append(argv) or '{}')

    policy.show('run sho ip prefix-l detail IMPORT | count')
    policy.clear('run clear route-m counter IMPORT')

    assert calls == [['vtysh', '-c', 'show ip prefix-list detail IMPORT'],
                     ['vtysh', '-c', 'clear route-map counters IMPORT']]


def test_raw_keeps_native_daemon_structure(monkeypatch, capsys):
    calls = []
    data = '{"zebra":{"IMPORT":{}},"bgpd":{"IMPORT":{"invoked":3}}}'
    monkeypatch.setattr(vtysh, 'cmd', lambda argv: calls.append(argv) or data)

    opmode.run(['show', 'show route-map IMPORT', '--raw'], namespace=vars(policy))

    assert calls == [['vtysh', '-c', 'show route-map IMPORT json']]
    assert capsys.readouterr().out == data + '\n'


@pytest.mark.parametrize('line', [
    'show ip prefix-list IMPORT 192.0.2.0/24',
    'show ipv6 prefix-list IMPORT 2001:db8::/32 first-match',
])
def test_prefix_lookup_does_not_claim_json_support(monkeypatch, line):
    monkeypatch.setattr(vtysh, 'show', lambda *args, **kwargs: pytest.fail('Unsupported JSON executed'))
    with pytest.raises(RouterError, match='does not provide JSON'):
        policy.show(line, raw=True)


@pytest.mark.parametrize('line', [
    'show route-map IMPORT json', 'show route-map "IMPORT\nconfigure terminal"',
    'show ip prefix-list IMPORT detail', 'show ip prefix-list IMPORT seq 0',
    'show ip prefix-list IMPORT seq 4294967296', 'show ip prefix-list IMPORT seq',
    'show ip prefix-list IMPORT 2001:db8::/32', 'show ipv6 prefix-list IMPORT 192.0.2.0/24',
    'show bgp ipv4 unicast route-map IMPORT', 'show ip route', 'clear route-map counters',
])
def test_invalid_policy_commands_do_not_execute(monkeypatch, line):
    monkeypatch.setattr(vtysh, 'show', lambda *args, **kwargs: pytest.fail('Invalid display executed'))
    with pytest.raises(RouterError):
        policy.show(line)


@pytest.mark.parametrize('line', ['clear route-map', 'clear route-map counters *', 'clear bgp *', 'show route-map'])
def test_invalid_counter_resets_do_not_execute(monkeypatch, line):
    monkeypatch.setattr(vtysh, 'clear', lambda *args: pytest.fail('Invalid reset executed'))
    with pytest.raises(RouterError):
        policy.clear(line)


def test_operator_can_inspect_but_cannot_reset(controller, monkeypatch):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'native output')
    token = access.role.set('read-only')
    try:
        assert controller.execute('show route-map')['text'] == 'native output'
        with pytest.raises(RouterError, match='net-admin'):
            controller.execute('clear route-map counter IMPORT')
        assert 'route-map' not in dict(controller.completion('clear ', explicit=True)['candidates'])
    finally:
        access.role.reset(token)

    assert calls == [['policy.nvyr.op', 'show', 'show route-map']]


def test_network_admin_can_clear_in_both_modes(controller, session, monkeypatch):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    token = access.role.set('net-admin')
    try:
        controller.execute('clear route-map counters IMPORT')
        controller.execute('run clear route-map counters', session)
    finally:
        access.role.reset(token)

    assert calls == [['policy.nvyr.op', 'clear', 'clear route-map counters IMPORT'],
                     ['policy.nvyr.op', 'clear', 'run clear route-map counters']]


def test_policy_name_completion_and_native_keywords(controller):
    controller.engine.running = {'policy': {
        'route-map': {'IMPORT': {}},
        'prefix-list': {'ipv4': {'V4': {}}, 'ipv6': {'V6': {}}},
        'community-list': {'standard': {'STANDARD': {}}, 'expanded': {'EXPANDED': {}}},
    }}

    route_maps = dict(controller.completion('show route-map ', explicit=True)['candidates'])
    assert {'IMPORT', '<Enter>'} <= route_maps.keys()
    assert not {'name', 'json', 'raw'} & route_maps.keys()
    prefixes = dict(controller.completion('show ipv6 prefix-list ', explicit=True)['candidates'])
    assert {'V6', 'summary', 'detail'} <= prefixes.keys()
    assert 'V4' not in prefixes
    communities = dict(controller.completion('show bgp community-list ', explicit=True)['candidates'])
    assert {'STANDARD', 'EXPANDED', '<Enter>'} <= communities.keys()
    selected = dict(controller.completion('show bgp community-list STANDARD ', explicit=True)['candidates'])
    assert {'detail', 'exact-match', '<Enter>'} <= selected.keys()
