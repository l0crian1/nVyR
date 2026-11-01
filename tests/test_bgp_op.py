"""Native-order BGP commands, completion, authorization and internal raw output."""

import pytest

from nvyr import opmode
from nvyr.errors import RouterError
from nvyr.helpers import access, suggestors
from nvyr.op_scripts import bgp


@pytest.mark.parametrize('line', [
    'show bgp', 'show bgp summary', 'show bgp summary failed',
    'show bgp summary established neighbor 192.0.2.2 terse wide',
    'show bgp summary remote-as external', 'show bgp summary remote-as 65001 terse',
    'show bgp ipv4 unicast', 'show bgp ipv6 unicast summary',
    'show bgp vrf BLUE ipv4 unicast summary', 'show bgp vrf all ipv6 unicast',
    'show bgp ipv4 unicast 192.0.2.0/24',
    'show bgp ipv6 unicast 2001:db8::/32 longer-prefixes',
    'show bgp ipv4 unicast 192.0.2.0/24 internal bestpath',
    'show bgp neighbors', 'show bgp neighbors 192.0.2.2',
    'show bgp ipv6 neighbors 2001:db8::2 graceful-restart',
    'show bgp vrf BLUE ipv4 unicast neighbors 192.0.2.2 advertised-routes detail',
    'show bgp ipv6 unicast neighbors 2001:db8::2 routes',
    'show bgp ipv4 unicast neighbors 192.0.2.2 received-routes',
    'show bgp ipv4 unicast neighbors 192.0.2.2 prefix-counts',
    'show bgp ipv4 unicast route-map IMPORT',
    'show bgp ipv6 unicast prefix-list PREFIXES',
    'show bgp ipv4 unicast access-list ACL',
    'show bgp ipv4 unicast filter-list ASN_FILTER',
    'show bgp ipv4 unicast community 65000:10 exact-match',
    'show bgp ipv6 unicast large-community 65000:10:20',
    'show bgp ipv4 unicast community-list COMMUNITY exact-match',
    'show bgp ipv6 unicast large-community-list LARGE',
    'show bgp ipv4 unicast version 10', 'show bgp ipv6 unicast statistics',
    'show bgp ipv4 unicast self-originate', 'show bgp ipv4 unicast dampening parameters',
    'show bgp router', 'show bgp vrfs', 'show bgp vrfs BLUE',
    'show bgp vrf BLUE bestpath', 'show bgp peer-group', 'show bgp peer-group PEERS',
    'show bgp vrf BLUE nexthop 192.0.2.2 detail', 'show bgp import-check-table detail',
])
def test_display_preserves_native_word_order(monkeypatch, line):
    calls = []
    monkeypatch.setattr(bgp.vtysh, 'show', lambda words, **kwargs: calls.append((words, kwargs)) or 'native output')

    assert bgp.show(line) == 'native output'
    assert calls == [(tuple(line.split()), {'raw': False})]


@pytest.mark.parametrize('line', [
    'clear bgp *', 'clear bgp 192.0.2.2', 'clear bgp 2001:db8::2',
    'clear bgp 65001 soft', 'clear bgp external out', 'clear bgp peer-group PEERS soft in',
    'clear bgp ipv4 unicast * soft out', 'clear bgp ipv6 unicast 2001:db8::2 in',
    'clear bgp vrf BLUE ipv4 unicast 192.0.2.2 soft in',
    'clear bgp vrf BLUE * message-stats', 'clear bgp 192.0.2.2 capabilities',
    'clear bgp 192.0.2.2 in prefix-filter',
])
def test_reset_preserves_native_word_order(monkeypatch, line):
    calls = []
    monkeypatch.setattr(bgp.vtysh, 'clear', lambda words: calls.append(words) or '')
    assert bgp.clear(line) == ''
    assert calls == [tuple(line.split())]


def test_abbreviation_run_and_pipe_are_resolved_without_reordering(monkeypatch):
    calls = []
    monkeypatch.setattr(bgp.vtysh, 'show', lambda words, **kwargs: calls.append(words) or '{}')
    bgp.show('run sho bgp vrf BLUE ipv6 uni summ | count', raw=True)
    assert calls == [('show', 'bgp', 'vrf', 'BLUE', 'ipv6', 'unicast', 'summary')]


@pytest.mark.parametrize('line', [
    '', 'show ip route', 'show bgp vrf', 'show bgp ipv4 unicast neighbors',
    'show bgp ipv4 unicast neighbors 192.0.2.2',
    'show bgp summary remote-as 0', 'show bgp summary remote-as 4294967296',
    'show bgp ipv4 unicast 192.0.2.1 longer-prefixes',
    'show bgp ipv4 unicast vrf BLUE', 'show bgp summary ipv4',
    'show bgp l2vpn evpn', 'show bgp ipv4 multicast',
    'show bgp json', 'show bgp raw', 'show bgp vrf "BLUE\nconfigure terminal"',
])
def test_invalid_displays_do_not_execute(monkeypatch, line):
    monkeypatch.setattr(bgp.vtysh, 'show', lambda *args, **kwargs: pytest.fail('Invalid command executed'))
    with pytest.raises(RouterError):
        bgp.show(line)


@pytest.mark.parametrize('line', [
    'clear bgp', 'clear bgp vrf BLUE', 'clear bgp ipv4 unicast',
    'clear bgp 0', 'clear bgp 4294967296', 'clear bgp 192.0.2.2 hard',
    'clear bgp 192.0.2.2 soft in out', 'show bgp summary',
    'clear bgp "*\nconfigure terminal"',
])
def test_invalid_resets_do_not_execute(monkeypatch, line):
    monkeypatch.setattr(bgp.vtysh, 'clear', lambda *args: pytest.fail('Invalid reset executed'))
    with pytest.raises(RouterError):
        bgp.clear(line)


def test_raw_returns_frr_json_through_shared_wrapper(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(bgp.vtysh, 'cmd', lambda argv: calls.append(argv) or '{"ipv4Unicast": {}}')
    opmode.run(['show', 'show bgp summary', '--raw'], namespace=vars(bgp))
    assert calls == [['vtysh', '-c', 'show bgp summary json']]
    assert capsys.readouterr().out == '{"ipv4Unicast": {}}\n'

    with pytest.raises(RouterError, match='wide is a text'):
        bgp.show('show bgp summary wide', raw=True)


def test_operator_can_display_but_cannot_clear(controller, monkeypatch):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'output\n')
    token = access.role.set('read-only')
    try:
        assert controller.execute('show bgp summary')['text'] == 'output\n'
        with pytest.raises(RouterError, match='net-admin'):
            controller.execute('clear bgp *')
        assert 'bgp' not in dict(controller.completion('clear ', explicit=True)['candidates'])
    finally:
        access.role.reset(token)
    assert calls == [['bgp.nvyr.op', 'show', 'show bgp summary']]


def test_network_admin_can_clear_in_both_modes(controller, session, monkeypatch):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    token = access.role.set('net-admin')
    try:
        controller.execute('clear bgp 192.0.2.2 soft in')
        controller.execute('run clear bgp vrf BLUE * soft out', session)
    finally:
        access.role.reset(token)
    assert calls == [
        ['bgp.nvyr.op', 'clear', 'clear bgp 192.0.2.2 soft in'],
        ['bgp.nvyr.op', 'clear', 'run clear bgp vrf BLUE * soft out'],
    ]


def test_completion_keeps_frr_keywords_and_hides_schema_placeholders(controller):
    candidates = dict(controller.completion('show bgp ipv4 unicast ', explicit=True)['candidates'])
    assert {'summary', 'neighbors', 'route-map', '<Enter>'} <= candidates.keys()
    assert not {'destination', 'json', 'raw', 'vrf'} & candidates.keys()
    candidates = dict(controller.completion('show bgp ipv4 unicast neighbors 192.0.2.2 ', explicit=True)['candidates'])
    assert 'advertised-routes' in candidates
    assert '<Enter>' not in candidates


@pytest.mark.parametrize('scope', ['empty', 'default', 'vrf'])
@pytest.mark.parametrize('configuration_mode', [False, True])
def test_peer_completion_with_missing_configuration_sections(controller, session, scope, configuration_mode):
    instance = {'neighbor': {'192.0.2.2': {}}, 'peer-group': {'CORE': {}}}
    configurations = {
        'empty': {},
        'default': {'protocols': {'bgp': instance}},
        'vrf': {'vrf': {'name': {'BLUE': {'protocols': {'bgp': instance}}}}},
    }
    controller.engine.running = configurations[scope]
    prefix = 'run ' if configuration_mode else ''
    active_session = session if configuration_mode else None

    for command, value in [('clear bgp ', '192.0.2.2'),
                           ('clear bgp peer-group ', 'CORE'),
                           ('show bgp neighbors ', '192.0.2.2')]:
        candidates = dict(controller.completion(prefix + command, active_session, explicit=True)['candidates'])
        if scope == 'empty':
            assert value not in candidates
        else:
            assert candidates[value] == 'VRF: ' + ('default' if scope == 'default' else 'BLUE')


def test_peer_suggestors_include_vrf_ownership(controller):
    configuration = {
        'protocols': {'bgp': {'neighbor': {'192.0.2.2': {}}, 'peer-group': {'CORE': {}}}},
        'vrf': {'name': {'BLUE': {'protocols': {'bgp': {'neighbor': {'192.0.2.2': {}, '2001:db8::2': {}}}}}}},
    }
    context = suggestors.Context(configuration=configuration)
    peers = {item.value: item.description for item in suggestors.bgp_peers(context)}
    assert peers == {'192.0.2.2': 'VRF: BLUE, default', '2001:db8::2': 'VRF: BLUE'}
    assert [item.value for item in suggestors.bgp_peer_groups(context)] == ['CORE']

    controller.engine.running = configuration
    candidates = dict(controller.completion('show bgp neighbors ', explicit=True)['candidates'])
    assert candidates['192.0.2.2'] == 'VRF: BLUE, default'
    candidates = dict(controller.completion('clear bgp peer-group ', explicit=True)['candidates'])
    assert candidates['CORE'] == 'VRF: default'
