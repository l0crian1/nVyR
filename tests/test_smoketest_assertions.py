"""Shared assertion contracts; no live router is involved."""

import json

import pytest

from smoketests import assertions
from smoketests.assertions import (
    assert_true, assert_false, assert_equal, assert_not_equal,
    assert_in, assert_not_in, assert_is_none, assert_is_not_none, assert_raises,
)


def test_accounting_does_not_accept_an_earlier_flow(monkeypatch):
    """Shared topology must not let an old successful flow satisfy a new probe."""
    from nvyr.helpers import conntrack

    old = {'status': ['offload'],
           'original': {'source-port': 40000, 'destination-port': 50000, 'packets': 6},
           'reply': {'packets': 6}}
    current = {'status': ['offload'],
               'original': {'source-port': 40001, 'destination-port': 50001, 'packets': 6},
               'reply': {'packets': 6}}
    monkeypatch.setattr(conntrack, 'read', lambda **kwargs: [old])

    def check(read, matches, **kwargs):
        assert not matches(read())
        assert matches([old, current])

    monkeypatch.setattr(assertions, 'wait_for', check)
    assertions.assert_connection_accounting('ipv4', '192.0.2.1', '192.0.2.2', 6,
                                           source_port=40001, destination_port=50001)


def test_chain_properties_reject_wrong_priority_and_missing_chain(monkeypatch):
    record = {'name': 'ingress', 'table': 'nvyr_filter', 'family': 'inet', 'hook': 'ingress', 'prio': -10}
    document = {'nftables': [{'metainfo': {}}, {'chain': record}]}
    monkeypatch.setattr(assertions, 'cmd', lambda argv: json.dumps(document))

    assertions.assert_firewall_chain('ingress', hook='ingress', prio=-10)
    with pytest.raises(AssertionError, match='ingress: prio'):
        assertions.assert_firewall_chain('ingress', prio=0)

    with pytest.raises(AssertionError, match='Expected one installed chain'):
        assertions.assert_firewall_chain('missing', prio=-10)


def test_timeout_assertion_reads_installed_object_and_checks_states(monkeypatch):
    """Timeout checks fail on missing objects or wrong lifetimes, not text layout."""
    record = {'name': 'ipv4_timeout_group_DNS', 'protocol': 'udp',
              'l3proto': 'ip', 'policy': {'unreplied': 10, 'replied': 30}}
    monkeypatch.setattr(assertions, 'cmd', lambda *args, **kwargs:
                        json.dumps({'nftables': [{'ct timeout': record}]}))

    assertions.assert_firewall_timeout('ipv4_timeout_group_DNS', 'udp', 'ip', unreplied=10)
    with pytest.raises(AssertionError):
        assertions.assert_firewall_timeout('ipv4_timeout_group_DNS', 'udp', 'ip', unreplied=20)
    with pytest.raises(AssertionError, match='Expected one installed timeout policy'):
        assertions.firewall_timeout_object('ipv4_timeout_group_MISSING')


@pytest.mark.parametrize('check, passing, failing, detail', [
    (assert_true, ([1],), ([],), 'not true'),
    (assert_false, ([],), ([1],), 'not false'),
    (assert_equal, ({'distance': 10}, {'distance': 10}), ({'distance': 10}, {'distance': 20}), 'distance'),
    (assert_not_equal, (10, 20), (10, 10), '10'),
    (assert_in, ('blackhole', 'route blackhole'), ('reject', 'route blackhole'), 'reject'),
    (assert_not_in, ('reject', ['blackhole']), ('reject', ['reject']), 'reject'),
    (assert_is_none, (None,), (False,), 'not None'),
    (assert_is_not_none, (False,), (None,), 'None'),
])
def test_value_checks_report_failures_with_optional_context(check, passing, failing, detail):
    assert check(*passing) is None

    with pytest.raises(AssertionError, match=detail):
        check(*failing)

    with pytest.raises(AssertionError, match='Route verification failed'):
        check(*failing, msg='Route verification failed')


def test_raises_is_pytest_and_exposes_the_original_exception():
    assert assert_raises is pytest.raises
    failure = ValueError('invalid next hop')

    with assert_raises(ValueError, match='next hop') as captured:
        raise failure

    assert captured.value is failure


def test_raises_fails_when_nothing_is_raised():
    with pytest.raises(pytest.fail.Exception, match='DID NOT RAISE'):
        with assert_raises(ValueError):
            pass


def test_raises_does_not_hide_unexpected_errors_or_messages():
    with pytest.raises(TypeError, match='unexpected'):
        with assert_raises(ValueError):
            raise TypeError('unexpected')

    with pytest.raises(AssertionError, match='Regex pattern did not match'):
        with assert_raises(ValueError, match='next hop'):
            raise ValueError('different problem')


@pytest.mark.parametrize('prefix, action, family, kernel_action', [
    ('192.0.2.0/24', 'blackhole', '-4', 'blackhole'),
    ('2001:db8:100::/64', 'reject', '-6', 'unreachable'),
])
def test_route_present_checks_frr_once_and_polls_kernel(monkeypatch, prefix, action, family, kernel_action):
    frr_family = 'ipv6' if family == '-6' else 'ip'
    responses = iter([
        f'{frr_family} route {prefix} {action}\n',
        '',
        f'{kernel_action} {prefix} proto static\n',
    ])
    commands = []

    def command(argv, **options):
        commands.append(argv)
        return next(responses)

    monkeypatch.setattr(assertions, 'cmd', command)
    monkeypatch.setattr('smoketests.support.time.sleep', lambda seconds: None)

    assertions.assert_route_present(prefix, action)

    assert commands == [
        ['vtysh', '-c', 'show running-config'],
        ['ip', family, 'route', 'show', 'table', 'main', 'exact', prefix],
        ['ip', family, 'route', 'show', 'table', 'main', 'exact', prefix],
    ]


def test_route_present_rejects_named_vrf_match_without_polling(monkeypatch):
    output = 'vrf BLUE\n ip route 192.0.2.0/24 blackhole\nexit-vrf\n'
    monkeypatch.setattr(assertions, 'cmd', lambda argv, **options: output)
    monkeypatch.setattr(assertions, 'wait_for', lambda *args, **kwargs: pytest.fail('Must fail before polling'))

    with pytest.raises(AssertionError, match='not found'):
        assertions.assert_route_present('192.0.2.0/24', 'blackhole')


def test_route_absent_polls_withdrawal_and_ignores_named_vrf_config(monkeypatch):
    responses = iter([
        'vrf BLUE\n ip route 192.0.2.0/24 blackhole\nexit-vrf\n',
        'blackhole 192.0.2.0/24 proto static\n',
        '\n',
    ])
    monkeypatch.setattr(assertions, 'cmd', lambda argv, **options: next(responses))
    monkeypatch.setattr('smoketests.support.time.sleep', lambda seconds: None)

    assertions.assert_route_absent('192.0.2.0/24', 'blackhole')

    assert list(responses) == []


def test_route_absent_fails_immediately_when_still_configured(monkeypatch):
    monkeypatch.setattr(assertions, 'cmd', lambda argv, **options: 'ip route 192.0.2.0/24 blackhole\n')
    monkeypatch.setattr(assertions, 'wait_for', lambda *args, **kwargs: pytest.fail('Must fail before polling'))

    with pytest.raises(AssertionError, match='unexpectedly found'):
        assertions.assert_route_absent('192.0.2.0/24', 'blackhole')


def test_no_static_routes_checks_each_test_prefix(monkeypatch):
    commands = []

    def command(argv, **options):
        commands.append(argv)
        return ''

    monkeypatch.setattr(assertions, 'cmd', command)

    assertions.assert_no_static_routes('192.0.2.0/24', '2001:db8:100::/64')

    assert commands == [
        ['vtysh', '-c', 'show running-config'],
        ['ip', '-4', 'route', 'show', 'table', 'main', 'exact', '192.0.2.0/24'],
        ['ip', '-6', 'route', 'show', 'table', 'main', 'exact', '2001:db8:100::/64'],
    ]


def test_no_static_routes_rejects_other_default_vrf_routes(monkeypatch):
    monkeypatch.setattr(assertions, 'cmd', lambda argv, **options: 'ip route 198.51.100.0/24 blackhole\n')

    with pytest.raises(AssertionError, match='Default-VRF static routes remain'):
        assertions.assert_no_static_routes('192.0.2.0/24')


def test_route_polling_timeout_reports_last_kernel_state(monkeypatch):
    responses = iter(['ip route 192.0.2.0/24 blackhole\n', 'unreachable 192.0.2.0/24\n'])
    monkeypatch.setattr(assertions, 'cmd', lambda argv, **options: next(responses))
    wait_for = assertions.wait_for

    def immediate_timeout(read, matches, *, description):
        return wait_for(read, matches, description=description, timeout=0)

    monkeypatch.setattr(assertions, 'wait_for', immediate_timeout)

    with pytest.raises(AssertionError, match='Last observation:\nunreachable 192.0.2.0/24'):
        assertions.assert_route_present('192.0.2.0/24', 'blackhole')


def test_frr_assertions_keep_vrf_sections_separate(monkeypatch):
    """Same-prefix routes in different VRFs must never satisfy each other's checks."""
    output = (
        'vrf BLUE\n ip route 192.0.2.0/24 reject\nexit-vrf\n'
        'vrf RED\n ip route 192.0.2.0/24 198.51.100.1\nexit-vrf\n'
        'ip route 192.0.2.0/24 blackhole\n'
    )
    monkeypatch.setattr(assertions, 'cmd', lambda argv, **options: output)

    assertions.assert_frr_routes('ip route 192.0.2.0/24 reject', vrf='BLUE')
    assertions.assert_frr_routes('ip route 192.0.2.0/24 blackhole')
    assertions.assert_frr_route_absent('ip route 192.0.2.0/24 blackhole', vrf='BLUE')
    with pytest.raises(AssertionError, match='Missing static configuration in VRF BLUE'):
        assertions.assert_frr_routes('ip route 192.0.2.0/24 198.51.100.1', vrf='BLUE')


def test_kernel_assertion_requires_one_matching_snapshot(monkeypatch):
    """Do not combine partial observations or accept a stale disabled next hop."""
    outputs = iter(['via one', 'via two', 'via one via two via old', 'via one via two'])
    commands = []

    def command(argv, **options):
        """Return successive kernel observations without touching the host."""
        commands.append(argv)
        return next(outputs)

    monkeypatch.setattr(assertions, 'cmd', command)
    monkeypatch.setattr('smoketests.support.time.sleep', lambda seconds: None)

    assertions.assert_kernel_route('2001:db8::/64', 'via one', 'via two', absent=('via old',),
                                   vrf='BLUE', source='2001:db8:1::/64')

    assert len(commands) == 4
    assert commands[0] == ['ip', '-6', 'route', 'show', 'vrf', 'BLUE', 'exact',
                           '2001:db8::/64', 'from', '2001:db8:1::/64']


def test_kernel_absence_uses_requested_vrf_and_source(monkeypatch):
    """Withdrawal checks must target the same route scope as installation checks."""
    commands = []

    def command(argv, **options):
        """Capture the query and report an empty routing-table selection."""
        commands.append(argv)
        return ''

    monkeypatch.setattr(assertions, 'cmd', command)
    assertions.assert_kernel_route_absent('2001:db8::/64', vrf='BLUE', source='2001:db8:1::/64')

    assert commands == [['ip', '-6', 'route', 'show', 'vrf', 'BLUE', 'exact',
                         '2001:db8::/64', 'from', '2001:db8:1::/64']]


@pytest.mark.parametrize('routes', [None, [], [{'prefix': '192.0.2.0/24'}]])
def test_static_instance_must_exist_and_be_empty(monkeypatch, routes):
    """An empty instance is valid; remaining routes or a missing instance are not."""
    import json

    instance = {'type': 'frr-staticd:staticd', 'name': 'staticd', 'vrf': 'BLUE'}
    if routes is not None:
        instance['frr-staticd:staticd'] = {'route-list': routes}
    data = {'frr-routing:routing': {'control-plane-protocols': {'control-plane-protocol': [instance]}}}
    monkeypatch.setattr(assertions, 'cmd', lambda argv, **options: json.dumps(data))

    if routes:
        with pytest.raises(AssertionError):
            assertions.assert_static_instance_empty('BLUE')
    else:
        assertions.assert_static_instance_empty('BLUE')

    with pytest.raises(AssertionError, match='missing for VRF default'):
        assertions.assert_static_instance_empty()


@pytest.mark.parametrize('configuration', [
    {'interfaces': {'dummy': {'dum997': {}}}},
    {'firewall': {'inbound-interface': ['dum997']}},
    {'protocols': {'next-hop': {'vrf': 'NVYRSMOKE'}}},
])
def test_reserved_test_resources_detects_definitions_and_references(configuration):
    """Preflight must reject references even when the resource does not yet exist."""
    with pytest.raises(AssertionError, match='already configured or referenced'):
        assertions.assert_config_names_unused(configuration, 'dum997', 'NVYRSMOKE')

    assertions.assert_config_names_unused({'description': 'Using dum997 in a sentence', 'value': 997}, 'dum997')


@pytest.mark.parametrize('first, second, interface, success', [
    (2, 3, 'dum997', True),
    (170, 255, 'dum997', True),
    (3, 2, 'dum997', False),
    (1, 1, 'dum997', False),
    (0, 0, 'dum997', False),
    (170, 255, 'eth0', False),
])
def test_kernel_weights_check_ratios_and_member_identity(monkeypatch, first, second, interface, success):
    """Accept Zebra's scaled weights, but reject reversed weights or wrong links."""
    output = (
        f' nexthop via 198.18.97.2 dev {interface} weight {first}\n'
        f' nexthop via 198.18.97.3 dev {interface} weight {second}\n'
    )
    monkeypatch.setattr(assertions, 'cmd', lambda argv, **options: output)
    wait_for = assertions.wait_for

    def immediate_timeout(read, matches, *, description):
        """Fail mismatches immediately while exercising the production predicate."""
        return wait_for(read, matches, description=description, timeout=0)

    monkeypatch.setattr(assertions, 'wait_for', immediate_timeout)
    weights = {('198.18.97.2', 'dum997'): 2, ('198.18.97.3', 'dum997'): 3}
    if success:
        assertions.assert_kernel_multipath_weights('192.0.2.0/24', weights)
    else:
        with pytest.raises(AssertionError, match='multipath weights'):
            assertions.assert_kernel_multipath_weights('192.0.2.0/24', weights)
