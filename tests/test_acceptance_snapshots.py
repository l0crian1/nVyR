"""Native comparisons preserve policy differences while ignoring runtime activity."""

from copy import deepcopy
from unittest.mock import MagicMock, patch

import pytest

from acceptance import snapshots
from acceptance import checks


def ruleset():
    """Use native JSON shapes for counters, last-used, limits and learned sets."""
    return {'nftables': [
        {'metainfo': {'version': '1.1.7'}},
        {'table': {'family': 'inet', 'name': 'nvyr_filter', 'handle': 1}},
        {'set': {'name': 'learned', 'flags': ['dynamic', 'timeout'], 'timeout': 600,
                 'elem': ['192.0.2.1'], 'count': 1, 'handle': 2}},
        {'set': {'name': 'configured', 'elem': ['192.0.2.2', '192.0.2.1'], 'handle': 3}},
        {'rule': {'chain': 'input', 'handle': 4, 'expr': [
            {'match': {'left': {'ct': {'key': 'bytes'}}, 'right': 1000}},
            {'counter': {'packets': 5, 'bytes': 500}},
            {'last': {'used': True, 'msecs': 1234}},
            {'quota': {'val': 4096, 'used': 123}},
            {'accept': None},
        ]}},
        {'rule': {'chain': 'input', 'handle': 5, 'expr': [{'drop': None}]}},
    ]}


def test_runtime_state_does_not_fail_reboot_comparison():
    before = ruleset()
    after = deepcopy(before)
    for entry in after['nftables']:
        for value in entry.values():
            if 'handle' in value:
                value['handle'] += 100
    after['nftables'][2]['set']['elem'] = []
    after['nftables'][2]['set'].pop('count')
    after['nftables'][3]['set']['elem'].reverse()
    expressions = after['nftables'][4]['rule']['expr']
    expressions[1]['counter'].update(packets=0, bytes=0)
    expressions[2]['last'].update(used=False, msecs=0)
    expressions[3]['quota']['used'] = 0

    assert snapshots.firewall(before) == snapshots.firewall(after)
    assert before['nftables'][4]['rule']['handle'] == 4


def test_rule_order_and_expression_changes_are_detected():
    before = ruleset()
    reordered = deepcopy(before)
    reordered['nftables'][-2:] = reversed(reordered['nftables'][-2:])
    assert snapshots.firewall(before) != snapshots.firewall(reordered)

    changed = deepcopy(before)
    changed['nftables'][4]['rule']['expr'][0]['match']['right'] = 2000
    assert snapshots.firewall(before) != snapshots.firewall(changed)


def test_configured_elements_and_dynamic_definition_changes_are_detected():
    before = ruleset()
    changed = deepcopy(before)
    changed['nftables'][3]['set']['elem'].pop()
    assert snapshots.firewall(before) != snapshots.firewall(changed)

    changed = deepcopy(before)
    changed['nftables'][2]['set']['timeout'] = 1200
    assert snapshots.firewall(before) != snapshots.firewall(changed)


def test_routing_commands_and_context_are_not_discarded():
    before = 'Building configuration...\n!\nrouter bgp 65000 vrf BLUE\n neighbor 192.0.2.1 remote-as 65001\nexit\n'
    assert snapshots.routing(before) == snapshots.routing(before.replace('!\n', '! comment\n'))
    assert snapshots.routing(before) != snapshots.routing(before.replace('BLUE', 'RED'))


def test_comparison_names_failures_and_keeps_a_diff():
    before = {'firewall': snapshots.firewall(ruleset()), 'routing': ['router bgp 65000'], 'vrf_conntrack': {}}
    after = deepcopy(before)
    after['firewall']['chains']['input'].pop()
    result = snapshots.compare(before, after)
    assert result[0]['check'] == 'firewall_native_configuration'
    assert result[0]['status'] == 'FAIL'
    assert 'drop' in result[0]['reason']
    assert result[1]['status'] == 'PASSED'


def test_routing_hostname_metadata_is_not_policy_drift():
    """Daemons can start before the OS hostname changes; routing must still match."""
    before = {'firewall': {}, 'vrf_conntrack': {}, 'routing': [
        'hostname localhost.localdomain', 'hostname nvyr',
        'router bgp 65000', ' neighbor 192.0.2.1 remote-as 65001', 'exit',
    ]}
    after = deepcopy(before)
    after['routing'].remove('hostname localhost.localdomain')
    assert snapshots.compare(before, after)[1]['status'] == 'PASSED'

    after['routing'][2] = ' neighbor 192.0.2.1 remote-as 65002'
    assert snapshots.compare(before, after)[1]['status'] == 'FAIL'


def test_os_hostname_is_verified_independently():
    """Ignoring FRR's cached names must not hide an incorrect system hostname."""
    session = MagicMock()
    session.__enter__.return_value.get_config.return_value = {'system': {'host-name': 'lab-router'}}
    with patch.object(checks, 'ConfigurationSession', return_value=session):
        with patch.object(checks.socket, 'gethostname', return_value='lab-router'):
            checks.check_system_hostname({})
        with patch.object(checks.socket, 'gethostname', return_value='localhost.localdomain'):
            with pytest.raises(AssertionError):
                checks.check_system_hostname({})


def test_os_hostname_uses_nvyr_default():
    """An omitted hostname still has the same default as the configuration script."""
    session = MagicMock()
    session.__enter__.return_value.get_config.return_value = {}
    with patch.object(checks, 'ConfigurationSession', return_value=session):
        with patch.object(checks.socket, 'gethostname', return_value='nvyr'):
            checks.check_system_hostname({})


def test_flowtable_prefix_changes_are_not_hidden_by_snapshot_normalization():
    """Replacing a subscription with today's exact interfaces changes saved policy."""
    before = {'nftables': [{'flowtable': {'family': 'inet', 'table': 'nvyr_filter',
              'name': 'flowtable_BOOTFAST', 'handle': 10, 'dev': ['veth995*', 'veth997*']}}]}
    after = deepcopy(before)
    after['nftables'][0]['flowtable']['handle'] = 20
    assert snapshots.firewall(before) == snapshots.firewall(after)

    after['nftables'][0]['flowtable']['dev'] = ['veth995', 'veth997']
    assert snapshots.firewall(before) != snapshots.firewall(after)


def test_flowtable_definition_without_attached_hooks_fails_acceptance(monkeypatch):
    """A restored prefix declaration alone is insufficient evidence of forwarding hooks."""
    monkeypatch.setattr(checks, 'assert_firewall_object',
                        lambda *args, **kwargs: 'flow add @flowtable_BOOTFAST counter; ct state vmap')
    monkeypatch.setattr(checks, 'cmd', lambda command: '')

    with pytest.raises(AssertionError):
        checks.check_firewall_flowtable({})


def test_vrf_zone_reallocation_preserves_ownership_but_detects_wrong_membership():
    before = {'nftables': [
        {'table': {'family': 'inet', 'name': 'nvyr_vrf_conntrack'}},
        {'map': {'name': 'interfaces', 'elem': [['BLUE', 4], ['RED', 8], ['eth1', 4], ['eth2', 8]]}},
    ]}
    after = deepcopy(before)
    after['nftables'][1]['map']['elem'] = [['BLUE', 1], ['RED', 2], ['eth1', 1], ['eth2', 2]]
    assert snapshots.vrf_conntrack(before, ['BLUE', 'RED']) == snapshots.vrf_conntrack(after, ['BLUE', 'RED'])

    after['nftables'][1]['map']['elem'][-1] = ['eth2', 1]
    assert snapshots.vrf_conntrack(before, ['BLUE', 'RED']) != snapshots.vrf_conntrack(after, ['BLUE', 'RED'])

    after['nftables'][1]['map']['elem'][1] = ['RED', 1]
    with pytest.raises(AssertionError, match='shared VRF'):
        snapshots.vrf_conntrack(after, ['BLUE', 'RED'])
