"""Quota configuration, shared lifecycle, display and authorized resets."""

from copy import deepcopy
import json

import pytest

from nvyr.errors import OperationalError, RouterError
from nvyr.helpers import nftables
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.helpers.validators import quota_bytes
from nvyr.op_scripts import firewall
from tests.test_firewall_maps import rendered
from tests.test_login import as_role
from tests.test_nftables_lifecycle import destroyed


def configuration():
    return {'firewall': {
        'group': {'quota-group': {'SHARED': {'bytes': '1g', 'over': True}}},
        'ipv4': {'output': {'filter': {'rule': {
            '10': {'quota': {'group': 'SHARED'}, 'action': 'drop'},
        }}}},
        'ipv6': {'output': {'filter': {'rule': {
            '10': {'quota': {'group': 'SHARED'}, 'action': 'drop'},
        }}}},
    }}


@pytest.mark.parametrize('value,valid', [
    ('0', True), ('100', True), ('64k', True), ('100m', True), ('10g', True),
    ('9223372036854775807', True), ('9223372036854775808', False),
    ('8589934592g', False), ('-1', False), ('1.5g', False), ('10G', False),
    ('1g/s', False), ('1gbytes', False), ('1;drop', False), ('9' * 5000, False),
])
def test_quota_byte_units_and_kernel_bounds(value, valid):
    assert quota_bytes(value) is valid


@pytest.mark.parametrize('mode', [None, 'until', 'over'])
@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_inline_modes_precede_side_effects(family, mode):
    tree = configuration()
    rule = tree['firewall'][family]['output']['filter']['rule']['10']
    rule.update({'quota': {'bytes': '64k'}, 'counter': {}, 'log': {}})
    if mode:
        rule['quota'][mode] = True

    text = rendered(tree)
    expression = f'quota {mode or "until"} 65536 bytes'
    assert expression in text
    line = next(line for line in text.splitlines() if expression in line)
    assert line.index(expression) < line.index('log prefix') < line.index('counter') < line.index('drop')


@pytest.mark.parametrize('options,error', [
    ({}, 'requires bytes'),
    ({'bytes': '1m', 'over': True, 'until': True}, 'mutually exclusive'),
    ({'group': 'MISSING'}, 'not configured'),
    ({'group': 'SHARED', 'until': True}, 'inline'),
    ({'group': 'SHARED', 'bytes': '1m'}, 'inline'),
])
def test_invalid_rule_quotas(options, error):
    tree = configuration()
    tree['firewall']['ipv4']['output']['filter']['rule']['10']['quota'] = options
    with pytest.raises(RouterError, match=error):
        rendered(tree)


@pytest.mark.parametrize('options', [{}, {'bytes': '1m', 'over': True, 'until': True}])
def test_unused_quota_groups_are_verified(options):
    with pytest.raises(RouterError, match='quota'):
        rendered({'firewall': {'group': {'quota-group': {'UNUSED': options}}}})


def test_shared_quota_lifecycle_and_nested_jumps():
    tree = configuration()
    tree['firewall']['ipv4']['name'] = {
        'FIRST': {'rule': {'10': {'action': 'jump', 'jump-target': 'SECOND'}}},
        'SECOND': {'rule': {'10': {'action': 'drop', 'quota': {'group': 'SHARED'}}}},
    }
    rule = tree['firewall']['ipv4']['output']['filter']['rule']['10']
    rule.clear()
    rule.update({'action': 'jump', 'jump-target': 'FIRST'})
    text = rendered(tree)
    assert text.count('quota quota_group_SHARED {') == 1
    assert text.count('quota name quota_group_SHARED') == 2
    assert not destroyed(rendered(tree, tree), 'quota')

    # A consumer rebuild must not reset the shared allowance.
    changed = deepcopy(tree)
    changed['firewall']['ipv4']['name']['SECOND']['rule']['10']['description'] = 'Changed rule'
    text = rendered(changed, tree)
    assert 'ipv4_name_SECOND' in destroyed(text)
    assert not destroyed(text, 'quota')

    # A changed provider rebuilds its direct and nested callers in both families.
    changed = deepcopy(tree)
    changed['firewall']['group']['quota-group']['SHARED']['bytes'] = '2g'
    text = rendered(changed, tree)
    assert destroyed(text, 'quota') == {'quota_group_SHARED'}
    assert {'ipv4_output', 'ipv4_name_FIRST', 'ipv4_name_SECOND', 'ipv6_output'} <= destroyed(text)
    assert text.index('flush chain') < text.index('destroy quota')

    # Global tracking flags do not recreate quota objects.
    changed = deepcopy(tree)
    changed['firewall']['global-options'] = {'counter': True, 'last-used': True}
    assert not destroyed(rendered(changed, tree), 'quota')


def test_quota_cli_completion_dependency_and_config_mode_reset(controller, engine, session, monkeypatch):
    controller.execute('set firewall group quota-group SHARED bytes 100g over description "Guest allowance"', session)
    controller.execute('set firewall ipv4 forward filter rule 10 quota group SHARED action drop', session)
    controller.execute('set firewall group counter-group TOTAL', session)

    for command in ['set firewall ipv6 forward filter rule 20 quota group ',
                    'run clear firewall quota ']:
        assert 'SHARED' in dict(controller.completion(command, session, explicit=True)['candidates'])
    assert 'TOTAL' in dict(controller.completion('run clear firewall counter ', session, explicit=True)['candidates'])
    with pytest.raises(RouterError, match='referenced'):
        controller.execute('delete firewall group quota-group SHARED', session)

    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    with as_role('net-admin'):
        controller.execute('run clear firewall quota SHARED', session)
    assert calls[-1] == ['firewall.nvyr.op', 'clear_quota', 'SHARED']
    assert engine.view(session)['firewall']['group']['quota-group']['SHARED']['bytes'] == '100g'


@pytest.mark.parametrize('role', ['read-only', 'net-admin', 'sys-admin'])
@pytest.mark.parametrize('kind', ['counter', 'quota'])
def test_reset_role_enforcement(controller, monkeypatch, role, kind):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    with as_role(role):
        if role == 'read-only':
            with pytest.raises(RouterError, match='net-admin'):
                controller.execute(f'clear firewall {kind} TEST')
            assert calls == []
        else:
            controller.execute(f'clear firewall {kind} TEST')
            assert calls == [['firewall.nvyr.op', 'clear_' + kind, 'TEST']]


@pytest.mark.parametrize('kind', ['counter', 'quota'])
def test_reset_targets_only_requested_object(kind, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(firewall, 'rc_cmd', lambda argv: (calls.append(argv) or (0, 'native object dump')))
    function = getattr(firewall, 'clear_' + kind)
    function('TEST')
    assert calls == [['nft', 'reset', kind, 'inet', 'nvyr_filter', kind + '_group_TEST']]
    assert capsys.readouterr().out == f'{kind.capitalize()} TEST reset.\n'

    with pytest.raises(OperationalError, match='Invalid'):
        function('TEST; flush ruleset')
    assert len(calls) == 1

    monkeypatch.setattr(firewall, 'rc_cmd', lambda argv: (1, 'No such file or directory'))
    with pytest.raises(OperationalError, match='Cannot reset'):
        function('MISSING')


def test_quota_normalization_and_display(monkeypatch, capsys):
    document = {'nftables': [
        {'quota': {'family': 'inet', 'table': 'nvyr_filter', 'name': 'quota_group_SHARED',
                   'bytes': 1024, 'used': 1024, 'inv': True, 'comment': 'Guest allowance'}},
        {'rule': {'family': 'inet', 'table': 'nvyr_filter', 'chain': 'ipv4_output',
                  'expr': [{'quota': {'val': 1, 'val_unit': 'mbytes', 'used': 2, 'used_unit': 'kbytes'}}]}},
        {'rule': {'family': 'inet', 'table': 'nvyr_filter', 'chain': 'ipv6_output',
                  'expr': [{'quota': 'quota_group_SHARED'}]}},
    ]}
    table = normalize(document)['tables']['inet']['nvyr_filter']
    assert table['quotas']['quota_group_SHARED']['exhausted'] is True
    assert table['quotas']['quota_group_SHARED']['remaining'] == 0
    assert table['chains']['ipv4_output']['rules'][0]['quota'] == {
        'bytes': 1024**2, 'used': 2048, 'mode': 'until',
    }
    assert table['chains']['ipv6_output']['rules'][0]['quota'] == {'group': 'SHARED'}

    monkeypatch.setattr(firewall, '_load_table', lambda *, failsafe=False: table)
    for detail in (False, True):
        firewall.show(section='group', group_kind='quota-group', group_name='SHARED', detail=detail)
        text = capsys.readouterr().out
        assert all(label in text for label in ['Allowance (bytes)', 'Used (bytes)', 'Remaining (bytes)', 'Exhausted'])
        assert 'Yes' in text and 'over' in text and 'Guest allowance' in text


def test_quota_recovery_inventory_uses_owned_namespace(monkeypatch):
    records = [
        {'quota': {'family': 'inet', 'table': 'nvyr_filter', 'name': 'quota_group_TEST'}},
        {'quota': {'family': 'inet', 'table': 'external', 'name': 'quota_group_TEST'}},
        {'quota': {'family': 'inet', 'table': 'nvyr_filter', 'name': 'external'}},
    ]
    monkeypatch.setattr(nftables, 'cmd', lambda argv: json.dumps({'nftables': records}))
    assert nftables.Manager().named_state() == [('quota', 'quota_group_TEST')]
