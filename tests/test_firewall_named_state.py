"""Named allowances and counters share state without sharing rule verdicts."""

from copy import deepcopy
import json

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import nftables
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


def configuration(per=None):
    options = {'rate': {'packets': '1/h'}, 'burst': {'packets': '2'}, 'over': True}
    if per:
        options['per'] = per

    return {'firewall': {
        'group': {'limit-group': {'ipv4': {'SHARED': options}},
                  'counter-group': {'TOTAL': {'description': 'Shared total'}}},
        'ipv4': {'output': {'filter': {'rule': {
            '10': {'action': 'continue', 'limit': {'group': 'SHARED'}, 'counter': {'group': 'TOTAL'}},
            '20': {'action': 'drop', 'limit': {'group': 'SHARED'}, 'counter': {'group': 'TOTAL'}},
        }}}},
    }}


@pytest.mark.parametrize('per', [None, 'source-address,destination-address'])
def test_shared_definitions_and_consumer_changes(per):
    tree = configuration(per)
    text = rendered(tree)
    native = 'ipv4_limit_group_SHARED'
    kind = 'set' if per else 'limit'
    assert f'{kind} {native} {{' in text
    assert text.count('counter name counter_group_TOTAL') == 2
    assert text.count('update @' + native if per else 'limit name ' + native) == 2

    # Rebuilding a consumer must preserve the shared object's runtime state.
    changed = deepcopy(tree)
    changed['firewall']['ipv4']['output']['filter']['rule']['10']['description'] = 'Changed'
    text = rendered(changed, tree)
    assert 'ipv4_output' in destroyed(text)
    assert native not in destroyed(text, kind)
    assert 'counter_group_TOTAL' not in destroyed(text, 'counter')

    # Changing a provider rebuilds both it and the chains referencing it.
    changed = deepcopy(tree)
    changed['firewall']['group']['limit-group']['ipv4']['SHARED']['rate']['packets'] = '2/h'
    text = rendered(changed, tree)
    assert native in destroyed(text, kind)
    assert 'ipv4_output' in destroyed(text)


def test_references_completion_and_deletion_protection(controller, session):
    controller.execute('set firewall group limit-group ipv4 L rate packets 10/s', session)
    controller.execute('set firewall group counter-group C', session)
    controller.execute('set firewall ipv4 input filter rule 10 action drop limit group L counter group C', session)

    prefix = 'set firewall ipv4 input filter rule 20 limit group '
    assert 'L' in dict(controller.completion(prefix, session)['candidates'])
    assert 'L' not in dict(controller.completion(prefix.replace('ipv4', 'ipv6'), session)['candidates'])
    for command in ('delete firewall group limit-group ipv4 L', 'delete firewall group counter-group C'):
        with pytest.raises(RouterError, match='referenced'):
            controller.execute(command, session)


@pytest.mark.parametrize('change, message', [
    ({'limit': {'group': 'MISSING'}}, 'not configured'),
    ({'limit': {'group': 'SHARED', 'over': True}}, 'inline'),
    ({'counter': {'group': 'MISSING'}}, 'not configured'),
    ({'log': {'flags': 'all,ether'}}, 'cannot be combined'),
])
def test_invalid_references_and_options(change, message):
    tree = configuration()
    tree['firewall']['ipv4']['output']['filter']['rule']['10'].update(change)
    with pytest.raises(RouterError, match=message):
        rendered(tree)


def test_named_limits_inherit_nested_jump_hook_restrictions():
    tree = configuration('inbound-interface')
    rules = tree['firewall']['ipv4']['output']['filter']['rule']
    tree['firewall']['ipv4']['name'] = {
        'FIRST': {'rule': {'10': {'action': 'jump', 'jump-target': 'SECOND'}}},
        'SECOND': {'rule': deepcopy(rules)},
    }
    rules.clear()
    rules['10'] = {'action': 'jump', 'jump-target': 'FIRST'}
    with pytest.raises(RouterError, match='inbound-interface in output'):
        rendered(tree)


def test_logging_and_global_counter_preserve_explicit_named_counter():
    tree = configuration()
    tree['firewall']['global-options'] = {'counter': True}
    rule = tree['firewall']['ipv4']['output']['filter']['rule']['10']
    rule['log'] = {'level': 'info', 'flags': 'tcp-sequence,tcp-options,ip-options,skuid,ether'}
    text = rendered(tree)
    assert 'level info flags tcp sequence flags tcp options flags ip options flags skuid flags ether' in text
    assert text.count('counter name counter_group_TOTAL') == 2


def test_unused_group_is_verified():
    tree = configuration()
    tree['firewall']['group']['limit-group']['ipv6'] = {'BAD': {'per': 'source-address'}}
    with pytest.raises(RouterError, match='requires rate'):
        rendered(tree)


def test_bare_log_and_counter_survive_return_to_outer_anchor(controller, engine, session):
    controller.execute('set firewall ipv4 input filter rule 10 log counter last-used action accept', session)
    rule = engine.view(session)['firewall']['ipv4']['input']['filter']['rule']['10']
    assert rule['log'] == {}
    assert rule['counter'] == {}
    assert rule['last-used'] is True
    assert rule['action'] == 'accept'


def test_log_flags_joinable_suggestions_and_invalid_values(controller, engine, session):
    command = 'set firewall ipv4 input filter rule 10 log flags '
    assert 'tcp-options' in dict(controller.completion(command, session)['candidates'])
    controller.execute(command + 'tcp-sequence and tcp-options level debug action drop', session)
    rule = engine.view(session)['firewall']['ipv4']['input']['filter']['rule']['10']
    assert rule['log'] == {'flags': 'tcp-sequence,tcp-options', 'level': 'debug'}
    for value in ('tcp-optios', 'tcp-options and invalid', 'tcp-options and tcp-options'):
        with pytest.raises(RouterError):
            controller.execute(command + value, session)


def test_group_change_rebuilds_nested_jump_consumers():
    tree = configuration()
    rule = tree['firewall']['ipv4']['output']['filter']['rule']['10']
    tree['firewall']['ipv4']['name'] = {
        'FIRST': {'rule': {'10': {'action': 'jump', 'jump-target': 'SECOND'}}},
        'SECOND': {'rule': {'10': deepcopy(rule)}},
    }
    tree['firewall']['ipv4']['output']['filter']['rule'] = {
        '10': {'action': 'jump', 'jump-target': 'FIRST'},
    }
    changed = deepcopy(tree)
    changed['firewall']['group']['counter-group']['TOTAL']['description'] = 'New description'
    text = rendered(changed, tree)
    assert {'ipv4_output', 'ipv4_name_FIRST', 'ipv4_name_SECOND'} <= destroyed(text)
    assert 'counter_group_TOTAL' in destroyed(text, 'counter')
    assert not destroyed(text, 'limit')


def test_recovery_inventory_ignores_unmanaged_objects(monkeypatch):
    records = [
        {'counter': {'family': 'inet', 'table': 'nvyr_filter', 'name': 'counter_group_TOTAL'}},
        {'limit': {'family': 'inet', 'table': 'nvyr_filter', 'name': 'ipv4_limit_group_LOGIN'}},
        {'set': {'family': 'inet', 'table': 'nvyr_filter', 'name': 'ipv6_limit_group_SUBNETS'}},
        {'counter': {'family': 'inet', 'table': 'other', 'name': 'counter_group_TOTAL'}},
        {'counter': {'family': 'ip', 'table': 'nvyr_filter', 'name': 'counter_group_TOTAL'}},
        {'counter': {'family': 'inet', 'table': 'nvyr_filter', 'name': 'external_counter'}},
    ]
    requests = []

    def inventory(argv):
        requests.append(argv)
        return json.dumps({'nftables': records})

    monkeypatch.setattr(nftables, 'cmd', inventory)
    assert set(nftables.Manager().named_state()) == {
        ('counter', 'counter_group_TOTAL'), ('limit', 'ipv4_limit_group_LOGIN'),
        ('set', 'ipv6_limit_group_SUBNETS'),
    }
    assert all('ruleset' not in argv for argv in requests)
