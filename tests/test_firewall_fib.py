"""FIB syntax, combinations, and hook restrictions across the jump graph."""

from copy import deepcopy

import pytest

from nvyr.errors import RouterError
from tests.test_firewall_maps import rendered


def fib_rule(fields=('source-address',), result=None):
    return {'action': 'accept', 'fib': {
        'lookup': dict.fromkeys(fields, True),
        'result': result if result is not None else {'outbound-interface': ['missing']},
    }}


def configured(rule, family='ipv4', hook='forward', stage='filter'):
    return {'firewall': {family: {hook: {stage: {'rule': {'10': rule}}}}}}


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_fib_cli_anchoring_completion_and_multiple_results(controller, engine, session, family):
    prefix = f'set firewall {family} forward filter rule 10'
    controller.execute(prefix + ' action accept fib lookup source-address inbound-interface packet-mark', session)
    controller.execute(prefix + ' fib result outbound-interface eth0', session)
    controller.execute(prefix + ' fib result outbound-interface eth1', session)

    choices = dict(controller.completion(prefix + ' fib lookup source-address ', session, explicit=True)['candidates'])
    assert {'inbound-interface', 'outbound-interface', 'packet-mark'} <= choices.keys()
    assert 'source-address' not in choices
    text = rendered(engine.view(session))
    assert 'fib saddr . iif . mark oifname { "eth0", "eth1" } accept' in text, text

    with pytest.raises(RouterError):
        controller.execute(prefix + ' fib result route-type invalid', session)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('hook,stage', [('prerouting', 'raw'), ('input', 'filter'),
                                      ('forward', 'filter'), ('output', 'filter'), ('output', 'raw')])
@pytest.mark.parametrize('modifier', [None, 'inbound-interface', 'outbound-interface'])
@pytest.mark.parametrize('result', [{'outbound-interface': ['missing']}, {'outbound-interface': ['exists']},
                                  {'outbound-interface': ['eth0', 'eth1']}, {'route-type': ['local', 'unicast']}])
def test_fib_hook_matrix(family, hook, stage, modifier, result):
    fields = ['destination-address', 'packet-mark']
    if modifier:
        fields.append(modifier)
    rule = fib_rule(fields, result)
    tree = configured(rule, family, hook, stage)
    interface_result = 'outbound-interface' in result
    invalid = (
        (interface_result and modifier == 'outbound-interface')
        or (hook == 'output' and (interface_result or modifier == 'inbound-interface'))
        or (hook in ('input', 'prerouting') and modifier == 'outbound-interface')
    )

    if invalid:
        with pytest.raises(RouterError, match='fib:'):
            rendered(tree)
    else:
        text = rendered(tree)
        assert 'fib daddr' in text and '. mark' in text


@pytest.mark.parametrize('fib,error', [
    ({}, 'exactly one'),
    ({'lookup': {'packet-mark': True}}, 'exactly one'),
    ({'lookup': {'source-address': True, 'destination-address': True}}, 'exactly one'),
    ({'lookup': {'source-address': True, 'inbound-interface': True, 'outbound-interface': True}}, 'mutually exclusive'),
    ({'lookup': {'source-address': True}}, 'result requires'),
    ({'lookup': {'source-address': True}, 'result': {}}, 'result requires'),
    ({'lookup': {'source-address': True}, 'result': {'route-type': ['local'], 'outbound-interface': ['eth0']}}, 'result requires'),
    ({'lookup': {'source-address': True}, 'result': {'outbound-interface': ['exists', 'missing']}}, 'cannot be combined'),
    ({'lookup': {'source-address': True}, 'result': {'outbound-interface': ['eth0', 'missing']}}, 'cannot be combined'),
])
def test_incomplete_or_conflicting_fib(fib, error):
    with pytest.raises(RouterError, match=error):
        rendered(configured({'action': 'accept', 'fib': fib}))


def test_fib_nested_anchor_returns_to_rule_and_respects_edit(controller, engine, session):
    controller.execute('set firewall ipv4 forward filter rule 10 fib lookup sou in packet-m '
                       'log fib result outbound-interface missing action drop', session)
    rule = engine.view(session)['firewall']['ipv4']['forward']['filter']['rule']['10']
    assert rule == {
        'action': 'drop', 'log': {},
        'fib': {'lookup': {'source-address': True, 'inbound-interface': True, 'packet-mark': True},
                'result': {'outbound-interface': ['missing']}},
    }

    # Once the command returns to rule options, an interface match is a normal valued leaf.
    controller.execute('set firewall ipv4 forward filter rule 20 fib lookup source-address log '
                       'inbound-interface eth0 fib result route-type local action accept', session)
    rule = engine.view(session)['firewall']['ipv4']['forward']['filter']['rule']['20']
    assert rule['inbound-interface'] == ['eth0']
    assert rule['fib']['lookup'] == {'source-address': True}

    controller.execute('edit firewall ipv4 forward filter rule 10 fib lookup', session)
    with pytest.raises(RouterError):
        controller.execute('set source-address log', session)
    assert 'log' not in dict(controller.completion('set source-address ', session)['candidates'])


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('via_map', [False, True])
def test_named_chain_checks_every_caller_through_nested_jumps(family, via_map):
    entry = {'action': 'jump', 'jump-target': 'FIRST'}
    tree = configured(entry, family)
    tree['firewall'][family]['name'] = {
        'FIRST': {'rule': {'10': {'action': 'jump', 'jump-target': 'LAST'}}},
        'LAST': {'rule': {'20': fib_rule()}},
    }
    if via_map:
        tree['firewall']['group'] = {'map': {family: {'DISPATCH': {
            'match': {'packet-mark': True}, 'result-type': 'verdict',
            'entry': {'one': {'packet-mark': '1', 'result': deepcopy(entry)}},
        }}}}
        tree['firewall'][family]['forward']['filter']['rule']['10'] = {'map': 'DISPATCH'}

    # Forward can reach the same FIB query through either kind of jump.
    rendered(tree)
    tree['firewall'][family]['output'] = deepcopy(tree['firewall'][family]['forward'])
    with pytest.raises(RouterError, match=f'{family} name LAST rule 20 fib:.*output hook'):
        rendered(tree)

    # A disabled caller does not impose hook restrictions on its targets.
    tree['firewall'][family]['output']['filter']['rule']['10']['disable'] = True
    rendered(tree)


def test_unreferenced_and_disabled_named_fib_rules():
    tree = {'firewall': {'ipv4': {'name': {'RPF': {'rule': {'10': fib_rule()}}}}}}
    rendered(tree)
    tree['firewall']['ipv4']['output'] = {'raw': {'rule': {'10': {'action': 'jump', 'jump-target': 'RPF'}}}}
    tree['firewall']['ipv4']['name']['RPF']['rule']['10']['disable'] = True
    text = rendered(tree)
    assert 'fib saddr' not in text


def test_fib_precedes_statements_and_coexists_with_map():
    rule = fib_rule()
    del rule['action']
    rule.update({'map': 'VERDICT', 'counter': {}, 'log': {}, 'notrack': True})
    tree = configured(rule, hook='prerouting', stage='raw')
    tree['firewall']['group'] = {'map': {'ipv4': {'VERDICT': {
        'match': {'source-address': True}, 'result-type': 'verdict',
    }}}}

    text = rendered(tree)
    line = next(line for line in text.splitlines() if 'fib saddr' in line)
    assert line.index('fib saddr') < line.index('counter')
    assert line.index('fib saddr') < line.index('notrack')
    assert 'vmap @ipv4_map_VERDICT' in line


def test_fib_jump_cycle_does_not_loop_in_verification():
    tree = configured({'action': 'jump', 'jump-target': 'A'})
    tree['firewall']['ipv4']['name'] = {
        'A': {'rule': {'10': {'action': 'jump', 'jump-target': 'B'}}},
        'B': {'rule': {'10': fib_rule(), '20': {'action': 'jump', 'jump-target': 'A'}}},
    }
    # nftables still rejects the cycle when checking the generated transaction.
    rendered(tree)
