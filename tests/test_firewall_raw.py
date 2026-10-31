"""Raw hooks, interface availability, and independent whole-chain replacement."""

from copy import deepcopy

import pytest

from nvyr.errors import RouterError
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('hook,available,unavailable', [
    ('prerouting', 'inbound-interface', 'outbound-interface'),
    ('output', 'outbound-interface', 'inbound-interface'),
])
def test_raw_cli_validation_completion_and_rendering(controller, engine, session, family, hook, available, unavailable):
    prefix = f'firewall {family} {hook} raw'
    controller.execute(f'set {prefix} rule 10 action continue notrack {available} eth0 log counter', session)
    controller.execute(f'set {prefix} default-log', session)

    choices = dict(controller.completion(f'set {prefix} rule 20 ', session, explicit=True)['candidates'])
    assert {'notrack', available, available + '-group'} <= choices.keys()
    assert unavailable not in choices and unavailable + '-group' not in choices

    for option in (unavailable + ' eth0', unavailable + '-group WAN', 'notrack true', 'action offload'):
        with pytest.raises(RouterError):
            controller.execute(f'set {prefix} rule 20 {option}', session)

    text = rendered(engine.view(session))
    native = 'output_raw' if hook == 'output' else 'prerouting'
    label = 'OUT' if hook == 'output' else 'PRE'
    assert f'chain {family}_{native} {{' in text
    assert f'type filter hook {hook} priority raw; policy accept;' in text
    assert f'{family} : jump {family}_{native}' in text
    assert 'notrack continue' in text
    assert f'[{family}-{label}-raw-10-C]' in text
    assert f'[{family}-{label}-raw-default-A]' in text

    controller.execute(f'delete {prefix} rule 10 action', session)
    with pytest.raises(RouterError, match='action is required'):
        rendered(engine.view(session))


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('kind', ['map', 'match-group'])
@pytest.mark.parametrize('hook,field', [('prerouting', 'outbound-interface'), ('output', 'inbound-interface')])
def test_raw_rejects_unavailable_fields_in_group_matches(family, kind, hook, field):
    definition = {'match': {field: True}}
    rule = {kind: 'G'}
    if kind == 'map':
        definition['result-type'] = 'verdict'
    else:
        rule['action'] = 'accept'
    tree = {'firewall': {
        'group': {kind: {family: {'G': definition}}},
        family: {hook: {'raw': {'rule': {'10': rule}}}},
    }}

    with pytest.raises(RouterError, match=f'cannot match {field} in {hook} raw'):
        rendered(tree)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('hook,field', [('prerouting', 'outbound-interface'), ('output', 'inbound-interface')])
def test_raw_rejects_unavailable_fields_in_learning_targets(family, hook, field):
    tree = {'firewall': {
        'group': {'match-group': {family: {'G': {'match': {field: True}, 'dynamic': {}}}}},
        family: {hook: {'raw': {'rule': {'10': {'action': 'accept', 'add-to-group': {'match-group': 'G'}}}}}},
    }}

    with pytest.raises(RouterError, match=f'cannot extract {field} in {hook} raw'):
        rendered(tree)


def raw_and_filter():
    firewall = {'global-options': {'state-policy': {'established': {'action': 'accept'}}}}
    for family in ('ipv4', 'ipv6'):
        firewall[family] = {
            'output': {
                'raw': {'rule': {'10': {'action': 'continue', 'notrack': True, 'log': {}}}},
                'filter': {'rule': {'10': {'action': 'accept', 'log': {}}}},
            },
            'prerouting': {'raw': {}},
        }
    return {'firewall': firewall}


def test_both_families_and_stages_coexist_without_raw_state_policy():
    text = rendered(raw_and_filter())
    assert text.count('ct state vmap') == 1
    for family in ('ipv4', 'ipv6'):
        for native in ('output', 'output_raw', 'prerouting'):
            assert f'chain {family}_{native} {{' in text
        for stage in ('raw', 'filter'):
            assert f'[{family}-OUT-{stage}-10-' in text
    assert 'ipv4 : jump ipv4_output_raw, ipv6 : jump ipv6_output_raw' in text
    assert 'ipv4 : jump ipv4_prerouting, ipv6 : jump ipv6_prerouting' in text


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('stage,native', [('raw', 'output_raw'), ('filter', 'output')])
def test_changed_and_deleted_stage_preserves_other_stages(family, stage, native):
    before = raw_and_filter()
    after = deepcopy(before)
    after['firewall'][family]['output'][stage]['rule']['10']['description'] = 'Changed'
    assert destroyed(rendered(after, before)) == {native, family + '_' + native}

    del after['firewall'][family]['output'][stage]
    text = rendered(after, before)
    assert destroyed(text) == {native, family + '_' + native}
    assert f'chain {family}_{native} {{' not in text
    assert f'{family} : jump {family}_{native}' not in text


def test_state_policy_changes_do_not_rebuild_raw_chains():
    before = raw_and_filter()
    after = deepcopy(before)
    after['firewall']['global-options']['state-policy']['invalid'] = {'action': 'drop'}
    assert destroyed(rendered(after, before)) == {'output'}


def test_recovery_covers_all_raw_chains_and_removal_of_last_family():
    before = raw_and_filter()
    text = rendered(before, before, recovery=True)
    for family in ('ipv4', 'ipv6'):
        assert {family + '_output_raw', family + '_prerouting'} <= destroyed(text)
    assert {'output_raw', 'prerouting'} <= destroyed(text)

    text = rendered({}, before)
    assert {'output_raw', 'prerouting', 'ipv4_output_raw', 'ipv6_output_raw',
            'ipv4_prerouting', 'ipv6_prerouting'} <= destroyed(text)
    assert 'priority raw' not in text
