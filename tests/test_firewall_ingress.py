"""Ingress schema, transitive hook constraints and whole-chain lifecycle."""

from copy import deepcopy
import ast
from pathlib import Path

import pytest

from nvyr.errors import RouterError
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.helpers.log_reader import select
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


def ingress_tree(family='ipv4', rule=None):
    """Provide a bound chain without depending on a local interface inventory."""
    return {'firewall': {family: {'ingress': {'filter': {
        'interface': ['future*'], 'rule': {'10': rule or {'action': 'accept'}},
    }}}}}


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_ingress_schema_excludes_unavailable_commands(controller, engine, session, family):
    """Hidden commands must be rejected by parsing, not deferred to commit."""
    prefix = f'firewall {family} ingress filter'
    controller.execute(f'set {prefix} interface future*', session)
    choices = dict(controller.completion(f'set {prefix} rule 10 ', session, explicit=True)['candidates'])
    assert {'notrack', 'vlan', 'limit', 'map', 'match-group', 'inbound-interface'} <= choices.keys()
    assert not {'connection', 'fib', 'outbound-interface', 'outbound-interface-group',
                'outbound-link-group', 'offload-target'} & choices.keys()

    for option in ('connection state established', 'fib lookup source-address',
                   'outbound-interface eth0', 'outbound-interface-group WAN',
                   'outbound-link-group 1', 'action offload', 'limit per connection-mark',
                   'limit per outbound-interface', 'limit per outbound-link-group'):
        with pytest.raises(RouterError):
            controller.execute(f'set {prefix} rule 10 {option}', session)

    controller.execute(f'set {prefix} rule 10 action continue notrack vlan id 100 priority 5', session)
    text = rendered(engine.view(session))
    assert 'vlan id 100 vlan pcp 5 notrack continue' in text


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_ingress_requires_attachment_and_is_excluded_from_failsafe(controller, session, family):
    """An ingress chain cannot be globally attached or used as the boot firewall."""
    with pytest.raises(RouterError):
        controller.execute(f'set firewall fail-safe {family} ingress filter interface eth1', session)
    tree = ingress_tree(family)
    del tree['firewall'][family]['ingress']['filter']['interface']
    with pytest.raises(RouterError, match='at least one interface'):
        rendered(tree)


def test_ingress_family_attachments_and_state_policy_are_independent():
    """A shared native hook must dispatch each family only on its own devices."""
    tree = ingress_tree()
    tree['firewall']['ipv6'] = {'ingress': {'filter': {'interface': ['other0']}}}
    tree['firewall']['global-options'] = {'state-policy': {'established': {'action': 'accept'}}}
    text = rendered(tree)
    assert 'devices = { "future*", "other0" } priority -10' in text
    assert 'meta nfproto ipv4 iifname { "future*" } jump ipv4_ingress' in text
    assert 'meta nfproto ipv6 iifname { "other0" } jump ipv6_ingress' in text
    assert 'ct state' not in text

    after = deepcopy(tree)
    after['firewall']['ipv4']['ingress']['filter']['interface'] = ['new0']
    assert destroyed(rendered(after, tree)) == {'ingress', 'ipv4_ingress'}

    after = deepcopy(tree)
    after['firewall']['global-options']['state-policy']['invalid'] = {'action': 'drop'}
    assert not destroyed(rendered(after, tree))


@pytest.mark.parametrize('kind', ['map', 'match-group'])
@pytest.mark.parametrize('field', ['outbound-interface', 'outbound-link-group', 'connection'])
def test_ingress_rejects_group_inherited_fields(kind, field):
    """Shared groups cannot bypass the reduced ingress rule schema."""
    rule = {kind: 'G'}
    definition = {'match': {field: {'mark': True} if field == 'connection' else True}}
    if kind == 'map':
        definition['result-type'] = 'verdict'
    else:
        rule['action'] = 'accept'
    tree = ingress_tree(rule=rule)
    tree['firewall']['group'] = {kind: {'ipv4': {'G': definition}}}
    with pytest.raises(RouterError, match='unavailable in ingress'):
        rendered(tree)


def test_ingress_rejects_negative_and_dynamic_group_inherited_fields():
    """Both exclusions and packet-learned keys need the hook's field restrictions."""
    tree = ingress_tree(rule={'action': 'accept', 'not': {'match-group': 'G'}})
    tree['firewall']['group'] = {'match-group': {'ipv4': {
        'G': {'match': {'connection': {'mark': True}}, 'dynamic': {}},
    }}}
    with pytest.raises(RouterError, match='unavailable in ingress'):
        rendered(tree)

    tree['firewall']['ipv4']['ingress']['filter']['rule']['10'] = {
        'action': 'accept', 'add-to-group': {'match-group': 'G'},
    }
    with pytest.raises(RouterError, match='unavailable in ingress'):
        rendered(tree)


def test_ingress_nested_verdict_map_jump_checks_named_limits():
    """Trace map -> named chain -> named chain -> shared rate group."""
    tree = ingress_tree(rule={'map': 'ENTRY'})
    tree['firewall']['group'] = {
        'map': {'ipv4': {'ENTRY': {
            'match': {'source-address': True}, 'result-type': 'verdict',
            'entry': {'one': {'source-address': '192.0.2.1', 'result': {'action': 'jump', 'jump-target': 'FIRST'}}},
        }}},
        'limit-group': {'ipv4': {'RATE': {'rate': {'packets': '10/s'}, 'per': 'connection-mark'}}},
    }
    tree['firewall']['ipv4']['name'] = {
        'FIRST': {'rule': {'10': {'action': 'jump', 'jump-target': 'LAST'}}},
        'LAST': {'rule': {'10': {'action': 'accept', 'limit': {'group': 'RATE'}}}},
    }
    with pytest.raises(RouterError, match='connection-mark unavailable in ingress'):
        rendered(tree)

    tree['firewall']['group']['limit-group']['ipv4']['RATE']['per'] = 'source-address'
    text = rendered(tree)
    assert 'jump ipv4_name_FIRST' in text and 'jump ipv4_name_LAST' in text


def test_ingress_nested_named_chain_rejects_fib_and_connection_limit():
    """General named chains remain reusable, but every caller must be compatible."""
    tree = ingress_tree(rule={'action': 'jump', 'jump-target': 'FIRST'})
    tree['firewall']['ipv4']['name'] = {
        'FIRST': {'rule': {'10': {'action': 'jump', 'jump-target': 'LAST'}}},
        'LAST': {'rule': {'10': {'action': 'drop', 'fib': {
            'lookup': {'source-address': True}, 'result': {'outbound-interface': ['missing']},
        }}}},
    }
    with pytest.raises(RouterError, match='not supported from the ingress hook'):
        rendered(tree)
    tree['firewall']['ipv4']['name']['LAST']['rule']['10'] = {
        'action': 'drop', 'connection': {'limit': {'over': '5'}},
    }
    with pytest.raises(RouterError, match='unavailable in ingress'):
        rendered(tree)


def test_vlan_group_keys_render_and_enforce_hook_availability():
    """VLAN fields share the normal typed group formatter and reference validation."""
    tree = ingress_tree(rule={'map': 'VLAN'})
    tree['firewall']['group'] = {'map': {'ipv4': {'VLAN': {
        'match': {'vlan': {'id': True, 'priority': True}}, 'result-type': 'verdict',
        'entry': {'one': {'vlan': {'id': '100', 'priority': '5'}, 'result': {'action': 'accept'}}},
    }}}}
    text = rendered(tree)
    assert 'typeof vlan id . vlan pcp : verdict' in text
    assert '100 . 5 comment "one|" : accept' in text
    assert 'vlan id . vlan pcp vmap @ipv4_map_VLAN' in text

    tree['firewall']['ipv4']['forward'] = {'filter': {'rule': {'10': {'map': 'VLAN'}}}}
    with pytest.raises(RouterError, match='unavailable in forward'):
        rendered(tree)


def test_ingress_log_prefix_and_vlan_normalization():
    """Installed VLAN predicates and ingress log selectors retain their CLI identity."""
    tree = ingress_tree(rule={'action': 'drop', 'log': {}})
    assert '[ipv4-ING-filter-10-D]' in rendered(tree)
    _, pattern = select('firewall', family='ipv4', hook='ingress', stage='filter', rule='10')
    assert pattern.search('[ipv4-ING-filter-10-D]')
    assert not pattern.search('[ipv4-INP-filter-10-D]')
    data = normalize({'nftables': [{'rule': {
        'family': 'inet', 'table': 'nvyr_filter', 'chain': 'ipv4_ingress', 'comment': '10|',
        'expr': [{'match': {'op': '==', 'left': {'payload': {'protocol': 'vlan', 'field': 'id'}}, 'right': 100}}, {'drop': None}],
    }}]})
    rule = data['tables']['inet']['nvyr_filter']['chains']['ipv4_ingress']['rules'][0]
    assert 'unsupported' not in rule
    assert rule['vlan-id'] == 100


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_ingress_operational_dispatch(controller, session, monkeypatch, family):
    """Scoped views and logs dispatch to the same scripts as existing hooks."""
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    controller.execute(f'run show firewall {family} ingress filter rule 10', session)
    assert calls.pop() == ['firewall.nvyr.op', 'show', '--family', family, '--hook', 'ingress',
                           '--stage', 'filter', '--rule', '10']
    controller.execute(f'show firewall {family} ingress filter rule 10 limit')
    assert calls.pop() == ['firewall.nvyr.op', 'runtime', 'limit', '--family', family, '--hook', 'ingress',
                           '--stage', 'filter', '--rule', '10']
    controller.execute(f'show firewall {family} ingress filter quotas')
    assert calls.pop() == ['firewall.nvyr.op', 'runtime', 'quota', '--family', family, '--hook', 'ingress',
                           '--stage', 'filter']
    result = controller.execute(f'show log firewall {family} ingress filter rule 10')
    assert result['event'] == 'command'
    assert result['argv'] == ['logs.nvyr.op', 'show', 'firewall', '--family', family, '--hook', 'ingress',
                              '--stage', 'filter', '--rule', '10']


def test_ingress_summary_does_not_call_dispatch_a_state_policy(monkeypatch, capsys):
    """Synthetic ingress dispatch has no connection-state policy to display."""
    from nvyr.op_scripts import firewall

    monkeypatch.setattr(firewall, '_load_table', lambda **kwargs: {'chains': {
        'ingress': {'rules': []}, 'ipv4_ingress': {'rules': [
            {'number': '10', 'action': 'drop', 'vlan-id': 100},
            {'number': 'default', 'action': 'accept'},
        ]},
    }})
    firewall.show()
    output = capsys.readouterr().out
    assert 'IPv4 ingress filter' in output
    assert 'State policy (ingress)' not in output
    firewall.show(family='ipv4', hook='ingress', stage='filter', detail=True)
    assert 'VLAN ID' in capsys.readouterr().out


def test_ingress_smoketest_commands_parse(controller, engine, session):
    """Check installed-suite command examples without mutating a router in build tests."""
    source = Path(__file__).parents[1] / 'smoketests/test_firewall_ingress.py'
    for function in ast.parse(source.read_text()).body:
        if not isinstance(function, ast.FunctionDef) or not function.name.startswith('test_'):
            continue
        if 'schema_rejects' in function.name:
            continue
        engine.discard(session)
        for statement in function.body:
            if not isinstance(statement, ast.Expr) or not isinstance(statement.value, ast.Call):
                continue
            call = statement.value
            if isinstance(call.func, ast.Attribute) and call.func.attr == 'set':
                controller.execute(ast.literal_eval(call.args[0]), session)
