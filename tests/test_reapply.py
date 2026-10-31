"""Declarative watches select scripts once and preserve transaction boundaries."""

from copy import deepcopy
import json

import pytest

from build_tools.schema_builder import SchemaBuildError, build_schemas
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import reapply
from nvyr.helpers.dependencies import Dependencies
from nvyr.helpers.reapply_schema import validate_reapply
from nvyr.schema import Schema


def initial(controller, session, engine):
    controller.execute('set vrf name BLUE table 100', session)
    controller.execute('set vrf name RED table 101', session)
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('set firewall ipv4 input filter rule 10 inbound-interface dum0 action accept', session)
    assert all(result['success'] for result in engine.commit(session)['results'].values())
    for module in engine.modules.values():
        module.calls.clear()


def test_membership_change_runs_consumer_once_and_passes_reference_paths(controller, session, engine, monkeypatch):
    initial(controller, session, engine)
    controller.execute('set firewall ipv4 input filter rule 20 inbound-interface not dum0 action drop', session)
    engine.commit(session)
    contexts = []
    module = engine.modules['firewall']
    original = module.generate

    def record(configuration, context):
        contexts.append(context)
        return original(configuration, context)

    monkeypatch.setattr(module, 'generate', record)
    module.calls.clear()
    controller.execute('set interfaces dummy dum0 vrf BLUE', session)
    result = engine.commit(session)

    assert list(result['results']) == ['vrf_conntrack', 'dummy', 'firewall']
    assert len(contexts) == 1
    assert contexts[0].reapply_paths == {
        ('firewall', 'ipv4', 'input', 'filter', 'rule', '10', 'inbound-interface'),
        ('firewall', 'ipv4', 'input', 'filter', 'rule', '20', 'not', 'inbound-interface'),
    }
    assert not contexts[0].get_changed()


def test_unwatched_changes_and_unreferenced_interfaces_do_not_run_firewall(controller, session, engine):
    initial(controller, session, engine)
    controller.execute('set interfaces dummy dum0 link-group 123', session)
    assert set(engine.commit(session)['results']) == {'vrf_conntrack', 'dummy'}
    controller.execute('set interfaces dummy dum1 vrf BLUE', session)
    assert set(engine.commit(session)['results']) == {'vrf_conntrack', 'dummy'}


def test_check_includes_reapplied_script_without_apply(controller, session, engine):
    initial(controller, session, engine)
    controller.execute('set interfaces dummy dum0 vrf BLUE', session)
    assert set(engine.check(session)['results']) == {'vrf_conntrack', 'dummy', 'firewall'}
    assert [stage for _, stage, _ in engine.modules['firewall'].calls] == ['get_config', 'verify']
    assert 'vrf' not in engine.running['interfaces']['dummy']['dum0']


def test_new_vrf_membership_cannot_break_a_shared_named_chain(controller, session, engine):
    initial(controller, session, engine)
    controller.execute('set firewall ipv4 name SHARED rule 10 inbound-interface dum0 action accept', session)
    controller.execute('set firewall ipv4 input filter rule 20 action jump jump-target SHARED', session)
    controller.execute('set firewall ipv4 forward filter rule 10 action jump jump-target SHARED', session)
    assert engine.commit(session)['results']['firewall']['success']

    controller.execute('set interfaces dummy dum0 vrf BLUE', session)
    result = engine.commit(session)
    assert not result['changed']
    assert 'VRF-aware inbound matches cannot be shared' in result['results']['firewall']['error']
    assert not result['results']['dummy']['success']
    assert 'vrf' not in engine.running['interfaces']['dummy']['dum0']
    assert engine.view(session)['interfaces']['dummy']['dum0']['vrf'] == 'BLUE'


def test_failed_consumer_restores_provider_and_leaves_unrelated_success(controller, session, engine, monkeypatch):
    initial(controller, session, engine)
    controller.execute('set interfaces dummy dum0 vrf BLUE', session)
    controller.execute('set system host-name changed', session)
    recovered = []
    module = engine.modules['firewall']
    original = module.verify

    def fail(configuration, context):
        if not context.recovery:
            raise ValidationError('intentional firewall failure')
        recovered.append(context.effective['interfaces']['dummy']['dum0'])
        original(configuration, context)

    monkeypatch.setattr(module, 'verify', fail)
    result = engine.commit(session)
    assert result['results']['system']['success']
    assert not result['results']['dummy']['success']
    assert not result['results']['firewall']['success']
    assert 'vrf' not in engine.running['interfaces']['dummy']['dum0']
    assert engine.view(session)['interfaces']['dummy']['dum0']['vrf'] == 'BLUE'
    assert recovered and 'vrf' not in recovered[0]
    assert not engine.unhealthy


def test_failed_provider_prevents_consumer_using_unapplied_state(controller, session, engine, monkeypatch):
    initial(controller, session, engine)
    controller.execute('set interfaces dummy dum0 vrf BLUE', session)

    def fail(configuration, context):
        raise ValidationError('intentional interface failure')

    monkeypatch.setattr(engine.modules['dummy'], 'verify', fail)
    result = engine.commit(session)
    assert not result['results']['firewall']['success']
    # Preparatory zone changes require restoring the whole component, but the
    # firewall must never apply the failed target configuration.
    assert all(recovery for _, _, recovery in engine.modules['firewall'].calls)
    assert not result['changed']


def test_commit_confirm_restoration_reapplies_unchanged_firewall(controller, session, engine):
    initial(controller, session, engine)
    controller.execute('set interfaces dummy dum0 vrf BLUE', session)
    engine.commit(session, minutes=1, confirmed_minutes=1)
    engine.modules['firewall'].calls.clear()
    engine.clock = lambda: engine.pending['deadline'] + 1
    engine.tick()
    assert ('firewall', 'apply', True) in engine.modules['firewall'].calls
    assert 'vrf' not in engine.running['interfaces']['dummy']['dum0']
    assert engine.pending is None


def test_watch_is_generic_and_compares_only_declared_provider_fields():
    root = {'kind': 'node', 'children': {
        'objects': {'kind': 'tag_node', 'dependency': 'object', 'script': {'name': 'provider', 'priority': 20},
                    'children': {'selected': {'kind': 'leaf_node'}, 'other': {'kind': 'leaf_node'}}},
        'consumer': {'kind': 'leaf_node', 'depends': 'object', 'reapply-on-change': ['selected'],
                     'script': {'name': 'consumer', 'priority': 1}},
    }}
    schema = Schema(root)
    registrar = Dependencies(schema)
    before = {'objects': {'a': {'selected': 'one'}}, 'consumer': 'a'}
    after = deepcopy(before)
    after['objects']['a']['other'] = 'irrelevant'
    assert not reapply.plan(registrar, before, after).paths
    after['objects']['a']['selected'] = 'two'
    plan = reapply.plan(registrar, before, after)
    assert plan.paths == {'consumer': {('consumer',)}}
    assert plan.order({'provider'}, schema) == ['provider', 'consumer']


def test_watch_before_prepares_provider_and_retains_failure_component():
    """Preparation overrides numeric priority and rolls back with its provider."""
    schema = Schema({'kind': 'node', 'children': {
        'links': {'kind': 'tag_node', 'script': {'name': 'links', 'priority': 1},
                  'children': {'description': {'kind': 'leaf_node'}}},
        'prepare': {'kind': 'node', 'script': {'name': 'prepare', 'priority': 99,
                                             'watch-before': ['links']}},
    }})
    before = {'prepare': {}, 'links': {'one': {}}}
    after = {'prepare': {}, 'links': {'one': {'description': 'changed'}}}
    plan = reapply.plan(Dependencies(schema), before, after)
    assert plan.order({'links'}, schema) == ['prepare', 'links']
    assert plan.retain({'links'}) == {'links', 'prepare'}
    assert plan.retain({'prepare'}) == {'links', 'prepare'}


def test_watch_before_conflicting_after_order_is_rejected():
    """A declaration cannot require both directions of the same dependency."""
    schema = Schema({'kind': 'node', 'children': {
        'provider': {'kind': 'leaf_node', 'script': {'name': 'provider', 'priority': 1}},
        'prepare': {'kind': 'node', 'script': {'name': 'prepare', 'priority': 99,
                                             'watch-before': ['provider'], 'watch': ['provider']}},
    }})
    plan = reapply.plan(Dependencies(schema), {'prepare': {}, 'provider': 'a'},
                        {'prepare': {}, 'provider': 'b'})
    with pytest.raises(ValidationError, match='Cyclic'):
        plan.order({'provider'}, schema)


@pytest.mark.parametrize('watch', [None, True, 'vrf', [], [''], ['vrf', 'vrf'], ['bad-field']])
def test_invalid_watch_declarations_fail_schema_validation(watch):
    root = deepcopy(Schema.bundled().root)
    leaf = root['children']['firewall']['children']['ipv4']['children']['input']['children']['filter']['children']['rule']['children']['inbound-interface']
    leaf['reapply-on-change'] = watch
    with pytest.raises(ValueError, match='reapply-on-change'):
        validate_reapply(root)


def test_large_reference_inventory_selects_only_changed_identity():
    schema = Schema.bundled()
    before = {'interfaces': {'dummy': {'dum0': {}, 'dum1': {}}}, 'firewall': {'ipv4': {'input': {'filter': {'rule': {
        str(number): {'inbound-interface': ['dum1'], 'action': 'accept'} for number in range(1, 1001)
    }}}}}}
    before['firewall']['ipv4']['input']['filter']['rule']['1001'] = {'inbound-interface': ['dum0'], 'action': 'accept'}
    after = deepcopy(before)
    after['interfaces']['dummy']['dum0']['vrf'] = 'BLUE'
    result = reapply.plan(Dependencies(schema), before, after)
    assert result.paths == {'firewall': {('firewall', 'ipv4', 'input', 'filter', 'rule', '1001', 'inbound-interface')}}


def test_bad_watch_fails_generation_with_consumer_and_field_path(tmp_path):
    root = {'kind': 'node', 'children': {
        'objects': {'kind': 'tag_node', 'dependency': 'object', 'script': {'name': 'provider', 'priority': 1},
                    'children': {'selected': {'kind': 'leaf_node'}}},
        'consumer': {'kind': 'leaf_node', 'depends': 'object', 'reapply-on-change': ['misspelled'],
                     'script': {'name': 'consumer', 'priority': 2}},
    }}
    source = tmp_path / 'schemas'
    source.mkdir()
    (source / 'configuration.yaml').write_text(json.dumps(root))
    with pytest.raises(SchemaBuildError, match="consumer.*reapply-on-change.*misspelled"):
        build_schemas(source, tmp_path / 'output')
    assert not (tmp_path / 'output').exists()


def test_cyclic_reapply_dependencies_rejected_before_application():
    plan = reapply.ReapplyPlan(paths={'dummy': {('a',)}, 'firewall': {('b',)}},
                              requires={'dummy': {'firewall'}, 'firewall': {'dummy'}})
    with pytest.raises(ValidationError, match='Cyclic configuration reapply dependencies'):
        plan.order({'dummy'}, Schema.bundled())


def test_recovery_failure_retains_durable_transaction(controller, session, engine, monkeypatch):
    initial(controller, session, engine)
    before = deepcopy(engine.running)
    controller.execute('set interfaces dummy dum0 vrf BLUE', session)

    def fail(configuration, context):
        raise ValidationError('intentional failure including recovery')

    monkeypatch.setattr(engine.modules['firewall'], 'verify', fail)
    with pytest.raises(RouterError, match='Recovery failed for firewall'):
        engine.commit(session)
    assert engine.unhealthy
    assert engine.store.read('transaction.json')['before'] == before
    assert engine.running == before


def test_watch_tag_field_ignores_nested_owners():
    """A preparatory table watcher must not couple unrelated routing transactions."""
    from nvyr.helpers.reapply import watched_values

    before = {'vrf': {'name': {'BLUE': {'table': '101', 'protocols': {'static': {}}}}}}
    after = {'vrf': {'name': {'BLUE': {'table': '101', 'protocols': {'bgp': {}}},
                            'RED': {'table': '102'}}}}
    pattern = ('vrf', 'name', '*', 'table')
    assert watched_values(before, pattern) == {('vrf', 'name', 'BLUE', 'table'): '101'}
    assert watched_values(after, pattern) == {
        ('vrf', 'name', 'BLUE', 'table'): '101', ('vrf', 'name', 'RED', 'table'): '102'}
    assert watched_values({}, pattern) == {}
