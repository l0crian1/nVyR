"""Multiple/nested script locations remain single, independent commit units."""

from copy import deepcopy

import pytest

from nvyr.engine import Engine
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import interfaces
from nvyr.schema import Schema
from nvyr.tree import lookup
from tests.lifecycle import recorded_registry


@pytest.fixture
def calls(engine, monkeypatch):
    records = []
    monkeypatch.setattr(interfaces, 'local_addresses', lambda vrf=None: set())
    for owner in ('vrf', 'static'):
        module = engine.modules[owner]
        original = module.apply

        def apply(generated, context, original=original):
            records.append((context.owner, context, generated))
            return original(generated, context)

        monkeypatch.setattr(module, 'apply', apply)

    return records


def configure(controller, session, name='BLUE', table=100):
    controller.execute(f'set vrf name {name} table {table}', session)
    controller.execute(f'set vrf name {name} protocols static route 192.0.2.0/24 next-hop 198.51.100.1', session)


def test_nested_registration_dispatch_and_unchanged_vrfs(controller, engine, session, calls):
    configure(controller, session)
    configure(controller, session, 'RED', 101)
    controller.execute('set protocols static route6 2001:db8::/32 next-hop 2001:db8::1', session)
    assert set(engine.configuration_status(session)['changed']) == {'vrf_conntrack', 'vrf', 'static'}
    assert all(result['success'] for result in engine.commit(session)['results'].values())
    assert [owner for owner, _, _ in calls] == ['vrf', 'static']
    context = calls[-1][1]
    assert set(context.scripts['static']['vrf']) == {'default', 'BLUE', 'RED'}
    assert context.previous_scripts == {}
    assert set(calls[-1][2]) == {'default', 'BLUE', 'RED'}
    assert lookup(engine.running, ('vrf', 'name', 'BLUE', 'protocols', 'static',
                                   'route', '192.0.2.0/24', 'next-hop', '198.51.100.1')) == {}

    calls.clear()
    controller.execute('set vrf name BLUE protocols static route 192.0.2.0/24 next-hop 198.51.100.1 distance 10', session)
    assert engine.configuration_status(session)['changed'] == ['static']
    assert engine.commit(session)['results'] == {'static': {'success': True}}
    assert [owner for owner, _, _ in calls] == ['static']
    assert set(calls[0][1].scripts['static']['vrf']) == {'default', 'BLUE', 'RED'}
    assert calls[0][1].scripts == calls[0][1].previous_scripts


def test_first_nested_protocol_does_not_change_existing_vrf(controller, engine, session, calls):
    controller.execute('set vrf name BLUE table 100', session)
    engine.commit(session)
    calls.clear()

    controller.execute('set vrf name BLUE protocols static route 192.0.2.0/24 next-hop 198.51.100.1', session)
    assert engine.commit(session)['results'] == {'static': {'success': True}}
    assert [owner for owner, _, _ in calls] == ['static']


def test_delete_parent_selects_both_owners_and_reports_owned_removals(controller, engine, session, calls):
    configure(controller, session)
    configure(controller, session, 'RED', 101)
    engine.commit(session)
    calls.clear()

    controller.execute('delete vrf name BLUE', session)
    assert all(result['success'] for result in engine.commit(session)['results'].values())
    assert [owner for owner, _, _ in calls] == ['vrf', 'static']
    context = calls[1][1]
    assert context.scripts['static']['vrf'] == ('RED',)
    assert set(context.previous_scripts['static']['vrf']) == {'BLUE', 'RED'}
    assert set(context.get_deleted()) == {('vrf', 'name', 'BLUE', 'protocols', 'static')}
    assert calls[0][1].get_deleted()[('vrf', 'name', 'BLUE')] == {'table': '100'}
    assert set(calls[1][2]) == {'default', 'RED'}


@pytest.mark.parametrize('stage', ['verify', 'generate', 'apply'])
def test_failed_nested_owner_retains_intent_and_successful_parent(controller, engine, session, calls, monkeypatch, stage):
    configure(controller, session)
    intended = deepcopy(engine.view(session))
    module = engine.modules['static']
    original = getattr(module, stage)

    def fail(*args):
        raise ValidationError('Static failed')

    monkeypatch.setattr(module, stage, fail)
    result = engine.commit(session)
    assert result['results']['vrf']['success']
    assert not result['results']['static']['success']
    assert engine.running == {'vrf': {'name': {'BLUE': {'table': '100'}}}}
    assert engine.view(session) == intended
    assert engine.schema.ownership.snapshot(engine.running).registrations == {'vrf': {}, 'vrf_conntrack': {}}

    monkeypatch.setattr(module, stage, original)
    calls.clear()
    assert engine.commit(session)['results'] == {'static': {'success': True}}
    assert engine.running == intended


def test_failed_parent_creation_blocks_child(controller, engine, session, calls):
    controller.execute('set vrf name BLUE protocols static route 192.0.2.0/24 next-hop 198.51.100.1', session)
    intended = deepcopy(engine.view(session))
    results = engine.commit(session)['results']
    assert not results['vrf']['success'] and not results['static']['success']
    assert not calls and engine.running == {}
    assert engine.view(session) == intended


@pytest.mark.parametrize('existing_parent', [False, True])
def test_failed_vrf_consumer_restores_new_parent_children(controller, engine, session, calls, monkeypatch,
                                                        existing_parent):
    if existing_parent:
        controller.execute('set vrf name BLUE table 100', session)
        engine.commit(session)

    configure(controller, session)
    controller.execute('set container network TEST subnet 192.0.2.0/24', session)
    controller.execute('set container network TEST vrf BLUE disable-dns', session)
    controller.execute('set system host-name independent', session)
    intended = deepcopy(engine.view(session))
    module = engine.modules['container']
    original = module.verify

    def fail(configuration, context):
        if not context.recovery:
            raise ValidationError('Container image lookup failed')
        original(configuration, context)

    monkeypatch.setattr(module, 'verify', fail)
    result = engine.commit(session)

    assert result['results']['container']['error'] == 'Container image lookup failed'
    assert result['results']['system']['success']
    assert result['results']['static']['success'] == existing_parent
    assert not engine.unhealthy
    assert engine.store.read('transaction.json') is None
    assert engine.view(session) == intended
    if existing_parent:
        assert engine.running['vrf'] == intended['vrf']
        assert not any(owner == 'static' and context.recovery for owner, context, _ in calls)
    else:
        assert engine.running == {'system': {'host-name': 'independent'}}
        assert any(owner == 'static' and context.recovery for owner, context, _ in calls)

    monkeypatch.setattr(module, 'verify', original)
    assert all(row['success'] for row in engine.commit(session)['results'].values())
    assert engine.running == intended


def test_failed_child_removal_preserves_parent(controller, engine, session, calls, monkeypatch):
    configure(controller, session)
    engine.commit(session)
    before = deepcopy(engine.running)
    calls.clear()

    def fail(*args):
        raise ValidationError('Static failed')

    monkeypatch.setattr(engine.modules['static'], 'apply', fail)
    controller.execute('delete vrf', session)
    result = engine.commit(session)
    assert not result['changed']
    assert not result['results']['vrf']['success']
    assert engine.running == before and engine.view(session) == {}
    assert [owner for owner, _, _ in calls] == ['vrf', 'vrf']
    assert calls[-1][1].recovery
    assert calls[-1][2] == {'BLUE': {'kind': 'vrf', 'attributes': {'table': 100}}}


def test_failed_parent_restoration_requires_recovery(controller, engine, session, calls, monkeypatch):
    configure(controller, session)
    engine.commit(session)
    before = deepcopy(engine.running)

    def fail_static(*args):
        raise ValidationError('Static failed')

    def fail_recovery(generated, context):
        if context.recovery:
            raise ValidationError('VRF recovery failed')

    monkeypatch.setattr(engine.modules['static'], 'apply', fail_static)
    monkeypatch.setattr(engine.modules['vrf'], 'apply', fail_recovery)
    controller.execute('delete vrf', session)

    with pytest.raises(RouterError, match='Recovery failed for vrf'):
        engine.commit(session)

    assert engine.unhealthy and engine.running == before
    assert engine.store.read('transaction.json')['before'] == before


def test_failed_leaf_intents_still_rebase_on_other_sessions(controller, engine, session, calls, monkeypatch):
    configure(controller, session)
    original = engine.modules['static'].verify

    def fail(*args):
        raise ValidationError('Static failed')

    monkeypatch.setattr(engine.modules['static'], 'verify', fail)
    engine.commit(session)
    monkeypatch.setattr(engine.modules['static'], 'verify', original)

    other = engine.open('other', 'test')
    engine.request_lock(other, session.id)
    controller.execute('set vrf name BLUE protocols static route 203.0.113.0/24 next-hop 198.51.100.2', other)
    engine.commit(other)
    engine.request_lock(session, other.id)
    engine.commit(session, expected_id=engine.commit_id)

    assert set(engine.running['vrf']['name']['BLUE']['protocols']['static']['route']) == {
        '192.0.2.0/24', '203.0.113.0/24'}


def test_nested_check_defaults_and_restart(controller, engine, session, calls, monkeypatch):
    configure(controller, session)
    seen = []
    original = engine.modules['static'].verify

    def verify(configuration, context):
        seen.append((configuration, context))
        original(configuration, context)

    monkeypatch.setattr(engine.modules['static'], 'verify', verify)
    assert all(row['success'] for row in engine.check(session)['results'].values())
    assert not calls and not engine.running
    config, context = seen[-1]
    assert context.check_only and set(config) == {'default', 'BLUE'}
    assert config['BLUE']['route']['192.0.2.0/24']['next-hop']['198.51.100.1']['distance'] == '1'
    engine.commit(session)

    restarted = Engine(engine.schema, recorded_registry(engine.schema), engine.store)
    assert restarted.running == engine.running
    assert [stage for owner, stage, recovery in restarted.modules['static'].calls if recovery] == [
        'get_config', 'verify', 'generate', 'apply']


def test_confirm_rollback_recovers_each_owner_once(controller, engine, session, calls):
    configure(controller, session)
    engine.commit(session, minutes=1, confirmed_minutes=1)
    calls.clear()
    engine.clock = lambda: engine.pending['deadline'] + 1
    engine.tick()
    assert engine.running == {}
    assert [owner for owner, _, _ in calls] == ['vrf', 'static']


@pytest.mark.parametrize('operation', ['copy', 'rename', 'load'])
def test_multi_owner_tree_operations(controller, engine, session, calls, operation):
    if operation == 'rename':
        # Exercise generic nested ownership; the bundled VRF policy forbids renaming.
        engine.schema.root['children']['vrf']['children']['name']['rename'] = True

    configure(controller, session)
    engine.commit(session)
    calls.clear()
    if operation == 'load':
        target = {'vrf': {'name': {'BLUE': {'table': '100'}}}}
        engine.stage_configuration(session, target, replace=True)
        assert engine.commit(session)['results'] == {'static': {'success': True}}
        assert engine.running == target
    else:
        getattr(engine, operation)(session, ['vrf', 'name', 'BLUE'], ['vrf', 'name', 'RED'])
        controller.execute('set vrf name RED table 101', session)
        assert all(row['success'] for row in engine.commit(session)['results'].values())
        assert [owner for owner, _, _ in calls] == ['vrf', 'static']
        assert 'RED' in engine.running['vrf']['name']
        assert ('BLUE' in engine.running['vrf']['name']) == (operation == 'copy')


def test_generic_registration_literals_tags_and_multiple_locations():
    leaf = {'kind': 'leaf_node'}
    script = {'name': 'feature', 'priority': 10, 'register': {'vrf': {'tag': 'name'}, 'category': 'test'}}
    node = {'kind': 'node', 'script': script, 'children': {'value': leaf}}
    schema = Schema({'kind': 'node', 'children': {'name': {'kind': 'tag_node', 'children': {
        'first': node, 'second': deepcopy(node)}}}})
    config = {'name': {'BLUE': {'first': {'value': '1'}, 'second': {}}, 'RED': {'first': {}}}}
    snapshot = schema.ownership.snapshot(config)
    assert snapshot.registrations == {'feature': {'vrf': ['BLUE', 'RED'], 'category': ['test']}}
    assert len(snapshot.sections['feature']) == 3

    for replacement in ({'tag': 'missing'}, {'tag': []}, [], 2):
        broken = deepcopy(schema.root)
        broken['children']['name']['children']['first']['script']['register']['vrf'] = replacement
        with pytest.raises(ValueError, match='register vrf'):
            Schema(broken)


@pytest.mark.parametrize('removal', [False, True])
def test_nested_restoration_follows_multiple_parent_levels(removal):
    grandchild = {'kind': 'node', 'script': {'name': 'grandchild', 'priority': 3}}
    child = {'kind': 'node', 'script': {'name': 'child', 'priority': 2},
             'children': {'grandchild': grandchild}}
    parent = {'kind': 'tag_node', 'script': {'name': 'parent', 'priority': 1},
              'children': {'child': child}}
    schema = Schema({'kind': 'node', 'children': {'parent': parent}})
    configured = {'parent': {'TEST': {'child': {'grandchild': {}}}}}
    before, after = (configured, {}) if removal else ({}, configured)
    failed = {'grandchild'} if removal else {'parent'}

    retained = schema.ownership.retained_owners(schema.ownership.snapshot(before),
                                               schema.ownership.snapshot(after), failed)

    assert retained == {'parent', 'child', 'grandchild'}
    assert schema.ownership.publish(before, after, retained) == before


def test_conflicting_priorities_rejected():
    with pytest.raises(ValueError, match='conflicting priorities'):
        Schema({'kind': 'node', 'children': {
            'a': {'kind': 'node', 'script': {'name': 'x', 'priority': 1}},
            'b': {'kind': 'node', 'script': {'name': 'x', 'priority': 2}},
        }})


def test_build_checks_script_registration(tmp_path):
    from build_tools.schema_builder import build_schemas, SchemaBuildError

    source = tmp_path / 'sources'
    source.mkdir()
    path = source / 'configuration.yaml'
    path.write_text('''kind: node
children:
  feature:
    kind: node
    script:
      name: feature
      priority: 10
      register:
        vrf: {tag: missing}
''')
    with pytest.raises(SchemaBuildError, match='feature: register vrf'):
        build_schemas(source, tmp_path / 'output')

    assert not (tmp_path / 'output').exists()


def test_registration_and_owned_sections_cannot_modify_configuration(controller, engine, session, calls):
    configure(controller, session)
    engine.commit(session)
    context = calls[-1][1]

    with pytest.raises(TypeError):
        context.scripts['static']['vrf'][0] = 'other'

    section = context.sections[('vrf', 'name', 'BLUE', 'protocols', 'static')]
    with pytest.raises(TypeError):
        section['route']['192.0.2.0/24'] = {}


def test_owner_declaration_does_not_scan_candidate_on_each_set(controller, engine, session, monkeypatch):
    def no_snapshot(*args):
        raise AssertionError('Script snapshots belong to commit/status, not individual set commands')

    monkeypatch.setattr(engine.schema.ownership, 'snapshot', no_snapshot)
    for number in range(100):
        controller.execute(f'set vrf name BLUE protocols static route 192.0.2.{number}/32 next-hop 198.51.100.1', session)


def test_failed_nested_leaf_intents_do_not_need_tree_diff(controller, engine, session, monkeypatch):
    controller.execute('set vrf name BLUE table 100', session)
    engine.commit(session)
    for number in range(100):
        controller.execute(f'set vrf name BLUE protocols static route 192.0.2.{number}/32 next-hop 198.51.100.1', session)

    original = list(session.mutations)
    intended = engine.view(session)

    def no_diff(*args):
        raise AssertionError('Single-owner leaf intents should be retained directly')

    monkeypatch.setattr('nvyr.engine.changes', no_diff)
    assert list(engine._remaining_mutations(engine.running, intended, original, {'static'})) == original
    assert not engine._remaining_mutations(intended, intended, original, set())
