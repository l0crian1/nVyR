"""Configuration scripts can inspect effective removals without tracking intents."""

import copy

import pytest

from nvyr.engine import Engine
from nvyr.errors import ValidationError
from nvyr.modules import CommitContext
from tests.lifecycle import LifecycleStub
from nvyr.schema import Schema
from nvyr.storage import Store
from nvyr.tree import ReadOnlyTree, deleted, lookup


@pytest.mark.parametrize('before,after,expected', [
    ({}, {'feature': {'new': {}}}, {}),
    ({'feature': {'value': 'old'}}, {'feature': {'value': 'new'}}, {}),
    ({'feature': {'disabled': True}}, {'feature': {}}, {('feature', 'disabled'): True}),
    ({'feature': {'empty': {}}}, {'feature': {}}, {('feature', 'empty'): {}}),
    ({'feature': {'group': {'old': {'description': 'Example'}}}},
     {'feature': {'group': {}}},
     {('feature', 'group', 'old'): {'description': 'Example'}}),
    ({'feature': {'value': 'old'}}, {}, {('feature',): {'value': 'old'}}),
    ({'feature': {'values': ['c', 'a', 'b']}}, {'feature': {'values': ['b', 'd']}},
     {('feature', 'values'): ('c', 'a')}),
    ({'feature': {'values': ['a', 'b']}}, {'feature': {'values': ['b', 'a']}}, {}),
    ({'feature': {'values': ['a', 'b']}}, {'feature': {}},
     {('feature', 'values'): ('a', 'b')}),
])
@pytest.mark.parametrize('readonly', [False, True])
def test_deletion_shapes(before, after, expected, readonly):
    if readonly:
        before, after = ReadOnlyTree(before), ReadOnlyTree(after)

    assert deleted(before, after) == expected


def test_context_scope_immutability_and_on_demand_computation(monkeypatch):
    before = {'feature': {'old': {'values': ['a', 'b']}}, 'other': {'deleted': True}}
    after = {'feature': {}}
    snapshots = copy.deepcopy((before, after))
    calls = []

    def observe(*args):
        calls.append(args)
        return deleted(*args)

    monkeypatch.setattr('nvyr.modules.deleted', observe)
    context = CommitContext(ReadOnlyTree(after), ReadOnlyTree(before), 'feature', ('feature',),
                            previous_effective=ReadOnlyTree(before))

    assert calls == []

    result = context.get_deleted()

    assert len(calls) == 1
    assert set(result) == {('feature', 'old')}

    old = result[('feature', 'old')]

    with pytest.raises(TypeError):
        result[('feature', 'new')] = {}

    with pytest.raises(TypeError):
        old['values'] = []

    with pytest.raises(TypeError):
        old['values'][0] = 'changed'

    assert (before, after) == snapshots
    assert context.get_deleted() == result


def test_missing_effective_snapshot_is_not_replaced_with_explicit_configuration():
    with pytest.raises(TypeError, match='previous_effective'):
        CommitContext(ReadOnlyTree({}), ReadOnlyTree({}), 'feature', ('feature',))


@pytest.mark.parametrize('mode', ['always', 'direct'])
def test_effective_defaults_and_multi_defaults(tmp_path, mode):
    default = lambda value: {'mode': mode, 'value': value}
    schema = Schema({'kind': 'node', 'children': {'feature': {
        'kind': 'node', 'script': {'name': 'feature', 'priority': 1}, 'children': {
            'scalar': {'kind': 'leaf_node', 'default': default('fallback')},
            'values': {'kind': 'leaf_node', 'multi': True, 'default': default(['a', 'b'])},
        }}}})
    module, seen = LifecycleStub(), []
    engine = Engine(schema, {'feature': module}, Store(tmp_path))
    module.apply = lambda generated, context: seen.append(context.get_deleted())
    session = engine.open('alice', 'test')
    engine.mutate(session, 'set', ['feature', 'scalar', 'explicit'])
    engine.mutate(session, 'set', ['feature', 'values', 'a'])
    engine.mutate(session, 'set', ['feature', 'values', 'c'])
    engine.commit(session)
    engine.mutate(session, 'delete', ['feature', 'scalar'])
    engine.mutate(session, 'delete', ['feature', 'values'])
    engine.commit(session)

    # The scalar still exists through its default. Only c vanishes from the list.
    assert seen[-1] == {('feature', 'values'): ('c',)}
    assert engine.running == {'feature': {}}

    engine.mutate(session, 'delete', ['feature'])
    engine.commit(session)

    assert seen[-1][('feature',)] == {'scalar': 'fallback', 'values': ('a', 'b')}


def test_rename_and_deletion_visibility_in_every_lifecycle_stage(engine, session):
    engine.mutate(session, 'set', ['interfaces', 'dummy', 'dum0', 'description', 'Original'])
    engine.commit(session)
    observed = []

    class Observer(LifecycleStub):
        def _stage(self, stage, context):
            observed.append((stage, context, context.get_deleted()))

    engine.modules['dummy'] = Observer()
    engine.rename(session, ['interfaces', 'dummy', 'dum0'], ['interfaces', 'dummy', 'dum1'])
    engine.commit(session)

    assert [stage for stage, _, _ in observed] == ['get_config', 'verify', 'generate', 'apply']
    assert len({id(context) for _, context, _ in observed}) == 1

    for _, _, removed in observed:
        assert set(removed) == {('interfaces', 'dummy', 'dum0')}
        assert removed[('interfaces', 'dummy', 'dum0')]['description'] == 'Original'
        assert removed[('interfaces', 'dummy', 'dum0')]['mtu'] == '1500'

    assert lookup(engine.running, ('interfaces', 'dummy', 'dum1', 'description')) == 'Original'


def test_final_diff_ignores_cancelled_deletions_and_new_objects(engine, session):
    engine.mutate(session, 'set', ['interfaces', 'dummy', 'dum0', 'description', 'Keep'])
    engine.commit(session)
    seen = []
    engine.modules['dummy'].apply = lambda plan, context: seen.append(context.get_deleted())
    engine.mutate(session, 'delete', ['interfaces', 'dummy', 'dum0'])
    engine.mutate(session, 'set', ['interfaces', 'dummy', 'dum0', 'description', 'Keep'])
    engine.mutate(session, 'set', ['interfaces', 'dummy', 'dum1'])
    engine.mutate(session, 'delete', ['interfaces', 'dummy', 'dum1'])
    engine.mutate(session, 'set', ['interfaces', 'dummy', 'dum2'])
    engine.commit(session)

    assert seen == [{}]


def test_partial_commit_retries_deletions_from_previous_running(engine, session):
    engine.mutate(session, 'set', ['interfaces', 'dummy', 'dum0'])
    engine.mutate(session, 'set', ['firewall', 'description', 'Remove'])
    engine.commit(session)
    seen = []

    def failing_verify(configuration, context):
        seen.append(context.get_deleted())
        raise ValidationError('Injected failure')

    engine.modules['dummy'].verify = failing_verify
    engine.mutate(session, 'delete', ['interfaces'])
    engine.mutate(session, 'delete', ['firewall'])
    result = engine.commit(session)

    assert result['results']['firewall']['success']
    assert not result['results']['dummy']['success']
    assert 'dum0' in lookup(engine.running, ('interfaces', 'dummy'))
    assert set(seen[0]) == {('interfaces', 'dummy')}

    engine.modules['dummy'].verify = lambda configuration, context: seen.append(context.get_deleted())
    engine.commit(session)

    assert seen[0] == seen[1]
    assert engine.running == {} and session.mutations == []


def test_commit_confirm_recovery_compares_recovery_target(engine, session):
    now = [100.0]
    engine.clock = lambda: now[0]
    engine.mutate(session, 'set', ['interfaces', 'dummy', 'dum0'])
    engine.commit(session)
    seen = []
    engine.modules['dummy'].apply = lambda plan, context: seen.append((context.recovery, context.get_deleted()))
    engine.rename(session, ['interfaces', 'dummy', 'dum0'], ['interfaces', 'dummy', 'dum1'])
    engine.commit(session, minutes=1, confirmed_minutes=1)

    assert not seen[-1][0] and set(seen[-1][1]) == {('interfaces', 'dummy', 'dum0')}

    now[0] = 161
    engine.tick()

    assert seen[-1][0] and set(seen[-1][1]) == {('interfaces', 'dummy', 'dum1')}
    assert lookup(engine.running, ('interfaces', 'dummy')) == {'dum0': {}}
