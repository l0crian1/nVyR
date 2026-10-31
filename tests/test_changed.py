"""Lazy effective before/after changes follow configuration ownership."""

import pytest

from nvyr.modules import CommitContext
from nvyr.tree import MISSING, ReadOnlyTree


def context(before, after, **kwargs):
    return CommitContext(ReadOnlyTree(after), ReadOnlyTree(before), 'feature', ('feature',),
                         previous_effective=ReadOnlyTree(before), **kwargs)


def test_changes_include_additions_replacements_removals_and_lists():
    before = {'feature': {'removed': {'x': 'old'}, 'value': 'old', 'list': ['a', 'b'], 'same': True}}
    after = {'feature': {'added': {}, 'value': 'new', 'list': ['b', 'c'], 'same': True}}
    result = context(before, after).get_changed()
    assert set(result) == {('feature', field) for field in ('removed', 'added', 'value', 'list')}
    assert result['feature', 'removed']['effective'] is MISSING
    assert result['feature', 'removed']['previous'] == {'x': 'old'}
    assert result['feature', 'added']['previous'] is MISSING
    assert result['feature', 'added']['effective'] == {}
    assert result['feature', 'value'] == {'previous': 'old', 'effective': 'new'}
    assert result['feature', 'list'] == {'previous': ('a', 'b'), 'effective': ('b', 'c')}
    with pytest.raises(TypeError):
        result['feature', 'removed']['previous']['x'] = 'changed'


def test_scopes_clip_whole_removed_or_added_subtrees():
    before = {'feature': {'a': {'b': 'old'}}}
    removed = context(before, {})
    assert set(removed.get_changed()) == {('feature',)}
    assert removed.get_changed(('feature', 'a', 'b'))['feature', 'a', 'b']['previous'] == 'old'
    assert removed.get_changed(('other',)) == {}
    added = context({}, before)
    assert added.get_changed(('feature', 'a'))['feature', 'a']['previous'] is MISSING


def test_results_are_lazy_and_cached_by_scope(monkeypatch):
    from nvyr import modules
    original = modules.changes
    calls = []

    def observe(*args):
        calls.append(args)
        yield from original(*args)

    monkeypatch.setattr(modules, 'changes', observe)
    current = context({'feature': {'a': 'old'}}, {'feature': {'a': 'new'}})
    assert not calls
    result = current.get_changed()
    assert len(calls) == 1
    assert current.get_changed() is result
    assert current.get_changed(('feature',)) == result
    assert len(calls) == 2


def test_disjoint_owner_sections_include_removals_and_exclude_other_owners():
    before = {('feature',): {'a': 'old'}, ('vrf', 'BLUE', 'feature'): {'b': 'gone'}}
    after = {('feature',): {'a': 'new'}}
    current = context({}, {}, sections=ReadOnlyTree(after), previous_sections=ReadOnlyTree(before))
    assert set(current.get_changed()) == {('feature', 'a'), ('vrf', 'BLUE', 'feature')}
    assert set(current.get_changed(('vrf',))) == {('vrf', 'BLUE', 'feature')}
    assert not current.get_changed(('interfaces',))


def test_engine_defaults_full_owner_scope_and_rollback(controller, engine, session, monkeypatch):
    seen = []
    now = [100.0]
    engine.clock = lambda: now[0]
    monkeypatch.setattr(engine.modules['dummy'], 'apply', lambda generated, ctx: seen.append(ctx.get_changed()))
    controller.execute('set interfaces dummy dum0 mtu 1400', session)
    engine.commit(session)
    assert seen[-1]['interfaces', 'dummy']['effective']['dum0']['mtu'] == '1400'

    controller.execute('delete interfaces dummy dum0 mtu', session)
    engine.commit(session, minutes=1, confirmed_minutes=1)
    changed = seen[-1]['interfaces', 'dummy', 'dum0', 'mtu']
    assert changed == {'previous': '1400', 'effective': '1500'}
    now[0] = 161
    engine.tick()
    assert seen[-1]['interfaces', 'dummy', 'dum0', 'mtu'] == {'previous': '1500', 'effective': '1400'}
