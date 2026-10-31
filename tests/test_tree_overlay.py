"""Batch replay must match individual edits without mutating shared snapshots."""

from copy import deepcopy
import random

import pytest

from nvyr import tree
from nvyr.tree import Mutation, apply, overlay


def sequential(original, mutations):
    """Use the public single-edit operation as a reference for batch semantics."""
    result = original
    for mutation in mutations:
        result = apply(result, mutation)
    return result


def test_overlay_preserves_running_and_other_candidate_snapshots():
    """A second overlay must not retain write ownership from the first."""
    original = {'rules': {'1': {'action': 'accept'}}, 'untouched': {'value': 1}}
    first = overlay(original, [Mutation('set', ('rules', '2', 'action'), 'drop')])
    second = overlay(first, [Mutation('set', ('rules', '2', 'action'), 'accept')])

    assert original == {'rules': {'1': {'action': 'accept'}}, 'untouched': {'value': 1}}
    assert first['rules']['2']['action'] == 'drop'
    assert second['rules']['2']['action'] == 'accept'
    assert first['rules']['1'] is original['rules']['1']
    assert second['untouched'] is first['untouched'] is original['untouched']


def test_overlay_does_not_modify_inserted_subtrees_or_shared_aliases():
    """Editing an inserted value must leave its owner and other uses intact."""
    shared = {'action': 'accept', 'protocol': ['tcp']}
    original = {'rules': {'1': shared, '2': shared}}
    mutations = [
        Mutation('set', ('rules', '3'), shared),
        Mutation('set', ('rules', '3', 'action'), 'drop'),
        Mutation('add', ('rules', '3', 'protocol'), 'udp'),
        Mutation('delete', ('rules', '1', 'action')),
        Mutation('subtract', ('rules', '1', 'protocol'), 'tcp'),
    ]
    result = overlay(original, mutations)

    assert result == sequential(original, mutations)
    assert shared == {'action': 'accept', 'protocol': ['tcp']}
    assert result['rules']['1'] == {}
    assert result['rules']['2'] is shared
    assert result['rules']['3'] == {'action': 'drop', 'protocol': ['tcp', 'udp']}


def test_overlay_keeps_ancestor_deletion_and_replacement_order():
    """Removing, recreating and replacing a branch must discard its old contents."""
    original = {'rules': {'1': {'action': 'accept'}}}
    replacement = {'1': {'action': 'drop'}}
    mutations = [
        Mutation('set', ('rules', '2', 'action'), 'drop'),
        Mutation('delete', ('rules',)),
        Mutation('ensure', ('rules', '3')),
        Mutation('set', ('rules',), replacement),
        Mutation('set', ('rules', '1', 'description'), 'replacement'),
    ]

    assert overlay(original, mutations) == sequential(original, mutations)
    assert original == {'rules': {'1': {'action': 'accept'}}}
    assert replacement == {'1': {'action': 'drop'}}


def test_overlay_root_replacement_does_not_borrow_write_ownership():
    """Root replacement and reset have the same isolation as nested operations."""
    original = {'old': {}}
    replacement = {'new': {'items': ['one']}}
    mutations = [
        Mutation('set', ('temporary',), True),
        Mutation('delete', ()),
        Mutation('set', (), replacement),
        Mutation('add', ('new', 'items'), 'two'),
    ]

    assert overlay(original, mutations) == {'new': {'items': ['one', 'two']}}
    assert original == {'old': {}}
    assert replacement == {'new': {'items': ['one']}}


def test_overlay_exception_leaves_inputs_unmodified():
    """An invalid later edit cannot expose partial writes through input aliases."""
    original = {'node': {'value': 'original'}}
    inserted = {'value': 'inserted'}
    mutations = [
        Mutation('set', ('node', 'value'), 'changed'),
        Mutation('set', ('inserted',), inserted),
        Mutation('set', ('inserted', 'value'), 'changed'),
        Mutation('set', ('invalid',), 1),
        Mutation('set', ('invalid', 'child'), True),
    ]

    with pytest.raises(TypeError):
        overlay(original, mutations)

    assert original == {'node': {'value': 'original'}}
    assert inserted == {'value': 'inserted'}


def test_overlay_empty_and_ineffective_edits_preserve_values():
    """Ensure and missing deletes must not invent branches or replace values."""
    original = {'present': {'items': ['one']}}
    mutations = [
        Mutation('ensure', ('present',)),
        Mutation('delete', ('absent', 'child')),
        Mutation('subtract', ('missing',), 'one'),
        Mutation('add', ('present', 'items'), 'one'),
    ]

    assert overlay(original, []) is original
    assert overlay(original, mutations) == original


def test_overlay_mixed_sequences_match_single_edit_semantics():
    """Exercise ordered roots, subtrees, collections and reusable input values."""
    rng = random.Random(712)
    shared = {'value': 'shared', 'items': ['one']}
    original = {'a': {'one': shared, 'two': shared}, 'b': {}}
    mutations = []

    for _ in range(300):
        branch = rng.choice(('a', 'b'))
        node = (branch, rng.choice(('one', 'two', 'three')))
        mutations.append(rng.choice([
            Mutation('set', node + ('value',), str(rng.randrange(10))),
            Mutation('set', node, shared),
            Mutation('add', node + ('items',), rng.choice(('one', 'two'))),
            Mutation('subtract', node + ('items',), rng.choice(('one', 'two'))),
            Mutation('ensure', node),
            Mutation('delete', node),
            Mutation('delete', (branch,)),
            Mutation('set', (), {'a': {'one': shared}}),
            Mutation('delete', ()),
        ]))

        before = deepcopy(original)
        inputs = deepcopy(mutations)
        assert overlay(original, mutations) == sequential(original, mutations)
        assert original == before
        assert mutations == inputs


def test_overlay_wide_rule_dictionary_copy_work_is_linear(monkeypatch):
    """Bound copied entries rather than asserting fragile wall-clock timings."""
    count = 1000
    original = {'rules': {str(number): {'action': 'accept'} for number in range(count)}}
    mutations = []
    for number in range(count):
        mutations.append(Mutation('set', ('rules', str(number), 'action'), 'drop'))
        mutations.append(Mutation('set', ('rules', str(number), 'description'), 'updated'))

    copied_entries = 0

    def counted_copy(value):
        nonlocal copied_entries
        copied_entries += len(value)
        return dict(value)

    monkeypatch.setattr(tree, 'dict', counted_copy, raising=False)
    result = overlay(original, mutations)

    assert copied_entries < 10 * count
    assert len(result['rules']) == count
    assert all(rule['action'] == 'drop' for rule in result['rules'].values())
    assert all(rule['action'] == 'accept' for rule in original['rules'].values())
