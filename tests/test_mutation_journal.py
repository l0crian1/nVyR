"""Indexed candidate lookups preserve mutation order without scanning other paths."""

import random

import pytest

from nvyr.tree import Mutation, MutationJournal, lookup, overlay, projected_value


def test_large_paste_duplicate_checks_and_scalar_updates_do_not_scan_journal(controller, session, monkeypatch):
    def command(number, action='accept'):
        return (f'set firewall ipv4 forward filter rule {number} action {action} '
                'source-address 1.1.1.1 destination-address 2.2.2.2 destination-port 22 protocol tcp')

    for number in range(1, 1001):
        controller.execute(command(number), session)

    controller.execute('delete interfaces', session)  # Unrelated ancestor deletion.
    initial_count = len(session.mutations)

    def no_scan(self):
        raise AssertionError('An individual set must not iterate the candidate journal')

    with monkeypatch.context() as patch:
        patch.setattr(MutationJournal, '__iter__', no_scan)

        assert controller.execute(command(1001), session)['text'] == ''
        assert controller.execute(command(1001), session)['text'].count('Configuration already exists:') == 5
        result = controller.execute(command(1001, 'drop'), session)
        assert result['text'].count('Configuration already exists:') == 4

        # Sets beneath a pending ancestor deletion must not build a full overlay.
        assert controller.execute('set interfaces dummy dum0 mtu 1400', session)['text'] == ''
        assert controller.execute('set interfaces dummy dum0 mtu 1400', session)['text'].startswith('Configuration already exists:')

    assert len(session.mutations) == initial_count + 6


def test_journal_filters_unrelated_paths_and_keeps_ancestor_order():
    journal = MutationJournal(Mutation('set', ('rules', str(n), 'action'), 'accept') for n in range(2000))
    journal.append(Mutation('delete', ('rules',)))
    journal.append(Mutation('set', ('rules', '10', 'action'), 'drop'))
    journal.append(Mutation('delete', ('interfaces',)))

    assert journal.related(('rules', '10', 'action')) == [
        Mutation('delete', ('rules',)), Mutation('set', ('rules', '10', 'action'), 'drop')]
    assert journal.related(('other',)) == []
    assert projected_value({}, journal, ('rules', '10', 'action')) == 'drop'

    copied = MutationJournal(journal)
    journal.clear()

    assert not journal and journal.related(('rules',)) == []
    assert len(copied) == 2002
    copied.append(Mutation('set', ('rules', '10', 'action'), 'accept'))
    assert projected_value({}, copied, ('rules', '10', 'action')) == 'accept'


@pytest.mark.parametrize('seed', range(5))
def test_indexed_projection_matches_full_overlay_through_mixed_changes(seed):
    rng = random.Random(seed)
    running = {'a': {'one': {'value': 'original', 'items': ['x']}}, 'b': {'two': {}}}
    journal, reference = MutationJournal(), []
    paths = [(), ('a',), ('b',), ('missing',)]
    for branch in ('a', 'b'):
        for name in ('one', 'two', 'three'):
            paths.extend([(branch, name), (branch, name, 'value'), (branch, name, 'items')])

    for _ in range(100):
        branch, name = rng.choice(('a', 'b')), rng.choice(('one', 'two', 'three'))
        root = (branch, name)
        mutation = rng.choice([
            Mutation('set', root + ('value',), rng.choice(('old', 'new'))),
            Mutation('set', root, {'value': 'replaced'}),
            Mutation('add', root + ('items',), rng.choice(('x', 'y'))),
            Mutation('subtract', root + ('items',), rng.choice(('x', 'y'))),
            Mutation('ensure', root), Mutation('delete', root),
            Mutation('delete', (branch,)),
        ])
        if mutation.kind == 'set':
            reference = [existing for existing in reference if existing.path != mutation.path]

        reference.append(mutation)
        journal.append(mutation)
        assert list(journal) == reference
        intended = overlay(running, reference)

        for path in paths:
            assert projected_value(running, journal, path) == lookup(intended, path), (mutation, path)

        # Projection reads current running state, never a cached candidate root.
        running = {'a': {'one': {'value': str(rng.randrange(10)), 'items': ['x']}}, 'b': {'two': {}}}
