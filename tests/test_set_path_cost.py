"""Insertion must follow the selected path, independent of unrelated schema growth."""

import pytest

from nvyr.errors import ParseError
from nvyr.schema import resolve_word


def test_dependency_path_checks_match_declaration_boundaries(engine):
    """Ancestors, tag instances and descendants retain the original overlap semantics."""
    dependencies = engine.dependencies
    paths = {(), ('missing',), ('firewall', 'ipv4', 'forward', 'filter', 'rule', '10', 'action')}
    for patterns in dependencies.patterns.values():
        for pattern in patterns:
            path = tuple('instance' if part is None else part for part in pattern)
            paths.update(path[:length] for length in range(len(path) + 1))
            paths.add((*path, 'descendant'))

    for category, patterns in dependencies.patterns.items():
        for path in paths:
            expected = any(
                all(declared is None or declared == actual for declared, actual in zip(pattern, path))
                for pattern in patterns
            )
            assert dependencies.affects(path, category) == expected, (category, path)


def test_candidate_insertion_does_not_scan_dependency_patterns(controller, engine, session, monkeypatch):
    """The benchmark command must not enumerate providers or consumers for every setting."""
    class UnscannablePatterns(list):
        def __iter__(self):
            pytest.fail('Insertion scanned the full schema dependency-pattern list')

    for category, patterns in engine.dependencies.patterns.items():
        monkeypatch.setitem(engine.dependencies.patterns, category, UnscannablePatterns(patterns))

    controller.execute(
        'set firewall ipv4 forward filter rule 10 action accept source-address 1.1.1.1 '
        'destination-address 2.2.2.2 destination-port 22 protocol tcp', session,
    )
    rule = engine.view(session)['firewall']['ipv4']['forward']['filter']['rule']['10']
    assert rule['action'] == 'accept'
    assert rule['protocol'] == ['tcp']
    assert rule['source-address'] == {'1.1.1.1': {}}


def test_exact_keyword_does_not_enumerate_siblings():
    """Adding unrelated commands must not slow resolution of a fully typed keyword."""
    class ExactLookupOnly(dict):
        def items(self):
            pytest.fail('An exact keyword enumerated sibling definitions')

    assert resolve_word('action', ExactLookupOnly(action={'kind': 'leaf_node'})) == 'action'


def test_keyword_fast_path_preserves_hidden_nodes_and_abbreviations():
    """Internal negation branches stay hidden, including exact and abbreviated input."""
    children = {
        'action': {'kind': 'leaf_node'},
        'address': {'kind': 'leaf_node'},
        'not': {'kind': 'node', '_negation_branch': True},
    }
    assert resolve_word('act', children) == 'action'
    with pytest.raises(ParseError, match='more than one'):
        resolve_word('a', children)
    with pytest.raises(ParseError, match='Unknown command'):
        resolve_word('not', children)
    with pytest.raises(ParseError, match='Unknown command'):
        resolve_word('n', children)
