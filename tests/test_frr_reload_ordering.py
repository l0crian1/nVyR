"""Regression checks for the small patch to FRR's bulk reload ordering."""

from pathlib import Path
import os
import runpy

import pytest


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_RELOAD_TEST') != '1',
                                reason='requires the built FRR package with its reload patch')


@pytest.fixture(scope='module')
def reorder():
    source = Path('/usr/lib/frr/frr-reload.py')
    return runpy.run_path(str(source))['ignore_delete_re_add_lines']


@pytest.mark.parametrize(('before', 'after'), [
    ('bgp as-path access-list TEST seq 10 permit _65000_',
     'bgp as-path access-list TEST seq 10 permit _65001_'),
    ('bgp community-list standard TEST seq 10 permit 65000:1',
     'bgp community-list expanded TEST seq 10 permit ^65000:'),
    ('bgp large-community-list standard TEST seq 10 permit 65000:1:2',
     'bgp large-community-list expanded TEST seq 10 permit ^65000:'),
    ('bgp extcommunity-list standard TEST seq 10 permit rt 65000:1',
     'bgp extcommunity-list expanded TEST seq 10 permit RT:65000:'),
])
def test_list_replacement_removes_old_entry_first(reorder, before, after):
    additions, deletions = reorder([((after,), None)], [((before,), None)])

    assert deletions == []
    assert additions == [((f'no {before}',), None), ((after,), None)]


def test_implicit_sequence_equivalence_remains_a_noop(reorder):
    before = 'bgp as-path access-list TEST seq 10 permit _65000_'
    after = 'bgp as-path access-list TEST permit _65000_'

    additions, deletions = reorder([((after,), None)], [((before,), None)])

    assert additions == []
    assert deletions == []


def test_all_old_list_entries_precede_new_type(reorder):
    before = [
        (('bgp community-list standard TEST seq 10 permit 65000:1',), None),
        (('bgp community-list standard TEST seq 20 deny 65000:2',), None),
    ]
    after = (('bgp community-list expanded TEST seq 10 permit ^65000:',), None)

    additions, deletions = reorder([after], before.copy())

    assert deletions == []
    assert additions == [
        (('no bgp community-list standard TEST seq 10 permit 65000:1',), None),
        (('no bgp community-list standard TEST seq 20 deny 65000:2',), None),
        after,
    ]
