"""Absent delete targets produce notices without staging redundant mutations."""

import pytest

from nvyr.errors import RouterError


@pytest.mark.parametrize('path', [
    'interfaces',
    'interfaces dummy dum0',
    'interfaces dummy dum0 description',
    'interfaces dummy dum0 description absent',
    'interfaces dummy dum0 disable',
    'interfaces dummy dum0 address 192.0.2.1/24',
    'firewall ipv4 input filter rule 10 source-address not 192.0.2.1',
])
def test_absent_target_is_reported_without_mutation(controller, session, path):
    before = list(session.mutations)

    result = controller.execute('delete ' + path, session)

    assert result['text'] == f'Nothing to delete: {path} is not configured.\n'
    assert list(session.mutations) == before


@pytest.mark.parametrize('committed', [False, True])
def test_existing_empty_object_and_repeated_delete(controller, engine, session, committed):
    controller.execute('set interfaces dummy dum0', session)
    if committed:
        engine.commit(session)

    assert controller.execute('delete interfaces dummy dum0', session)['text'] == ''
    before = list(session.mutations)

    assert controller.execute('delete interfaces dummy dum0', session)['text'] == (
        'Nothing to delete: interfaces dummy dum0 is not configured.\n')
    assert list(session.mutations) == before


def test_pending_ancestor_delete_and_recreated_value(controller, engine, session):
    controller.execute('set interfaces dummy dum0 address 192.0.2.1/24', session)
    engine.commit(session)
    controller.execute('delete interfaces', session)

    assert controller.execute('delete interfaces dummy dum0 address 192.0.2.1/24', session)['text'].startswith(
        'Nothing to delete:')

    controller.execute('set interfaces dummy dum0 address 192.0.2.1/24', session)
    assert controller.execute('delete interfaces dummy dum0 address 192.0.2.1/24', session)['text'] == ''


def test_missing_multi_member_preserves_other_members(controller, engine, session):
    controller.execute('set interfaces dummy dum0 address 192.0.2.1/24 address 192.0.2.2/24', session)
    before = engine.view(session)
    mutations = list(session.mutations)

    result = controller.execute('delete interfaces dummy dum0 address 192.0.2.3/24', session)

    assert result['text'].startswith('Nothing to delete:')
    assert engine.view(session) == before
    assert list(session.mutations) == mutations


def test_negative_member_notice_and_whole_field_delete(controller, engine, session):
    path = 'firewall ipv4 input filter rule 10 source-address'
    controller.execute(f'set {path} not 192.0.2.1', session)
    controller.execute(f'set {path} not 192.0.2.2', session)

    assert controller.execute(f'delete {path} not 192.0.2.1', session)['text'] == ''
    mutations = list(session.mutations)
    assert controller.execute(f'delete {path} not 192.0.2.1', session)['text'] == (
        f'Nothing to delete: {path} not 192.0.2.1 is not configured.\n')
    assert list(session.mutations) == mutations

    assert controller.execute(f'delete {path}', session)['text'] == ''
    assert engine.view(session)['firewall']['ipv4']['input']['filter']['rule']['10'] == {}


def test_relative_abbreviation_reports_full_path_and_quoted_value(controller, session):
    controller.execute('edit interfaces dummy dum0', session)

    assert controller.execute('del desc "WAN | interface"', session)['text'] == (
        "Nothing to delete: interfaces dummy dum0 description 'WAN | interface' is not configured.\n")


def test_implicit_default_is_not_explicit_configuration(controller, session):
    controller.execute('set interfaces dummy dum0', session)

    assert controller.execute('delete interfaces dummy dum0 mtu', session)['text'] == (
        'Nothing to delete: interfaces dummy dum0 mtu is not configured.\n')


@pytest.mark.parametrize('command', [
    'delete interfaces dummy dum0 unknown',
    'delete interfaces dummy dum0 address invalid',
    'delete interfaces dummy dum0 description other',
])
def test_invalid_paths_values_and_scalar_mismatches_remain_errors(controller, session, command):
    controller.execute('set interfaces dummy dum0 description existing', session)
    before = list(session.mutations)

    with pytest.raises(RouterError):
        controller.execute(command, session)

    assert list(session.mutations) == before
