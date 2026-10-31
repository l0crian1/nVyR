"""Configuration-path completion uses each request's projected candidate view."""

import pytest

from nvyr.helpers.suggestors import BoundSuggestor, Context, config_path, registry
from nvyr.schema import Schema
from nvyr.tree import lookup


def test_config_path_supports_mapping_and_targeted_lookup():
    tree = {'firewall': {'flowtable': {'FAST': {}, 'SLOW': {}}}}
    expected = ['FAST', 'SLOW']
    assert [item.value for item in config_path(Context(configuration=tree), 'firewall flowtable')] == expected

    paths = []

    def configuration(path):
        paths.append(path)
        return lookup(tree, path)

    callback = registry()['config-path']
    assert isinstance(callback, BoundSuggestor)
    assert [item.value for item in callback.suggest(configuration, path='firewall flowtable')] == expected
    assert paths == [('firewall', 'flowtable')]
    assert callback(path='firewall flowtable') == []


@pytest.mark.parametrize('tree', [None, {}, {'objects': []}, {'objects': 'text'}, {'objects': {}}])
def test_config_path_missing_or_non_mapping_target_returns_no_suggestions(tree):
    assert config_path(Context(configuration=tree), 'objects') == []


def test_config_path_supports_quoted_instance_names():
    context = Context(configuration={'objects': {'two words': {'members': {'member1': {}}}}})
    values = config_path(context, 'objects "two words" members')
    assert [item.value for item in values] == ['member1']


def test_config_path_schema_callback_validates_arguments():
    node = {'kind': 'leaf_node', 'suggestors': [
        {'name': 'config-path', 'args': {'path': 'firewall flowtable'}},
    ]}
    schema = Schema({'kind': 'node', 'children': {'target': node}})
    assert dict(schema.candidates(schema.resolve(['target']), '', {
        'firewall': {'flowtable': {'FAST': {}}},
    })) == {'FAST': ''}

    node['suggestors'][0]['args'] = {'typo': 'firewall flowtable'}
    with pytest.raises(ValueError):
        Schema({'kind': 'node', 'children': {'target': node}})


def test_flowtable_anchor_preserves_multi_leaves_and_edit_context(controller, engine, session):
    controller.execute('set firewall flowtable FAST interface eth0 interface eth1 offload software', session)
    assert engine.view(session)['firewall']['flowtable']['FAST'] == {
        'interface': ['eth0', 'eth1'], 'offload': {'software': True},
    }

    controller.execute('edit firewall flowtable FAST', session)
    controller.execute('set interface eth2 offload software', session)
    assert engine.view(session)['firewall']['flowtable']['FAST']['interface'] == ['eth0', 'eth1', 'eth2']

    candidates = dict(controller.completion('set interface eth0 ', session, explicit=True)['candidates'])
    assert {'interface', 'offload', '<Enter>'} <= candidates.keys()


def test_state_policy_is_anchored_and_retains_existing_configuration(controller, engine, session):
    node = engine.schema.resolve(['firewall', 'global-options', 'state-policy']).node
    assert node['anchor'] is True
    assert node['kind'] == 'node'
    assert all(child['kind'] == 'node' for child in node['children'].values())
    controller.execute('set firewall global-options state-policy established action accept', session)
    controller.execute('edit firewall global-options state-policy established', session)
    controller.execute('set action drop', session)
    assert engine.view(session)['firewall']['global-options']['state-policy'] == {
        'established': {'action': 'drop'},
    }

    candidates = dict(controller.completion('set action drop ', session, explicit=True)['candidates'])
    assert '<Enter>' in candidates
    assert 'action' not in candidates


@pytest.mark.parametrize('options', [{}, {'tab': True}, {'space': True}, {'explicit': True}])
def test_offload_targets_follow_current_candidate_and_stay_session_local(controller, engine, session, monkeypatch, options):
    monkeypatch.setattr('nvyr.helpers.interfaces.exists', lambda name: True)
    controller.execute('set firewall flowtable OLD interface eth0', session)
    engine.commit(session)
    other = engine.open('bob', '/dev/pts/2')
    controller.execute('delete firewall flowtable OLD', session)
    controller.execute('set firewall flowtable FAST interface eth1', session)

    command = 'set firewall ipv4 forward filter rule 10 action offload offload-target '
    assert 'FAST' in dict(controller.completion(command, session, **options)['candidates'])
    assert 'OLD' not in dict(controller.completion(command, session, **options)['candidates'])
    other_values = dict(controller.completion(command, other, **options)['candidates'])
    assert 'OLD' in other_values
    assert 'FAST' not in other_values
    assert 'FAST' in dict(controller.completion(command, session, **options)['candidates'])

    result = controller.completion(command + 'FA', session, **options)
    assert result['replacement'] == 'FAST'

    controller.execute('edit firewall ipv4 forward filter', session)
    result = controller.completion('set rule 10 action offload offload-target FA', session, **options)
    assert result['replacement'] == 'FAST'

    controller.execute('top', session)
    engine.discard(session)
    values = dict(controller.completion(command, session, **options)['candidates'])
    assert 'FAST' not in values
    assert 'OLD' in values


def test_offload_target_completion_never_materializes_the_full_candidate(controller, engine, session, monkeypatch):
    controller.execute('set firewall flowtable FAST interface eth0', session)
    queried = []
    from nvyr.controller import projected_value

    def targeted(tree, mutations, path):
        queried.append(path)
        return projected_value(tree, mutations, path)

    def full_view(*args):
        raise AssertionError('Completion must not build the full candidate')

    monkeypatch.setattr('nvyr.controller.projected_value', targeted)
    monkeypatch.setattr(engine, 'view', full_view)
    result = controller.completion(
        'set firewall ipv6 forward filter rule 10 offload-target ', session,
    )
    assert dict(result['candidates']) == {'FAST': ''}
    assert ('firewall', 'flowtable') in queried
    assert all(path for path in queried)
