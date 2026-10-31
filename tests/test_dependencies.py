"""Candidate-time reference guards; no prerequisite existence or commit scheduling."""

import json

import pytest

from build_tools.schema_builder import SchemaBuildError, build_schemas
from nvyr.engine import Engine
from nvyr.errors import ValidationError
from nvyr.helpers.dependencies import Dependencies
from nvyr.lexer import lex
from nvyr.schema import Schema
from nvyr.tree import lookup


RULE = 'firewall ipv4 forward filter rule 10'


def configure(controller, session):
    controller.execute('set interfaces dummy dum0', session)
    controller.execute(f'set {RULE} action accept inbound-interface dum0 outbound-interface dum0', session)


def test_delete_is_rejected_immediately_with_all_reference_paths(controller, session, engine):
    configure(controller, session)
    before = list(session.mutations)

    with pytest.raises(ValidationError) as error:
        controller.execute('delete interfaces dummy dum0', session)

    assert 'Cannot remove interface dum0' in str(error.value)
    assert f'{RULE} inbound-interface' in str(error.value)
    assert f'{RULE} outbound-interface' in str(error.value)
    assert list(session.mutations) == before
    assert lookup(engine.view(session), ('interfaces', 'dummy', 'dum0')) == {}

    controller.execute(f'delete {RULE} inbound-interface dum0', session)
    with pytest.raises(ValidationError, match='outbound-interface'):
        controller.execute('delete interfaces dummy dum0', session)

    controller.execute(f'delete {RULE} outbound-interface dum0', session)
    controller.execute('delete interfaces dummy dum0', session)


def test_missing_provider_allowed_and_references_do_not_create_it(controller, session, engine):
    controller.execute(f'set {RULE} action accept inbound-interface dum999', session)
    controller.execute('delete interfaces dummy dum999', session)
    assert 'interfaces' not in engine.view(session)

    controller.execute('set interfaces dummy dum999', session)
    with pytest.raises(ValidationError, match='dum999'):
        controller.execute('delete interfaces dummy dum999', session)


def test_parent_deletion_edit_context_and_non_provider_attributes(controller, session):
    configure(controller, session)
    controller.execute('set interfaces dummy dum0 address 192.0.2.1/24', session)
    controller.execute('delete interfaces dummy dum0 address', session)

    with pytest.raises(ValidationError, match='dum0'):
        controller.execute('delete interfaces', session)

    controller.execute('edit interfaces', session)
    with pytest.raises(ValidationError, match=RULE):
        controller.execute('delete dummy dum0', session)


def test_rename_is_atomic_and_does_not_rewrite_consumers(controller, session, engine):
    configure(controller, session)
    before = engine.view(session)
    with pytest.raises(ValidationError, match='dum0'):
        controller.execute('rename interfaces dummy dum0 to interfaces dummy dum1', session)
    assert engine.view(session) == before

    controller.execute(f'delete {RULE}', session)
    controller.execute('rename interfaces dummy dum0 to interfaces dummy dum1', session)
    assert lookup(engine.view(session), ('interfaces', 'dummy')) == {'dum1': {}}


@pytest.mark.parametrize('set_format', [False, True])
def test_replace_load_checks_result_and_preserves_candidate_on_failure(controller, session, engine, set_format):
    configure(controller, session)
    before = engine.view(session)
    content = f'set {RULE} action accept inbound-interface dum0' if set_format else json.dumps({'firewall': before['firewall']})

    with pytest.raises(ValidationError, match='dum0'):
        controller.load(session, content, replace=True, set_format=set_format)
    assert engine.view(session) == before

    controller.load(session, '' if set_format else '{}', replace=True, set_format=set_format)
    assert engine.view(session) == {}


def test_running_changes_discard_and_sessions_do_not_share_reference_cache(controller, session, engine):
    controller.execute('set interfaces dummy dum0', session)
    engine.commit(session)
    other = engine.open('bob', 'test', draft=True)
    controller.execute(f'set {RULE} action accept inbound-interface dum0', other)

    with pytest.raises(ValidationError):
        controller.execute('delete interfaces dummy dum0', other)
    controller.execute('delete interfaces dummy dum0', session)
    engine.discard(session)

    engine.discard(other)
    controller.execute('delete interfaces dummy dum0', other)
    engine.discard(other)

    controller.execute(f'set {RULE} action accept inbound-interface dum0', session)
    engine.commit(session)
    with pytest.raises(ValidationError):
        controller.execute('delete interfaces dummy dum0', other)


def test_saved_metadata_is_derived_and_untrusted_on_load(controller, session, engine):
    configure(controller, session)
    engine.commit(session)
    engine.save(session)
    saved = json.loads(engine.store.path('boot.json').read_text())
    entry = saved['_nvyr']['dependencies']['interface']['dum0']

    assert entry['providers'] == [['interfaces', 'dummy', 'dum0']]
    assert entry['references'] == [RULE.split() + ['inbound-interface'], RULE.split() + ['outbound-interface']]
    assert '_nvyr' not in controller.get_config(session)

    saved['_nvyr']['dependencies'] = {}
    controller.load(session, json.dumps(saved), replace=True)
    with pytest.raises(ValidationError, match='dum0'):
        controller.execute('delete interfaces dummy dum0', session)

    restarted = Engine(engine.schema, engine.modules, engine.store)
    new_session = restarted.open('test', 'test')
    with pytest.raises(ValidationError, match='dum0'):
        restarted.mutate(new_session, 'delete', lex('interfaces dummy dum0'))


def test_schema_reuse_covers_ethernet_nat_and_named_ipv6_chains(controller, session):
    controller.execute('set interfaces ethernet eth0', session)
    controller.execute('set firewall ipv6 name CUSTOM rule 1 action accept inbound-interface eth0', session)
    with pytest.raises(ValidationError, match='firewall ipv6 name CUSTOM'):
        controller.execute('delete interfaces ethernet eth0', session)

    controller.execute('delete firewall', session)
    controller.execute('set nat source rule 10 outbound-interface eth0', session)
    with pytest.raises(ValidationError, match='nat source rule 10 outbound-interface'):
        controller.execute('delete interfaces ethernet eth0', session)


@pytest.mark.parametrize('key', ['dependency', 'depends'])
@pytest.mark.parametrize('node', [
    {'kind': 'node'}, {'kind': 'leaf_node', 'valueless': True},
    {'kind': 'tag_node', 'value': None}, {'kind': 'leaf_node', 'value': ['interface']},
    {'kind': 'leaf_node', 'value': ''}, {'kind': 'tag_node', 'value': 'two types'},
])
def test_invalid_declarations_rejected_at_build_and_runtime(tmp_path, key, node):
    node = dict(node)
    node[key] = node.pop('value', 'interface')
    root = {'kind': 'node', 'children': {'bad': node}}
    with pytest.raises(ValueError, match=f'bad.*{key}'):
        Schema(root)

    source = tmp_path / 'source'
    source.mkdir()
    (source / 'configuration.yaml').write_text(json.dumps(root))
    with pytest.raises(SchemaBuildError, match=f'bad.*{key}'):
        build_schemas(source, tmp_path / 'out')


def test_shared_parent_can_remove_provider_and_consumer_together():
    schema = Schema({'kind': 'node', 'children': {'objects': {'kind': 'tag_node', 'dependency': 'object', 'children': {
        'uses': {'kind': 'leaf_node', 'multi': True, 'depends': 'object'}}}}})
    registry = Dependencies(schema)
    before = {'objects': {'a': {}, 'b': {'uses': ['a', 'missing']}}}

    registry.check_trees(before, {})
    with pytest.raises(ValidationError, match='objects b uses'):
        registry.check_trees(before, {'objects': {'b': {'uses': ['a', 'missing']}}})


def test_many_interface_deletions_reuse_references_without_materializing_candidate(controller, session, engine, monkeypatch):
    for number in range(1000):
        controller.execute(f'set interfaces dummy dum{number}', session)
    controller.execute(f'set {RULE} inbound-interface dum0', session)

    calls = []
    original = engine.dependencies.collect

    def collect(get, keys, category, scope=(), **kwargs):
        if category == 'depends':
            calls.append(scope)
        return original(get, keys, category, scope, **kwargs)

    monkeypatch.setattr(engine.dependencies, 'collect', collect)
    monkeypatch.setattr(engine, 'view', lambda *args: pytest.fail('individual deletion materialized the full candidate'))

    with pytest.raises(ValidationError):
        controller.execute('delete interfaces dummy dum0', session)
    for number in range(1, 1000):
        controller.execute(f'delete interfaces dummy dum{number}', session)

    # Only one global reference scan is needed. Scoped checks may inspect the
    # deleted interface for its own references (such as an optional VRF).
    assert calls.count(()) == 1
    assert all(not scope or scope[:2] == ('interfaces', 'dummy') and len(scope) == 3
               for scope in calls)
    controller.execute(f'delete {RULE} inbound-interface', session)
    controller.execute('delete interfaces dummy dum0', session)
    assert calls.count(()) == 1


def test_deleting_vrf_members_updates_cached_references_incrementally(controller, session, engine, monkeypatch):
    controller.execute('set vrf name BLUE table 100', session)
    for number in range(100):
        controller.execute(f'set interfaces dummy dum{number} vrf BLUE', session)

    # A blocked deletion populates the index with all current member references.
    with pytest.raises(ValidationError):
        controller.execute('delete vrf name BLUE', session)

    original = engine.dependencies.collect

    def collect(get, keys, category, scope=(), **kwargs):
        if category == 'depends' and not scope:
            pytest.fail('member deletion rebuilt the global reference index')

        return original(get, keys, category, scope, **kwargs)

    monkeypatch.setattr(engine.dependencies, 'collect', collect)
    for number in range(99):
        controller.execute(f'delete interfaces dummy dum{number}', session)

    # Remaining members still protect the VRF; deleting the last one releases it.
    with pytest.raises(ValidationError, match='dum99'):
        controller.execute('delete vrf name BLUE', session)

    controller.execute('delete interfaces dummy dum99', session)
    controller.execute('delete vrf name BLUE', session)


def test_multi_owner_parent_delete_is_checked_as_a_unit(engine, session):
    schema = Schema({'kind': 'node', 'children': {'group': {'kind': 'node', 'children': {
        'objects': {'kind': 'tag_node', 'dependency': 'object', 'script': {'name': 'objects', 'priority': 1}},
        'references': {'kind': 'leaf_node', 'multi': True, 'depends': 'object', 'script': {'name': 'references', 'priority': 2}},
    }}}})
    engine.schema = schema
    engine.dependencies = Dependencies(schema)
    engine.mutate(session, 'set', lex('group objects example'))
    engine.mutate(session, 'set', lex('group references example'))

    engine.mutate(session, 'delete', lex('group'))
    assert engine.view(session) == {}


def test_valued_providers_and_anchored_removal_are_checked_before_staging(engine, session):
    schema = Schema({'kind': 'node', 'children': {'group': {
        'kind': 'tag_node', 'anchor': True, 'script': {'name': 'group', 'priority': 1}, 'children': {
            'provider': {'kind': 'leaf_node', 'dependency': 'object'},
            'consumer': {'kind': 'leaf_node', 'depends': 'object'},
        }}}})
    engine.schema = schema
    engine.dependencies = Dependencies(schema)
    engine.mutate(session, 'set', lex('group a provider old consumer old'))
    before = list(session.mutations)

    with pytest.raises(ValidationError, match='old'):
        engine.mutate(session, 'set', lex('group a provider new'))
    assert list(session.mutations) == before

    engine.mutate(session, 'set', lex('group a provider new consumer new'))
    assert engine.view(session) == {'group': {'a': {'provider': 'new', 'consumer': 'new'}}}


def test_same_identity_can_have_multiple_provider_paths(engine, session):
    schema = Schema({'kind': 'node', 'children': {
        name: {'kind': 'tag_node', 'dependency': 'object', 'script': {'name': name, 'priority': 1}}
        for name in ('first', 'second')
    } | {'uses': {'kind': 'leaf_node', 'depends': 'object', 'script': {'name': 'uses', 'priority': 2}}}})
    engine.schema = schema
    engine.dependencies = Dependencies(schema)
    for command in ('first shared', 'second shared', 'uses shared'):
        engine.mutate(session, 'set', lex(command))

    engine.mutate(session, 'delete', lex('first shared'))
    with pytest.raises(ValidationError, match='uses'):
        engine.mutate(session, 'delete', lex('second shared'))


def test_multi_provider_values_and_merge_load_are_validated_atomically(engine, session):
    schema = Schema({'kind': 'node', 'children': {'group': {
        'kind': 'node', 'script': {'name': 'group', 'priority': 1}, 'children': {
            'providers': {'kind': 'leaf_node', 'multi': True, 'dependency': 'object'},
            'provider': {'kind': 'leaf_node', 'dependency': 'object'},
            'consumer': {'kind': 'leaf_node', 'depends': 'object'},
        }}}})
    engine.schema = schema
    engine.dependencies = Dependencies(schema)
    engine.mutate(session, 'set', lex('group providers a'))
    engine.mutate(session, 'set', lex('group providers b'))
    engine.mutate(session, 'set', lex('group consumer a'))

    with pytest.raises(ValidationError, match='a'):
        engine.mutate(session, 'delete', lex('group providers a'))
    engine.mutate(session, 'delete', lex('group providers b'))

    engine.mutate(session, 'set', lex('group provider old'))
    engine.mutate(session, 'set', lex('group consumer old'))
    before = engine.view(session)
    with pytest.raises(ValidationError, match='old'):
        engine.stage_configuration(session, {'group': {'provider': 'new'}})
    assert engine.view(session) == before

    engine.stage_configuration(session, {'group': {'provider': 'new', 'consumer': 'new'}})
    assert engine.view(session)['group']['provider'] == 'new'
