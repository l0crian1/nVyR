"""List defaults stay effective-only throughout the configuration lifecycle."""

import copy
import json

import pytest

from build_tools.schema_builder import build_schemas
from nvyr.controller import Controller
from nvyr.engine import Engine
from nvyr.errors import ValidationError
from tests.lifecycle import LifecycleStub
from nvyr.schema import Schema
from nvyr.storage import Store
from nvyr.tree import ReadOnlyTree, lookup


def leaf(mode='direct', values=None):
    return {'kind': 'leaf_node', 'multi': True,
            'validators': {'checks': {'list': {'name': 'list', 'args': {'values': 'one two three'}}}},
            'default': {'mode': mode, 'value': ['two', 'one'] if values is None else values}}


def schema_for(mode='direct'):
    return Schema({'kind': 'node', 'children': {'service': {'kind': 'node', 'children': {
        'example': {'kind': 'node', 'script': {'name': 'example', 'priority': 1},
                    'children': {'values': leaf(mode)}}}}}})


@pytest.mark.parametrize('mode', ['direct', 'always'])
def test_list_defaults_are_valid_and_isolated_between_effective_views(mode):
    schema = schema_for(mode)
    explicit = {'service': {'example': {}}}
    original = copy.deepcopy(schema.root)
    first, second = schema.defaults(explicit), schema.defaults(explicit)

    assert first == second == {'service': {'example': {'values': ['two', 'one']}}}

    schema.validate_configuration(first)

    assert lookup(ReadOnlyTree(first), ('service', 'example', 'values')) == ('two', 'one')

    first['service']['example']['values'].append('three')

    assert second['service']['example']['values'] == ['two', 'one']
    assert schema.root == original
    assert explicit == {'service': {'example': {}}}


@pytest.mark.parametrize('mode', ['direct', 'always'])
def test_activation_explicit_override_and_tag_boundaries(mode):
    root = {'kind': 'node', 'children': {'service': {'kind': 'node', 'children': {
        'nested': {'kind': 'node', 'children': {'values': leaf(mode), 'direct': leaf('direct')}},
        'instance': {'kind': 'tag_node', 'children': {'values': leaf(mode)}}}}}}
    schema = Schema(root)

    assert schema.defaults({}) == {}

    effective = schema.defaults({'service': {}})

    assert effective == ({'service': {'nested': {'values': ['two', 'one']}}}
                         if mode == 'always' else {'service': {}})

    configured = {'service': {'nested': {}, 'instance': {'a': {}, 'b': {'values': ['three']}}}}
    effective = schema.defaults(configured)

    assert effective['service']['nested'] == {'values': ['two', 'one'], 'direct': ['two', 'one']}
    assert effective['service']['instance'] == {'a': {'values': ['two', 'one']}, 'b': {'values': ['three']}}

    schema.validate_configuration(effective)

    assert configured['service']['nested'] == {}


@pytest.mark.parametrize('values', [[], 'one', ['one', 'one'], ['one', 'invalid'], ['one', 2], [['one']]])
def test_invalid_multi_defaults_are_rejected(values):
    with pytest.raises((ValueError, ValidationError)):
        Schema({'kind': 'node', 'children': {'values': leaf(values=values)}})


@pytest.mark.parametrize('mode', ['direct', 'always'])
def test_scalar_and_valueless_defaults_remain_unchanged(mode):
    schema = Schema({'kind': 'node', 'children': {
        'single': {'kind': 'leaf_node', 'default': {'mode': mode, 'value': 'one'}},
        'flag': {'kind': 'leaf_node', 'valueless': True, 'default': {'mode': mode}}}})

    assert schema.defaults({}) == {'single': 'one', 'flag': True}
    assert schema.defaults({'single': 'two'}) == {'single': 'two', 'flag': True}

    with pytest.raises(ValidationError):
        Schema({'kind': 'leaf_node', 'default': {'mode': mode, 'value': ['one', 'two']}})


@pytest.mark.parametrize('mode', ['direct', 'always'])
def test_lists_reach_lifecycle_but_not_candidates_history_or_saved_config(tmp_path, mode):
    schema, module, applied = schema_for(mode), LifecycleStub(), []
    module.apply = lambda generated, context: applied.append((
        tuple(generated.get('values', ())),
        lookup(context.previous_effective, ('service', 'example', 'values'), ()), context.recovery))
    store = Store(tmp_path)
    engine = Engine(schema, {'example': module}, store)
    controller = Controller(engine)
    session = engine.open('alice', 'pts/1')
    controller.execute('set service example', session)

    assert engine.view(session) == {'service': {'example': {}}}

    result = controller.execute('commit', session)

    assert 'example: done' in result['text']
    assert applied[-1] == (('two', 'one'), (), False)

    controller.execute('save', session)

    assert engine.running == store.read('boot.json') == {'service': {'example': {}}}
    assert store.read('state.json')['configuration'] == engine.running
    assert store.historical(engine.commit_id, 0) == engine.running
    assert 'values' not in controller.execute('show running-configuration | commands', session)['text']

    # Explicit values replace the whole default list; removing the last value
    # restores defaults without adding them to the candidate or running tree.
    controller.execute('set service example values three', session)
    controller.execute('commit', session)

    assert applied[-1] == (('three',), ('two', 'one'), False)

    controller.execute('delete service example values three', session)

    assert engine.view(session) == {'service': {'example': {}}}

    controller.execute('commit', session)

    assert applied[-1] == (('two', 'one'), ('three',), False)

    # Restart recovery recomputes defaults from the explicit persisted tree.
    restarted = Engine(schema, {'example': module}, store)

    assert restarted.running == {'service': {'example': {}}}
    assert applied[-1] == (('two', 'one'), ('two', 'one'), True)

    session = restarted.open('alice', 'pts/2')
    now = [100.0]
    restarted.clock = lambda: now[0]
    restarted.mutate(session, 'set', ['service', 'example', 'values', 'three'])
    restarted.commit(session, minutes=1, confirmed_minutes=1)
    now[0] = 161.0
    restarted.tick()

    assert restarted.running == {'service': {'example': {}}}
    assert applied[-1] == (('two', 'one'), ('three',), True)


@pytest.mark.parametrize('mode', ['direct', 'always'])
def test_yaml_list_defaults_build_and_apply_in_order(tmp_path, mode):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'configuration.yaml').write_text('''kind: node
children:
  values:
    kind: leaf_node
    multi: true
    description: Example values
    validators:
      list: {values: 'one two'}
    default:
      mode: ''' + mode + '''
      value:
        - two
        - one
''')
    output = tmp_path / 'output'
    build_schemas(source, output)
    root = json.loads((output / 'configuration.json').read_text())

    assert root['children']['values']['description'] == 'Example values (default: ["two", "one"])'

    schema = Schema(root)

    assert schema.defaults({}) == {'values': ['two', 'one']}
