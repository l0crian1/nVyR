"""Keyword-free operational values retain ordinary validation and completion."""

from copy import deepcopy
import json

import pytest

from build_tools.command_tree import render_tree
from build_tools.schema_builder import SchemaBuildError, build_schemas
from nvyr.errors import RouterError
from nvyr.helpers import access
from nvyr.helpers.process import operational_argv
from nvyr.lexer import lex
from nvyr.schema import Schema


@pytest.fixture
def positional_build(tmp_path):
    source = tmp_path / 'schemas'
    source.mkdir()
    output = tmp_path / 'output'
    value = {
        'kind': 'tag_node', 'positional': True, 'command': ['echo', '@line'],
        'validators': {'regex': {'pattern': '[A-Z]+'}},
        'hints': {'name': 'Object name'},
        'choices': {'BLUE': 'Blue object'},
        'children': {'detail': {'kind': 'node', 'command': ['echo', '@line']}},
    }
    root = {'kind': 'node', 'children': {'probe': {
        'kind': 'node', 'command': ['echo', '@line'], 'children': {
            'identifier': value,
            'summary': {'kind': 'node', 'command': ['echo', '@line']},
            'support': {'kind': 'node', 'command': ['echo', '@line']},
        },
    }}}

    def build(document=None, filename='operational'):
        document = root if document is None else document
        (source / f'{filename}.yaml').write_text(json.dumps(document))
        build_schemas(source, output)
        return Schema(json.loads((output / f'{filename}.json').read_text()))

    return root, build


def test_positional_values_do_not_consume_keyword_positions(positional_build):
    _, build = positional_build
    schema = build()
    tokens = lex('probe BLUE detail')
    cursor = schema.operational(tokens)

    assert cursor.path == ('probe', 'identifier', 'BLUE', 'detail')
    assert schema.command_path(cursor.path) == ('probe', 'BLUE', 'detail')
    assert cursor.omitted_positions == ()
    assert operational_argv({'argv': ['echo', '@1', '@2', '@3']}, tokens, 'probe BLUE detail',
                            omitted_positions=cursor.omitted_positions) == ['echo', 'probe', 'BLUE', 'detail']


def test_keyword_precedence_and_ambiguity_are_preserved(positional_build):
    _, build = positional_build
    schema = build()

    assert schema.operational(lex('probe summ')).path == ('probe', 'summary')
    with pytest.raises(RouterError, match='matches more than one command'):
        schema.operational(lex('probe su'))
    with pytest.raises(RouterError, match='Invalid value'):
        schema.operational(lex('probe identifier'))
    with pytest.raises(RouterError, match='Invalid value'):
        schema.operational(lex('probe bad-value'))


def test_consecutive_positional_values_preserve_their_order(positional_build):
    document, build = positional_build
    first = document['children']['probe']['children']['identifier']
    first['children']['second'] = {
        'kind': 'tag_node', 'positional': True, 'command': ['echo', '@line'],
        'validators': {'integer-range': {'minimum': 1, 'maximum': 10}},
    }
    schema = build(document)

    cursor = schema.operational(lex('probe BLUE 7'))
    assert schema.command_path(cursor.path) == ('probe', 'BLUE', '7')
    with pytest.raises(RouterError, match='Invalid value'):
        schema.operational(lex('probe BLUE 11'))


def test_nonterminal_positional_requires_a_child_command(controller, positional_build, monkeypatch):
    document, build = positional_build
    del document['children']['probe']['children']['identifier']['command']
    controller.operational = build(document)
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'ok')

    candidates = dict(controller.completion('probe BLUE ', explicit=True)['candidates'])
    assert 'detail' in candidates
    assert '<Enter>' not in candidates
    with pytest.raises(RouterError):
        controller.execute('probe BLUE')
    assert calls == []

    assert controller.execute('probe BLUE detail')['text'] == 'ok'
    assert calls == [['echo', 'probe BLUE detail']]


def test_positional_help_and_value_completion(controller, positional_build):
    _, build = positional_build
    controller.operational = build()

    help = controller.completion('probe ', explicit=True)
    assert ('name', 'Object name') in help['hints']
    assert {'BLUE', 'summary', 'support', '<Enter>'} <= dict(help['candidates']).keys()
    assert 'identifier' not in dict(help['candidates'])
    assert controller.completion('probe BL', tab=True)['replacement'] == 'BLUE'
    assert controller.completion('probe BL', space=True)['replacement'] == 'BLUE'
    assert 'detail' in dict(controller.completion('probe BLUE ', explicit=True)['candidates'])
    assert '<Enter>' not in dict(controller.completion('probe invalid ', explicit=True)['candidates'])


def test_positional_access_controls_execution_and_discovery(controller, positional_build, monkeypatch):
    document, build = positional_build
    document['children']['probe']['children']['identifier']['access'] = 'sys-admin'
    controller.operational = build(document)
    monkeypatch.setattr('nvyr.controller.cmd', lambda *args, **kwargs: pytest.fail('Restricted command executed'))

    role = access.role.set('read-only')
    try:
        help = controller.completion('probe ', explicit=True)
        assert not help['hints']
        assert 'BLUE' not in dict(help['candidates'])
        with pytest.raises(RouterError):
            controller.execute('probe BLUE')
    finally:
        access.role.reset(role)


def test_positional_choices_do_not_reexpose_restricted_keywords(controller, positional_build):
    document, build = positional_build
    document['children']['probe']['children']['BLUE'] = {
        'kind': 'node', 'access': 'sys-admin', 'command': ['echo', '@line'],
    }
    controller.operational = build(document)

    role = access.role.set('read-only')
    try:
        help = controller.completion('probe ', explicit=True)
        assert 'BLUE' not in dict(help['candidates'])
    finally:
        access.role.reset(role)


@pytest.mark.parametrize('change', [
    {'positional': 'true'}, {'kind': 'node'}, {'optional_value': True}, {'anchor': True},
    {'negatable': True}, {'command': None},
])
def test_invalid_positional_declarations_fail_during_build(positional_build, change):
    document, build = positional_build
    document['children']['probe']['children']['identifier'].update(change)
    with pytest.raises(SchemaBuildError, match='positional'):
        build(document)


def test_multiple_positionals_and_configuration_declarations_are_rejected(positional_build):
    document, build = positional_build
    children = document['children']['probe']['children']
    children['other'] = deepcopy(children['identifier'])
    with pytest.raises(SchemaBuildError, match='only one positional'):
        build(document)

    del children['other']
    with pytest.raises(SchemaBuildError, match='positional'):
        build(document, filename='configuration')


def test_documentation_omits_internal_positional_names(positional_build):
    _, build = positional_build
    tree = render_tree('operational', build().root)
    assert '<BLUE|name>' in tree
    assert 'identifier' not in tree
