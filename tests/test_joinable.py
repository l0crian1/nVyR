"""Joined leaf values retain ordinary completion and configuration semantics."""

import pytest

from build_tools.schema_builder import SchemaBuildError, _normalize_callbacks
from nvyr.errors import RouterError
from nvyr.lexer import lex
from nvyr.opmode import command_arguments
from nvyr.render import diff_commands, set_commands
from nvyr.schema import Schema
from nvyr.tree import lookup


RULE = 'firewall ipv4 forward filter rule 10'
PATH = tuple(RULE.split())


def test_joined_values_are_one_mutation_and_repeated_leaves_are_alternatives(controller, engine, session):
    controller.execute(f'set {RULE} connection status confirmed and snat and dnat '
                       'counter connection status assured and seen-reply action accept', session)

    rule = lookup(engine.view(session), PATH)
    assert rule['connection']['status'] == ['confirmed,snat,dnat', 'assured,seen-reply']
    assert rule['counter'] == {}
    assert rule['action'] == 'accept'
    assert len(session.mutations) == 4


@pytest.mark.parametrize('suffix', ['confirmed and', 'confirmed and typo', 'confirmed and and',
                                    'confirmed and snat and'])
def test_invalid_suffix_is_atomic(controller, session, suffix):
    before = list(session.mutations)

    with pytest.raises(RouterError):
        controller.execute(f'set {RULE} counter connection status {suffix}', session)

    assert session.mutations == before


def test_completion_continues_the_leaf_or_the_anchor(controller, session):
    prefix = f'set {RULE} connection status confirmed '
    result = controller.completion(prefix, session, explicit=True)
    candidates = dict(result['candidates'])

    assert {'and', 'counter', 'status', '<Enter>'} <= candidates.keys()
    assert controller.completion(prefix + 'an', session)['replacement'] == 'and'

    result = controller.completion(prefix + 'and ', session, explicit=True)
    candidates = dict(result['candidates'])
    assert {'snat', 'dnat', 'assured'} <= candidates.keys()
    assert 'confirmed' not in candidates
    assert '<Enter>' not in candidates
    assert 'counter' not in candidates
    assert result['hints']
    assert controller.completion(prefix + 'and sn', session)['extension'] == 'at'


def test_edit_delete_and_command_round_trip(controller, engine, session):
    controller.execute(f'edit {RULE}', session)
    controller.execute('set connection status confirmed and snat and dnat', session)
    controller.execute('set connection status assured', session)
    tree = engine.view(session)
    commands = list(set_commands(engine.schema, tree))
    assert commands == [f'set {RULE} connection status confirmed and snat and dnat',
                        f'set {RULE} connection status assured']

    controller.execute('delete connection status confirmed and snat and dnat', session)
    without = engine.view(session)
    assert list(diff_commands(engine.schema, tree, without)) == [
        f'delete {RULE} connection status confirmed and snat and dnat']
    assert not controller.load(session, '\n'.join(commands), set_format=True, replace=True)
    assert engine.view(session) == tree

    with pytest.raises(RouterError, match="after 'and'"):
        controller.execute('delete connection status confirmed and', session)

    assert engine.view(session) == tree
    assert '<Enter>' not in dict(controller.completion(
        'delete connection status confirmed and ', session, explicit=True)['candidates'])


def test_join_validation_reports_combined_value_and_offending_token(controller, session):
    command = f'set {RULE} connection status confirmed and misspelled'

    with pytest.raises(RouterError) as error:
        controller.execute(command, session)

    assert 'confirmed,misspelled' in str(error.value)
    assert error.value.start == command.index('misspelled')


def joined_schema(*, anchored=False, multi=False):
    leaf = {'kind': 'leaf_node', 'joinable': True, 'multi': multi,
            'choices': {'red': 'Red', 'blue': 'Blue', 'green': 'Green'},
            'suggestors': [{'name': 'colors'}]}
    parent = {'kind': 'node', 'children': {'colors': leaf, 'quiet': {
        'kind': 'leaf_node', 'valueless': True}}}
    if anchored:
        parent.update(anchor=True, command={'argv': ['example', '@line']})

    return Schema({'kind': 'node', 'children': {'example': parent}},
                  suggestors={'colors': lambda: ['red', 'green', 'yellow']})


def test_scalar_leaf_without_anchor_and_suggestor_filtering():
    schema = joined_schema()
    cursors = schema.set_paths(lex('example colors red and blue'))
    assert len(cursors) == 1
    assert cursors[0].value == 'red,blue'
    assert dict(schema.candidates(cursors[0], '', {})) == {
        'and': 'Join another value to this combination'}

    cursor = schema.resolve(lex('example colors red and'))
    candidates = dict(schema.candidates(cursor, '', {}))
    assert set(candidates) == {'blue', 'green', 'yellow'}
    assert list(set_commands(schema, {'example': {'colors': 'red,blue'}})) == [
        'set example colors red and blue']


def test_operational_anchor_and_command_arguments():
    schema = joined_schema(anchored=True, multi=True)
    line = 'example colors red and blue quiet colors green'
    assert schema.operational(lex(line)).path == ('example',)
    anchor, arguments = command_arguments(line, {'colors': '--color', 'quiet': '--quiet'}, schema=schema)
    assert anchor == ('example',)
    assert arguments == [
        '--color', 'red,blue', '--quiet', '--color', 'green']

    with pytest.raises(RouterError):
        schema.operational(lex('example colors red and'))


def test_operational_completion_uses_joined_leaf_choices(controller):
    controller.operational = joined_schema(anchored=True, multi=True)
    result = controller.completion('example colors red ', explicit=True)
    assert {'and', 'quiet', '<Enter>'} <= dict(result['candidates']).keys()
    assert [group['name'] for group in result['groups']] == ['colors', 'example']
    assert result['groups'][0]['candidates'] == ['and']

    result = controller.completion('example colors red and ', explicit=True)
    assert {'blue', 'green', 'yellow'} == dict(result['candidates']).keys()
    assert result['groups'] == []


def test_join_keyword_preserves_abbreviation_ambiguity(controller, session):
    # Both action and and are available after a joined leaf, so a is ambiguous.
    with pytest.raises(RouterError, match='more than one command'):
        controller.execute(f'set {RULE} connection status confirmed a snat', session)

    controller.execute(f'set {RULE} connection status confirmed an snat act accept', session)


def test_nonanchored_delete_completion_and_quoted_values(controller, session):
    result = controller.completion(f'delete {RULE} connection status confirmed ', session, explicit=True)
    assert {'and', '<Enter>'} <= dict(result['candidates']).keys()
    assert 'counter' not in dict(result['candidates'])

    schema = joined_schema()
    cursor = schema.configuration_path(lex('example colors "light blue" and green'))
    assert cursor.value == 'light blue,green'
    assert list(set_commands(schema, {'example': {'colors': cursor.value}})) == [
        "set example colors 'light blue' and green"]


@pytest.mark.parametrize('properties', [
    {'kind': 'node', 'joinable': True},
    {'kind': 'tag_node', 'joinable': True},
    {'kind': 'leaf_node', 'joinable': 'true'},
    {'kind': 'leaf_node', 'joinable': True, 'valueless': True},
    {'kind': 'leaf_node', 'joinable': True, 'rest': True},
])
def test_invalid_schema_declarations_fail_in_builder_and_runtime(properties):
    with pytest.raises(SchemaBuildError, match='joinable'):
        _normalize_callbacks(properties, ('example',))

    with pytest.raises(ValueError, match='joinable'):
        Schema({'kind': 'node', 'children': {'example': properties}})


def test_ordinary_leaves_do_not_interpret_and(controller, engine, session):
    controller.execute(f'set {RULE} description "red and blue" action accept', session)
    assert lookup(engine.view(session), PATH)['description'] == 'red and blue'

    with pytest.raises(RouterError):
        controller.execute(f'set {RULE} protocol tcp and udp', session)
