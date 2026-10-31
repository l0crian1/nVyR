import json

import pytest

from nvyr.errors import RouterError
from nvyr.render import marked_json
from nvyr.schema import Schema, completion_sort_key
from nvyr.tree import MISSING


def side(text, marker):
    return json.loads('\n'.join(line[2:] for line in text.splitlines() if line.startswith(('  ', marker + ' '))))


def test_deleted_firewall_and_recreated_sibling_keep_tree_structure(controller, engine, session):
    prefix = 'set firewall ipv4 forward filter rule 10 '

    for suffix in ['action accept', 'destination-address 2.2.2.2/32', 'destination-port 22',
                   'protocol tcp', 'source-address 1.1.1.1/32']:
        controller.execute(prefix + suffix, session)

    engine.commit(session)
    before = engine.running
    controller.execute('delete firewall', session)
    deleted = controller.execute('show candidate-configuration', session)['text']

    assert side(deleted, '-') == before and side(deleted, '+') == {}

    controller.execute('set firewall ipv4 forward filter default-action accept', session)
    rendered = controller.execute('show candidate-configuration', session)['text']

    assert side(rendered, '-') == before
    assert side(rendered, '+') == engine.view(session)

    # The added sibling precedes the complete deleted rule block, never its contents.
    assert rendered.index('+           "default-action"') < rendered.index('-           "rule"')
    assert all(not line.startswith('+ ') for line in rendered.split('-           "rule"', 1)[1].splitlines())
    assert controller.execute('show candidate-configuration | commands', session)['text'] == (
        'set firewall ipv4 forward filter default-action accept\ndelete firewall ipv4 forward filter rule\n')

    scoped = controller.execute('show candidate-configuration firewall ipv4 forward filter', session)['text']

    assert side(scoped, '-') == before['firewall']['ipv4']['forward']['filter']
    assert side(scoped, '+') == {'default-action': 'accept'}


@pytest.mark.parametrize('before,after', [
    ({'a': {'value': 'same-looking'}, 'z': True}, {'b': 'same-looking', 'z': True}),
    ({'z': {'a': True}}, {'a': {'z': True}}),
    ({'a': 1, 'b': 2}, {'a': 1}),
    ({'a': 1}, {'a': 1, 'b': 2}),
    ({'a': {}}, {'a': {'b': {}}}),
    ({'a': {'b': {}}}, {'a': {}}),
    ({'quote"\n': ['one', 'two']}, {'quote"\n': ['two', 'three']}),
    ({'scalar': True}, {'scalar': 'true'}),
    ({}, {'a': {'b': 'new'}}),
    ({'a': {'b': 'old'}}, {}),
    (['one', 'two'], ['two']),
    ('old', 'new'),
    ({'a': True}, {'a': True}),
])
def test_structural_diff_reconstructs_both_json_sides(before, after):
    rendered = marked_json(before, after)

    assert side(rendered, '-') == before
    assert side(rendered, '+') == after


def test_missing_scopes_render_whole_blocks():
    assert marked_json(MISSING, {'10': {}}) == '+ {\n+   "10": {}\n+ }\n'
    assert marked_json({'10': {}}, MISSING) == '- {\n-   "10": {}\n- }\n'


def test_choice_descriptions_survive_configuration_and_discovery(controller, engine, session):
    text = 'set firewall ipv4 forward filter default-action '
    expected = {
        'accept': 'Accept matching traffic',
        'drop': 'Silently drop matching traffic',
        'reject': 'Reject matching traffic with the global error response',
    }

    assert dict(controller.completion(text, session, explicit=True)['candidates']) == expected

    controller.execute(text + 'accept', session)

    assert dict(controller.completion(text, session, explicit=True)['candidates']) == expected
    assert controller.completion(text + 'a', session)['replacement'] == 'accept'

    with pytest.raises(RouterError, match='permitted values'):
        controller.execute(text + 'unsupported', session)

    with pytest.raises(RouterError):
        engine.stage_configuration(session, {'firewall': {'ipv4': {'forward': {'filter': {'default-action': 'unsupported'}}}}})

    schema = Schema({'kind': 'node', 'children': {'value': {
        'kind': 'leaf_node', 'choices': {'one': 'The first value'}, 'suggestors': [{'name': 'test'}],
    }}}, suggestors={'test': lambda: ['one']})

    assert schema.candidates(schema.resolve(['value']), '', {'value': 'one'}, explicit=True) == [('one', 'The first value')]


@pytest.mark.parametrize('choices', ['accept', ['accept'], [10], {'accept': 1}, {'accept': ''}])
def test_invalid_choice_definitions_fail_when_schema_loads(choices):
    with pytest.raises(ValueError, match='Choices require'):
        Schema({'kind': 'node', 'children': {'value': {'kind': 'leaf_node', 'choices': choices}}})


def test_choice_mappings_preserve_numeric_completion_order():
    schema = Schema({'kind': 'node', 'children': {'value': {'kind': 'leaf_node', 'choices': {v: 'Number' for v in ['10', '2', '1']}}}})

    assert schema.resolve(['value', '2']).value == '2'
    assert [value for value, _ in schema.candidates(schema.resolve(['value']), '', {})] == ['1', '2', '10']
    assert schema.resolve(['value', '3']).value == '3'


def test_common_completion_orders_history_tags_choices_and_mixed_values(controller, engine, session):
    for index in range(12):
        controller.execute(f'set system host-name r{index}', session)
        engine.commit(session)

    numbers = [str(index) for index in range(13)]

    assert [v for v, _ in controller.completion('rollback ', session, tab=True)['candidates']] == numbers
    assert [v for v, _ in controller.completion('compare ', session, explicit=True)['candidates']] == numbers + ['saved', '<Enter>']
    assert [v for v, _ in controller.completion('rollback 1', session, explicit=True)['candidates']] == ['1', '10', '11', '12', '<Enter>']

    for number in ['100', '2', '10', '1']:
        controller.execute(f'set firewall ipv4 forward filter rule {number}', session)

    assert [v for v, _ in controller.completion('set firewall ipv4 forward filter rule ', session)['candidates']] == ['1', '2', '10', '100']
    assert sorted(['saved', '12', '01', '0', '2', '1', 'alpha'], key=completion_sort_key) == ['0', '1', '01', '2', '12', 'alpha', 'saved']

    # Sorting must not invoke int() on unrestricted completion tokens.
    assert sorted(['9' * 5000, '1', '9' * 4999], key=completion_sort_key)[0] == '1'
