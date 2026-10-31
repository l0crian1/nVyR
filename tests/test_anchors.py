import pytest

from nvyr.controller import Controller
from nvyr.engine import Engine
from nvyr.errors import RouterError
from nvyr.lexer import lex
from tests.lifecycle import LifecycleStub, recorded_registry
from nvyr.schema import Schema
from nvyr.storage import Store
from nvyr.tree import lookup


RULE = 'firewall ipv4 forward filter rule 10 '
SET = 'set ' + RULE
PROPERTIES = ['action accept', 'protocol tcp', 'source-address 1.1.1.1/32',
              'destination-address 2.2.2.2/32', 'destination-port 22']


def test_anchor_matches_individual_intents_diff_commit_and_persistence(controller, engine, session):
    separate = engine.open('separate', '/dev/pts/2', draft=True)

    for setting in PROPERTIES:
        controller.execute(SET + setting, separate)

    controller.execute(SET + ' '.join(PROPERTIES), session)

    assert session.mutations == separate.mutations
    assert len(session.mutations) == 5

    commands = controller.execute('show candidate-configuration | commands', session)['text']

    assert sorted(commands.splitlines()) == sorted(SET + setting for setting in PROPERTIES)

    engine.modules['firewall'].calls.clear()

    assert engine.commit(session)['results']['firewall']['success']
    assert [stage for _, stage, _ in engine.modules['firewall'].calls] == ['get_config', 'verify', 'generate', 'apply']

    engine.save(session)

    assert engine.store.read('boot.json') == engine.running
    assert engine.store.historical(engine.commit_id, 0) == engine.running

    restarted = Engine(engine.schema, recorded_registry(engine.schema), Store(engine.store.directory))

    assert restarted.running == engine.running


@pytest.mark.parametrize('command', [
    SET + 'action accept protocol',
    SET + 'action accept protocol nope',
    SET + 'action accept destination-port 70000',
    SET + 'action accept d foo',
    SET + 'action accept unexpected value',
    SET + 'description new action accept source-address wrong',
    SET + 'action accept rule 20 action drop',
    SET + 'action accept description "unclosed',
    SET + 'action accept | count',
])
def test_bad_suffix_never_stages_any_part(controller, engine, session, command):
    controller.execute(SET + 'description previous', session)
    before = list(session.mutations)
    candidate = engine.view(session)

    with pytest.raises(RouterError):
        controller.execute(command, session)

    assert session.mutations == before
    assert engine.view(session) == candidate


def test_error_span_points_to_later_segment(controller, session):
    text = SET + 'action accept protocol invalid'

    with pytest.raises(RouterError) as error:
        controller.execute(text, session)

    assert error.value.start == text.index('invalid')
    assert 'firewall ipv4 forward filter rule 10 protocol' in str(error.value)


def test_other_operations_keep_single_path_grammar(controller, engine, session):
    controller.execute(SET + 'action accept protocol tcp', session)
    before = list(session.mutations)

    for verb in ['delete', 'edit', 'show']:
        with pytest.raises(RouterError):
            controller.execute(verb + ' ' + RULE + 'action accept protocol tcp', session)

    assert session.mutations == before

    controller.execute('delete ' + RULE + 'protocol', session)

    assert 'protocol' not in lookup(engine.view(session), tuple(RULE.split()))


def test_edit_at_or_above_anchor_and_absolute_load(controller, engine, session):
    controller.execute('edit firewall ipv4 forward filter', session)
    controller.execute('set rule 10 action accept protocol tcp destination-port 22', session)

    assert len(session.mutations) == 3

    controller.execute('edit rule 10', session)
    controller.execute('set description "Local rule" log', session)

    assert session.edit == tuple(RULE.split())
    assert controller.completion('set action accept pro', session)['replacement'] == 'protocol'

    errors = controller.load(session, 'set interfaces dummy dum0 description "WAN Interface" disable', set_format=True)

    assert not errors
    assert engine.view(session)['interfaces']['dummy']['dum0'] == {'description': 'WAN Interface', 'disable': True}


def test_multi_values_flags_keyword_values_and_order(controller, engine, session):
    controller.execute('set interfaces dummy dum0 address 192.0.2.1/24 description disable '
                       'address 192.0.2.2/24 disable address 192.0.2.1/24 description "WAN | address"', session)

    assert engine.view(session)['interfaces']['dummy']['dum0'] == {
        'address': ['192.0.2.1/24', '192.0.2.2/24'], 'description': 'WAN | address', 'disable': True}

    before = list(session.mutations)

    with pytest.raises(RouterError):
        controller.execute('set interfaces dummy dum0 address 192.0.2.3/24 192.0.2.4/24', session)

    assert session.mutations == before


def test_load_error_is_atomic_per_line_and_replace_uses_same_grammar(controller, engine, session):
    errors = controller.load(session, SET + 'action accept protocol invalid\n' +
                             'set interfaces dummy dum0 description kept disable', set_format=True)

    assert len(errors) == 1 and errors[0]['line'] == 1
    assert 'firewall' not in engine.view(session)
    assert engine.view(session)['interfaces']['dummy']['dum0']['disable'] is True
    assert not controller.load(session, SET + 'action accept protocol udp', set_format=True, replace=True)
    assert set(engine.view(session)) == {'firewall'}


@pytest.mark.parametrize('suffix,expected', [
    ('action accept ', {'protocol', 'log', 'destination-port', '<Enter>'}),
    ('action accept pro', {'protocol'}),
    ('action accept protocol ', {'tcp', 'udp', 'icmp'}),
    ('action accept protocol tcp ', {'log', '<Enter>'}),
    ('log ', {'protocol', 'action', '<Enter>'}),
    ('description "WAN Interface" ', {'protocol', 'action', '<Enter>'}),
])
def test_completion_at_boundaries(controller, session, suffix, expected):
    result = controller.completion(SET + suffix, session, explicit=True)

    assert expected <= set(dict(result['candidates']))
    assert not session.mutations


def test_partial_values_quotes_and_bad_segments_do_not_complete_as_paths(controller, session):
    for suffix in ['protocol ', 'protocol invalid ', 'action accept d ', 'description "WAN ',
                   'action accept description "WAN', 'action accept description WAN\\']:
        result = controller.completion(SET + suffix, session, explicit=True)

        assert '<Enter>' not in dict(result['candidates'])
        assert 'action' not in dict(result['candidates'])

    assert controller.completion(SET + 'action accept pro', session)['extension'] == 'tocol'
    assert controller.completion(SET + 'action accept pro', session, space=True)['replacement'] == 'protocol'
    assert controller.completion(SET + 'action accept pro', session, tab=True)['replacement'] == 'protocol'

    controller.execute('se fire ipv4 forw filt ru 10 act accept pro tcp destination-port 22', session)

    assert len(session.mutations) == 3


@pytest.fixture
def nested(tmp_path):
    leaf = {'kind': 'leaf_node'}
    schema = Schema({'kind': 'node', 'children': {
        'objects': {'kind': 'tag_node', 'anchor': True, 'script': {'name': 'objects', 'priority': 10},
                    'children': {
                        'description': leaf,
                        'settings': {'kind': 'node', 'children': {'value': leaf}},
                        'member': {'kind': 'tag_node', 'anchor': True, 'children': {
                            'description': leaf, 'metric': {'kind': 'leaf_node', 'validators': {'checks': {'positive-integer': {'name': 'positive-integer'}}}}}},
                        'peer': {'kind': 'tag_node', 'validators': {'checks': {'ipv4-address': {'name': 'ipv4-address'}}}},
                    }},
        'plain': {'kind': 'tag_node', 'anchor': False, 'script': {'name': 'plain', 'priority': 20},
                  'children': {'value': leaf, 'flag': {'kind': 'leaf_node', 'valueless': True}}},
        'system': {'kind': 'node', 'children': {'value': leaf}},
    }})
    engine = Engine(schema, {name: LifecycleStub() for name in schema.owners}, Store(tmp_path))

    return Controller(engine), engine, engine.open('test', '/dev/pts/1')


def test_nested_anchors_keep_local_scope_until_an_outer_keyword(nested):
    controller, engine, session = nested
    controller.execute('set objects x settings value one member m description inner '
                       'description outer member m metric 10 peer 192.0.2.1 description final', session)

    assert engine.view(session)['objects']['x'] == {
        'settings': {'value': 'one'}, 'member': {'m': {'description': 'outer', 'metric': '10'}},
        'peer': {'192.0.2.1': {}}, 'description': 'final'}

    controller.execute('set objects x member empty', session)

    assert engine.view(session)['objects']['x']['member']['empty'] == {}

    controller.execute('set objects x settings', session)
    controller.execute('set objects x description replacement settings', session)

    assert engine.view(session)['objects']['x']['settings'] == {'value': 'one'}

    for command in ['set objects x member m metric bad description outer',
                    'set objects x member m unknown 192.0.2.2', 'set plain p value one flag']:
        before = list(session.mutations)

        with pytest.raises(RouterError):
            controller.execute(command, session)

        assert session.mutations == before

    assert '<Enter>' in dict(controller.completion('set objects x description ok settings ', session, explicit=True)['candidates'])
    assert 'description' in dict(controller.completion('set objects x settings value one ', session, explicit=True)['candidates'])
    assert 'peer' in dict(controller.completion('set objects x member m ', session, explicit=True)['candidates'])


def test_edit_never_escapes_root_and_nested_anchor_can_be_chosen_explicitly(nested):
    controller, engine, session = nested
    controller.execute('edit objects x member m', session)
    controller.execute('set metric 10 description inner', session)

    assert set(engine.view(session)['objects']['x']) == {'member'}

    controller.execute('top', session)
    controller.execute('edit objects x settings', session)

    with pytest.raises(RouterError):
        controller.execute('set value one description escaped', session)

    assert not controller.completion('set value one ', session)['candidates']
    assert 'settings' not in engine.view(session)['objects']['x']


def test_invalid_nested_tags_remain_navigable_but_not_executable(nested):
    controller, engine, session = nested
    line = 'set objects x peer invalid '

    assert 'description' in dict(controller.completion(line, session, explicit=True)['candidates'])
    assert '<Enter>' not in dict(controller.completion(line, session, explicit=True)['candidates'])
    assert controller.completion(line + 'des', session, tab=True)['replacement'] == 'description'

    member = engine.schema.root['children']['objects']['children']['member']
    member['validators'] = {'checks': {'positive-integer': {'name': 'positive-integer'}}}

    assert controller.completion('set objects x member invalid met', session)['replacement'] == 'metric'

    with pytest.raises(RouterError):
        controller.execute('set objects x member invalid metric 10', session)

    assert not session.mutations


def test_absent_anchor_and_unowned_paths_do_not_stage(nested):
    controller, engine, session = nested

    with pytest.raises(RouterError):
        controller.execute('set system value one value two', session)

    assert not session.mutations

    # Normal ownership checks apply to every expanded operation before appending.
    engine.schema.root['children']['objects'].pop('script')

    with pytest.raises(RouterError, match='not supported'):
        controller.execute('set objects x description one peer 192.0.2.1', session)

    assert not session.mutations


def test_anchor_completion_preserves_values_quoting_and_dynamic_suggestors(controller, engine, session):
    controller.execute(SET + 'description "WAN Interface"', session)
    line = SET + 'action accept description "W'
    result = controller.completion(line, session)

    assert result['extension'] == 'AN Interface"'
    assert result['replacement'] == "'WAN Interface'"
    assert result['start'] == line.index('"W')
    assert '<Enter>' not in dict(controller.completion(line, session, explicit=True)['candidates'])

    calls = []
    rule = engine.schema.resolve(RULE.split()).node
    rule['children']['source-address']['suggestors'] = [{'name': 'test-address'}]
    engine.schema.suggestors['test-address'] = lambda: calls.append(True) or ['192.0.2.1/32']
    line = SET + 'action accept source-address 192'

    assert controller.completion(line, session)['replacement'] == '192.0.2.1/32'
    assert len(calls) == 1
    assert controller.completion(line, session, explicit=True)['replacement'] == '192.0.2.1/32'
    assert len(calls) == 2


def test_later_anchor_under_unanchored_tag_and_childless_tag_completion(nested):
    controller, engine, session = nested
    engine.schema.root['children']['objects']['anchor'] = False
    controller.execute('set objects x member m metric 10 description inner', session)

    assert engine.view(session)['objects']['x']['member']['m'] == {'metric': '10', 'description': 'inner'}

    engine.schema.root['children']['objects']['anchor'] = True
    result = controller.completion('set objects x peer 192.0.2.1 ', session, explicit=True)

    assert {'description', 'member', '<Enter>'} <= set(dict(result['candidates']))

    result = controller.completion('set objects x description outer member ', session, explicit=True)

    assert dict(result['candidates'])['m'] == ''


@pytest.mark.parametrize('kind,anchor', [('node', 'true'), ('leaf_node', True), ('tag_node', 'true'),
                                         ('tag_node', 1), ('tag_node', None)])
def test_anchor_schema_flag_is_explicit_and_typed(kind, anchor):
    with pytest.raises(ValueError, match='anchor'):
        Schema({'kind': 'node', 'children': {'bad': {'kind': kind, 'anchor': anchor}}})


def test_nested_tag_continuation_preserves_local_shorthand(nested):
    controller, engine, session = nested
    controller.execute('set objects x member m me 10 peer 192.0.2.1', session)

    assert engine.view(session)['objects']['x'] == {
        'member': {'m': {'metric': '10'}}, 'peer': {'192.0.2.1': {}}}

    for mode in ({'space': True}, {'tab': True}, {}):
        result = controller.completion('set objects x member m me', session, **mode)

        assert result['replacement'] == 'metric'


@pytest.mark.parametrize('mode', [{}, {'explicit': True}, {'tab': True}, {'space': True}])
def test_consumed_leaves_do_not_complete_but_explicit_repeats_still_work(controller, session, mode):
    line = SET + 'act accept last-used '
    result = controller.completion(line, session, **mode)

    assert {'action', 'last-used'}.isdisjoint(dict(result['candidates']))
    assert 'protocol' in dict(result['candidates'])

    for prefix in ('act', 'action', 'last-u'):
        result = controller.completion(line + prefix, session, **mode)
        assert not result['extension']
        assert result['replacement'] is None

    # Discovery does not restrict the parser or reject deliberately repeated input.
    controller.execute(line + 'action drop last-used', session)
    assert controller.completion(line + 'action ', session)['candidates']
    assert 'action' in dict(controller.completion(SET, session)['candidates'])


def test_consumption_respects_multi_values_quotes_and_edit_context(controller, session):
    controller.execute('edit interfaces dummy dum0', session)
    line = 'set description "WAN address" disable address 192.0.2.1/24 '
    result = controller.completion(line, session, explicit=True)

    assert {'description', 'disable'}.isdisjoint(dict(result['candidates']))
    assert {'address', 'mtu', '<Enter>'} <= set(dict(result['candidates']))
    assert 'description' in dict(controller.completion('set ', session)['candidates'])
    assert 'description' in dict(controller.completion('set address 192.0.2.1/24 ', session)['candidates'])


def test_nested_consumption_is_scoped_to_full_paths(nested):
    controller, engine, session = nested
    base = 'set objects x settings value one member m description inner '
    names = dict(controller.completion(base, session)['candidates'])

    assert 'settings' not in names
    assert {'member', 'peer'} <= set(names)
    assert 'description' not in names  # Consumed local option shadows the outer name.

    same = dict(controller.completion(base + 'member m ', session)['candidates'])
    other = dict(controller.completion(base + 'member n ', session)['candidates'])
    assert 'description' not in same  # Local child takes precedence over anchor child.
    assert 'metric' in same
    assert 'description' in other

    settings = engine.schema.root['children']['objects']['children']['settings']
    settings['children']['other'] = {'kind': 'leaf_node'}
    assert 'settings' in dict(controller.completion(base, session)['candidates'])
    assert set(dict(controller.completion(base + 'settings ', session)['candidates'])) == {'other'}


def test_address_tags_remain_available_and_masks_are_per_address(controller, session):
    base = SET + 'source-address 192.0.2.1 mask 255.255.255.0 '
    assert 'source-address' in dict(controller.completion(base, session)['candidates'])
    assert 'mask' not in dict(controller.completion(base + 'source-address 192.0.2.1 ', session)['candidates'])
    assert 'mask' in dict(controller.completion(base + 'source-address 192.0.2.2 ', session)['candidates'])


@pytest.mark.parametrize('root', ['', 'firewall global-options', 'firewall global-options state-policy'])
def test_node_anchor_stages_all_states_with_edit_context(controller, engine, session, root):
    if root:
        controller.execute('edit ' + root, session)

    path = 'firewall global-options state-policy'.removeprefix(root).strip()
    controller.execute(f'set {path} established action accept related action accept invalid action drop', session)

    assert engine.view(session)['firewall']['global-options']['state-policy'] == {
        'established': {'action': 'accept'},
        'related': {'action': 'accept'},
        'invalid': {'action': 'drop'},
    }
    assert len(session.mutations) == 3


@pytest.mark.parametrize('mode', [{}, {'tab': True}, {'space': True}, {'explicit': True}])
def test_node_anchor_completion_returns_to_unused_states(controller, session, mode):
    line = 'set firewall global-options state-policy established action accept '
    candidates = dict(controller.completion(line, session, **mode)['candidates'])

    assert {'related', 'invalid'} <= candidates.keys()
    if mode.get('explicit'):
        assert '<Enter>' in candidates
    assert {'established', 'action'}.isdisjoint(candidates)
    assert controller.completion(line + 're', session, **mode)['replacement'] == 'related'
    assert controller.completion(line + 'related act', session, **mode)['replacement'] == 'action'


@pytest.mark.parametrize('suffix', ['related action return', 'unknown action accept', 'related action'])
def test_invalid_node_anchor_suffix_does_not_stage_partial_changes(controller, session, suffix):
    with pytest.raises(RouterError):
        controller.execute('set firewall global-options state-policy established action accept ' + suffix, session)

    assert not session.mutations


def test_node_anchor_abbreviations_and_deeper_edit_boundary(controller, engine, session):
    controller.execute('set firewall global-options state-policy est act accept rel act drop', session)
    assert engine.view(session)['firewall']['global-options']['state-policy'] == {
        'established': {'action': 'accept'}, 'related': {'action': 'drop'},
    }

    controller.execute('edit firewall global-options state-policy established', session)
    before = list(session.mutations)
    with pytest.raises(RouterError):
        controller.execute('set action drop related action accept', session)

    assert session.mutations == before
    assert 'related' not in dict(controller.completion('set action accept ', session)['candidates'])


def test_normal_node_anchor_supports_nested_tags_multi_values_and_flags(nested):
    controller, engine, session = nested
    objects = engine.schema.root['children']['objects']
    objects['kind'] = 'node'
    objects['children']['flag'] = {'kind': 'leaf_node', 'valueless': True}
    objects['children']['values'] = {'kind': 'leaf_node', 'multi': True}
    engine.schema = Schema(engine.schema.root)

    controller.execute('set objects description "Two words" member m metric 10 '
                       'peer 192.0.2.1 values one flag values two settings value final', session)

    assert engine.view(session)['objects'] == {
        'description': 'Two words', 'member': {'m': {'metric': '10'}},
        'peer': {'192.0.2.1': {}}, 'values': ['one', 'two'], 'flag': True,
        'settings': {'value': 'final'},
    }


def test_nested_node_anchor_keeps_local_options_and_returns_to_outer_object(nested):
    controller, engine, session = nested
    settings = engine.schema.root['children']['objects']['children']['settings']
    settings['anchor'] = True
    settings['children'].update({
        'description': {'kind': 'leaf_node'},
        'member': {'kind': 'tag_node', 'children': {'metric': {'kind': 'leaf_node'}}},
    })

    controller.execute('set objects x settings value one description inner member empty '
                       'peer 192.0.2.1 description outer', session)
    assert engine.view(session)['objects']['x'] == {
        'settings': {'value': 'one', 'description': 'inner', 'member': {'empty': {}}},
        'peer': {'192.0.2.1': {}}, 'description': 'outer',
    }

    # A local prefix wins over an outer option; consumed paths remain hidden.
    command = 'set objects x settings value one '
    assert controller.completion(command + 'des', session)['replacement'] == 'description'
    choices = dict(controller.completion(command, session)['candidates'])
    assert 'value' not in choices
    assert {'description', 'member', 'peer'} <= choices.keys()
