"""Help ordering is separate from candidate discovery and insertion."""

from copy import deepcopy
from types import SimpleNamespace

import pytest
from prompt_toolkit.document import Document
from prompt_toolkit.keys import Keys

from nvyr.cli import CLI, TreeSuggestion, completion_rows
from nvyr.errors import SessionExpiredError
from nvyr.helpers.suggestors import Suggestion
from nvyr.schema import Cursor, Schema


@pytest.mark.parametrize('key', ['?', Keys.ControlI])
def test_completion_listings_capture_each_prompt_without_changing_input(monkeypatch, key):
    """Deferred help keeps its original command, even after the user edits again."""
    callbacks, displayed, requests = [], [], []
    monkeypatch.setattr('nvyr.cli.run_in_terminal', callbacks.append)
    monkeypatch.setattr('nvyr.cli.print_formatted_text', displayed.append)
    monkeypatch.setattr('nvyr.cli.getpass.getuser', lambda: 'nvyr')
    monkeypatch.setattr('nvyr.cli.socket.gethostname', lambda: 'router')

    def request(operation, **arguments):
        requests.append((operation, arguments))
        return {'display': True, 'candidates': [('not', 'Exclude the following value')]}

    cli = CLI(SimpleNamespace(request=request))
    cli.mode = 'normal'
    handler = cli.bindings().get_bindings_for_keys((key,))[0].handler
    address = Document('set firewall ipv4 forward filter rule 10 source-address ')
    # Help resolves the cursor prefix, but its context shows the entire editable command.
    port = Document('set firewall ipv4 forward filter rule 10 source-port 443', cursor_position=52)
    buffer = SimpleNamespace(document=address)

    handler(SimpleNamespace(current_buffer=buffer))
    assert buffer.document == address
    buffer.document = port
    handler(SimpleNamespace(current_buffer=buffer))
    assert buffer.document == port

    buffer.document = Document('show interfaces')
    cli.mode = None
    for callback in callbacks:
        callback()

    assert len(displayed) == 2
    assert displayed[0].startswith('nvyr@router# ' + address.text + '\n\nPossible completions:\n')
    assert displayed[1].startswith('nvyr@router# ' + port.text + '\n\nPossible completions:\n')
    assert all(output.endswith('\n') for output in displayed)
    assert [operation for operation, _ in requests] == ['complete', 'complete']
    assert requests[1][1]['text'] == port.text_before_cursor
    assert buffer.document.text == 'show interfaces'


@pytest.mark.parametrize('key, expire_on_request', [
    ('?', 1),
    (Keys.ControlI, 1),
    (Keys.ControlI, 2),
])
def test_expired_session_help_displays_error_without_changing_input(monkeypatch, key, expire_on_request):
    message = 'Configuration session expired. Exit configuration mode and open a new session.'
    requests = []
    callbacks = []
    output = []

    def request(operation, **arguments):
        requests.append((operation, arguments))

        if len(requests) == expire_on_request:
            raise SessionExpiredError(message)

        return {}

    # Terminal output runs after the key handler returns.
    monkeypatch.setattr('nvyr.cli.run_in_terminal', callbacks.append)
    client = SimpleNamespace(request=request)
    cli = CLI(client, emit=output.append)
    cli.mode = 'normal'
    document = Document('set system host-name router', cursor_position=8)
    buffer = SimpleNamespace(document=document)
    handler = cli.bindings().get_bindings_for_keys((key,))[0].handler

    handler(SimpleNamespace(current_buffer=buffer))

    assert len(callbacks) == 1
    callbacks[0]()

    assert output == [message]
    assert buffer.document == document
    assert cli.mode == 'normal' and not cli.done
    assert len(requests) == expire_on_request
    assert requests[-1][1]['text'] == document.text_before_cursor


def test_interface_help_order_and_question_key(controller, monkeypatch):
    controller.operational.suggestors['interfaces'] = lambda prefix='': [
        Suggestion(name, '') for name in ['pimreg', 'eth2', 'lo', 'dum0', 'eth1', 'pim6reg', 'eth0']
        if name.startswith(prefix)]
    result = controller.completion('show interfaces ', explicit=True)
    before = deepcopy(result)
    rows = completion_rows(result)

    assert [name for name, _ in rows] == [
        '<Enter>', '<interface>', 'bridge', 'detail', 'ethernet', 'hardware-statistics',
        'offload', 'queues', 'statistics', 'transceiver',
        'dum0', 'eth0', 'eth1', 'eth2', 'lo', 'pim6reg', 'pimreg']
    assert rows[1] == ('<interface>', 'Interface name (for example eth0)')
    assert all(not description for _, description in rows[10:])
    assert result == before
    assert 'interface' not in dict(result['candidates'])

    displayed = []
    monkeypatch.setattr('nvyr.cli.run_in_terminal', lambda function: function())
    monkeypatch.setattr('nvyr.cli.print_formatted_text', displayed.append)
    client = SimpleNamespace(request=lambda operation, **kw: controller.completion(kw['text'], explicit=True))
    cli = CLI(client, emit=lambda _: None)
    handler = cli.bindings().get_bindings_for_keys(('?',))[0].handler
    handler(SimpleNamespace(current_buffer=SimpleNamespace(document=Document('show interfaces '))))

    listing = displayed[0].split('Possible completions:\n', 1)[1]
    assert [line.split()[0] for line in listing.splitlines()] == [name for name, _ in rows]

    assert controller.completion('show interfaces det', tab=True)['replacement'] == 'detail'

    client.request = lambda operation, **kw: controller.completion(kw['text'])

    assert TreeSuggestion(cli).get_suggestion(None, Document('show interfaces det')).text == 'ail'


def test_choice_hint_and_suggestor_provenance_preserves_candidates():
    node = {'kind': 'leaf_node', 'choices': {'zebra': 'Declared choice', 'alpha': 'First choice'},
            'suggestors': [{'name': 'test'}],
            'hints': {'z-format': 'Another value format', 'middle': 'Value format'}}
    schema = Schema(node, suggestors={'test': lambda: ['zebra', 'zulu', 'aardvark']})
    suggested = set()
    candidates = schema.candidates(Cursor(node, ('value',), expect='value'), '', {}, suggested=suggested)

    assert suggested == {'zulu', 'aardvark'}
    assert candidates == schema.candidates(Cursor(node, ('value',), expect='value'), '', {})

    rows = completion_rows({'candidates': candidates, 'hints': list(node['hints'].items()),
                            'suggested': list(suggested)})

    assert [name for name, _ in rows] == ['<middle>', '<z-format>', 'alpha', 'zebra', 'aardvark', 'zulu']
    assert dict(rows)['zebra'] == 'Declared choice'


@pytest.mark.parametrize('key', ['?', Keys.ControlI])
def test_address_hints_are_bracketed_in_terminal_help(controller, session, monkeypatch, key):
    line = 'set interfaces dummy dum0 address '
    displayed = []
    monkeypatch.setattr('nvyr.cli.run_in_terminal', lambda function: function())
    monkeypatch.setattr('nvyr.cli.print_formatted_text', displayed.append)
    client = SimpleNamespace(request=lambda operation, **kw: controller.completion(
        kw['text'], session, explicit=kw.get('explicit', False), tab=kw.get('tab', False)))
    cli = CLI(client, emit=lambda _: None)
    handler = cli.bindings().get_bindings_for_keys((key,))[0].handler
    handler(SimpleNamespace(current_buffer=SimpleNamespace(document=Document(line))))

    listing = displayed[0].split('Possible completions:\n', 1)[1]
    names = [row.split()[0] for row in listing.splitlines()]
    assert names == ['<x.x.x.x/x>', '<x:x:x:x:x:x/x>']
    assert TreeSuggestion(cli).get_suggestion(None, Document(line)) is None


def test_help_preserves_numeric_completion_order():
    node = {'kind': 'tag_node', 'choices': {'2': 'Two', '10': 'Ten'}, 'hints': {'number': 'Numeric value'}}
    schema = Schema(node)
    candidates = schema.candidates(Cursor(node, expect='tag'), '', {})

    assert [name for name, _ in candidates] == ['2', '10']

    rows = completion_rows({'candidates': candidates, 'hints': list(node['hints'].items())})

    assert [name for name, _ in rows] == ['<number>', '2', '10']


def test_numeric_and_word_suggestions_use_shared_sorting_without_mutation():
    values = ['zebra', '10', '2', 'alpha', '001', '1', '0']
    result = {'candidates': [(value, 'Discovered value') for value in values] +
                           [('<Enter>', 'Execute'), ('detail', 'Schema node')],
              'suggested': values, 'hints': [('number', 'Value format')]}
    before = deepcopy(result)

    assert [name for name, _ in completion_rows(result)] == [
        '<Enter>', '<number>', 'detail', '0', '1', '001', '2', '10', 'alpha', 'zebra']
    assert result == before


@pytest.mark.parametrize('key', ['?', Keys.ControlI])
def test_history_numbers_are_numeric_in_terminal_help(controller, engine, session, monkeypatch, key):
    for number in range(12):
        controller.execute(f'set system host-name router{number}', session)
        engine.commit(session)

    displayed = []
    monkeypatch.setattr('nvyr.cli.run_in_terminal', lambda function: function())
    monkeypatch.setattr('nvyr.cli.print_formatted_text', displayed.append)
    client = SimpleNamespace(request=lambda operation, **kw: controller.completion(
        kw['text'], session, explicit=kw.get('explicit', False), tab=kw.get('tab', False)))
    cli = CLI(client, emit=lambda _: None)
    handler = cli.bindings().get_bindings_for_keys((key,))[0].handler
    handler(SimpleNamespace(current_buffer=SimpleNamespace(document=Document('compare '))))

    listing = displayed[0].split('Possible completions:\n', 1)[1]
    names = [line.split()[0] for line in listing.splitlines()]
    assert names == ['<Enter>', '<revisions>', 'saved'] + [str(number) for number in range(13)]


def test_execution_help_survives_candidate_display_limit(controller):
    controller.operational.suggestors['interfaces'] = lambda: [f'eth{number}' for number in range(300)]
    result = controller.completion('show interfaces ', explicit=True)

    assert len(result['candidates']) == 256 and result['total'] > 256
    assert completion_rows(result)[0][0] == '<Enter>'


@pytest.mark.parametrize('key', ['?', Keys.ControlI])
def test_consumed_anchor_options_are_hidden_in_terminal_help(controller, session, monkeypatch, key):
    line = 'set firewall ipv4 forward filter rule 10 action accept last-used '
    displayed = []
    monkeypatch.setattr('nvyr.cli.run_in_terminal', lambda function: function())
    monkeypatch.setattr('nvyr.cli.print_formatted_text', displayed.append)
    client = SimpleNamespace(request=lambda operation, **kw: controller.completion(
        kw['text'], session, explicit=kw.get('explicit', False), tab=kw.get('tab', False)))
    cli = CLI(client, emit=lambda _: None)
    handler = cli.bindings().get_bindings_for_keys((key,))[0].handler
    handler(SimpleNamespace(current_buffer=SimpleNamespace(document=Document(line))))

    listing = displayed[0].split('Possible completions:\n', 1)[1]
    names = [row.split()[0] for row in listing.splitlines()]
    assert names[0] == '<Enter>'
    assert {'action', 'last-used'}.isdisjoint(names)
    assert 'protocol' in names
    assert TreeSuggestion(cli).get_suggestion(None, Document(line + 'act')) is None
    assert TreeSuggestion(cli).get_suggestion(None, Document(line + 'pro')).text == 'tocol'


@pytest.mark.parametrize('key', ['?', Keys.ControlI])
def test_nested_anchor_help_groups_local_parameters_last(controller, session, monkeypatch, key):
    line = 'set firewall ipv4 forward filter rule 10 limit rate packets 10/s '
    result = controller.completion(line, session, explicit=True)
    before = deepcopy(result)
    rows = completion_rows(result)
    labels = [name for name, _ in rows]

    assert labels[0] == '<Enter>'
    assert labels.index('Current context: limit') < labels.index('burst')
    assert labels.index('Other rule parameters:') < labels.index('action') < labels.index('Current context: limit')
    assert labels.index('Current context: limit') < labels.index('timeout')
    # The rate node still offers its other child; consumed leaves remain hidden.
    assert 'rate' in labels
    assert result == before
    assert set(dict(result['candidates'])) == set(labels) - {
        '', 'Current context: limit', 'Other rule parameters:',
    }

    displayed = []
    monkeypatch.setattr('nvyr.cli.run_in_terminal', lambda function: function())
    monkeypatch.setattr('nvyr.cli.print_formatted_text', displayed.append)
    client = SimpleNamespace(request=lambda operation, **kw: controller.completion(
        kw['text'], session, explicit=kw.get('explicit', False), tab=kw.get('tab', False)))
    cli = CLI(client, emit=lambda _: None)
    handler = cli.bindings().get_bindings_for_keys((key,))[0].handler
    handler(SimpleNamespace(current_buffer=SimpleNamespace(document=Document(line))))

    assert '\n\nCurrent context: limit' in displayed[0]
    assert '\n\nOther rule parameters:' in displayed[0]
    assert controller.completion(line + 'bur', session, tab=True)['replacement'] == 'burst'
    assert controller.completion(line + 'pro', session, tab=True)['replacement'] == 'protocol'
    assert TreeSuggestion(cli).get_suggestion(None, Document(line + 'bur')).text == 'st'


def test_help_only_groups_when_outer_parameters_are_offered(controller, session):
    prefix = 'set firewall ipv4 forward filter rule 10 '
    for command in [prefix, prefix + 'limit rate ', prefix + 'limit rate packets 10/s bur']:
        result = controller.completion(command, session, explicit=True)
        assert result['groups'] == []
        assert not any('parameters:' in name for name, _ in completion_rows(result))

    controller.execute('edit firewall ipv4 forward filter rule 10 limit', session)
    result = controller.completion('set rate packets 10/s ', session, explicit=True)
    assert result['groups'] == []
    assert 'action' not in dict(result['candidates'])


def test_nested_tag_help_uses_node_name_not_instance(controller, session):
    result = controller.completion(
        'set firewall ipv4 forward filter rule 123 source-address 192.0.2.1 ', session, explicit=True)
    labels = [name for name, _ in completion_rows(result)]

    assert labels.index('Current context: source-address') < labels.index('mask')
    assert labels.index('Other rule parameters:') < labels.index('Current context: source-address')
    assert not any('123' in name for name in labels)


def test_grouped_help_keeps_joinable_in_local_context(controller, session):
    result = controller.completion(
        'set firewall ipv4 forward filter rule 10 limit per source-address ', session, explicit=True)
    groups = result['groups']
    assert [group['name'] for group in groups] == ['per', 'limit', 'rule']
    assert groups[0]['candidates'] == ['and']
    assert 'and' not in groups[1]['candidates'] + groups[2]['candidates']


@pytest.mark.parametrize('key', ['?', Keys.ControlI])
@pytest.mark.parametrize('value', ['confirmed', 'confirmed and snat', 'not confirmed and snat'])
def test_joinable_leaf_help_keeps_and_in_last_context(controller, session, monkeypatch, key, value):
    line = 'set firewall ipv4 input filter rule 10 action accept connection status ' + value + ' '
    result = controller.completion(line, session, explicit=True)
    original = deepcopy(result)
    labels = [name for name, _ in completion_rows(result)]

    assert labels[:3] == ['<Enter>', '', 'Other rule parameters:']
    assert labels[-3:] == ['', 'Current context: status', 'and']
    assert labels.index('Other rule parameters:') < labels.index('Other connection parameters:')
    assert 'action' not in labels
    assert 'status' in labels
    assert result == original

    displayed = []
    monkeypatch.setattr('nvyr.cli.run_in_terminal', lambda function: function())
    monkeypatch.setattr('nvyr.cli.print_formatted_text', displayed.append)
    client = SimpleNamespace(request=lambda operation, **kw: controller.completion(
        kw['text'], session, explicit=kw.get('explicit', False), tab=kw.get('tab', False)))
    cli = CLI(client, emit=lambda _: None)
    handler = cli.bindings().get_bindings_for_keys((key,))[0].handler
    handler(SimpleNamespace(current_buffer=SimpleNamespace(document=Document(line))))

    assert displayed[0].index('Current context: status') < displayed[0].index('Join another value')
    assert displayed[0].index('Other rule parameters:') < displayed[0].index('Current context: status')
    assert controller.completion(line + 'an', session, tab=True)['replacement'] == 'and'
    assert TreeSuggestion(cli).get_suggestion(None, Document(line + 'an')).text == 'd'

    # After `and`, only the next value is accepted, with its normal hints and choices.
    pending = controller.completion(line + 'and ', session, explicit=True)
    assert pending['groups'] == []
    assert completion_rows(pending)[0][0] == '<flag>'
    assert 'confirmed' not in dict(pending['candidates'])
    assert 'protocol' not in dict(pending['candidates'])

    controller.execute(line + 'counter', session)


def test_joinable_leaf_grouping_respects_edit_root_and_prefix(controller, session):
    controller.execute('edit firewall ipv4 input filter rule 10', session)
    line = 'set connection status confirmed '
    result = controller.completion(line, session, explicit=True)

    assert [group['name'] for group in result['groups']] == ['status', 'connection', 'rule']
    assert controller.completion(line + 'pro', session, tab=True)['replacement'] == 'protocol'
    assert controller.completion(line + 'pro', session, explicit=True)['groups'] == []


def test_grouped_help_preserves_hints_choices_and_suggestions_order():
    result = {
        'candidates': [('zebra', 'Choice'), ('eth10', ''), ('alpha', 'Choice'),
                       ('eth2', ''), ('outer', 'Outer parameter'), ('<Enter>', 'Execute')],
        'hints': [('interface', 'Interface name')],
        'suggested': ['eth10', 'eth2'],
        'groups': [
            {'name': 'inner', 'current': True, 'candidates': ['zebra', 'eth10', 'alpha', 'eth2']},
            {'name': 'parent', 'current': False, 'candidates': ['outer']},
        ],
    }

    assert [name for name, _ in completion_rows(result)] == [
        '<Enter>', '', 'Other parent parameters:', 'outer',
        '', 'Current context: inner', '<interface>', 'alpha', 'zebra', 'eth10', 'eth2',
    ]


def test_three_anchor_levels_and_shadowed_names_keep_nearest_context():
    leaf = {'kind': 'leaf_node'}
    schema = Schema({'kind': 'node', 'children': {
        'outer': {'kind': 'node', 'anchor': True, 'children': {
            'shared': leaf,
            'outside': leaf,
            'middle': {'kind': 'node', 'anchor': True, 'children': {
                'shared': leaf,
                'between': leaf,
                'inner': {'kind': 'node', 'anchor': True, 'children': {
                    'shared': leaf,
                    'inside': leaf,
                }},
            }},
        }},
    }})
    state = schema.set_cursor()
    for token in ['outer', 'middle', 'inner']:
        state = schema.advance_set(state, token)

    cursor = state.completion()
    candidates = schema.candidates(cursor, '', {})
    groups = state.completion_groups(cursor, candidates)

    assert [group['name'] for group in groups] == ['inner', 'middle', 'outer']
    assert 'shared' in groups[0]['candidates']
    assert 'shared' not in groups[1]['candidates'] + groups[2]['candidates']
    assert 'between' in groups[1]['candidates']
    assert 'outside' in groups[2]['candidates']

    labels = [name for name, _ in completion_rows({'candidates': candidates, 'groups': groups})]
    assert labels.index('Other outer parameters:') < labels.index('Other middle parameters:')
    assert labels.index('Other middle parameters:') < labels.index('Current context: inner')


def test_connection_tuple_help_places_current_context_nearest_prompt(controller, session):
    line = 'set firewall ipv4 forward filter rule 10 connection original '
    result = controller.completion(line, session, explicit=True)
    labels = [name for name, _ in completion_rows(result)]

    assert labels[0] == '<Enter>'
    assert labels.index('Other rule parameters:') < labels.index('Other connection parameters:')
    assert labels.index('Other connection parameters:') < labels.index('Current context: original')
    assert labels.index('Current context: original') < labels.index('source-address')
    assert labels[-1] == 'zone'


def test_modify_help_excludes_shadowed_rule_connection(controller, session):
    line = 'set firewall ipv4 forward filter rule 10 modify '
    result = controller.completion(line, session, explicit=True)
    groups = {group['name']: group['candidates'] for group in result['groups']}

    assert 'connection' not in dict(result['candidates'])
    assert 'connection-mark' in groups['modify']
    assert 'action' in groups['rule']
    assert controller.completion(line + 'conn', session, tab=True)['replacement'] == 'connection-mark'

    completed = controller.completion(line + 'connection-mark 1 ', session, explicit=True)
    assert 'connection' not in dict(completed['candidates'])

    rule = controller.completion('set firewall ipv4 forward filter rule 10 ', session, explicit=True)
    assert 'connection' in dict(rule['candidates'])


@pytest.mark.parametrize('kind', ['node', 'tag_node'])
def test_nested_help_excludes_ancestor_prefixes_of_local_parameters(kind):
    leaf = {'kind': 'leaf_node'}
    schema = Schema({'kind': 'node', 'children': {
        'outer': {'kind': 'node', 'anchor': True, 'children': {
            'connection': leaf,
            'packet': leaf,
            'outside': leaf,
            'inner': {'kind': kind, 'children': {
                'connection-mark': leaf,
                'packet-mark': leaf,
                'packet-type': leaf,
            }, **({'anchor': True} if kind == 'node' else {})},
        }},
    }})
    state = schema.set_cursor()
    tokens = ['outer', 'inner', 'test'] if kind == 'tag_node' else ['outer', 'inner']
    for token in tokens:
        state = schema.advance_set(state, token)

    cursor = state.completion()
    candidates = schema.candidates(cursor, '', {})
    names = dict(candidates)

    assert 'connection' not in names
    assert 'packet' not in names
    assert 'outside' in names
    assert {'connection-mark', 'packet-mark', 'packet-type'} <= names.keys()
    assert state.completion_groups(cursor, candidates)
