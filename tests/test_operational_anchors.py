"""Retained operational anchor traversal, placeholders and terminal execution."""

import itertools
import json
import sys
from types import SimpleNamespace

import pytest

from nvyr.cli import CLI, TreeSuggestion
from nvyr.errors import RouterError
from nvyr.lexer import lex
from nvyr.schema import Schema


SCRIPT = '''from nvyr import opmode
import json
@opmode.command
def probe(destination, line=None):
    return json.dumps(dict(destination=destination, line=line))
opmode.run()
'''


def probe_schema(*, stream=False):
    children = {}

    for name in ('source-address', 'interface', 'interval', 'size', 'ttl', 'count', 'numeric', 'description'):
        node = {'kind': 'leaf_node', 'description': name}

        if name == 'numeric':
            node['valueless'] = True
        else:
            node['hints'] = {'value': 'Value for ' + name}

        if name in ('size', 'ttl', 'count'):
            node['validators'] = {'checks': {'regex': {'name': 'regex', 'args': {'pattern': '[0-9]+'}}}}

        children[name] = node

    return Schema({'kind': 'node', 'children': {'ping': {
        'kind': 'tag_node', 'anchor': True, 'description': 'Test probe (no packets sent)',
        'validators': {'checks': {'ipv4-address': {'name': 'ipv4-address'}}},
        'command': {'argv': [sys.executable, '-c', SCRIPT, 'probe', '@2', '--line', '@line'], 'stream': stream},
        'children': children}}})


@pytest.fixture
def probe(controller):
    controller.operational = probe_schema()
    return controller


def test_anchor_preserves_order_independent_traversal_and_original_input(probe, session):
    orders = [
        'source-address 10.0.0.1 interface eth0 interval .01 size 1000 ttl 15 count 1 numeric',
        'count 1 numeric size 1000 interface eth0 ttl 15 interval .01 source-address 10.0.0.1']

    for suffix in orders:
        for prefix, mode in [('ping ', None), ('run ping ', session)]:
            line = prefix + '1.1.1.1 ' + suffix

            assert json.loads(probe.execute(line, mode)['text']) == dict(destination='1.1.1.1', line=line)

    assert not session.mutations


def test_all_parameter_permutations_and_abbreviations(probe):
    for items in itertools.permutations(('count 1', 'num', 'siz 1000', 'interf eth0')):
        cursor = probe.operational.operational(lex('pi 1.1.1.1 ' + ' '.join(items)))

        assert cursor.node is probe.operational.root['children']['ping']
        assert cursor.value == '1.1.1.1'


@pytest.mark.parametrize('suffix', ['count', 'count invalid', 'i eth0', 'unknown value', 'numeric extra'])
def test_malformed_or_ambiguous_suffix_never_executes(probe, monkeypatch, suffix):
    monkeypatch.setattr('nvyr.controller.cmd', lambda *a, **k: pytest.fail('Invalid command executed'))

    with pytest.raises(RouterError):
        probe.execute('ping 1.1.1.1 ' + suffix)

    assert '<Enter>' not in dict(probe.completion('ping 1.1.1.1 ' + suffix, explicit=True)['candidates'])


def test_quotes_keyword_values_and_dash_values(probe):
    for value in ['"WAN interface | numeric"', 'numeric', '"--numeric"', '""']:
        text = 'ping 1.1.1.1 description ' + value + ' count 2'

        assert json.loads(probe.execute(text)['text'])['line'] == text


def test_tag_and_node_anchors(probe):
    assert json.loads(probe.execute('ping 1.1.1.1')['text'])['destination'] == '1.1.1.1'

    node = probe.operational.root['children']['ping']
    node.update(kind='node', command={'argv': [sys.executable, '-c', SCRIPT, 'probe', '127.0.0.1', '--line', '@line']})
    probe.operational = Schema(probe.operational.root)

    assert json.loads(probe.execute('ping numeric count 2')['text']) == dict(destination='127.0.0.1', line='ping numeric count 2')


def test_normal_nodes_and_nested_tags_use_same_boundary_rules(probe):
    node = probe.operational.root['children']['ping']
    node['children']['format'] = {'kind': 'node', 'children': {
        'description': {'kind': 'leaf_node'}}}
    node['children']['via'] = {'kind': 'tag_node', 'children': {
        'size': {'kind': 'leaf_node'}}}
    probe.operational = Schema(probe.operational.root)
    line = 'ping 1.1.1.1 via eth0 size 100 format description test numeric'

    assert json.loads(probe.execute(line)['text'])['line'] == line

    with pytest.raises(RouterError, match='incomplete'):
        probe.execute('ping 1.1.1.1 format')


def test_help_tab_and_fish_suggestions(probe, session):
    from prompt_toolkit.document import Document

    for prefix, mode in [('ping ', None), ('run ping ', session)]:
        for suffix in ('', 'count 2 ', 'numeric count 2 '):
            result = probe.completion(prefix + '1.1.1.1 ' + suffix, mode, explicit=True)

            consumed = {'count', 'numeric'} & set(suffix.split())
            assert {'count', 'numeric', 'size', '<Enter>'} - consumed <= set(dict(result['candidates']))
            assert consumed.isdisjoint(dict(result['candidates']))

        assert probe.completion(prefix + '1.1.1.1 numeric si', mode)['replacement'] == 'size'
        assert probe.completion(prefix + '1.1.1.1 numeric si', mode, space=True)['replacement'] == 'size'
        assert ('value', 'Value for count') in probe.completion(prefix + '1.1.1.1 count', mode, explicit=True)['hints']

    client = SimpleNamespace(request=lambda operation, **kw: probe.completion(kw['text']))
    cli = CLI(client, emit=lambda _: None)
    document = Document('ping 1.1.1.1 numeric sour')

    assert TreeSuggestion(cli).get_suggestion(None, document).text == 'ce-address'
    assert TreeSuggestion(cli).get_suggestion(None, Document('ping 1.1.1.1 numeric num')) is None
    assert probe.completion('ping 1.1.1.1 count 2 cou', tab=True)['replacement'] is None
    assert 'count' in dict(probe.completion('ping bad numeric ', explicit=True)['candidates'])

    with pytest.raises(RouterError):
        probe.execute('ping bad numeric')


def test_stream_event_resolves_for_daemon_and_pipes_are_rejected(probe, session):
    probe.operational = probe_schema(stream=True)
    line = 'ping 1.1.1.1 numeric count 2'
    event = probe.execute(line)

    assert event['event'] == 'command' and event['timeout'] is None
    assert event['argv'][-3:] == ['1.1.1.1', '--line', line]
    assert probe.execute('run ping 1.1.1.1 numeric', session)['event'] == 'command'

    with pytest.raises(RouterError, match='not supported on streaming commands'):
        probe.execute('ping 1.1.1.1 numeric | count')

    output = []
    client = SimpleNamespace(request=lambda *a, **kw: {'event': 'command', 'returncode': 7})
    cli = CLI(client, emit=output.append)
    cli.execute_line(line)

    assert cli.returncode == 7 and output == []
