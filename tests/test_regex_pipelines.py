"""Regex filters and safe rejection of modifiers on terminal commands."""

import pytest

from nvyr.cli import CLI
from nvyr.errors import ParseError
from nvyr.lexer import lex, quote, split_pipeline
from nvyr.pipeline import Output, Pipelines
from nvyr.protocol import Client
from nvyr.schema import Schema
from tests.test_integration import daemon


@pytest.mark.parametrize('pattern,text,expected', [
    ('(0.0.0.0|10.0.101)', '0.0.0.0/0\n10.0.101.12/24\n192.0.2.0/24\n', '0.0.0.0/0\n10.0.101.12/24\n'),
    (r'^10\.0\.[0-9]{1,3}\.\d+/\d+$', '10.0.101.0/24\nvia 10.0.101.0/24\n', '10.0.101.0/24\n'),
    ('ab+c?', 'ab\nabbc\na\n', 'ab\nabbc\n'),
    ('x.*y', 'xy\nx123y\nx123\n', 'xy\nx123y\n'),
    ('^$', 'first\n\nlast\n', '\n'),
    ('route$', 'route\r\nrouteX\nroute', 'route\r\nroute'),
    (r'\bvia\s+\S+', 'via eth0\nnotvia eth1\n', 'via eth0\n'),
    ('', 'one\ntwo', 'one\ntwo'),
    ('absent', 'one\ntwo', ''),
])
def test_regex_search_features_and_preserved_line_endings(pattern, text, expected):
    pipelines = Pipelines(Schema.bundled())

    for name in ('match', 'except'):
        parsed = pipelines.parse(split_pipeline('show | ' + name + ' ' + quote(pattern))[1:])
        output = pipelines.execute(Output(text), parsed).text

        if name == 'match':
            assert output == expected
        else:
            assert output == ''.join(line for line in text.splitlines(keepends=True)
                                     if line not in expected.splitlines(keepends=True))


def test_double_quoted_regex_escapes_and_literal_pipe():
    stages = split_pipeline(r'show ip route | match "(0.0.0.0|10.0.101)" | except "\.12/"')

    assert len(stages) == 3
    assert stages[1][1].value == '(0.0.0.0|10.0.101)'
    assert stages[2][1].value == r'\.12/'
    assert lex(r'"\d+\s\b\[\]\$"')[0].value == r'\d+\s\b\[\]\$'
    assert lex(r'"quote\" and slash\\"')[0].value == 'quote" and slash\\'
    assert lex(r'unquoted\ space')[0].value == 'unquoted space'
    assert lex(r"'\.12/'")[0].value == r'\.12/'

    pipelines = Pipelines(Schema.bundled())
    result = pipelines.execute(Output('a|b\naXb\n'), pipelines.parse(
        split_pipeline(r'show | match "a\|b"')[1:]))

    assert result.text == 'a|b\n'


@pytest.mark.parametrize('prefix', ['', 'run '])
def test_chained_filters_through_controller(controller, session, monkeypatch, prefix):
    monkeypatch.setattr('nvyr.controller.cmd', lambda *args, **kwargs:
                        '0.0.0.0/0\n10.0.101.12/24\n10.0.101X12/24\n10.0.101.1/24\n192.0.2.0/24\n')
    mode = session if prefix else None
    command = prefix + 'show ip route'

    assert controller.execute(command + ' | match "(0.0.0.0|10.0.101)" | count', mode)['text'] == '4\n'
    assert controller.execute(command + ' | except "(0.0.0.0|10.0.101)"', mode)['text'] == '192.0.2.0/24\n'
    assert controller.execute(command + r' | match 10.0.101 | except "\.12/"', mode)['text'] == '10.0.101X12/24\n10.0.101.1/24\n'


@pytest.mark.parametrize('modifier', ['match', 'except'])
@pytest.mark.parametrize('pattern', ['[', '(', '*', '\\', 'a{9999999999999999999999}'])
def test_invalid_regex_is_rejected_before_execution(controller, monkeypatch, modifier, pattern):
    monkeypatch.setattr('nvyr.controller.cmd', lambda *a, **kw: pytest.fail('must not launch'))

    with pytest.raises(ParseError, match=f'Invalid regular expression for {modifier}'):
        controller.execute('show ip route | ' + modifier + ' ' + quote(pattern))


@pytest.mark.parametrize('command', ['ping 1.1.1.1', 'shellcmd /bin/echo test'])
@pytest.mark.parametrize('modifier', ['match 1.1.1.1', 'except test', 'count', 'commands',
                                    'strip-private', 'export /tmp/nvyr-pipe-test', 'match test | count'])
def test_streaming_pipes_never_launch(controller, session, monkeypatch, command, modifier):
    monkeypatch.setattr('nvyr.controller.cmd', lambda *a, **kw: pytest.fail('must not launch'))

    for prefix, mode in [('', None), ('run ', session)]:
        with pytest.raises(ParseError, match='not supported on streaming commands'):
            controller.execute(prefix + command + ' | ' + modifier, mode)

        assert controller.execute(prefix + command, mode)['event'] == 'command'


def test_cli_and_rpc_survive_streaming_pipe_and_regex_errors(daemon):
    client = Client(daemon)
    messages = []
    cli = CLI(client, emit=messages.append)

    try:
        for mode in ('operational', 'configuration'):
            prefix = '' if mode == 'operational' else 'run '
            if prefix:
                cli.execute_line('configure')

            for line, error in [('ping 1.1.1.1 | match 1.1.1.1', 'streaming commands'),
                                ('show version | match "["', 'Invalid regular expression')]:
                messages.clear()
                cli.execute_line(prefix + line)

                assert error in '\n'.join(messages)
                assert 'Traceback' not in '\n'.join(messages)

                messages.clear()
                cli.execute_line(prefix + 'show version | match "^ (Version|Build date)"')

                assert 'Version    |' in '\n'.join(messages) and 'Build date |' in '\n'.join(messages)
                assert 'commit_id' in client.request('status')
    finally:
        client.close()
