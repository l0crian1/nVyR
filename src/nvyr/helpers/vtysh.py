"""Schema-approved FRR operational commands, preserving native token order."""

import json
import re

from nvyr.errors import ParseError
from nvyr.helpers.process import CommandError, cmd
from nvyr.lexer import split_pipeline
from nvyr.schema import Schema, resolve_word


def command_words(line, script, operation):
    """Resolve a complete command owned by this script without moving arguments."""
    schema = Schema.bundled('operational')
    tokens = split_pipeline(line)[0]
    if tokens and resolve_word(tokens[0].value, [*schema.root['children'], 'run']) == 'run':
        tokens = tokens[1:]

    cursor = schema.operational(tokens)
    command = cursor.node.get('command', {})
    if (not isinstance(command, dict)
            or command.get('argv') != [script, operation, '@line']
            or cursor.expect in {'tag', 'value'} and not cursor.node.get('optional_value')):
        raise ParseError(f'Expected a complete {operation} command')

    return schema.command_path(cursor.path)


def clear(words):
    """Execute one schema-approved peer or policy-counter reset."""
    bgp = tuple(words[:2]) == ('clear', 'bgp') and len(words) >= 3
    route_map = tuple(words[:3]) == ('clear', 'route-map', 'counters') and len(words) in {3, 4}
    if (not (bgp or route_map)
            or any(not isinstance(word, str)
                   or not (bgp and word == '*') and not re.fullmatch(r'[a-zA-Z0-9_.:/%-]+', word)
                   for word in words)):
        raise ValueError('Expected a single FRR clear bgp or clear route-map counters command')

    return cmd(['vtysh', '-c', ' '.join(words)])


def show(words, *, raw=False):
    """Return FRR's text or JSON without changing its output structure.

    Callers resolve their command through the operational schema first. Tokens
    remain a single vtysh command; shell execution and embedded commands are
    never accepted.
    """
    if (not words or words[0] != 'show'
            or any(not isinstance(word, str) or not re.fullmatch(r'[a-zA-Z0-9_.:/%-]+', word)
                   for word in words)):
        raise ValueError('Expected a single FRR show command')

    command = ' '.join(words)
    if raw:
        command += ' json'

    output = cmd(['vtysh', '-c', command])
    if raw:
        try:
            json.loads(output)
        except ValueError as error:
            raise CommandError('FRR did not return valid JSON for this command.') from error

    return output
