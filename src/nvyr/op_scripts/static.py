#!/usr/bin/env python3
"""Display Zebra routes and staticd next-hop status through vtysh."""

from nvyr import opmode
from nvyr.errors import ParseError
from nvyr.helpers import vtysh
from nvyr.lexer import split_pipeline
from nvyr.schema import Schema, resolve_word


@opmode.command
def show(line: str, raw: bool = False):
    """Display a schema-approved route command; raw selects FRR's JSON output."""
    schema = Schema.bundled('operational')
    tokens = split_pipeline(line)[0]
    if tokens and resolve_word(tokens[0].value, [*schema.root['children'], 'run']) == 'run':
        tokens = tokens[1:]

    cursor = schema.operational(tokens)
    command = cursor.node.get('command', {})
    if (not isinstance(command, dict)
            or command.get('argv') != ['static.nvyr.op', 'show', '@line']
            or cursor.expect in {'tag', 'value'} and not cursor.node.get('optional_value')):
        raise ParseError('Expected a route display command')

    words = schema.command_path(cursor.path)
    # Leaf values are separate from their schema path (for example route tags).
    if cursor.node['kind'] == 'leaf_node':
        words += (cursor.value,)

    # FRR's longer-prefixes form requires a prefix, not a bare host lookup.
    lookup_path = cursor.path[:-1] if cursor.path[-1] == 'static' else cursor.path
    if (lookup_path[-3:-2] == ('destination',) and lookup_path[-1] == 'longer-prefixes'
            and '/' not in lookup_path[-2]):
        raise ParseError('longer-prefixes requires a destination prefix with a prefix length.')

    return vtysh.show(words, raw=raw)


if __name__ == '__main__':
    opmode.run()
