"""Resolve unattended actions with the installed operational grammar."""

from functools import cache

from nvyr.errors import ValidationError
from nvyr.helpers import access
from nvyr.helpers.process import operational_argv
from nvyr.lexer import split_pipeline
from nvyr.schema import Schema


@cache
def schema():
    return Schema.bundled('operational')


def eligible(node, path):
    command = node.get('command')
    if not access.allows(schema().minimum_access(node), current='net-admin'):
        return False
    if isinstance(command, str):
        return command in ('version', 'license')
    if not command:
        return False
    # Captured displays are bounded. Streamed actions must opt in explicitly.
    return node.get('unattended', False) or (path[:1] == ('show',) and not command.get('stream'))


def resolve(line):
    stages = split_pipeline(line)
    if len(stages) != 1:
        raise ValidationError('Scheduled operational commands do not accept output pipes')
    tokens = stages[0]
    cursor = schema().operational(tokens)
    if ((cursor.expect in ('value', 'tag') and not cursor.node.get('optional_value'))
            or not eligible(cursor.node, cursor.path)
            or any(not access.allows(role, current='net-admin') for role in cursor.required_access)):
        raise ValidationError('Expected a complete operational command that supports unattended execution')

    command = cursor.node['command']
    if isinstance(command, str):
        return ['tasks.nvyr.op', 'identity', command], 15
    timeout = None if command.get('stream') else command.get('timeout', 15)
    return operational_argv(command, tokens, line, omitted_positions=cursor.omitted_positions), timeout
