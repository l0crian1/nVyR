#!/usr/bin/env python3
"""Administrator system commands; configd owns authorization and privilege."""

from nvyr import opmode
from nvyr.errors import ParseError
from nvyr.helpers.process import call
from nvyr.lexer import split_pipeline
from nvyr.schema import resolve_word


def _argv(line):
    tokens = split_pipeline(line)[0]
    if resolve_word(tokens[0].value, ('run', 'shellcmd')) == 'run':
        tokens = tokens[1:]

    if not tokens:
        raise ParseError('shellcmd requires a system command')

    resolve_word(tokens[0].value, ('shellcmd',))
    argv = [token.value for token in tokens[1:]]
    if not argv or not argv[0]:
        raise ParseError('shellcmd requires a system command')

    if any('\x00' in argument for argument in argv):
        raise ParseError('System command arguments cannot contain NUL bytes')

    return argv


@opmode.command
def execute(line: str):
    """Execute the original command's arguments without an implicit shell."""
    raise SystemExit(call(_argv(line), new_process_group=False))


if __name__ == '__main__':
    opmode.run()
