#!/usr/bin/env python3
"""Schema-approved IS-IS displays and scoped adjacency resets."""

from nvyr import opmode
from nvyr.helpers import vtysh


def native_words(line, operation):
    words = list(vtysh.command_words(line, 'isis.nvyr.op', operation))
    scope_end = 4 if len(words) > 2 and words[2] == 'vrf' else 2
    tail = words[scope_end:]
    if tail[:1] == ['spf-delay']:
        words[scope_end] = 'spf-delay-ietf'
    if len(tail) > 1 and tail[0] in ('route', 'topology') and tail[1] == 'level':
        del words[scope_end + 1]
    elif tail[:3] == ['fast-reroute', 'summary', 'level']:
        del words[scope_end + 2]
    if operation == 'show' and len(words) == scope_end:
        words.append('summary')
    if operation == 'clear' and scope_end == 2:
        words[2:2] = ['vrf', 'default']
    return words


@opmode.command
def show(line: str):
    return vtysh.show(native_words(line, 'show'))


@opmode.command
def clear(line: str):
    return vtysh.clear(native_words(line, 'clear'))


if __name__ == '__main__':
    opmode.run()
