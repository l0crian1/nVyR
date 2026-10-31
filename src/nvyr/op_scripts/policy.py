#!/usr/bin/env python3
"""Inspect installed routing policies and reset their native FRR counters."""

from nvyr import opmode
from nvyr.errors import ParseError
from nvyr.helpers import vtysh


@opmode.command
def show(line: str, raw: bool = False):
    """Pass schema-approved policy commands to FRR without reordering arguments."""
    words = vtysh.command_words(line, 'policy.nvyr.op', 'show')
    # FRR's prefix lookup forms provide text only; list/sequence/detail views support JSON.
    if raw and len(words) > 4 and words[2] == 'prefix-list' and '/' in words[4]:
        raise ParseError('FRR does not provide JSON for prefix-list prefix lookups.')

    return vtysh.show(words, raw=raw)


@opmode.command
def clear(line: str):
    """Clear route-map statistics; access is enforced by the privileged dispatcher."""
    words = vtysh.command_words(line, 'policy.nvyr.op', 'clear')
    return vtysh.clear(words)


if __name__ == '__main__':
    opmode.run()
