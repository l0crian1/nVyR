#!/usr/bin/env python3
"""Native FRR BGP displays and peer resets through the operational command tree."""

from nvyr import opmode
from nvyr.errors import ParseError
from nvyr.helpers import vtysh


@opmode.command
def show(line: str, raw: bool = False):
    """Preserve native text, or return unmodified FRR JSON for internal callers."""
    words = vtysh.command_words(line, 'bgp.nvyr.op', 'show')
    if 'longer-prefixes' in words and '/' not in words[words.index('longer-prefixes') - 1]:
        raise ParseError('longer-prefixes requires a destination prefix with a prefix length.')
    if raw and words[-1] == 'wide':
        raise ParseError('wide is a text display option and cannot be used with raw output.')
    if (raw and words[:2] == ('show', 'bgp')
            and words[2:3] in {('community-list',), ('large-community-list',)}
            and (len(words) == 3 or len(words) == 5 and words[-1] == 'detail')):
        raise ParseError('FRR does not provide JSON for community-list definitions.')

    return vtysh.show(words, raw=raw)


@opmode.command
def clear(line: str):
    """Reset or refresh peers; the privileged dispatcher enforces net-admin access."""
    words = vtysh.command_words(line, 'bgp.nvyr.op', 'clear')
    return vtysh.clear(words)


if __name__ == '__main__':
    opmode.run()
