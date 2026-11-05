#!/usr/bin/env python3
"""Native RIP displays and explicitly scoped route resets."""

from nvyr import opmode
from nvyr.helpers import vtysh


def native_words(line, operation):
    words = list(vtysh.command_words(line, 'rip.nvyr.op', operation))
    if operation == 'clear':
        protocol = words[1]
        family = 'ip' if protocol == 'rip' else 'ipv6'
        suffix = words[2:]
        if suffix == ['all']:
            suffix = []
        elif not suffix:
            suffix = ['vrf', 'default']
        return ['clear', family, protocol, *suffix]
    return words


@opmode.command
def show(line: str):
    return vtysh.show(native_words(line, 'show'))


@opmode.command
def clear(line: str):
    return vtysh.clear(native_words(line, 'clear'))


if __name__ == '__main__':
    opmode.run()
