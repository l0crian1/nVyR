#!/usr/bin/env python3
"""Native OSPF displays and explicit resets for the selected address family."""

from nvyr import opmode
from nvyr.helpers import vtysh


def native_words(line, operation):
    words = list(vtysh.command_words(line, 'ospf.nvyr.op', operation))
    if words[1] == 'ipv6':
        words[2] = 'ospf6'
        # FRR places the VRF after "process" only for this reset command.
        if operation == 'clear' and words[3:4] == ['vrf'] and words[-1] == 'process':
            words = words[:3] + ['process', 'vrf', words[4]]
    return words


@opmode.command
def show(line: str, raw: bool = False):
    return vtysh.show(native_words(line, 'show'), raw=raw)


@opmode.command
def clear(line: str):
    return vtysh.clear(native_words(line, 'clear'))


if __name__ == '__main__':
    opmode.run()
