#!/usr/bin/env python3
"""Schema-approved MPLS and LDP commands, using native FRR syntax and output."""

from nvyr import opmode
from nvyr.helpers import vtysh


@opmode.command
def show(line: str):
    return vtysh.show(vtysh.command_words(line, 'mpls.nvyr.op', 'show'))


@opmode.command
def clear(line: str):
    return vtysh.clear(vtysh.command_words(line, 'mpls.nvyr.op', 'clear'))


if __name__ == '__main__':
    opmode.run()
