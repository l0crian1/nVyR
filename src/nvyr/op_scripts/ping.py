#!/usr/bin/env python3
"""Send ICMP echo requests using the system ping utility."""

from nvyr import opmode
from nvyr.errors import ParseError
from nvyr.helpers.process import call


OPTIONS = {
    'adaptive': '-A',
    'allow-broadcast': '-b',
    'audible': '-a',
    'bypass-route': '-r',
    'count': '-c',
    'deadline': '-w',
    'do-not-fragment': ['-M', 'do'],
    'flood': '-f',
    'interface': '-I',
    'interval': '-i',
    'ipv4': '-4',
    'ipv6': '-6',
    'mark': '-m',
    'no-loopback': '-L',
    'numeric': '-n',
    'pattern': '-p',
    'quiet': '-q',
    'record-route': '-R',
    'size': '-s',
    'source-address': '-I',
    'timestamp': '-D',
    'tos': '-Q',
    'ttl': '-t',
    'verbose': '-v',
}


def _argv(line):
    selected = set()
    routing = []

    def vrf(value):
        routing[:] = ['ip', 'vrf', 'exec', value]
        return []

    def tos(value):
        selected.add('tos')
        return ['-Q', value]

    def dscp(value):
        selected.add('dscp')
        return ['-Q', str(int(value) * 4)]

    path, arguments = opmode.command_arguments(line, OPTIONS | {'tos': tos, 'dscp': dscp, 'vrf': vrf})
    if path[0] != 'ping':
        raise ParseError('Expected ping and a destination')

    if {'tos', 'dscp'} <= selected:
        raise ParseError('Cannot combine tos and dscp. Choose only one.')

    return [*routing, 'ping', *arguments, '--', path[1]]


@opmode.command
def ping(line: str):
    """Run a complete nVyR ping command with live terminal output."""
    raise SystemExit(call(_argv(line), new_process_group=False))


if __name__ == '__main__':
    opmode.run()
