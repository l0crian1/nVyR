#!/usr/bin/env python3
"""Trace network hops using the system traceroute utility."""

from functools import partial
from ipaddress import ip_address

from nvyr import opmode
from nvyr.errors import ParseError
from nvyr.helpers.process import call


OPTIONS = {
    'ipv4': '-4',
    'ipv6': '-6',
    'icmp': '-I',
    'tcp': '-T',
    'udp': '-U',
    'do-not-fragment': '-F',
    'interface': '-i',
    'max-ttl': '-m',
    'first-ttl': '-f',
    'no-resolve': '-n',
    'port': '-p',
    'source-address': '-s',
    'mark': lambda value: [f'--fwmark={value}'],
    'probes': '-q',
    'wait': '-w',
    'backward-hops': '--back',
    'direct': '-r',
}


def _argv(line):
    selected = set()
    packet_size = []
    routing = []
    values = {'first-ttl': '1', 'max-ttl': '30'}

    def vrf(value):
        routing[:] = ['ip', 'vrf', 'exec', value]
        return []

    def remember(name, value):
        values[name] = value
        return [OPTIONS[name], value]

    def tos(value):
        selected.add('tos')
        return ['-t', value]

    def dscp(value):
        selected.add('dscp')
        return ['-t', str(int(value) * 4)]

    def size(value):
        packet_size[:] = [value]
        return []  # The packet length follows the destination, regardless of input order.

    path, arguments = opmode.command_arguments(
        line, OPTIONS | {'tos': tos, 'dscp': dscp, 'size': size, 'vrf': vrf} |
        {name: partial(remember, name) for name in ('first-ttl', 'max-ttl', 'source-address')})
    if path[0] != 'traceroute':
        raise ParseError('Expected traceroute and a destination')

    for group in (('ipv4', 'ipv6'), ('icmp', 'tcp', 'udp')):
        selected.update(name for name in group if OPTIONS[name] in arguments)

    for group in (('ipv4', 'ipv6'), ('icmp', 'tcp', 'udp'), ('tos', 'dscp')):
        conflicts = [name for name in group if name in selected]
        if len(conflicts) > 1:
            raise ParseError(f'Cannot combine {" and ".join(conflicts)}. Choose only one.')

    if int(values['first-ttl']) > int(values['max-ttl']):
        raise ParseError(f"first-ttl ({values['first-ttl']}) cannot be greater than max-ttl ({values['max-ttl']}).")

    family = 4 if 'ipv4' in selected else 6 if 'ipv6' in selected else None
    try:
        destination = ip_address(path[1])
    except ValueError:
        destination = None  # Hostnames are resolved by traceroute, not by the CLI.

    if destination is not None:
        if family is not None and destination.version != family:
            raise ParseError(f'Destination {path[1]} is not an IPv{family} address.')

        family = destination.version

    if 'source-address' in values and family is not None:
        source = values['source-address']
        if ip_address(source).version != family:
            raise ParseError(f'source-address {source} must use IPv{family} to match the destination or selected address family.')

    return [*routing, 'traceroute', *arguments, '--', path[1], *packet_size]


@opmode.command
def traceroute(line: str):
    """Run a complete nVyR traceroute command with live terminal output."""
    raise SystemExit(call(_argv(line), new_process_group=False))


if __name__ == '__main__':
    opmode.run()
