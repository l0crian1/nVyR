"""Own RIP process blocks and RIP leaves inside shared FRR interface blocks."""

import re


def normalize(commands, protocol, interface):
    """Normalize only defaults omitted by FRR's native configuration writer."""
    commands = set(commands)
    if interface:
        prefix = 'ipv6 ripng' if protocol == 'ripng' else 'ip rip'
        commands.discard(prefix + ' split-horizon')
        commands = {line.removesuffix(' auth-length old-ripd') for line in commands}
    else:
        commands.difference_update({'default-metric 1', 'timers basic 30 180 120'})
        if 'passive-interface default' in commands:
            commands = {line for line in commands if not line.startswith('passive-interface ')
                        or line == 'passive-interface default'}
        else:
            commands = {line for line in commands if not line.startswith('no passive-interface ')}
    return commands


class Rip:
    def __init__(self, protocol):
        self.protocol = protocol
        self.interface_prefix = 'ipv6 ripng ' if protocol == 'ripng' else 'ip rip '
        self.process = re.compile(r'^router ' + self.protocol + r'(?: vrf \S+)?$')

    def lines(self, text):
        """The interface header belongs to all protocols; its RIP leaves do not."""
        context = None
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith('!'):
                yield line, None
                continue
            if self.process.fullmatch(line) or line.startswith('interface '):
                context = line
            elif line and not line[0].isspace() and not line.startswith('!'):
                context = None

            scope = None
            if context is not None:
                if context.startswith('router '):
                    scope = context
                elif line.strip().removeprefix('no ').startswith(self.interface_prefix):
                    scope = context
            yield line, scope

    def desired(self, text):
        scopes = {scope for _, scope in self.lines(text) if scope is not None}
        return self.select(text, sorted(scopes))

    def select(self, text, scopes):
        commands = {scope: set() for scope in scopes}
        present = set()
        for line, scope in self.lines(text):
            if scope not in commands:
                continue
            present.add(scope)
            if line != scope:
                commands[scope].add(' '.join(line.split()))

        result = {scope: [] for scope in scopes}
        for scope in present:
            interface = scope.startswith('interface ')
            lines = normalize(commands[scope], self.protocol, interface)
            if lines or not interface:
                result[scope] = ['\n'.join([scope, *(' ' + line for line in sorted(lines)), 'exit'])]
        return result

    def replace(self, text, desired):
        lines = []
        removing_process = False
        for line, scope in self.lines(text):
            if self.process.fullmatch(line):
                removing_process = scope in desired
            elif line == 'exit' and removing_process:
                removing_process = False
                continue
            elif line and not line[0].isspace() and not line.startswith('!'):
                removing_process = False
            if scope not in desired and line.strip() != 'end':
                lines.append(line)

        for scope, blocks in sorted(desired.items()):
            lines.extend(blocks)
        return '\n'.join([*lines, 'end', ''])


adapters = {protocol: Rip(protocol) for protocol in ('rip', 'ripng')}
