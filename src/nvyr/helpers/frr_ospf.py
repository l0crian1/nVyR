"""Select OSPF process blocks and their own commands inside shared interfaces."""

import re


def command_order(line):
    # Area-specific costs and NSSA ranges require the area type to exist first.
    if re.match(r'area \S+ (?:stub|nssa)(?: |$)', line) and ' range ' not in line:
        return (0, line)
    return (1, line)


def normalize(commands, protocol, interface):
    """Account for defaults omitted by FRR 10.7.1's configuration writers."""
    commands = set(commands)
    if interface:
        if protocol == 'ospf6':
            commands.difference_update({
                'ipv6 ospf6 hello-interval 10', 'ipv6 ospf6 dead-interval 40',
                'ipv6 ospf6 retransmit-interval 5', 'ipv6 ospf6 transmit-delay 1',
                'ipv6 ospf6 priority 1', 'ipv6 ospf6 instance-id 0',
                'ipv6 ospf6 graceful-restart hello-delay 10', 'no ipv6 ospf6 passive',
            })
        else:
            commands.discard('ip ospf graceful-restart hello-delay 10')
        return commands

    commands.difference_update({
        'auto-cost reference-bandwidth 100000', 'maximum-paths 256',
        'timers throttle spf 0 50 5000', 'timers lsa min-arrival 1000',
        'aggregation timer 5', 'graceful-restart helper supported-grace-time 1800',
    })
    if 'graceful-restart grace-period 120' in commands:
        commands.remove('graceful-restart grace-period 120')
        commands.add('graceful-restart')
    if protocol == 'ospf':
        commands.difference_update({'ospf abr-type cisco', 'ospf write-multiplier 20',
                                    'refresh timer 10', 'timers throttle lsa all 5000'})
        commands = {re.sub(r' metric-type 2(?= |$)', '', line) if line.startswith(
            ('redistribute ', 'default-information ', 'area ')) else line for line in commands}
        commands = {re.sub(r'(area \S+) shortcut default$', '', line) for line in commands}
        commands.discard('')
    else:
        commands.discard('write-multiplier 20')
    return commands


class Ospf:
    def __init__(self, version):
        self.protocol = 'ospf6' if version == 3 else 'ospf'
        self.interface_prefix = 'ipv6 ospf6 ' if version == 3 else 'ip ospf '
        self.process = re.compile(r'^router ' + self.protocol + r'(?: vrf \S+)?$')

    def settle_timeout(self, current, desired):
        """Process removal waits for an explicitly configured max-metric drain."""
        delays = []
        for scope, blocks in self.select(current, desired).items():
            if scope.startswith('router ospf') and not desired[scope]:
                for block in blocks:
                    match = re.search(r'^ max-metric router-lsa on-shutdown ([0-9]+)$', block, re.M)
                    if match:
                        delays.append(int(match[1]))
        return max(delays) + 2 if delays else 0

    def lines(self, text):
        """The interface header belongs to all protocols; its OSPF leaves do not."""
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
                result[scope] = ['\n'.join([scope, *(' ' + line for line in sorted(lines, key=command_order)), 'exit'])]
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


ipv4 = Ospf(2)
ipv6 = Ospf(3)
