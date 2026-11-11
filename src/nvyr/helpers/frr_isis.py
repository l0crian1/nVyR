"""Own IS-IS process blocks and IS-IS commands on shared FRR interfaces."""

import re


LEVELS = ('level-1', 'level-2')
INTERFACE_DEFAULTS = {'metric': '10', 'priority': '64', 'hello-interval': '3',
                      'hello-multiplier': '10', 'csnp-interval': '10', 'psnp-interval': '2'}


def normalize(commands, interface):
    """Expand FRR's combined level writers and omit only native default values."""
    result = set()
    for line in commands:
        words = line.split()
        # Circuit topology participation defaults to true; FRR writes only disables.
        if interface and line.startswith('isis topology '):
            continue
        if interface and len(words) >= 3 and words[0] == 'isis' and words[1] in INTERFACE_DEFAULTS:
            key = words[1]
            levels = [word for word in words if word in LEVELS] or LEVELS
            value = next(word for word in words[2:] if word not in LEVELS)
            if value != INTERFACE_DEFAULTS[key]:
                for level in levels:
                    operands = f'{level} {value}' if key in ('metric', 'hello-interval', 'hello-multiplier') else f'{value} {level}'
                    result.add(f'isis {key} {operands}')
            continue
        if not interface and words[0] in ('lsp-timers', 'spf-interval'):
            levels = [word for word in words if word in LEVELS] or LEVELS
            operands = ' '.join(word for word in words[1:] if word not in LEVELS)
            default = 'gen-interval 30 refresh-interval 900 max-lifetime 1200' if words[0] == 'lsp-timers' else '1'
            if operands != default:
                result.update(f'{words[0]} {level} {operands}' for level in levels)
            continue
        if 'fast-reroute' in words and not any(level in words for level in LEVELS):
            result.update(line + ' ' + level for level in LEVELS)
            continue
        if not interface and words[0] in ('redistribute', 'default-information'):
            line = re.sub(r' metric 0(?= |$)', '', line)
        result.add(line)
    if interface:
        result.difference_update({'no isis passive', 'no isis network point-to-point',
                                  'isis three-way-handshake', 'isis hello padding',
                                  'isis circuit-type level-1-2', 'isis topology standard'})
    else:
        result.difference_update({'is-type level-1-2', 'metric-style wide', 'hostname dynamic',
                                  'lsp-mtu 1497', 'set-overload-bit on-startup 0', 'attached-bit send'})
    return result


def command_order(line):
    # Origination and redistribution validate against the process's current level.
    prerequisites = {'net': 0, 'is-type': 1, 'metric-style': 2}
    return prerequisites.get(line.split()[0], 3), line


class Isis:
    def __init__(self):
        self.process = re.compile(r'^router isis nvyr(?: vrf \S+)?$')

    def lines(self, text):
        """The interface header belongs to all protocols; its IS-IS leaves do not."""
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
                elif line.strip().removeprefix('no ').startswith(('isis ', 'ip router isis ', 'ipv6 router isis ')):
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
            lines = normalize(commands[scope], interface)
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


adapter = Isis()
