"""Select named routing policies inside an integrated FRR configuration."""

import re


POLICY_LINE = re.compile(
    r'^(access-list|ipv6 access-list|ip prefix-list|ipv6 prefix-list|route-map|'
    r'bgp as-path access-list|bgp (?:large-)?community-list (?:standard|expanded)) (\S+) ')


def configuration_lines(text):
    """Associate route-map bodies and single-line filters with their named owner."""
    route_map = None
    key_chain = None
    for line in text.splitlines():
        stripped = line.strip()
        if line.startswith('key chain '):
            key_chain = line
            route_map = None
            yield line, key_chain
            continue
        if key_chain is not None and (line[:1].isspace() or line == 'exit'):
            yield line, key_chain
            if line == 'exit':
                key_chain = None
            continue
        key_chain = None
        match = POLICY_LINE.match(line)
        if match:
            kind = re.sub(r' (standard|expanded)$', '', match[1])
            scope = f'{kind} {match[2]}'
            route_map = scope if match[1] == 'route-map' else None
            yield line, scope
        elif route_map and (line[:1].isspace() or stripped == 'exit'):
            yield line, route_map
            if stripped == 'exit':
                route_map = None
        else:
            if stripped:
                route_map = None
            yield line, None


class Policies:
    def desired(self, text):
        scopes = {scope for _, scope in configuration_lines(text) if scope is not None}
        return self.select(text, sorted(scopes))

    def select(self, text, scopes):
        """Normalize writer ordering without losing route-map sequence boundaries."""
        result = {scope: [] for scope in scopes}
        entry = None
        keys = {}
        for line, scope in configuration_lines(text):
            if scope not in result:
                entry = None
                continue

            if scope.startswith('key chain '):
                if line.startswith('key chain '):
                    keys[scope] = {}
                elif line.strip().startswith('key '):
                    entry = []
                    keys[scope][int(line.split()[1])] = entry
                elif line.strip() != 'exit' and entry is not None:
                    entry.append(' '.join(line.split()))
                continue

            if line.startswith('route-map '):
                entry = [line.strip()]
                result[scope].append(entry)
            elif line.strip() == 'exit':
                entry = None
            elif line[:1].isspace() and entry is not None:
                entry.append(' ' + line.strip())
            else:
                result[scope].append([line.strip()])

        normalized = {}
        for scope, entries in result.items():
            normalized[scope] = sorted('\n'.join([entry[0], *sorted(entry[1:])]) for entry in entries)
        for scope, chain in keys.items():
            lines = [scope]
            for identifier, commands in sorted(chain.items()):
                lines.append(f' key {identifier}')
                lines.extend('  ' + command for command in sorted(commands))
                lines.append(' exit')
            lines.append('exit')
            normalized[scope] = ['\n'.join(lines)]
        return normalized

    def replace(self, text, desired):
        """Replace only claimed names; preserve static routes and other owners."""
        lines = []
        for line, scope in configuration_lines(text):
            if scope not in desired and line.strip() != 'end':
                lines.append(line)

        for scope, entries in sorted(desired.items()):
            for entry in entries:
                lines.append(entry)
                if scope.startswith('route-map '):
                    lines.append('exit')
        return '\n'.join([*lines, 'end', ''])


adapter = Policies()
