"""Own complete BGP instances while preserving every other FRR section."""

import re

from nvyr.helpers import bgp_parameters


INSTANCE = re.compile(r'^router bgp ([0-9]+)(?: vrf (\S+))?$')


def configuration_lines(text):
    scope = None
    for line in text.splitlines():
        if line.startswith('bgp route-map delay-timer '):
            scope = None
            yield line, '@global'
            continue
        match = INSTANCE.fullmatch(line)
        if match:
            scope = match[2] or 'default'
            yield line, scope
        elif scope is not None and (line[:1].isspace() or line == 'exit'):
            yield line, scope
            if line == 'exit':
                scope = None
        else:
            if line.strip():
                scope = None
            yield line, None


def normalize(header, sections):
    """Compare contexts, not writer ordering or redundant inherited statements."""
    global_lines = sections.setdefault('', set())
    bgp_parameters.normalize(global_lines)
    global_lines.discard('timers bgp 60 180')

    memberships = {}
    for line in global_lines:
        parts = line.split()
        if len(parts) == 4 and parts[0] == 'neighbor' and parts[2] == 'peer-group':
            memberships[parts[1]] = parts[3]
        elif parts[:1] == ['neighbor'] and parts[2:3] == ['interface'] and 'peer-group' in parts:
            memberships[parts[1]] = parts[-1]

    peers = {line.split()[1] for line in global_lines if line.startswith('neighbor ')}
    for name in ('dynamic', 'link-local', 'software-version'):
        default_active = f'bgp default {name}-capability' in global_lines
        # Capability defaults, like family defaults, only initialize new native peers.
        # Keep the effective value explicit so existing peers converge on changes too.
        for peer in peers:
            positive = f'neighbor {peer} capability {name}'
            negative = f'no neighbor {peer} capability {name}'
            if positive not in global_lines and negative not in global_lines:
                global_lines.add(positive if default_active else negative)

    for family in ('ipv4', 'ipv6'):
        default_active = ('no bgp default ipv4-unicast' not in global_lines if family == 'ipv4'
                          else 'bgp default ipv6-unicast' in global_lines)
        lines = sections.setdefault(f'address-family {family} unicast', set())
        # Express both states: changing a family default does not update existing peers.
        # FRR omits redundant activation lines, so reconstruct their effective state.
        for peer in peers - memberships.keys():
            positive = f'neighbor {peer} activate'
            negative = f'no neighbor {peer} activate'
            if positive not in lines and negative not in lines:
                lines.add(positive if default_active else negative)

    for lines in sections.values():
        for member, group in memberships.items():
            for line in tuple(lines):
                # These defaults can leave existing members with explicit overrides.
                # Retain their effective state even when it currently matches the group.
                if any(line.endswith(' capability ' + name) for name in ('dynamic', 'link-local', 'software-version')):
                    continue
                prefix = f'neighbor {member} '
                if line.startswith(prefix) and f'neighbor {group} ' + line[len(prefix):] in lines:
                    lines.remove(line)
                prefix = f'no neighbor {member} '
                if line.startswith(prefix) and f'no neighbor {group} ' + line[len(prefix):] in lines:
                    lines.remove(line)

    groups = {line.split()[1] for line in global_lines
              if line.startswith('neighbor ') and line.endswith(' peer-group')}

    def ordered(line):
        # Dynamic listeners refer to groups declared earlier in the same instance.
        if line.startswith('bgp listen range '):
            return (3, command_order(line))
        parts = line.split()
        peer = parts[2] if parts[:2] == ['no', 'neighbor'] else parts[1] if parts[0] == 'neighbor' else None
        category = 0 if peer is None else 1 if peer in groups else 2
        return (category, command_order(line))

    result = [header]
    result.extend(' ' + line for line in sorted(global_lines, key=ordered))
    for family, lines in sorted(sections.items()):
        if family and lines:
            result.append(' ' + family)
            result.extend('  ' + line for line in sorted(lines, key=ordered))
            result.append(' exit-address-family')
    result.append('exit')
    return '\n'.join(result)


def command_order(line):
    """Declare peer groups before assigning their members during a full reload."""
    parts = line.split()
    if parts[:2] == ['no', 'neighbor']:
        return (4, line)
    if len(parts) == 3 and parts[0] == 'neighbor' and parts[2] == 'peer-group':
        return (1, line)
    if parts[:1] == ['neighbor']:
        if parts[2] == 'remote-as' or (parts[2] == 'interface' and ('remote-as' in parts or 'peer-group' in parts)):
            return (2, line)
        if parts[2] == 'peer-group':
            return (3, line)
        return (4, line)
    return (0, line)


class Instances:
    def desired(self, text):
        scopes = {scope for _, scope in configuration_lines(text) if scope is not None}
        return self.select(text, sorted(scopes))

    def select(self, text, scopes):
        result = {scope: [] for scope in scopes}
        headers = {}
        sections = {}
        family = ''
        for line, scope in configuration_lines(text):
            if scope not in result:
                continue
            if scope == '@global':
                if line != 'bgp route-map delay-timer 5':
                    result[scope].append(line)
                continue
            if INSTANCE.fullmatch(line):
                headers[scope] = line
                sections[scope] = {'': set()}
                family = ''
                continue
            stripped = line.strip()
            if stripped.startswith('address-family '):
                family = stripped
                sections[scope].setdefault(family, set())
            elif stripped == 'exit-address-family':
                family = ''
            elif stripped not in ('', '!', 'exit'):
                # FRR abbreviates standard-community suppression and coalesces all three.
                if re.fullmatch(r'no neighbor \S+ send-community', stripped):
                    stripped += ' standard'
                if re.fullmatch(r'no neighbor \S+ send-community all', stripped):
                    for community in ('standard', 'extended', 'large'):
                        sections[scope][family].add(stripped[:-3] + community)
                else:
                    sections[scope][family].add(stripped)

        for scope, header in headers.items():
            result[scope] = [normalize(header, sections[scope])]
        return result

    def replace(self, text, desired):
        lines = [line for line, scope in configuration_lines(text)
                 if scope not in desired and line.strip() != 'end']
        for _, blocks in sorted(desired.items()):
            lines.extend(blocks)
        return '\n'.join([*lines, 'end', ''])


adapter = Instances()
