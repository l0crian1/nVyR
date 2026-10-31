"""Static-route CLI formatting and ownership inside integrated FRR configuration."""

import ipaddress


def route_prefix(keyword, prefix, source):
    """Canonical destination and optional non-default IPv6 source selector."""
    result = f'{keyword} route {ipaddress.ip_network(prefix)}'
    if source is not None and ipaddress.ip_network(source).prefixlen:
        result += f' from {ipaddress.ip_network(source)}'
    return result


def route_path(kind, name, hop, vrf):
    """Format one path using FRR's option order and omission of native defaults."""
    destination = name
    if kind == 'next-hop':
        destination = str(ipaddress.ip_address(name))
        if hop.get('interface'):
            destination += ' ' + hop['interface']

    parts = [destination]
    if int(hop.get('tag', 0)):
        parts.append(f"tag {int(hop['tag'])}")
    if int(hop.get('distance', 1)) != 1:
        parts.append(str(int(hop['distance'])))
    if int(hop.get('metric', 0)):
        parts.append(f"metric {int(hop['metric'])}")
    if hop.get('vrf', vrf) != vrf:
        parts.append('nexthop-vrf ' + hop['vrf'])
    if 'weight' in hop:
        parts.append(f"weight {int(hop['weight'])}")
    if 'onlink' in hop:
        parts.append('onlink')

    return ' '.join(parts)


def configuration_lines(text):
    """Identify only top-level or VRF-level unicast static-route statements."""
    context = None
    for line in text.splitlines():
        stripped = line.strip()
        if line.startswith('vrf '):
            context = line[4:].strip()
        elif stripped == 'exit-vrf':
            context = None
        elif line and not line[0].isspace() and not line.startswith('!'):
            context = None

        is_route = stripped.startswith(('ip route ', 'ipv6 route '))
        if is_route and (not line[0].isspace() or context is not None):
            yield line, context or 'default', stripped
        else:
            yield line, None, None


class StaticRoutes:
    def select(self, text, scopes):
        result = {scope: [] for scope in scopes}
        for _, scope, command in configuration_lines(text):
            if scope in result:
                result[scope].append(command)
        return {scope: sorted(lines) for scope, lines in result.items()}

    def replace(self, text, desired):
        # Keep VRF declarations and every non-static command. Never delete a
        # protocol/VRF instance merely because its final route was withdrawn.
        lines = []
        for line, scope, _ in configuration_lines(text):
            if scope not in desired and line.strip() != 'end':
                lines.append(line)

        for vrf, commands in sorted(desired.items()):
            if not commands:
                continue
            if vrf == 'default':
                lines.extend(commands)
            else:
                lines.append('vrf ' + vrf)
                lines.extend(' ' + command for command in commands)
                lines.append('exit-vrf')
        return '\n'.join([*lines, 'end', ''])


adapter = StaticRoutes()
