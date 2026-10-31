"""Unicast peer option rendering and identity helpers shared by groups and neighbors."""

import ipaddress


CAPABILITIES = {
    'extended-nexthop': 'capability extended-nexthop',
    'dynamic': 'capability dynamic',
    'link-local': 'capability link-local',
    'software-version': 'capability software-version',
    'disable-fqdn': 'capability fqdn',
    'disable-negotiation': 'dont-capability-negotiate',
    'strict-match': 'strict-capability-match',
    'override': 'override-capability',
}


def address(value):
    """Return an IP address, or None for an interface-based peer."""
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def name(value):
    parsed = address(value)
    return str(parsed) if parsed is not None else value


def internal(remote, local):
    return remote == 'internal' or str(remote) == str(local)


def commands(peer, options):
    """Render transport and session options in FRR's saved-config spelling."""
    prefix = f' neighbor {peer}'
    result = []
    alternate = options.get('local-as', {})
    if alternate:
        line = f'{prefix} local-as {int(alternate["number"])}'
        modifiers = alternate
        for key in ('no-prepend', 'replace-as', 'dual-as'):
            if key in modifiers:
                line += ' ' + key
                modifiers = modifiers[key]
        result.append(line)

    for key in ('port', 'tcp-mss'):
        if key in options:
            # FRR omits its standard transport port from running configuration.
            if key == 'port' and int(options[key]) == 179:
                continue
            result.append(f'{prefix} {key} {int(options[key])}')

    if 'graceful-shutdown' in options:
        result.append(f'{prefix} graceful-shutdown')
    if 'disable-connected-route-check' in options:
        result.append(f'{prefix} disable-connected-check')
    if 'disable-enforce-first-as' in options:
        result.append(f' no neighbor {peer} enforce-first-as')
    if 'graceful-restart' in options:
        native = {'helper': 'graceful-restart-helper', 'restart': 'graceful-restart',
                  'disable': 'graceful-restart-disable'}[options['graceful-restart']]
        result.append(f'{prefix} {native}')

    for key in options.get('capability', {}):
        command = CAPABILITIES[key]
        result.append(f' no neighbor {peer} {command}' if key == 'disable-fqdn' else f'{prefix} {command}')
    if 'role' in options:
        role = options['role']
        result.append(f'{prefix} local-role {role["type"]}' + (' strict-mode' if 'strict' in role else ''))

    timers = options.get('timers', {})
    if 'advertisement-interval' in timers:
        result.append(f'{prefix} advertisement-interval {int(timers["advertisement-interval"])}')
    if 'delay-open' in timers:
        result.append(f'{prefix} timers delayopen {int(timers["delay-open"])}')

    return result


def family_commands(peer, options):
    """Render independent unicast policy controls for one peer and family."""
    prefix = f'  neighbor {peer}'
    result = []
    for flag in ('as-override', 'route-server-client'):
        if flag in options:
            result.append(f'{prefix} {flag}')
    for key in ('weight', 'maximum-prefix-out'):
        if key in options:
            result.append(f'{prefix} {key} {int(options[key])}')
    if 'unsuppress-map' in options:
        result.append(f'{prefix} unsuppress-map {options["unsuppress-map"]}')

    allowed = options.get('allowas-in')
    if allowed is not None:
        line = f'{prefix} allowas-in'
        if 'route-map' in allowed:
            line += f' route-map {allowed["route-map"]}'
        if 'count' in allowed and int(allowed['count']) != 3:
            line += f' {int(allowed["count"])}'
        elif 'origin' in allowed:
            line += ' origin'
        result.append(line)

    if 'remove-private-as' in options:
        private = options['remove-private-as']
        line = f'{prefix} remove-private-AS'
        if 'all' in private:
            line += ' all'
        if 'replace' in private or 'replace' in private.get('all', {}):
            line += ' replace-AS'
        result.append(line)

    if 'soft-reconfiguration' in options:
        result.append(f'{prefix} soft-reconfiguration inbound')
    if 'maximum-prefix' in options:
        limit = options['maximum-prefix']
        line = f'{prefix} maximum-prefix {int(limit["limit"])}'
        if 'threshold' in limit and int(limit['threshold']) != 75:
            line += f' {int(limit["threshold"])}'
        if 'warning-only' in limit:
            line += ' warning-only'
        if 'restart' in limit:
            line += f' restart {int(limit["restart"])}'
        if 'force' in limit:
            line += ' force'
        result.append(line)

    if 'conditional-advertisement' in options:
        conditional = options['conditional-advertisement']
        condition = 'exist-map' if 'exist-map' in conditional else 'non-exist-map'
        result.append(f'{prefix} advertise-map {conditional["advertise-map"]} {condition} {conditional[condition]}')

    addpath = options.get('addpath', {})
    transmit = addpath.get('transmit', {})
    if 'all' in transmit:
        result.append(f'{prefix} addpath-tx-all-paths')
    if 'best-selected' in transmit:
        result.append(f'{prefix} addpath-tx-best-selected {int(transmit["best-selected"])}')
    if 'disable-receive' in addpath:
        result.append(f'{prefix} disable-addpath-rx')
    if 'receive-limit' in addpath:
        result.append(f'{prefix} addpath-rx-paths-limit {int(addpath["receive-limit"])}')

    unchanged = dict(options.get('attribute-unchanged', {}))
    # Native route-server-client always preserves next hops and writes that behavior explicitly.
    if 'route-server-client' in options:
        unchanged['next-hop'] = {}
    if unchanged:
        fields = ' '.join(key for key in ('as-path', 'next-hop', 'med') if key in unchanged)
        result.append(f'{prefix} attribute-unchanged {fields}')

    return result
