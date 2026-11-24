"""Format BGP operands and option commands within native template structure."""

import ipaddress

from nvyr.helpers import bgp_peer


COMMUNITIES = ('standard', 'extended', 'large')


def rd_rt(value):
    administrator, assigned = value.split(':')
    administrator = str(ipaddress.IPv4Address(administrator)) if '.' in administrator else str(int(administrator))
    return f'{administrator}:{int(assigned)}'


def timer_pair(options, defaults):
    return (int(options.get('keepalive', defaults.get('keepalive', 60))),
            int(options.get('holdtime', defaults.get('holdtime', 180))))


def peer_timer_defaults(defaults, groups, options):
    """A peer-group's timer values override the instance defaults for members."""
    result = dict(defaults)
    result.update(groups.get(options.get('peer-group'), {}).get('timers', {}))
    return result


def peer_commands(name, options, defaults, *, shutdown_default=False, interface_peer=False):
    prefix = f' neighbor {name}'
    commands = []
    for key in ('remote-as', 'description', 'password', 'update-source', 'ebgp-multihop'):
        if key not in options:
            continue
        value = options[key]
        if key == 'ebgp-multihop' or key == 'remote-as' and str(value).isdecimal():
            value = int(value)
            if key == 'ebgp-multihop' and value == 1:
                continue
        elif key in ('description', 'password'):
            value = ' '.join(value.split())
            if not value:
                continue
        elif key == 'update-source':
            try:
                value = str(ipaddress.ip_address(value))
            except ValueError:
                pass
        qualifier = ' interface' if key == 'remote-as' and interface_peer else ''
        if qualifier and 'ipv6-only' in options:
            qualifier += ' v6only'
        commands.append(f'{prefix}{qualifier} {key} {value}')

    if 'interface' in options:
        commands.append(f'{prefix} interface {options["interface"]}')

    if 'ttl-security' in options:
        commands.append(f'{prefix} ttl-security hops {int(options["ttl-security"]["hops"])}')
    if 'shutdown' in options or shutdown_default:
        commands.append(f'{prefix} shutdown')
    if 'passive' in options:
        commands.append(f'{prefix} passive')

    timers = options.get('timers', {})
    if 'keepalive' in timers or 'holdtime' in timers:
        keepalive, holdtime = timer_pair(timers, defaults)
        commands.append(f'{prefix} timers {keepalive} {holdtime}')
    if 'connect' in timers:
        commands.append(f'{prefix} timers connect {int(timers["connect"])}')
    commands.extend(bgp_peer.commands(name, options))
    return commands


def peer_family_commands(name, options, inherited_options):
    prefix = f'  neighbor {name}'
    if 'disable' in options:
        return [f'  no neighbor {name} activate']
    commands = [f'{prefix} activate']
    for kind in ('route-map', 'prefix-list', 'access-list', 'as-path-list'):
        native = {'access-list': 'distribute-list', 'as-path-list': 'filter-list'}.get(kind, kind)
        for direction, policy in options.get(kind, {}).items():
            if kind in ('route-map', 'as-path-list'):
                direction = {'import': 'in', 'export': 'out'}[direction]
            commands.append(f'{prefix} {native} {policy} {direction}')
    for flag in ('next-hop-self', 'route-reflector-client'):
        if flag in options:
            qualifier = ' force' if flag == 'next-hop-self' and 'force' in options[flag] else ''
            commands.append(f'{prefix} {flag}{qualifier}')
    if 'default-originate' in options:
        policy = options['default-originate'].get('route-map')
        commands.append(f'{prefix} default-originate' + (f' route-map {policy}' if policy else ''))

    if 'send-community' in options:
        selected = set(options['send-community'])
        inherited_classes = set(inherited_options.get('send-community', COMMUNITIES))
        for community in COMMUNITIES:
            if community not in selected:
                commands.append(f'  no neighbor {name} send-community {community}')
            elif community not in inherited_classes:
                commands.append(f'{prefix} send-community {community}')
    commands.extend(bgp_peer.family_commands(name, options))
    if 'site-of-origin' in options:
        commands.append(f'{prefix} soo {rd_rt(options["site-of-origin"])}')
    if 'accept-own' in options:
        commands.append(f'{prefix} accept-own')
    return commands


def evpn_attributes(options, padding):
    commands = []
    if 'route-distinguisher' in options:
        commands.append(padding + 'rd ' + rd_rt(options['route-distinguisher']))
    targets = options.get('route-target', {})
    for direction in ('import', 'export'):
        values = set(targets.get(direction, ())) | set(targets.get('both', ()))
        for value in sorted({rd_rt(rt) for rt in values}):
            commands.append(f'{padding}route-target {direction} {value}')

    for flag in ('advertise-default-gw', 'advertise-svi-ip', 'advertise-subnet'):
        if flag in options:
            commands.append(padding + flag)
    return commands


def evpn_commands(options):
    commands = evpn_attributes(options, '  ')
    for flag in ('advertise-all-vni', 'enable-resolve-overlay-index'):
        if flag in options:
            commands.append('  ' + flag)
    if 'rfc8365-compatible' in options.get('auto-route-target', {}):
        commands.append('  autort rfc8365-compatible')
    flooding = options.get('flooding', 'head-end-replication')
    if flooding == 'disable':
        commands.append('  flooding disable')

    detection = options.get('duplicate-address-detection', {})
    if 'disable' in detection:
        commands.append('  no dup-addr-detection')
    moves, window = int(detection.get('max-moves', 5)), int(detection.get('time', 180))
    if (moves, window) != (5, 180):
        commands.append(f'  dup-addr-detection max-moves {moves} time {window}')
    if 'freeze' in detection:
        freeze = detection['freeze']
        commands.append('  dup-addr-detection freeze ' + ('permanent' if freeze == 'permanent' else str(int(freeze))))

    for family, policy in options.get('advertise', {}).items():
        command = '  advertise ' + family.replace('-', ' ')
        if 'gateway-ip' in policy:
            command += ' gateway-ip'
        if 'route-map' in policy:
            command += ' route-map ' + policy['route-map']
        commands.append(command)
    for family in options.get('default-originate', {}):
        commands.append('  default-originate ' + family)

    for identifier, policy in options.get('vni', {}).items():
        commands.append(f'  vni {int(identifier)}')
        commands.extend(evpn_attributes(policy, '   '))
        if policy.get('flooding', flooding) != flooding:
            commands.append('   flooding ' + policy['flooding'])
        commands.append('  exit-vni')
    return commands


def family_commands(options, family='ipv4-unicast'):
    if family == 'l2vpn-evpn':
        return evpn_commands(options)

    commands = []
    for prefix, values in options.get('network', {}).items():
        if family.endswith('-vpn'):
            for rd, settings in values['route-distinguisher'].items():
                line = f'  network {ipaddress.ip_network(prefix)} rd {rd_rt(rd)} label {int(settings["label"])}'
                if 'route-map' in settings:
                    line += f' route-map {settings["route-map"]}'
                commands.append(line)
            continue
        line = f'  network {ipaddress.ip_network(prefix)}'
        if 'route-map' in values:
            line += f' route-map {values["route-map"]}'
        commands.append(line)
    for source, values in options.get('redistribute', {}).items():
        line = f'  redistribute {source}'
        if 'metric' in values:
            line += f' metric {int(values["metric"])}'
        if 'route-map' in values:
            line += f' route-map {values["route-map"]}'
        commands.append(line)
    for prefix, values in options.get('aggregate-address', {}).items():
        line = f'  aggregate-address {ipaddress.ip_network(prefix)}'
        for flag in ('as-set', 'summary-only'):
            if flag in values:
                line += f' {flag}'
        for key in ('route-map', 'origin'):
            if key in values:
                line += f' {key} {values[key]}'
        if 'matching-med-only' in values:
            line += ' matching-MED-only'
        if 'suppress-map' in values:
            line += f' suppress-map {values["suppress-map"]}'
        commands.append(line)
    for kind, count in options.get('maximum-paths', {}).items():
        # The pinned FRR build defaults to its compiled ECMP capacity of 256.
        if int(count) == 256:
            continue
        qualifier = ' ibgp' if kind == 'ibgp' else ''
        commands.append(f'  maximum-paths{qualifier} {int(count)}')
    if 'distance' in options:
        distance = options['distance']
        values = [int(distance.get(key, default)) for key, default in
                  (('external', 20), ('internal', 200), ('local', 200))]
        if values != [20, 200, 200]:
            commands.append('  distance bgp ' + ' '.join(str(value) for value in values))
    if 'prefer-global' in options.get('next-hop', {}):
        commands.append('  nexthop prefer-global')
    if 'disable-retain-route-target-all' in options:
        commands.append('  no bgp retain route-target all')
    vpn = options.get('vpn', {})
    for key, native in (('route-distinguisher', 'rd'), ('label', 'label'), ('next-hop', 'nexthop')):
        if key in vpn:
            value = vpn[key]
            if key == 'route-distinguisher':
                value = rd_rt(value)
            elif key == 'next-hop':
                value = str(ipaddress.ip_address(value))
            elif key == 'label' and value != 'auto':
                value = str(int(value))
            commands.append(f'  {native} vpn export {value}')
    if vpn.get('allocation-mode', 'per-vrf') != 'per-vrf':
        commands.append(f'  label vpn export allocation-mode {vpn["allocation-mode"]}')
    targets = vpn.get('route-target', {})
    for direction in ('import', 'export'):
        values = {rd_rt(value) for key in (direction, 'both') for value in targets.get(key, ())}
        if values:
            commands.append(f'  rt vpn {direction} ' + ' '.join(sorted(values)))
        if direction in vpn.get('route-map', {}):
            commands.append(f'  route-map vpn {direction} {vpn["route-map"][direction]}')
        if direction in vpn:
            commands.append(f'  {direction} vpn')
    return commands
