"""Pure formatting for OSPF's compound interface and authentication commands."""

import ipaddress
from collections.abc import Mapping


def area_id(value):
    return str(ipaddress.IPv4Address(int(value) if value.isdecimal() else value))


def metric_options(settings):
    parts = []
    for name in ('metric', 'metric-type', 'route-map'):
        if name in settings:
            value = settings[name] if name == 'route-map' else str(int(settings[name]))
            parts.extend((name, value))
    return ' '.join(parts)


def authentication(settings, version=2):
    commands = []
    if 'key-chain' in settings:
        keyword = 'keychain' if version == 3 else 'key-chain'
        commands.append(f'authentication {keyword} {settings["key-chain"]}')
    if 'none' in settings:
        commands.append('authentication null')
    if 'plaintext' in settings:
        commands.extend(('authentication', 'authentication-key ' + settings['plaintext']))
    if 'md5' in settings:
        commands.append('authentication message-digest')
        for identifier, key in sorted(settings['md5']['key'].items(), key=lambda item: int(item[0])):
            commands.append(f'message-digest-key {int(identifier)} md5 {key["secret"]}')
    for identifier, key in settings.get('key', {}).items():
        commands.append(f'authentication key-id {int(identifier)} hash-algo {key["algorithm"]} key {key["secret"]}')
    return commands


def interface_commands(settings, version, address=None):
    prefix = 'ipv6 ospf6' if version == 3 else 'ip ospf'
    suffix = ' ' + str(ipaddress.IPv4Address(address)) if address else ''
    commands = []
    if 'area' in settings:
        commands.append(f'{prefix} area {area_id(settings["area"])}{suffix}')
    for name in ('cost', 'priority', 'hello-interval', 'dead-interval', 'retransmit-interval',
                 'transmit-delay', 'retransmit-window', 'instance-id'):
        if name in settings:
            commands.append(f'{prefix} {name} {int(settings[name])}{suffix}')
    for name in ('mtu-ignore', 'prefix-suppression'):
        if name in settings:
            commands.append(f'{prefix} {name}{suffix}')
    if 'passive' in settings:
        negative = 'no ' if 'disable' in settings['passive'] else ''
        if version == 2 or not negative:
            commands.append(f'{negative}{prefix} passive{suffix}')
    if 'network' in settings:
        selection = settings['network']
        if isinstance(selection, str):
            value = selection
        else:
            value = next(iter(selection))
            if isinstance(selection[value], Mapping) and selection[value]:
                value += ' ' + next(iter(selection[value]))
        commands.append(f'{prefix} network {value}')
    if 'fast-hello' in settings:
        commands.append(f'{prefix} dead-interval minimal hello-multiplier {int(settings["fast-hello"])}{suffix}')
    for command in authentication(settings.get('authentication', {}), version):
        commands.append(f'{prefix} {command}{suffix}')
    for name, native in (('graceful-restart-hello-delay', 'graceful-restart hello-delay'),
                         ('mtu', 'ifmtu'), ('advertise-prefix-list', 'advertise prefix-list'),
                         ('neighbor-filter', 'neighbor-filter')):
        if name in settings:
            value = settings[name]
            if name in ('graceful-restart-hello-delay', 'mtu'):
                value = int(value)
            commands.append(f'{prefix} {native} {value}{suffix}')
    if 'disable-opaque-capability' in settings:
        commands.append(f'no {prefix} capability opaque{suffix}')
    if 'dead-timer-reset-any-control' in settings:
        commands.append(f'{prefix} dead-timer-reset any-control')
    for kind, value in settings.get('dscp', {}).items():
        commands.append(f'{prefix} dscp {kind} {int(value)}')
    for name, value in settings.get('neighbor-options', {}).items():
        native = 'config-neighbors-only' if name == 'configured-neighbors-only' else name
        operand = ' ' + value if name == 'connected-prefixes' else ''
        commands.append(f'{prefix} p2p-p2mp {native}{operand}')
    for address, neighbor in settings.get('neighbor', {}).items():
        command = f'{prefix} neighbor {ipaddress.IPv6Address(address)}'
        commands.append(command)
        for name in ('poll-interval', 'cost'):
            if name in neighbor:
                commands.append(command + f' {name} {int(neighbor[name])}')
    for local, overrides in settings.get('address', {}).items():
        commands.extend(interface_commands(overrides, version, local))
    return commands
