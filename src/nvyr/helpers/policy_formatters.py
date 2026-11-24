"""Format validated routing policies using native FRR configuration commands."""

import ipaddress

from nvyr.helpers.bgp_formatters import rd_rt
from nvyr.helpers.validators import BGP_COMMUNITY_NAMES


# FRR's config writer spells these well-known numeric communities as keywords.
COMMUNITY_NAMES = {tuple(int(part) for part in value.split(':')): name
                   for name, value in BGP_COMMUNITY_NAMES.items()}


def community_values(values, large=False):
    """Match FRR's numeric ordering and spelling of well-known values."""
    numbers = set()
    for value in values:
        if not large:
            value = BGP_COMMUNITY_NAMES.get(value, value)
        numbers.add(tuple(int(part) for part in value.split(':')))
    native = []
    for number in sorted(numbers):
        value = ':'.join(str(part) for part in number)
        native.append(value if large else COMMUNITY_NAMES.get(number, value))
    return ' '.join(native)


def filter_operand(rule, family=None):
    """Normalize prefixes and wildcard comparisons to FRR's native spelling."""
    if family == 'mac':
        return rule.get('address', 'any').lower()

    if 'prefix' in rule:
        operand = str(ipaddress.ip_network(rule['prefix']))
        if 'exact-match' in rule:
            operand += ' exact-match'
    elif 'address' in rule:
        mask = int(ipaddress.IPv4Address(rule['wildcard-mask']))
        address = int(ipaddress.IPv4Address(rule['address'])) & (~mask & 0xffffffff)
        if mask == 0:
            operand = str(ipaddress.IPv4Address(address))
        elif mask == 0xffffffff:
            operand = 'any'
        else:
            operand = f'{ipaddress.IPv4Address(address)} {ipaddress.IPv4Address(mask)}'
    else:
        operand = 'any'

    for key in ('ge', 'le'):
        if key in rule:
            operand += f' {key} {int(rule[key])}'
    return operand


def extended_values(rule):
    """Render each extended community with its native type discriminator."""
    return ' '.join(f'{native} {value}'
                    for key, native in (('route-target', 'rt'), ('site-of-origin', 'soo'))
                    for value in sorted({rd_rt(value) for value in rule.get(key, ())}))


def matches(values):
    commands = []
    evpn = values.get('evpn', {})
    if 'route-type' in evpn:
        names = {'1': 'ead', '2': 'macip', '3': 'multicast', '4': 'es', '5': 'prefix'}
        commands.append('match evpn route-type ' + names[evpn['route-type']])
    if 'vni' in evpn:
        commands.append(f"match evpn vni {int(evpn['vni'])}")
    if 'route-distinguisher' in evpn:
        commands.append('match evpn rd ' + rd_rt(evpn['route-distinguisher']))
    if 'default-route' in evpn:
        commands.append('match evpn default-route')
    if 'mac' in values:
        commands.append('match mac address ' + values['mac']['access-list'])

    for family, keyword in (('ipv4', 'ip'), ('ipv6', 'ipv6')):
        matches = values.get(family, {})
        for field, settings in (('address', matches), ('next-hop', matches.get('next-hop', {}))):
            for kind in ('access-list', 'prefix-list'):
                if kind in settings:
                    qualifier = ' prefix-list' if kind == 'prefix-list' else ''
                    commands.append(f'match {keyword} {field}{qualifier} {settings[kind]}')
            if field == 'next-hop' and 'address' in settings:
                commands.append(f"match {keyword} next-hop address {ipaddress.ip_address(settings['address'])}")

    for key in ('interface', 'metric', 'tag'):
        if key in values:
            value = values[key] if key == 'interface' else int(values[key])
            commands.append(f'match {key} {value}')
    for key, native in (('as-path-list', 'as-path'), ('as-path-count', 'as-path-count'),
                        ('local-preference', 'local-preference'), ('peer', 'peer'), ('source-peer', 'src-peer')):
        if key in values:
            value = values[key]
            if key in ('as-path-count', 'local-preference'):
                value = str(int(value))
            elif key in ('peer', 'source-peer'):
                try:
                    value = str(ipaddress.ip_address(value))
                except ValueError:
                    pass
            commands.append(f'match {native} {value}')
    for kind in ('community-list', 'large-community-list', 'extended-community-list'):
        for name, flags in values.get(kind, {}).items():
            suffix = ' exact-match' if 'exact-match' in flags else ' any' if 'any' in flags else ''
            native = 'extcommunity' if kind == 'extended-community-list' else kind.removesuffix('-list')
            commands.append(f'match {native} {name}{suffix}')
    if 'extended-community-limit' in values:
        commands.append(f'match extcommunity-limit {int(values["extended-community-limit"])}')
    return commands


def key_lifetime(values):
    """Translate router-local times to FRR's fixed English month syntax."""
    from datetime import datetime

    def native_time(value):
        instant = datetime.fromisoformat(value)
        month = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec')[instant.month - 1]
        return f'{instant:%H:%M:%S} {month} {instant.day} {instant.year}'

    start = native_time(values['start'])
    if 'end' in values:
        return start + ' ' + native_time(values['end'])
    if 'duration' in values:
        return start + ' duration ' + str(int(values['duration']))
    return start + ' infinite'


def actions(values):
    commands = []
    for family, address in values.get('evpn', {}).get('gateway-ip', {}).items():
        commands.append(f'set evpn gateway-ip {family} {ipaddress.ip_address(address)}')

    for key in ('metric-type', 'forwarding-address'):
        if key in values:
            commands.append(f'set {key} {values[key]}')
    if 'tag' in values:
        commands.append(f"set tag {int(values['tag'])}")
    for key in ('metric', 'local-preference', 'weight'):
        if key in values:
            value = values[key]
            sign = value[0] if value[0] in '+-' else ''
            commands.append(f'set {key} {sign}{abs(int(value))}')
    if 'origin' in values:
        commands.append(f"set origin {values['origin']}")

    for family, keyword in (('ipv4', 'ip'), ('ipv6', 'ipv6')):
        for mode, value in values.get(family, {}).get('next-hop', {}).items():
            if mode == 'address':
                command = str(ipaddress.ip_address(value))
            elif mode in ('global', 'local'):
                command = f'{mode} {ipaddress.ip_address(value)}'
            else:
                command = mode
            commands.append(f'set {keyword} next-hop {command}')

    prepend = values.get('as-path', {}).get('prepend')
    if prepend is not None:
        commands.append('set as-path prepend ' + ' '.join(str(int(asn)) for asn in prepend.split()))
    path = values.get('as-path', {})
    if 'prepend-last-as' in path:
        commands.append(f"set as-path prepend last-as {int(path['prepend-last-as'])}")
    for mode in ('exclude', 'replace'):
        selection = path.get(mode)
        if selection is None:
            continue
        if 'as-path-list' in selection:
            operand = 'as-path-access-list ' + selection['as-path-list']
        elif 'as-number' in selection:
            numbers = selection['as-number'] if mode == 'exclude' else [selection['as-number']]
            operand = ' '.join(str(int(number)) for number in numbers)
        else:
            operand = 'all' if mode == 'exclude' else 'any'
        if 'replacement' in selection:
            operand += f" {int(selection['replacement'])}"
        commands.append(f'set as-path {mode} {operand}')

    for kind in ('community', 'large-community'):
        communities = values.get(kind, ())
        if communities:
            text = 'none' if 'none' in communities else community_values(
                [value for value in communities if value != 'additive'], large=kind == 'large-community')
            if 'additive' in communities:
                text += ' additive'
            commands.append(f'set {kind} {text}')
        if kind + '-delete' in values:
            native = 'comm-list' if kind == 'community' else 'large-comm-list'
            commands.append(f"set {native} {values[kind + '-delete']} delete")
    extended = values.get('extended-community', {})
    if 'none' in extended:
        commands.append('set extcommunity none')
    if 'route-target' in extended:
        commands.append('set extcommunity rt ' + ' '.join(sorted({rd_rt(value) for value in extended['route-target']})))
    if 'site-of-origin' in extended:
        commands.append('set extcommunity soo ' + rd_rt(extended['site-of-origin']))
    if 'extended-community-delete' in values:
        commands.append(f'set extended-comm-list {values["extended-community-delete"]} delete')
    return commands
