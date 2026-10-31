"""Pure nftables formatting shared by firewall and NAT templates.

Values arrive schema-validated; verification and kernel mutations live elsewhere.
"""

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, replace

from nvyr.helpers import interface_patterns, nftables_helpers, nftables_timeouts
from nvyr.helpers.validators import duration_seconds, limit_amount, RATE_UNITS, DURATION_UNITS, LOG_FLAGS
from nvyr.helpers.validators import tcp_flags_mask, tcp_flag_values, tcp_flag_requirements
from nvyr.helpers.validators import connection_quantity, connection_label_mask
from nvyr.helpers.nftables_singletons import NFT_SINGLETON_GROUPS, included_members
from nvyr.tree import lookup
from nvyr.helpers import nftables_modify


# These transports share the source/destination port layout used by th expressions.
NFT_PORT_PROTOCOLS = frozenset({'tcp', 'udp', 'udplite', 'sctp', 'dccp'})
NFT_NAT_PORT_PROTOCOLS = frozenset({'tcp', 'udp'})


NFT_PACKET_HOOKS = frozenset({'ingress', 'prerouting', 'input', 'forward', 'output', 'postrouting'})


@dataclass(frozen=True)
class NftKey:
    expression: str
    side: str
    multi: bool = False
    flag: bool = False
    omit_value: str | None = None
    mask_kind: str | None = None
    comparisons: bool = False
    datatype: str | dict | None = None
    size: int | dict | None = None
    operator: str = ''
    dynamic: bool = False
    path: tuple = ()
    interval: bool = False
    hooks: frozenset = NFT_PACKET_HOOKS


# Insertion order is the canonical rule order, independent of CLI input order.
NFT_KEYMAP = {
    'state': NftKey('ct state', 'left', multi=True, datatype='ct_state', size=4, dynamic=True, path=('connection', 'state')),
    # Explicit equality prevents singleton sets becoming an implicit bit test.
    'connection-status': NftKey('ct status', 'left', multi=True, operator='==', datatype='ct_status', size=4, dynamic=True, path=('connection', 'status')),
    'packet-type': NftKey('meta pkttype', 'left', datatype='pkt_type', size=1, dynamic=True),
    'inbound-interface': NftKey('iifname', 'left', multi=True, datatype='ifname', size=16, dynamic=True),
    'outbound-interface': NftKey('oifname', 'left', multi=True, datatype='ifname', size=16, dynamic=True),
    'inbound-link-group': NftKey('meta iifgroup', 'left', multi=True, datatype='devgroup', size=4, dynamic=True),
    'outbound-link-group': NftKey('meta oifgroup', 'left', multi=True, datatype='devgroup', size=4, dynamic=True),
    'vlan-id': NftKey('vlan id', 'left', size=2, path=('vlan', 'id'), hooks=frozenset({'ingress'})),
    'vlan-priority': NftKey('vlan pcp', 'left', size=1, path=('vlan', 'priority'), hooks=frozenset({'ingress'})),
    'source-mac': NftKey('ether saddr', 'left', multi=True, mask_kind='mac', datatype='ether_addr', size=6, dynamic=True),
    'destination-mac': NftKey('ether daddr', 'left', multi=True, mask_kind='mac', datatype='ether_addr', size=6, dynamic=True),
    'source-address': NftKey('{family} saddr', 'left', multi=True, mask_kind='ip', datatype={4: 'ipv4_addr', 6: 'ipv6_addr'}, size={4: 4, 6: 16}, dynamic=True),
    'destination-address': NftKey('{family} daddr', 'left', multi=True, mask_kind='ip', datatype={4: 'ipv4_addr', 6: 'ipv6_addr'}, size={4: 4, 6: 16}, dynamic=True),
    'packet-mark': NftKey('meta mark', 'left', multi=True, datatype='mark', size=4, dynamic=True),
    'connection-mark': NftKey('ct mark', 'left', multi=True, datatype='mark', size=4, dynamic=True, path=('connection', 'mark'), interval=True),
    'dscp': NftKey('{family} dscp', 'left', multi=True, datatype='dscp', size=1, dynamic=True),
    'ttl': NftKey('{ttl}', 'left', comparisons=True),
    'protocol': NftKey('meta l4proto', 'left', multi=True, datatype='inet_proto', size=1, dynamic=True),
    'tcp-flags': NftKey('tcp flags', 'left', multi=True, operator='==', datatype='tcp_flag', size=1, dynamic=True),
    'packet-length': NftKey('meta length', 'left', multi=True),
    'icmp-type': NftKey('{icmp} type', 'left', multi=True, datatype={4: 'icmp_type', 6: 'icmpv6_type'}, size=1, dynamic=True),
    'icmp-code': NftKey('{icmp} code', 'left', multi=True, datatype={4: 'icmp_code', 6: 'icmpv6_code'}, size=1, dynamic=True),
    'source-port': NftKey('th sport', 'left', multi=True, datatype='inet_service', size=2, dynamic=True),
    'destination-port': NftKey('th dport', 'left', multi=True, datatype='inet_service', size=2, dynamic=True),
    'tcp-mss': NftKey('tcp option maxseg size', 'left', multi=True),
    'nftrace': NftKey('meta nftrace set 1', 'right', flag=True),
    'log': NftKey('log', 'right', flag=True),
    'counter': NftKey('counter', 'right', flag=True),
    'last-used': NftKey('last', 'right', flag=True),
    'notrack': NftKey('notrack', 'right', flag=True),
}

# Conntrack fields use the same keymap and native ordering as packet matches.
for _name, _expression, _datatype, _size, _interval in (
    ('direction', 'direction', 'ct_dir', 1, False),
    ('family', 'l3proto', 'nf_proto', 1, False),
    ('protocol', 'protocol', 'inet_proto', 1, False),
    ('zone', 'zone', None, 2, True),
    ('helper', 'helper', None, 16, False),
    ('id', 'id', None, 4, True),
    ('expiration', 'expiration', 'time', 4, True),
):
    NFT_KEYMAP['connection-' + _name] = NftKey(
        'ct ' + _expression, 'left', multi=True, datatype=_datatype, size=_size,
        path=('connection', _name), interval=_interval, comparisons=_name == 'expiration', dynamic=True)

NFT_KEYMAP['connection-label'] = NftKey(
    'ct label', 'left', multi=True, path=('connection', 'label'), size=16)

for _direction in ('original', 'reply', 'total'):
    for _name, _native in (('packets', 'packets'), ('bytes', 'bytes'), ('average-packet-size', 'avgpkt')):
        _expression = 'ct ' + ('' if _direction == 'total' else _direction + ' ') + _native
        NFT_KEYMAP[f'connection-{_direction}-{_name}'] = NftKey(
            _expression, 'left', comparisons=True, size=8, interval=True, dynamic=True,
            path=('connection', _direction, _name))

    if _direction == 'total':
        continue

    for _side, _native in (('source', 'src'), ('destination', 'dst')):
        NFT_KEYMAP[f'connection-{_direction}-{_side}-address'] = NftKey(
            f'ct {_direction} {{family}} {_native[0]}addr', 'left', multi=True,
            datatype={4: 'ipv4_addr', 6: 'ipv6_addr'}, size={4: 4, 6: 16},
            path=('connection', _direction, _side + '-address'), interval=True, dynamic=True)
        NFT_KEYMAP[f'connection-{_direction}-{_side}-port'] = NftKey(
            f'ct {_direction} proto-{_native}', 'left', multi=True,
            datatype='inet_service', size=2, interval=True, dynamic=True,
            path=('connection', _direction, _side + '-port'))

    NFT_KEYMAP[f'connection-{_direction}-zone'] = NftKey(
        f'ct {_direction} zone', 'left', multi=True, size=2, interval=True, dynamic=True,
        path=('connection', _direction, 'zone'))


NFT_FAMILY_FIELDS = frozenset(
    name for name, key in NFT_KEYMAP.items()
    if '{' in key.expression or name == 'connection-family')


# Connection metadata is unavailable before tracking, and ingress has no output device.
for _name, _key in tuple(NFT_KEYMAP.items()):
    if _key.path[:1] == ('connection',) or _name in {'outbound-interface', 'outbound-link-group'}:
        NFT_KEYMAP[_name] = replace(_key, hooks=_key.hooks - {'ingress'})


def nft_field_value(configuration, field, default=None, *, negative=False):
    path = NFT_KEYMAP[field].path or (field,)
    if negative:
        path = (*path[:-1], 'not', path[-1])
    return lookup(configuration, path, default)


def _field_index(*, negative=False):
    """Index field paths once so absent configuration branches require no lookups."""
    index = {}
    for field, key in NFT_KEYMAP.items():
        path = key.path or (field,)
        if negative:
            path = (*path[:-1], 'not', path[-1])

        branch = index
        for part in path[:-1]:
            branch = branch.setdefault(part, {})
        branch[path[-1]] = field
    return index


_FIELD_INDEX = _field_index()
_NEGATIVE_FIELD_INDEX = _field_index(negative=True)
_FIELD_ORDER = {name: position for position, name in enumerate(NFT_KEYMAP)}


def nft_present_fields(configuration, *, negative=False):
    """Visit configured matching fields, including nested connection exclusions."""
    fields = set()

    def visit(values, index):
        if not isinstance(values, Mapping):
            return

        for name in values:
            branch = index.get(name)
            if isinstance(branch, str):
                fields.add(branch)
            elif branch is not None:
                visit(values[name], branch)

    visit(configuration, _NEGATIVE_FIELD_INDEX if negative else _FIELD_INDEX)
    return fields


NFT_SINGLETON_REFERENCES = {
    'inbound-interface-group': ('interface-group', 'inbound-interface'),
    'outbound-interface-group': ('interface-group', 'outbound-interface'),
    'source-address-group': ('address-group', 'source-address'),
    'source-domain-group': ('domain-group', 'source-address'),
    'destination-domain-group': ('domain-group', 'destination-address'),
    'destination-address-group': ('address-group', 'destination-address'),
    'source-mac-group': ('mac-group', 'source-mac'),
    'destination-mac-group': ('mac-group', 'destination-mac'),
    'source-port-group': ('port-group', 'source-port'),
    'destination-port-group': ('port-group', 'destination-port'),
}

# nftables 1.1.7 defines these two symbols as bit positions (13 and 14),
# not masks. Keep their correct literals until the upstream symbols are fixed.
NFT_STATUS_LITERALS = {'helper': '0x2000', 'offload': '0x4000'}

# Native entrypoint names map to their configuration hook and priority stage.
NFT_FILTER_HOOKS = {
    'ingress': ('ingress', 'filter'),
    'input': ('input', 'filter'),
    'forward': ('forward', 'filter'),
    'output': ('output', 'filter'),
    'prerouting': ('prerouting', 'raw'),
    'output_raw': ('output', 'raw'),
}
NFT_HOOK_LABELS = {'ingress': 'ING', 'input': 'INP', 'output': 'OUT', 'forward': 'FWD', 'prerouting': 'PRE'}
NFT_COMPARISONS = {'eq': '==', 'lt': '<', 'gt': '>'}
NFT_VERDICT_LABELS = {'accept': 'A', 'drop': 'D', 'reject': 'R', 'continue': 'C',
                      'return': 'R', 'jump': 'J', 'offload': 'O', 'map': 'M'}

NFT_FIB_LOOKUP = {
    'source-address': 'saddr',
    'destination-address': 'daddr',
    'inbound-interface': 'iif',
    'outbound-interface': 'oif',
    'packet-mark': 'mark',
}

# Translation fragments concatenate into a target, followed by comma-separated
# flags. As with NFT_KEYMAP, insertion order defines canonical output order.
NFT_NAT_KEYMAP = {
    'address': NftKey(' ip to {value}', 'target', omit_value='masquerade'),
    'port': NftKey('{port_separator}{value}', 'target'),
    'persistent': NftKey('persistent', 'flags', flag=True),
    'port-mapping': NftKey('{value}', 'flags', omit_value='default'),
}
NFT_NAT_ACTIONS = {
    'source': ('snat', 'S'),
    'destination': ('dnat', 'D'),
    'masquerade': ('masquerade', 'M'),
    'exclude': ('return', 'E'),
}
NFT_NAT_HOOK_LABELS = {'source': 'POST', 'destination': 'PRE'}


def nft_group_fields(configuration):
    """Use keymap order for declarations, element tuples and packet lookups."""
    matches = configuration.get('match', {})
    if not matches:
        return []
    selected = nft_present_fields(matches)
    return [name for name, field in NFT_KEYMAP.items()
            if field.size and name != 'connection-label' and name in selected]


def nft_field_type(name, family):
    if family == 'inet' and name in NFT_FAMILY_FIELDS:
        raise ValueError(f'{name} is not a family-neutral field')
    field = NFT_KEYMAP[name]
    version = 4 if family == 'ipv4' else 6
    datatype = field.datatype[version] if isinstance(field.datatype, dict) else field.datatype
    size = field.size[version] if isinstance(field.size, dict) else field.size
    return datatype, size


def nft_field_expression(name, family):
    if family == 'inet' and name in NFT_FAMILY_FIELDS:
        raise ValueError(f'{name} is not a family-neutral field')
    return NFT_KEYMAP[name].expression.format(
        family='ip' if family == 'ipv4' else 'ip6',
        ttl='ip ttl' if family == 'ipv4' else 'ip6 hoplimit',
        icmp='icmp' if family == 'ipv4' else 'icmpv6',
    )


def nft_map_name(family, name):
    return f'{family}_map_{name}'


def nft_group_lookup(family, configuration):
    expressions = []
    for name in nft_group_fields(configuration):
        expression = nft_field_expression(name, family)
        if name == 'tcp-flags':
            mask = nft_group_tcp_mask(configuration)
            expression = f'(tcp flags & {mask})' if mask != 255 else expression
        expressions.append(expression)
    return ' . '.join(expressions)


def nft_group_tcp_mask(configuration):
    # Learned keys must retain all flags, independently of configured entries.
    if 'dynamic' in configuration:
        return 255
    values = [entry['tcp-flags'] for entry in configuration.get('entry', {}).values() if 'tcp-flags' in entry]
    return tcp_flags_mask(values) or 255


def nft_group_protocols(family, fields, result_type=None):
    """Packet protocols admitted by a group's structural header guard, if any."""
    fields = set(fields)
    if 'tcp-flags' in fields:
        return {'tcp'}
    if fields & {'icmp-type', 'icmp-code'}:
        return {'icmp' if family == 'ipv4' else 'ipv6-icmp'}
    if result_type in {'port', 'address-port'}:
        return NFT_NAT_PORT_PROTOCOLS
    if fields & {'source-port', 'destination-port'}:
        return NFT_PORT_PROTOCOLS
    return None


def nft_group_guard(family, fields, result_type=None):
    connection_ports = {name for name in fields if name.startswith('connection-') and name.endswith('-port')}
    protocols = ', '.join(sorted(NFT_PORT_PROTOCOLS))
    guard = f'ct protocol {{ {protocols} }} ' if connection_ports else ''
    packet_protocols = nft_group_protocols(family, fields, result_type)
    if packet_protocols:
        value = next(iter(packet_protocols)) if len(packet_protocols) == 1 else '{ ' + ', '.join(sorted(packet_protocols)) + ' }'
        guard += f'meta l4proto {value} '
    return guard


def nft_map_results(configuration):
    """Traverse explicit and fallback results for jump and hook analysis."""
    for entry in configuration.get('entry', {}).values():
        yield entry.get('result', {})
    if 'default-result' in configuration:
        yield configuration['default-result']


def _nft_group_value(name, value):
    if name in {'source-address', 'destination-address'} or (name.startswith('connection-') and name.endswith('-address')):
        if '/' in value:
            return str(ipaddress.ip_network(value, strict=False))

        if '-' in value:
            return '-'.join(str(ipaddress.ip_address(part)) for part in value.split('-'))

        return str(ipaddress.ip_address(value))

    if name in {'source-mac', 'destination-mac'}:
        return value.lower()

    return _nft_value(name, value)


def nft_match_group_name(family, name):
    return f'{family}_match_group_{name}'


def nft_learned_member(fields, values):
    """Format one exact runtime key in the group's canonical field order."""
    parts = []
    for field in fields:
        value = values[field]
        if field == 'tcp-flags':
            # A learned key stores the complete byte, not a rule's masked pattern.
            bits = int(value) if value.isdecimal() else tcp_flag_requirements(value)[1]
            parts.append(str(bits))
        else:
            parts.append(_nft_group_value(field, value))

    return ' . '.join(parts)


def nft_icmp_group_name(family, name):
    return f'{family}_icmp_group_{name}'


def nft_icmp_group_fields(configuration):
    return ['icmp-type', 'icmp-code'] if configuration['match'] == 'type-code' else ['icmp-type']


def nft_icmp_group(family, name, configuration, global_options=None):
    """Keep each code interval paired with its own type in a native set."""
    fields = nft_icmp_group_fields(configuration)
    declaration = ' . '.join(nft_field_type(field, family)[0] for field in fields)
    lines = [f'set {nft_icmp_group_name(family, name)} {{', f'    type {declaration};']
    if 'description' in configuration:
        lines.append(f'    comment "{configuration["description"]}";')

    values = []
    has_intervals = False
    for typename, options in sorted(configuration.get('type', {}).items()):
        if configuration['match'] == 'type-code':
            for code in sorted(options['code'], key=lambda value: int(value.split('-')[0])):
                values.append(typename + ' . ' + code)
                has_intervals = has_intervals or '-' in code
        else:
            values.append(typename)

    if has_intervals:
        lines.append('    flags interval;')
    lines.extend(_nft_group_tracking(configuration, global_options))
    if values:
        lines.append('    elements = { ' + ', '.join(values) + ' };')
    lines.append('}')
    return '\n'.join(lines)


def singleton_groups(configuration):
    """Iterate configured singleton groups without copying their contents."""
    for kind in NFT_SINGLETON_GROUPS:
        families = ('ipv4', 'ipv6') if kind in ('address-group', 'domain-group') else (None,)
        for family in families:
            definitions = configuration.get(kind, {})
            if family:
                definitions = definitions.get(family, {})
            for name, definition in definitions.items():
                yield kind, family, name, definition


def nft_singleton_name(kind, family, name):
    prefix = kind.replace('-', '_')
    if kind in ('address-group', 'domain-group'):
        prefix = family + '_' + prefix
    return prefix + '_' + name


def _nft_group_tracking(configuration, global_options):
    """Declare per-element tracking selected locally or inherited globally."""
    statements = []
    for option, statement in (('counter', 'counter'), ('last-used', 'last')):
        if option in configuration or option in (global_options or {}):
            statements.append(f'    {statement};')
    return statements


def nft_duration(value):
    """Serialize long durations without exceeding nft's eight-digit components."""
    seconds = duration_seconds(value)
    parts = []
    for suffix, unit in (('d', 86400), ('h', 3600), ('m', 60), ('s', 1)):
        count, seconds = divmod(seconds, unit)
        if count:
            parts.append(f'{count}{suffix}')
    return ''.join(parts)


def _nft_dynamic_options(configuration):
    if 'dynamic' not in configuration:
        return []

    options = configuration['dynamic']
    return [
        '    flags dynamic,timeout;',
        f"    timeout {nft_duration(options['timeout'])};",
        f"    size {options['size']};",
        f"    gc-interval {nft_duration(options['gc-interval'])};",
    ]


def nft_singleton_group(kind, family, name, configuration, global_options=None, groups=None):
    """Render a reusable one-field set, independent of its packet direction."""
    member, field = NFT_SINGLETON_GROUPS[kind]
    datatype, _ = nft_field_type(field, family)
    object_name = nft_singleton_name(kind, family, name)
    lines = [f'set {object_name} {{', f'    type {datatype};']
    if 'description' in configuration:
        lines.append(f'    comment "{configuration["description"]}";')

    members = configuration.get(member, ())
    if configuration.get('include-group') and kind != 'domain-group':
        definitions = groups[kind]
        if family:
            definitions = definitions[family]
        members = included_members(definitions, name, member)

    if kind == 'interface-group':
        members = interface_patterns.normalize(members)
        if any(member.endswith('*') for member in members):
            lines.append('    flags interval;')

    values = sorted({_nft_group_value(field, value) for value in members})
    if (kind in ('address-group', 'domain-group') and 'dynamic' not in configuration or
            kind == 'port-group' and any('/' in value or '-' in value for value in values)):
        # Native interval merging represents overlapping membership as a union.
        lines.extend(['    flags interval;', '    auto-merge;'])

    lines.extend(_nft_dynamic_options(configuration))
    lines.extend(_nft_group_tracking(configuration, global_options))

    if values:
        lines.append('    elements = { ' + ', '.join(values) + ' };')
    lines.append('}')
    return '\n'.join(lines)


def nft_map(family, name, configuration, global_options=None):
    return _nft_group(family, name, configuration, global_options, kind='map')


def nft_match_group(family, name, configuration, global_options=None):
    return _nft_group(family, name, configuration, global_options, kind='set')


def _nft_group(family, name, configuration, global_options, *, kind):
    """Render the same typed keys, comments and tracking for maps and sets."""
    fields = nft_group_fields(configuration)
    types = [nft_field_type(field, family)[0] for field in fields]
    use_typeof = None in types
    declaration = nft_group_lookup(family, configuration) if use_typeof else ' . '.join(types)
    object_name = nft_match_group_name(family, name)
    if kind == 'map':
        object_name = nft_map_name(family, name)
        address_type = nft_field_type('destination-address', family)[0] if family != 'inet' else ''
        result_type = {'verdict': 'verdict', 'address': address_type, 'port': 'inet_service',
                       'address-port': address_type + ' . inet_service'}[configuration['result-type']]
        if use_typeof:
            address = 'ip daddr' if family == 'ipv4' else 'ip6 daddr'
            result_type = {'verdict': 'verdict', 'address': address, 'port': 'th dport',
                           'address-port': address + ' . th dport'}[configuration['result-type']]
        declaration += ' : ' + result_type

    keyword = 'typeof' if use_typeof else 'type'
    lines = [f'{kind} {object_name} {{', f'    {keyword} {declaration};']
    if 'description' in configuration:
        lines.append(f'    comment "{configuration["description"]}";')

    entries = configuration.get('entry', {})
    tcp_mask = nft_group_tcp_mask(configuration) if 'tcp-flags' in fields else None

    # Prefixes and ranges need interval storage; exact groups avoid that overhead.
    if any(('/' in nft_field_value(entry, field) or '-' in nft_field_value(entry, field))
           for entry in entries.values() for field in fields
           if NFT_KEYMAP[field].interval or field in {'source-address', 'destination-address', 'source-port', 'destination-port',
                        'packet-mark', 'connection-mark', 'dscp'}):
        lines.append('    flags interval;')

    lines.extend(_nft_dynamic_options(configuration))
    lines.extend(_nft_group_tracking(configuration, global_options))

    if entries or (kind == 'map' and 'default-result' in configuration):
        elements = []
        for identifier, entry in sorted(entries.items()):
            flags = tcp_flag_values(entry['tcp-flags'], tcp_mask) if tcp_mask is not None else [None]
            for flag_value in flags:
                key = ' . '.join(str(flag_value) if field == 'tcp-flags' else _nft_group_value(field, nft_field_value(entry, field))
                                 for field in fields)
                element = key + ' comment ' + nft_comment(identifier, entry.get('description', ''))
                if kind == 'map':
                    element += ' : ' + _nft_map_result(family, configuration['result-type'], entry['result'])
                elements.append('        ' + element)
        if kind == 'map' and 'default-result' in configuration:
            value = _nft_map_result(family, configuration['result-type'], configuration['default-result'])
            elements.append('        * comment ' + nft_comment('default', '') + ' : ' + value)
        lines.extend(['    elements = {', ',\n'.join(elements), '    };'])

    lines.append('}')
    return '\n'.join(lines)


def _nft_map_result(family, kind, result):
    if kind == 'verdict':
        value = result['action']
        if value == 'jump':
            value += ' ' + nft_named_chain(family, result['jump-target'])
        return value

    values = []
    if 'address' in result:
        values.append(str(ipaddress.ip_address(result['address'])))
    if 'port' in result:
        values.append(result['port'])
    return ' . '.join(values)


def _nft_value(key, value):
    if key == 'icmp-code':
        return str(int(value))

    if key in {'inbound-interface', 'outbound-interface', 'connection-helper'}:
        return '"' + value + '"'

    if key == 'connection-status':
        flags = sorted(set(value.split(',')))
        symbols = [NFT_STATUS_LITERALS.get(flag, flag) for flag in flags]
        return ' | '.join(symbols)

    if key == 'connection-expiration':
        return str(connection_quantity(value, 'expiration')) + 's'
    if key.startswith('connection-') and key.endswith(('packets', 'bytes', 'average-packet-size')):
        kind = 'packets' if key.endswith('packets') else 'bytes'
        return str(connection_quantity(value, kind))

    return value


def connection_label_plan(values):
    """Reduce positive label alternatives, then bound any required expansion."""
    masks = sorted({connection_label_mask(value) for value in values}, key=int.bit_count)
    minimal = []
    for mask in masks:
        if not any(mask & prior == prior for prior in minimal):
            minimal.append(mask)

    mask = 0
    for value in minimal:
        mask |= value
    if len(minimal) == 1:
        return 'all', mask, [mask]
    if all(value.bit_count() == 1 for value in minimal):
        return 'any', mask, []

    alternatives = set()
    for required in minimal:
        free = [1 << bit for bit in range(128) if mask & (1 << bit) and not required & (1 << bit)]
        if 2 ** len(free) > 4096:
            raise ValueError('connection label alternatives exceed 4096 generated values; simplify the combinations')
        for selection in range(2 ** len(free)):
            value = required
            for index, bit in enumerate(free):
                if selection & (1 << index):
                    value |= bit
            alternatives.add(value)
            if len(alternatives) > 4096:
                raise ValueError('connection label alternatives exceed 4096 generated values; simplify the combinations')
    return 'set', mask, sorted(alternatives)


def nft_connection_labels(values, negative=False):
    mode, mask, alternatives = connection_label_plan(values)
    bits = [bit for bit in range(128) if mask & (1 << bit)]
    if mode == 'any':
        if negative:
            return ' '.join(f'ct label & {bit} != {bit}' for bit in bits)
        return 'ct label ' + ','.join(str(bit) for bit in bits)

    expression = 'ct label & (' + _nft_label_bits(mask) + ')'
    operator = ' != ' if negative else ' == '
    if mode == 'all':
        return expression + operator + '(' + _nft_label_bits(mask) + ')'
    return expression + operator + '{ ' + ', '.join(_nft_label_bits(value) for value in alternatives) + ' }'


def _nft_label_bits(mask):
    # ct_label literals identify bit positions; OR combines their actual masks.
    return ' | '.join(str(bit) for bit in range(128) if mask & (1 << bit))


def nft_comment(number, description=''):
    # nft's native lexer does not unescape quoted strings; JSON quoting would
    # corrupt backslashes. The schema excludes embedded quotes/control characters
    # and bounds the description and rule number to fit nft's comment limit.
    return f'"{number}|{description}"'


def nft_hook_families(firewall, entrypoint):
    from nvyr.helpers import nftables_zones as zones
    from nvyr.helpers import nftables_source_validation as source_validation

    hook, stage = NFT_FILTER_HOOKS[entrypoint]
    families = ('ipv4', 'ipv6')

    return [family for family in families
            if stage in firewall.get(family, {}).get(hook, {})
            or (entrypoint == 'prerouting' and source_validation.active(firewall, family))
            or (stage == 'filter' and hook in zones.active_hooks(firewall))
            or (entrypoint == 'forward' and 'flowtable' in firewall.get('global-options', {}))]


def nft_active_hooks(firewall):
    """Select hooks with direct inet rules or configured family chains."""
    from nvyr.helpers import nftables_source_validation as source_validation

    return [entrypoint for entrypoint, (hook, stage) in NFT_FILTER_HOOKS.items()
            if nft_hook_families(firewall, entrypoint)
            or (entrypoint in nftables_helpers.HOOKS and nftables_helpers.configured(firewall))
            or (entrypoint == 'prerouting' and source_validation.active(firewall, 'inet'))
            or stage in firewall.get('inet', {}).get(hook, {})]


def nft_family_dispatch(firewall, hook):
    """Dispatch a filter/raw hook to only the configured family chains."""
    if hook == 'ingress':
        lines = []
        for family in nft_hook_families(firewall, hook):
            devices = lookup(firewall, (family, 'ingress', 'filter', 'interface'), [])
            selectors = ', '.join(f'"{device}"' for device in interface_patterns.normalize(devices))
            lines.append(f'meta nfproto {family} iifname {{ {selectors} }} jump {family}_ingress')
        return '\n'.join(lines)
    return _nft_dispatch(nft_hook_families(firewall, hook), hook)


def nft_hook_declaration(firewall, entrypoint):
    """Bind ingress before flowtables; other entrypoints retain their native priorities."""
    hook, stage = NFT_FILTER_HOOKS[entrypoint]
    if hook == 'ingress':
        devices = []
        for family in (*nft_hook_families(firewall, entrypoint), 'inet'):
            devices.extend(lookup(firewall, (family, hook, stage, 'interface'), []))
        selectors = ', '.join(f'"{device}"' for device in interface_patterns.normalize(devices))
        return f'type filter hook ingress devices = {{ {selectors} }} priority -10; policy accept;'
    return f'type filter hook {hook} priority {stage}; policy accept;'


def _nft_dispatch(families, target):
    entries = [f'{family} : jump {family}_{target}' for family in families]
    return 'meta nfproto vmap { ' + ', '.join(entries) + ' }' if entries else ''


def nft_nat_dispatch(nat, hook):
    direction = {'prerouting': 'destination', 'postrouting': 'source'}[hook]
    return _nft_dispatch(['ipv4'] if direction in nat else [], 'nat_' + hook)


def nft_reject_response(rule, global_options=None):
    """Resolve the response without writing inherited values into configuration."""
    return rule.get('reject-response', (global_options or {}).get('reject-response'))


def nft_reject(family, response=None):
    """Use ICMPX for portable codes and native ICMP for family-specific codes."""
    if response is None:
        return 'reject'
    if response == 'tcp-reset':
        return 'reject with tcp reset'

    if response in {'port-unreachable', 'admin-prohibited', 'no-route', 'host-unreachable'}:
        protocol = 'icmpx'
    else:
        protocol = 'icmp' if family == 'ipv4' else 'icmpv6'
    return f'reject with {protocol} type {response}'


def nft_state_policy(policies, global_options=None, hook=None):
    """Render counted state policies; reject statements cannot be verdict-map values."""
    entries = []
    rejects = []
    for state, policy in sorted(policies.items()):
        if policy['action'] == 'reject':
            response = nft_reject(None, nft_reject_response({}, global_options))
            rejects.append(f'ct state {state} counter {response} comment {nft_comment(state)}')
        else:
            entries.append(f"{state} counter : {policy['action']}")

    lines = []
    target = (global_options or {}).get('flowtable')
    if hook == 'forward' and target is not None:
        lines.append('ct state established meta l4proto { tcp, udp } flow add @'
                     + nft_flowtable_name(target)
                     + ' counter comment "global-offload|Established forwarding flows"')

    if entries:
        lines.append('ct state vmap { ' + ', '.join(entries) + ' }')
    return '\n'.join(lines + rejects)


def nft_log_prefix(family, entrypoint, number, verdict):
    if entrypoint in NFT_FILTER_HOOKS:
        hook, stage = NFT_FILTER_HOOKS[entrypoint]
        label = f'{NFT_HOOK_LABELS[hook]}-{stage}'
    else:
        label = entrypoint

    return f'"[{family}-{label}-{number}-{NFT_VERDICT_LABELS[verdict]}]"'


def nft_named_chain(family, name):
    return f'{family}_name_{name}'


def nft_interface_contexts(configuration):
    """Resolve INPUT reachability once, including nested and verdict-map jumps."""
    from nvyr.helpers import nftables_zones as zones
    from nvyr.helpers.interfaces import configured

    firewall = configuration.get('firewall', {})
    members = {name for name, options in configured(configuration) if 'vrf' in options}
    groups = {name for name, options in firewall.get('group', {}).get('interface-group', {}).items()
              if 'vrf' in options}
    contexts = {}

    for family in ('ipv4', 'ipv6', 'inet'):
        chains = firewall.get(family, {}).get('name', {})
        maps = firewall.get('group', {}).get('map', {}).get(family, {})
        targets = {}
        for name, definition in maps.items():
            targets[name] = set()
            for verdict in nft_map_results(definition):
                if verdict.get('action') == 'jump' and 'jump-target' in verdict:
                    targets[name].add(verdict['jump-target'])

        pending = []
        for hook, target in zones.policy_targets(firewall, family):
            if target in chains:
                pending.append(('name_' + target, hook, chains[target]))
        for entrypoint, (hook, stage) in NFT_FILTER_HOOKS.items():
            chain = firewall.get(family, {}).get(hook, {}).get(stage)
            if chain is not None:
                pending.append((entrypoint, hook, chain))
        for name in chains:
            contexts[family, 'name_' + name] = {'hooks': set(), 'members': members, 'groups': groups}

        while pending:
            name, hook, chain = pending.pop()
            context = contexts.setdefault((family, name), {'hooks': set(), 'members': members, 'groups': groups})
            if hook in context['hooks']:
                continue
            context['hooks'].add(hook)

            for rule in chain.get('rule', {}).values():
                if 'disable' in rule:
                    continue
                jumps = targets.get(rule.get('map'), set())
                if rule.get('action') == 'jump' and 'jump-target' in rule:
                    jumps = jumps | {rule['jump-target']}
                for target in jumps:
                    if target in chains:
                        pending.append(('name_' + target, hook, chains[target]))
    return contexts


def nft_slave_match(matches, context, *, group=False):
    """VRF membership is declared in configuration, never inferred from the host."""
    if not context or 'input' not in context['hooks']:
        return False
    if group:
        return matches.get('inbound-interface-group') in context['groups']
    for selector in matches.get('inbound-interface', ()):
        if selector in context['members']:
            return True
        if selector.endswith('*') and any(interface_patterns.matches(selector, member)
                                         for member in context['members']):
            return True
    return False


def nft_slave_matches(chain, context):
    """Signature of expression choices, used for verification and chain lifecycle."""
    matches = set()
    for number, rule in chain.get('rule', {}).items():
        if 'disable' in rule:
            continue

        for negative, options in ((False, rule), (True, rule.get('not', {}))):
            for group in (False, True):
                if nft_slave_match(options, context, group=group):
                    matches.add((number, negative, group))
    return matches


def nft_flowtable_name(name):
    return f'flowtable_{name}'


def nft_flowtable(name, configuration):
    devices = ', '.join(f'"{device}"' for device in interface_patterns.normalize(configuration['interface']))
    counter = ' counter;' if 'counter' in configuration else ''
    return (f'flowtable {nft_flowtable_name(name)} {{ '
            f'hook ingress priority 0; devices = {{ {devices} }};{counter} }}')


def nft_default_rule(family, hook, configuration, global_options=None):
    action = configuration.get('default-action', 'accept')
    parts = ['counter']

    if 'default-log' in configuration:
        parts.append('log prefix ' + nft_log_prefix(family, hook, 'default', action))

    verdict = nft_reject(family, nft_reject_response({}, global_options)) if action == 'reject' else action
    parts.extend((verdict, 'comment ' + nft_comment('default', 'default-action ' + action)))

    return ' '.join(parts)


def _nft_mask_match(expression, address, mask, kind, operator='=='):
    """Compare only selected bits; a configured IP prefix also limits those bits."""
    if kind == 'ip':
        interface = ipaddress.ip_interface(address)
        address_type = type(interface.ip)
        bits = int(ipaddress.ip_address(mask)) & int(interface.network.netmask)
        mask = str(address_type(bits))
        value = str(address_type(int(interface.ip) & bits))
    else:
        bits = int(mask.replace(':', ''), 16)
        value = f'{int(address.replace(":", ""), 16) & bits:012x}'
        value = ':'.join(value[index:index + 2] for index in range(0, 12, 2))

    return f'{expression} & {mask} {operator} {value}'


def nft_fib(configuration):
    """Render a validated FIB query without binding interface names to indices."""
    fields = ' . '.join(flag for name, flag in NFT_FIB_LOOKUP.items()
                        if name in configuration['lookup'])
    parts = []
    for result, operator in ((configuration['result'], ''), (configuration['result'].get('not', {}), '!= ')):
        if 'route-type' in result:
            expression = 'type ' + operator + '{ ' + ', '.join(sorted(result['route-type'])) + ' }'
        elif 'outbound-interface' in result:
            interfaces = result['outbound-interface']
            if interfaces[0] in ('exists', 'missing'):
                expression = 'oif ' + interfaces[0]
            else:
                names = ', '.join(f'"{name}"' for name in sorted(interfaces))
                expression = 'oifname ' + operator + '{ ' + names + ' }'
        else:
            continue
        parts.append(f'fib {fields} {expression}')
    return ' '.join(parts)


def _nft_parts(family, rule, log_prefix, match_groups=None, limits=(), icmp_groups=None,
               interface_context=None, log_groups=None):
    """Shared match/statement rendering for filtering and NAT."""
    parts = []
    fields_by_polarity = {
        negative: sorted(nft_present_fields(rule, negative=negative), key=_FIELD_ORDER.__getitem__)
        for negative in (False, True)
    }

    for side in ('left', 'right'):
        for negative in (False, True):
            parts.extend(_nft_matches(family, rule, fields_by_polarity[negative], side, log_prefix,
                                      negative=negative, interface_context=interface_context, log_groups=log_groups))

        # Compound lookups and membership precede logging, counters and verdicts.
        if side == 'left':
            if 'fib' in rule:
                parts.append(nft_fib(rule['fib']))

            for matches, operator in ((rule, ''), (rule.get('not', {}), ' !=')):
                if 'icmp-group' in matches:
                    name = matches['icmp-group']
                    fields = nft_icmp_group_fields(icmp_groups[name])
                    expression = ' . '.join(nft_field_expression(field, family) for field in fields)
                    parts.append(expression + (operator or ' ==') + ' @' + nft_icmp_group_name(family, name))

                for reference, (kind, field) in NFT_SINGLETON_REFERENCES.items():
                    if reference in matches:
                        name = nft_singleton_name(kind, family, matches[reference])
                        expression = nft_field_expression(field, family)
                        if reference == 'inbound-interface-group' and nft_slave_match(matches, interface_context, group=True):
                            expression = 'meta sdifname'
                        parts.append(expression + operator + ' @' + name)

                if 'match-group' in matches:
                    configuration = match_groups[matches['match-group']]
                    guard = nft_group_guard(family, nft_group_fields(configuration)).rstrip()
                    if guard and guard not in parts:
                        parts.insert(0, guard)
                    name = nft_match_group_name(family, matches['match-group'])
                    comparison = operator or ' =='
                    parts.append(nft_group_lookup(family, configuration) + comparison + ' @' + name)

            # Apply limit matches before logging, counters and other side effects.
            parts.extend(limits)
            if 'quota' in rule:
                options = rule['quota']
                if 'group' in options:
                    parts.append('quota name ' + nft_quota_group_name(options['group']))
                else:
                    parts.append('quota ' + nft_quota(options))
    return parts


def _nft_matches(family, matches, fields, side, log_prefix, *, negative=False,
                 interface_context=None, log_groups=None):
    """Render selected keymap fields in caller order for one statement side.

    ``negative`` selects the rule's exclusion branch. Per-term TCP flag negation
    is encoded inside flag combinations instead. Interface context determines
    whether an inbound interface expression needs INPUT's VRF slave identity.
    """
    parts = []
    for key in fields:
        entry = NFT_KEYMAP[key]
        if entry.side != side:
            continue

        value = nft_field_value(matches, key, negative=negative)
        if value is None:
            continue

        expression = nft_field_expression(key, family)
        if key == 'inbound-interface' and nft_slave_match(matches.get('not', {}) if negative else matches, interface_context):
            expression = 'meta sdifname'
        comparison = '!=' if negative else entry.operator

        if key == 'connection-label':
            parts.append(nft_connection_labels(value, negative))
            continue

        if key == 'tcp-flags':
            # Use one mask across all alternatives. Expand unspecified bits under
            # that mask so combining alternatives preserves each term's meaning.
            mask = tcp_flags_mask(value)
            flags = set()
            for combination in value:
                flags.update(tcp_flag_values(combination, mask))
            expression = f'tcp flags & {mask}' if mask != 255 else expression
            rendered = '{ ' + ', '.join(str(bits) for bits in sorted(flags)) + ' }'
            parts.append(expression + ' == ' + rendered)
            continue

        if entry.comparisons:
            for operator, symbol in NFT_COMPARISONS.items():
                if operator in value:
                    parts.append(f'{expression} {symbol} {_nft_value(key, value[operator])}')
            if 'eq' in value.get('not', {}):
                parts.append(f"{expression} != {_nft_value(key, value['not']['eq'])}")
            continue

        if entry.flag:
            if key == 'log':
                parts.append(nft_log(value, log_prefix, log_groups))
            elif key == 'counter' and 'group' in value:
                parts.append('counter name ' + nft_counter_group_name(value['group']))
            else:
                parts.append(entry.expression)
            continue

        # Address tags retain their individual masks for either polarity.
        if entry.mask_kind and isinstance(value, Mapping):
            if not value:
                continue
            masked = [_nft_mask_match(expression, address, match['mask'], entry.mask_kind,
                                      '!=' if negative else '==')
                      for address, match in value.items() if 'mask' in match]
            if masked:
                parts.extend(masked)
                continue

        if entry.multi:
            if key in ('inbound-interface', 'outbound-interface'):
                value = interface_patterns.normalize(value)
            values = sorted(_nft_value(key, item) for item in value)
            if key == 'connection-status':
                values = sorted(set(values))
            rendered = '{ ' + ', '.join(values) + ' }'
        else:
            rendered = _nft_value(key, value)

        operator = f' {comparison}' if comparison else ''
        parts.append(expression + operator + ' ' + rendered)
    return parts


def nft_group_update(family, update, match_groups):
    """Extract an exact packet key and refresh its learned member's expiry."""
    if 'match-group' in update:
        name = nft_match_group_name(family, update['match-group'])
        configuration = match_groups[update['match-group']]
        key = nft_group_lookup(family, configuration)
        guard = nft_group_guard(family, nft_group_fields(configuration))
    else:
        field = 'source-address' if 'source-address' in update else 'destination-address'
        name = nft_singleton_name('address-group', family, update[field])
        key = nft_field_expression(field, family)
        guard = ''

    if 'timeout' in update:
        key += ' timeout ' + nft_duration(update['timeout'])

    return guard + f'update @{name} {{ {key} }}'


NFT_RULE_LIMIT_PATHS = {
    'limit': ('limit',),
    'connection-limit': ('connection', 'limit'),
}


def nft_rule_limit_kind(path):
    """Identify private rule limits without mistaking named groups for them."""
    for kind, suffix in NFT_RULE_LIMIT_PATHS.items():
        if len(path) > len(suffix) + 2 and path[-len(suffix):] == suffix:
            rule_path = path[:-len(suffix)]
            if rule_path[-2] == 'rule':
                return kind
    return None


def nft_limit_name(chain, number, kind):
    return f'rule_{kind.replace("-", "_")}_{chain}_{number}'


def limit_refill_seconds(configuration):
    """A rate key must not expire sooner than a full bucket would refill."""
    unit, value = next(iter(configuration['rate'].items()))
    quantity, period = value.split('/')
    rate = limit_amount(quantity)
    byte_rate = unit == 'bytes'
    burst = limit_amount(configuration.get('burst', {}).get(unit, '0' if byte_rate else '5'))
    capacity = rate + burst if byte_rate else burst
    return (capacity * DURATION_UNITS[period] + rate - 1) // rate


def nft_limit_sets(objects, configuration, rebuild):
    """Declare private per-rule sets alongside their owning chains."""
    from nvyr.tree import lookup

    lines = []
    for key, path in sorted(objects.items()):
        kind = nft_rule_limit_kind(path)
        if key not in rebuild or key[0] != 'set' or kind is None:
            continue
        options = lookup(configuration, path)
        lines.append(nft_limit_set(key[1], path[1], options, timed=kind == 'limit'))
    return '\n'.join(lines)


def nft_limit_key(family, options):
    """Use exact fields, or mask addresses into independently tracked subnets."""
    parts = []
    for field in options['per'].split(','):
        expression = nft_field_expression(field, family)
        prefix_option = field.replace('-address', '-prefix-length')
        if field in {'source-address', 'destination-address'} and prefix_option in options:
            address = '0.0.0.0' if family == 'ipv4' else '::'
            mask = ipaddress.ip_network(f'{address}/{options[prefix_option]}').netmask
            expression = f'({expression} & {mask})'
        parts.append(expression)
    return ' . '.join(parts)


def nft_rule_limits(family, hook, number, rule, limit_groups=None):
    """Native matches; per-key state lives in a bounded dynamic set."""
    statements = []
    for kind, path in NFT_RULE_LIMIT_PATHS.items():
        options = lookup(rule, path, None)
        if options is None:
            continue
        group = options.get('group')
        if group is not None:
            options = limit_groups[group]
            if 'per' not in options:
                statements.append('limit name ' + nft_limit_group_name(family, group))
                continue
        if kind == 'connection-limit':
            expression = 'ct count over ' + options['over']
        else:
            expression = 'limit ' + nft_rate(options)

        if 'per' in options:
            fields = options['per'].split(',')
            key = nft_limit_key(family, options)
            name = nft_limit_group_name(family, group) if group is not None else nft_limit_name(f'{family}_{hook}', number, kind)
            operation = 'update' if kind == 'limit' else 'add'
            guard = nft_group_guard(family, fields)
            expression = guard + f'{operation} @{name} {{ {key} {expression} }}'
        statements.append(expression)
    return statements


def nft_rule(family, hook, number, rule, global_options=None, maps=None, match_groups=None,
             limit_groups=None, icmp_groups=None, interface_context=None, log_groups=None):
    """Render matches, statements, verdict and comment from a configuration rule."""
    if 'disable' in rule:
        return ''

    rule = dict(rule)

    for key in ('counter', 'last-used'):
        if key in (global_options or {}) and key not in rule:
            rule[key] = {} if key == 'counter' else True

    action = 'map' if 'map' in rule else rule['action']
    limits = nft_rule_limits(family, hook, number, rule, limit_groups)
    parts = _nft_parts(family, rule, nft_log_prefix(family, hook, number, action), match_groups,
                       limits, icmp_groups, interface_context, log_groups)
    if action == 'map':
        configuration = maps[rule['map']]
        parts.insert(0, nft_group_guard(family, nft_group_fields(configuration), configuration.get('result-type')).rstrip())
        parts = [part for part in parts if part]
        verdict = nft_group_lookup(family, configuration) + ' vmap @' + nft_map_name(family, rule['map'])
    elif action == 'jump':
        verdict = 'jump ' + nft_named_chain(family, rule['jump-target'])
    elif action == 'reject':
        verdict = nft_reject(family, nft_reject_response(rule, global_options))
    elif action == 'offload':
        verdict = 'flow add @' + nft_flowtable_name(rule['offload-target'])
    else:
        verdict = action

    if 'timeout-group' in rule.get('connection', {}):
        parts.append(nftables_timeouts.statement(family, rule['connection']['timeout-group']))

    if 'add-to-group' in rule:
        parts.append(nft_group_update(family, rule['add-to-group'], match_groups))

    if 'modify' in rule:
        parts.extend(nftables_modify.statements(family, rule['modify']))

    parts.extend((verdict, 'comment ' + nft_comment(number, rule.get('description', ''))))

    return ' '.join(parts)


def nft_chain_body(family, hook, configuration, global_options=None, maps=None, match_groups=None,
                   limit_groups=None, icmp_groups=None, interface_context=None, zone_dispatch=(),
                   log_groups=None, *, default=True):
    """Render numbered rules, optionally followed by a chain default verdict."""
    rules = configuration.get('rule', {})
    numbers = sorted(rules, key=lambda number: (int(number), number))
    lines = []
    attachment = ''
    # A shared ingress base chain can also be bound by either IP family.
    # Restrict direct inet rules to their own configured attachments.
    if rules and family == 'inet' and hook == 'ingress':
        devices = interface_patterns.normalize(configuration['interface'])
        selectors = ', '.join(f'"{device}"' for device in devices)
        attachment = f'iifname {{ {selectors} }} '

    for number in numbers:
        rendered = nft_rule(family, hook, number, rules[number], global_options, maps, match_groups,
                            limit_groups, icmp_groups, interface_context, log_groups)
        if rendered:
            lines.append(attachment + rendered)

    lines.extend(zone_dispatch)
    if default:
        lines.append(nft_default_rule(family, hook, configuration, global_options))
    return '\n'.join(lines)


def _nft_nat_translation(statement, translation):
    """Render translation fields using the same key metadata as firewall rules."""
    address = translation.get('address')
    if address is None or address == 'masquerade':
        port_separator = ' to :'
    else:
        # Keep the prefix length and port colon separate for nft's lexer.
        port_separator = ' :' if '/' in address else ':'

    parts = {'target': [], 'flags': []}

    for key, entry in NFT_NAT_KEYMAP.items():
        if key not in translation:
            continue

        value = translation[key]
        if not entry.flag and value == entry.omit_value:
            continue

        parts[entry.side].append(entry.expression if entry.flag else
                                entry.expression.format(value=value, port_separator=port_separator))

    return statement + ''.join(parts['target']) + (
        ' ' + ','.join(parts['flags']) if parts['flags'] else '')


def nft_nat_rule(direction, number, rule, maps=None, match_groups=None, log_groups=None):
    """Render shared matches/statements followed by keymapped NAT translation."""
    if 'disable' in rule:
        return ''

    translation = rule.get('translation', {})
    action = ('exclude' if 'exclude' in rule else
              'masquerade' if translation.get('address') == 'masquerade' else direction)
    statement, label = NFT_NAT_ACTIONS[action]

    if 'map' in rule:
        configuration = maps[rule['map']]
        target = nft_group_lookup('ipv4', configuration) + ' map @' + nft_map_name('ipv4', rule['map'])
        statement += (' to : ' if configuration['result-type'] == 'port' else ' ip to ') + target
    elif action != 'exclude':
        statement = _nft_nat_translation(statement, translation)

    hook = NFT_NAT_HOOK_LABELS[direction]
    prefix = f'"[ipv4-{hook}-{number}-{label}]"'
    parts = _nft_parts('ipv4', rule, prefix, match_groups, log_groups=log_groups)
    if 'map' in rule:
        guard = nft_group_guard('ipv4', nft_group_fields(configuration), configuration.get('result-type')).rstrip()
        if guard:
            parts.insert(0, guard)
    parts.extend((statement, 'comment ' + nft_comment(number, rule.get('description', ''))))

    return ' '.join(parts)


def nft_cleanup(lifecycle, table='nvyr_filter'):
    """Release selected references before destroying complete objects atomically."""
    objects = lifecycle['remove']
    lines = []
    for kind, name in sorted(objects):
        if kind == 'chain':
            # Recovery may include missing chains; add is idempotent.
            lines.append(f'add chain inet {table} {name}')
            lines.append(f'flush chain inet {table} {name}')

    # Verdict maps can still reference chains after all selected rules are gone.
    for category in ('map', 'set', 'flowtable', 'counter', 'limit', 'quota', 'ct timeout', 'ct helper', 'chain'):
        for kind, name in sorted(objects):
            if kind == category:
                lines.append(f'destroy {kind} inet {table} {name}')
    return '\n'.join(lines)


def nft_chain_declarations(lifecycle, table='nvyr_filter'):
    """Declare rebuilt jump targets before maps or chains can reference them."""
    return '\n'.join(f'add chain inet {table} {name}'
                     for kind, name in sorted(lifecycle['rebuild'])
                     if kind == 'chain' and name.startswith(('ipv4_name_', 'ipv6_name_', 'inet_name_')))


def nft_log(options, prefix, log_groups=None):
    parts = ['log prefix ' + prefix]
    if 'group' in options:
        # NFLOG scalar arguments require literal numbers, not nft define references.
        group = log_groups[options['group']]
        parts.extend([f'group {group["id"]}', f'snaplen {group["snaplen"]}',
                      f'queue-threshold {group["queue-threshold"]}'])
    if 'level' in options:
        parts.append('level ' + options['level'])
    for flag in options.get('flags', '').split(','):
        if flag:
            parts.append('flags ' + LOG_FLAGS[flag])
    return ' '.join(parts)


def nft_counter_group_name(name):
    return 'counter_group_' + name


def nft_quota_group_name(name):
    return 'quota_group_' + name


def nft_quota(options):
    mode = 'over' if 'over' in options else 'until'
    return f'{mode} {limit_amount(options["bytes"])} bytes'


def nft_limit_group_name(family, name):
    return family + '_limit_group_' + name


def nft_rate(options):
    unit, value = next(iter(options['rate'].items()))
    quantity, period = value.split('/')
    amount = limit_amount(quantity)
    suffix = ' bytes' if unit == 'bytes' else ''
    expression = 'rate ' + ('over ' if 'over' in options else '')
    expression += f'{amount}{suffix}/{RATE_UNITS[period]}'
    if 'burst' in options:
        burst = limit_amount(options['burst'][unit])
        expression += f' burst {burst} {unit}'
    return expression


def nft_limit_set(name, family, options, *, timed=True):
    fields = options['per'].split(',')
    datatype = ' . '.join(nft_field_type(field, family)[0] for field in fields)
    lines = [f'set {name} {{', f'    type {datatype};',
             '    flags dynamic;', f'    size {options.get("size", "65536")};']
    if timed:
        timeout = options.get('timeout', f'{max(60, limit_refill_seconds(options))}s')
        lines.append(f'    timeout {nft_duration(timeout)};')
    if 'description' in options:
        lines.append(f'    comment "{options["description"]}";')
    lines.append('}')
    return '\n'.join(lines)


def nft_named_state(groups, rebuild, global_options=None):
    """Declare shared state independently of its consuming chains."""
    lines = [nftables_timeouts.definitions(groups, rebuild, global_options)]
    for name, options in sorted(groups.get('quota-group', {}).items()):
        native = nft_quota_group_name(name)
        if ('quota', native) in rebuild:
            lines.extend([f'quota {native} {{', '    ' + nft_quota(options) + ';'])
            if 'description' in options:
                lines.append(f'    comment "{options["description"]}";')
            lines.append('}')

    for name, options in sorted(groups.get('counter-group', {}).items()):
        native = nft_counter_group_name(name)
        if ('counter', native) in rebuild:
            lines.append(f'counter {native} {{')
            if 'description' in options:
                lines.append(f'    comment "{options["description"]}";')
            lines.append('}')

    for family, definitions in sorted(groups.get('limit-group', {}).items()):
        for name, options in sorted(definitions.items()):
            native = nft_limit_group_name(family, name)
            kind = 'set' if 'per' in options else 'limit'
            if (kind, native) not in rebuild:
                continue
            if kind == 'set':
                lines.append(nft_limit_set(native, family, options))
            else:
                lines.extend([f'limit {native} {{', '    ' + nft_rate(options) + ';'])
                if 'description' in options:
                    lines.append(f'    comment "{options["description"]}";')
                lines.append('}')
    return '\n'.join(lines)
