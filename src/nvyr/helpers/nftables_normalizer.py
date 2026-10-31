"""Turn nft JSON listings into configuration-style operational data.

This is a view of installed kernel objects, not a configuration import format.
No commands are executed here. Unsupported expressions remain visible rather
than being silently discarded or given different matching semantics.
"""

from copy import deepcopy
import ipaddress

from nvyr.helpers.nftables_formatters import (
    NFT_COMPARISONS,
    NFT_FIB_LOOKUP,
    NFT_KEYMAP,
    NFT_PORT_PROTOCOLS,
    NFT_SINGLETON_GROUPS,
    NFT_SINGLETON_REFERENCES,
    nft_field_expression,
    nft_field_type,
    nft_group_fields,
    nft_icmp_group_fields,
    nft_group_tcp_mask,
)
from nvyr.helpers.validators import DSCP_VALUES, RATE_UNITS, TCP_FLAGS, tcp_flag_expression, tcp_flag_values
from nvyr.helpers import firewall_scope, nftables_timeouts
from nvyr.tree import lookup


_FIELDS = {}
for _family in ('ipv4', 'ipv6'):
    for _name, _definition in NFT_KEYMAP.items():
        if _definition.side == 'left':
            _FIELDS[nft_field_expression(_name, _family)] = _name

_STATUS_FLAGS = {
    1: 'expected', 2: 'seen-reply', 4: 'assured', 8: 'confirmed',
    16: 'snat', 32: 'dnat', 64: 'seq-adjust', 128: 'snat-done',
    256: 'dnat-done', 512: 'dying', 1024: 'fixed-timeout',
    8192: 'helper', 16384: 'offload', 32768: 'hw-offload',
}

_GROUP_PREFIXES = {
    'inet_map_': 'map', 'inet_match_group_': 'match-group', 'inet_limit_group_': 'limit-group',
    'ipv4_map_': 'map', 'ipv6_map_': 'map',
    'ipv4_match_group_': 'match-group', 'ipv6_match_group_': 'match-group',
    'ipv4_address_group_': 'address-group', 'ipv6_address_group_': 'address-group',
    'ipv4_domain_group_': 'domain-group', 'ipv6_domain_group_': 'domain-group',
    'ipv4_icmp_group_': 'icmp-group', 'ipv6_icmp_group_': 'icmp-group',
    'interface_group_': 'interface-group', 'mac_group_': 'mac-group',
    'counter_group_': 'counter-group',
    'quota_group_': 'quota-group',
    'ipv4_limit_group_': 'limit-group', 'ipv6_limit_group_': 'limit-group',
    'port_group_': 'port-group', 'flowtable_': 'flowtable',
}


class _Unsupported(ValueError):
    """An expression cannot be represented faithfully by the supported fields."""


def _list(value):
    return value if isinstance(value, list) else [value]


def _group_identity(name, table):
    name = name.removeprefix('@')
    if table in firewall_scope.TABLES:
        timeout = nftables_timeouts.identity(name)
        if timeout:
            return 'timeout-group', timeout[1]
        for prefix, kind in _GROUP_PREFIXES.items():
            if name.startswith(prefix):
                return kind, name[len(prefix):]
    return None, name


def _target(name, table):
    if table in firewall_scope.TABLES:
        for prefix in ('ipv4_name_', 'ipv6_name_', 'inet_name_'):
            if name.startswith(prefix):
                return name[len(prefix):]
    return name


def _comment(value, *, identifier):
    result = {'comment': value}
    name, separator, description = value.partition('|')
    if separator:
        result.update({identifier: name, 'description': description})
    else:
        result['description'] = value
    return result


def _field(expression):
    if not isinstance(expression, dict) or len(expression) != 1:
        raise _Unsupported('Unknown packet field')

    if '&' in expression and _field(expression['&'][0]) == 'tcp-flags':
        return 'tcp-flags'

    if 'payload' in expression:
        payload = expression['payload']
        protocol = payload.get('protocol')
        name = payload.get('field')
        if name in ('sport', 'dport') and (protocol in NFT_PORT_PROTOCOLS or protocol == 'th'):
            protocol = 'th'
        text = f'{protocol} {name}'
    elif 'meta' in expression:
        name = expression['meta']['key']
        text = name if name in ('iifname', 'oifname') else f'meta {name}'
    elif 'ct' in expression and set(expression['ct']) <= {'key', 'dir'}:
        connection = expression['ct']
        direction = connection.get('dir')
        text = 'ct ' + (direction + ' ' if direction else '') + connection['key']
    elif expression == {'tcp option': {'name': 'maxseg', 'field': 'size'}}:
        text = 'tcp option maxseg size'
    else:
        raise _Unsupported('Unknown packet field')

    if text == 'meta sdifname':
        return 'inbound-interface'
    if text == 'meta oifkind':
        return 'outbound-interface-kind'
    if text == 'meta nfproto':
        return 'address-family'
    if text not in _FIELDS:
        raise _Unsupported('Unknown packet field')
    return _FIELDS[text]


def _fields(expression):
    parts = expression.get('concat', [expression])
    return [_field(part) for part in parts]


def _status(value):
    if isinstance(value, dict) and set(value) == {'|'}:
        names = []
        for part in value['|']:
            names.extend(_status(part).split(','))
        return ','.join(sorted(set(names)))

    if isinstance(value, int):
        names = []
        remaining = value
        for bit, name in _STATUS_FLAGS.items():
            if value & bit:
                names.append(name)
                remaining &= ~bit
        if remaining or not names:
            names.append(hex(remaining))
        return ','.join(sorted(names))

    if isinstance(value, str):
        return value
    raise _Unsupported('Unknown connection status')


def _value(value, field=None):
    if field == 'connection-status':
        return _status(value)
    if field == 'tcp-flags':
        return _tcp_bits(value)

    if isinstance(value, dict):
        if set(value) == {'prefix'}:
            prefix = value['prefix']
            return f"{prefix['addr']}/{prefix['len']}"
        if set(value) == {'range'}:
            start, end = value['range']
            return f'{_value(start, field)}-{_value(end, field)}'
        if set(value) == {'concat'}:
            return [_value(part) for part in value['concat']]
        raise _Unsupported('Unknown value expression')

    if field == 'dscp' and isinstance(value, str):
        return DSCP_VALUES.get(value, value)
    if field == 'connection-expiration' and isinstance(value, (int, float)):
        # The native time datatype is serialized in seconds.
        return f'{value:g}s'
    return value


def _tcp_bits(value):
    if isinstance(value, int) and 0 <= value <= 255:
        return value
    if isinstance(value, str) and value in TCP_FLAGS:
        return TCP_FLAGS[value]
    if isinstance(value, dict) and set(value) == {'|'}:
        bits = 0
        for part in value['|']:
            bits |= _tcp_bits(part)
        return bits
    raise _Unsupported('Unknown TCP flag value')


def _tracking(data):
    result = {}
    if 'counter' in data:
        counter = data['counter']
        if counter is not None and not isinstance(counter, dict):
            raise _Unsupported('Named counter reference')
        result['counter'] = counter if counter is not None else {}
    if 'last' in data:
        # nft JSON uses milliseconds for last.used, seconds for element timeouts.
        result['last-used'] = None if data['last'] is None else data['last']['used'] / 1000
    return result


def _fib_match(expression, value, comparison):
    """Decode named results and boolean route-existence tests."""
    flags = expression['flags']
    known_flags = set(NFT_FIB_LOOKUP.values())
    if comparison not in ('==', '!=') or set(flags) - known_flags:
        raise _Unsupported('Unsupported FIB comparison or lookup flag')

    fields = {name: True for name, flag in NFT_FIB_LOOKUP.items() if flag in flags}
    result_type = expression['result']
    if result_type == 'oif' and isinstance(value, bool):
        if comparison != '==':
            raise _Unsupported('Unsupported negated FIB existence test')
        result = {'outbound-interface': ['exists' if value else 'missing']}
    elif result_type == 'oif' and value in (0, '0'):
        # Numeric zero is the interface-index form of a missing reverse route.
        result = {'outbound-interface': ['missing']}
    elif result_type in ('oifname', 'type'):
        values = value['set'] if isinstance(value, dict) and set(value) == {'set'} else [value]
        if not all(isinstance(item, str) for item in values):
            raise _Unsupported('Unsupported FIB result values')
        key = 'outbound-interface' if result_type == 'oifname' else 'route-type'
        result = {key: values}
    else:
        raise _Unsupported('Unsupported FIB result')

    return {'fib': {'lookup': fields, 'result': {'not': result} if comparison == '!=' else result}}


def _match(match, table):
    expression = match['left']
    value = match['right']
    comparison = match['op']
    if isinstance(expression, dict) and set(expression) == {'fib'}:
        return _fib_match(expression['fib'], value, comparison)

    mask = None
    if isinstance(expression, dict) and '&' in expression:
        expression, mask = expression['&']

    fields = _fields(expression)
    if fields == ['connection-label']:
        return _label_match(value, mask, comparison)
    if mask is not None and fields != ['tcp-flags'] and (len(fields) != 1 or not NFT_KEYMAP.get(fields[0]) or
                             not NFT_KEYMAP[fields[0]].mask_kind):
        raise _Unsupported('Unsupported bitmask')
    comparisons = len(fields) == 1 and NFT_KEYMAP.get(fields[0]) and NFT_KEYMAP[fields[0]].comparisons
    if comparison == '!=' and not comparisons:
        return {'not': _match(dict(match, op='=='), table)}
    if isinstance(value, str) and value.startswith('@') and comparison == '==':
        kind, name = _group_identity(value, table)
        if table in firewall_scope.TABLES and name.startswith('source_validation_') and fields == ['inbound-interface']:
            return {'source-validation-interface-set': name}
        if kind == 'match-group':
            return {'match-group': name, 'match-group-fields': fields}
        if kind == 'icmp-group' and fields in (['icmp-type'], ['icmp-type', 'icmp-code']):
            return {'icmp-group': name}
        for reference, (group_kind, field) in NFT_SINGLETON_REFERENCES.items():
            if kind == group_kind and fields == [field]:
                return {reference: name}
        raise _Unsupported('Unknown set reference')

    if len(fields) != 1:
        raise _Unsupported('Anonymous concatenated match')
    field = fields[0]
    if comparisons and isinstance(value, dict) and set(value) == {'range'}:
        start, end = value['range']
        # nft coalesces adjacent TTL comparisons into an interval, sometimes
        # represented as the complement of a wrapping interval (high, low).
        if comparison == '!=' and start > end:
            return {field: {'gt': _value(end, field), 'lt': _value(start, field)}}
        if comparison == '==' and start <= end:
            return {field: {'gt': _value(start - 1, field), 'lt': _value(end + 1, field)}}
    if comparisons and comparison in NFT_COMPARISONS.values():
        operator = next(name for name, symbol in NFT_COMPARISONS.items() if symbol == comparison)
        return {field: {operator: _value(value, field)}}
    if comparisons and comparison == '!=':
        return {field: {'not': {'eq': _value(value, field)}}}
    # nft uses an implicit bit test for an individual conntrack state.
    if comparison == 'in' and field == 'state':
        comparison = '=='
    if comparison != '==':
        raise _Unsupported('Unsupported comparison')

    values = value['set'] if isinstance(value, dict) and set(value) == {'set'} else [value]
    if field == 'tcp-flags':
        tested = 255 if mask is None else _tcp_bits(mask)
        return {field: [tcp_flag_expression(tested, _tcp_bits(item)) for item in values]}
    values = [_value(item, field) for item in values]
    definition = NFT_KEYMAP.get(field)
    if definition and definition.mask_kind:
        return {field: {str(item): ({'mask': mask} if mask is not None else {}) for item in values}}
    if mask is not None:
        raise _Unsupported('Unsupported bitmask')
    if definition and definition.multi:
        return {field: values}
    return {field: values[0] if len(values) == 1 else values}


def _label_match(value, mask, comparison):
    """Describe the tested bits without exposing native expression trees."""
    if comparison == 'in' and mask is None:
        return {'connection-label': [str(bit) for bit in _list(value)]}
    if comparison not in ('==', '!='):
        raise _Unsupported('Unsupported connection label comparison')

    tested = (1 << 128) - 1 if mask is None else _label_bits(mask)
    values = value['set'] if isinstance(value, dict) and set(value) == {'set'} else [value]
    combinations = []
    for item in values:
        bits = _label_bits(item)
        terms = []
        for bit in range(128):
            if tested & (1 << bit):
                terms.append(str(bit) if bits & (1 << bit) else f'not {bit}')
        combinations.append(' and '.join(terms))

    result = {'connection-label': combinations}
    return {'not': result} if comparison == '!=' else result


def _label_bits(value):
    if isinstance(value, int) and 0 <= value <= 127:
        return 1 << value
    if isinstance(value, dict) and set(value) == {'|'}:
        bits = 0
        for part in value['|']:
            bits |= _label_bits(part)
        return bits
    raise _Unsupported('Unknown connection label bits')


def _verdict(statement, table):
    for action in ('accept', 'drop', 'continue', 'return', 'jump', 'goto', 'reject'):
        if action not in statement:
            continue
        result = {'action': action}
        if action in ('jump', 'goto'):
            result[action + '-target'] = _target(statement[action]['target'], table)
        if action == 'reject' and statement[action]:
            result['reject-protocol'] = statement[action]['type']
            result['reject-with'] = statement[action].get('expr')
        return result
    raise _Unsupported('Unknown verdict')


def _map_reference(mapping, table):
    if not isinstance(mapping['data'], str):
        raise _Unsupported('Not a named map')
    kind, name = _group_identity(mapping['data'], table)
    native = mapping['data'].removeprefix('@')
    if table in firewall_scope.TABLES and native in {
            f'{family}_zone_{hook}' for family in ('ipv4', 'ipv6') for hook in ('input', 'output', 'forward')}:
        return {'zone-dispatch': native, 'map-fields': _fields(mapping['key'])}
    if kind != 'map':
        raise _Unsupported('Unknown map reference')
    return {'map': name, 'map-fields': _fields(mapping['key'])}


def _element(value, table, datatypes=(), fields=()):
    metadata = value['elem'] if isinstance(value, dict) and set(value) == {'elem'} else {}
    key = metadata.get('val', value)
    parts = key['concat'] if isinstance(key, dict) and set(key) == {'concat'} else [key]
    # A native catch-all covers the entire key, not a wildcard in one component.
    if key == '*':
        parts = []
    values = []
    for index, part in enumerate(parts):
        datatype = datatypes[index] if index < len(datatypes) else None
        field = fields[index] if index < len(fields) else {
            'ct_status': 'connection-status', 'dscp': 'dscp', 'tcp_flag': 'tcp-flags',
        }.get(datatype)
        values.append(_value(part, field))
    result = {'key': values}
    result.update(_tracking(metadata))
    for option in ('timeout', 'expires'):
        if option in metadata:
            result[option] = metadata[option]
    if 'comment' in metadata:
        result.update(_comment(metadata['comment'], identifier='name'))
    if key == '*':
        result.update({'default': True, 'name': 'default'})
    return result


def _map_result(value, datatypes, table):
    if datatypes == ['verdict']:
        return _verdict(value, table)
    values = _list(_value(value))
    result = {}
    for datatype, part in zip(datatypes, values, strict=True):
        field = {'ipv4_addr': 'address', 'ipv6_addr': 'address', 'inet_service': 'port',
                 'ct helper': 'helper'}.get(datatype)
        if field is None or field in result:
            raise _Unsupported('Unsupported map result datatype')
        result[field] = part
    return result


def _vmap(mapping, table):
    if isinstance(mapping['data'], str):
        return _map_reference(mapping, table)
    entries = []
    for key, verdict in mapping['data']['set']:
        entry = _element(key, table)
        entry['result'] = _verdict(verdict, table)
        entries.append(entry)
    return {'verdict-map': {'fields': _fields(mapping['key']), 'entries': entries}}


def _translation(action, data, table):
    translation = {}
    result = {'action': action, 'translation': translation}
    for source, field in (('addr', 'address'), ('port', 'port')):
        if source not in data:
            continue
        value = data[source]
        if isinstance(value, dict) and 'map' in value:
            result.update(_map_reference(value['map'], table))
        else:
            translation[field] = _value(value)
    if action == 'masquerade':
        translation['address'] = 'masquerade'
    flags = _list(data.get('flags', []))
    if 'persistent' in flags:
        translation['persistent'] = True
    for flag in ('random', 'fully-random'):
        if flag in flags:
            translation['port-mapping'] = flag
    remaining = [flag for flag in flags if flag not in ('persistent', 'random', 'fully-random')]
    if remaining:
        translation['flags'] = remaining
    return result


def _update(data, table):
    if data.get('stmt') and table in firewall_scope.TABLES and data['set'].removeprefix('@').startswith(('rule_limit_', 'rule_connection_limit_')):
        return _keyed_limit(data)
    if data['op'] != 'update':
        raise _Unsupported('Not a group update')
    kind, name = _group_identity(data['set'], table)
    if kind == 'limit-group' and data.get('stmt'):
        parsed = _keyed_limit(data)
        if 'limit' not in parsed:
            raise _Unsupported('Unknown shared allowance statement')
        return {'limit': {'group': name}, 'runtime-limits': parsed['runtime-limits']}
    element = data['elem']
    metadata = element.get('elem', {})
    fields = _fields(metadata.get('val', element))
    if kind == 'match-group':
        update = {'match-group': name, 'match-fields': fields}
    elif kind == 'address-group' and fields in (['source-address'], ['destination-address']):
        update = {fields[0]: name}
    else:
        raise _Unsupported('Unknown group update')
    if 'timeout' in metadata:
        update['timeout'] = metadata['timeout']
    return {'add-to-group': update}


def _quota(data):
    """Normalize an anonymous quota's native byte units and match direction."""
    if set(data) - {'val', 'val_unit', 'used', 'used_unit', 'inv'}:
        raise _Unsupported('Unknown quota parameter')
    units = {'bytes': 1, 'kbytes': 1024, 'mbytes': 1024**2}
    value_unit = data.get('val_unit', 'bytes')
    used_unit = data.get('used_unit', 'bytes')
    if value_unit not in units or used_unit not in units:
        raise _Unsupported('Unknown quota byte unit')
    return {
        'bytes': data['val'] * units[value_unit],
        'used': data.get('used', 0) * units[used_unit],
        'mode': 'over' if data.get('inv') else 'until',
    }


def _limit(name, data):
    """Expose native bucket parameters without leaking nft's expression structure."""
    if name == 'ct count':
        if not data.get('inv') or set(data) - {'val', 'inv'}:
            raise _Unsupported('Unknown connection count comparison')
        return {'connection-limit': {'over': data['val']}}

    if set(data) - {'rate', 'per', 'burst', 'inv', 'rate_unit', 'burst_unit'}:
        raise _Unsupported('Unknown rate limit parameter')
    suffixes = {'packets': '', 'bytes': '', 'kbytes': 'k', 'mbytes': 'm'}
    rate_unit = data.get('rate_unit', 'packets')
    period = next((short for short, full in RATE_UNITS.items() if full == data['per']), None)
    if rate_unit not in suffixes or period is None:
        raise _Unsupported('Unknown rate limit unit')

    unit = 'packets' if rate_unit == 'packets' else 'bytes'
    result = {'rate': {unit: f'{data["rate"]}{suffixes[rate_unit]}/{period}'}}
    if 'burst' in data:
        burst_unit = data.get('burst_unit', unit)
        if burst_unit not in suffixes:
            raise _Unsupported('Unknown burst unit')
        result['burst'] = {unit: f'{data["burst"]}{suffixes[burst_unit]}'}
    if data.get('inv'):
        result['over'] = True
    return {'limit': result}


def _keyed_limit(data):
    statements = data['stmt']
    if len(statements) != 1 or len(statements[0]) != 1:
        raise _Unsupported('Multiple per-key statements')
    kind, definition = next(iter(statements[0].items()))
    if kind not in {'limit', 'ct count'}:
        raise _Unsupported('Unknown per-key limit')
    if data['op'] != ('update' if kind == 'limit' else 'add'):
        raise _Unsupported('Unknown per-key limit operation')
    result = _limit(kind, definition)
    options = next(iter(result.values()))
    fields = []
    element = data['elem']
    for expression in element.get('concat', [element]):
        if '&' in expression:
            address, mask = expression['&']
            field = _field(address)
            if field not in {'source-address', 'destination-address'}:
                raise _Unsupported('Masked non-address limit key')
            value = ipaddress.ip_address(mask)
            prefix = int(value).bit_count()
            if int(value) != ((1 << prefix) - 1) << (value.max_prefixlen - prefix):
                raise _Unsupported('Non-prefix limit mask')
            options[field.replace('-address', '-prefix-length')] = prefix
        else:
            field = _field(expression)
        fields.append(field)
    options['per'] = fields
    # Retain the installed reference separately from the public match parameters.
    # Operational views can then find live keys without guessing generated names.
    limit_kind = next(iter(result))
    result['runtime-limits'] = {
        limit_kind: {**deepcopy(options), 'set': data['set'].removeprefix('@')},
    }
    return result


def _statement(statement, table):
    if len(statement) != 1:
        raise _Unsupported('Unknown statement')
    name, data = next(iter(statement.items()))
    if name == 'match':
        return _match(data, table)
    if name == 'ct helper' and isinstance(data, dict):
        mapping = data.get('map', {})
        if (table in firewall_scope.TABLES and mapping.get('data') == '@conntrack_helpers'
                and mapping.get('key') == {'concat': [
                    {'meta': {'key': 'l4proto'}}, {'payload': {'protocol': 'th', 'field': 'dport'}}]}):
            return {'helper-map': 'conntrack_helpers'}
        raise _Unsupported('Unknown connection helper map reference')
    if name == 'ct timeout':
        if isinstance(data, str):
            kind, target = _group_identity(data, table)
            if kind == 'timeout-group':
                return {'connection-timeout-group': target}
        elif isinstance(data, dict) and table in firewall_scope.TABLES:
            mapping = data.get('map', {})
            entries = mapping.get('data', {}).get('set', [])
            if mapping.get('key') == {'meta': {'key': 'nfproto'}} and len(entries) == 2:
                values = dict(entries)
                identity = nftables_timeouts.identity(values.get('ipv4', ''))
                if identity and identity[0] == 'inet':
                    names = nftables_timeouts.native_names(*identity)
                    if values == {'ipv4': names['ip'], 'ipv6': names['ip6']}:
                        return {'connection-timeout-group': identity[1]}
        raise _Unsupported('Unknown connection timeout policy reference')
    if name == 'quota':
        if isinstance(data, str):
            kind, target = _group_identity(data, table)
            if kind != 'quota-group':
                raise _Unsupported('Unknown named quota')
            return {'quota': {'group': target}}
        return {'quota': _quota(data)}
    if name == 'counter' and isinstance(data, str):
        kind, target = _group_identity(data, table)
        if kind != 'counter-group':
            raise _Unsupported('Unknown named counter')
        return {'counter': {'group': target}}
    if name == 'limit' and isinstance(data, str):
        kind, target = _group_identity(data, table)
        if kind != 'limit-group':
            raise _Unsupported('Unknown named limit')
        return {'limit': {'group': target}}
    if name in ('counter', 'last'):
        return _tracking(statement)
    if name == 'log':
        return {'log': data or {}}
    if name == 'notrack':
        return {'notrack': True}
    if name == 'mangle' and data == {'key': {'meta': {'key': 'nftrace'}}, 'value': 1}:
        return {'nftrace': True}
    if name == 'mangle':
        field = _field(data['key'])
        if field not in {'packet-mark', 'connection-mark', 'dscp', 'ttl', 'tcp-mss'}:
            raise _Unsupported('Unknown modified field')
        value = data['value']
        if field == 'tcp-mss' and value == {'rt': {'key': 'mtu'}}:
            value = 'clamp-to-pmtu'
        else:
            value = _value(value, field)
        return {'modify': {field: value}}
    if name in ('limit', 'ct count'):
        return _limit(name, data)
    if name == 'vmap':
        return _vmap(data, table)
    if name in ('snat', 'dnat', 'masquerade'):
        return _translation(name, data or {}, table)
    if name == 'set':
        return _update(data, table)
    if name == 'flow' and data['op'] == 'add':
        kind, target = _group_identity(data['flowtable'], table)
        return {'action': 'offload', 'offload-target': target}
    return _verdict(statement, table)


def _merge(result, fields, *, negative=False):
    # Repeated equalities are AND conditions; never turn them into an OR list.
    fields = dict(fields)
    for field, value in fields.items():
        if field not in result or result[field] == value:
            continue
        if field == 'fib' and result[field].get('lookup') != value.get('lookup'):
            raise _Unsupported('Different FIB lookups cannot be flattened')
        if negative and field == 'connection-label' and isinstance(value, list):
            fields[field] = list(dict.fromkeys([*result[field], *value]))
            continue
        comparison = field in NFT_KEYMAP and NFT_KEYMAP[field].comparisons
        if (comparison or field in ('not', 'fib', 'lookup', 'result', 'runtime-limits', 'modify')) and isinstance(value, dict) and isinstance(result[field], dict):
            combined = dict(result[field])
            _merge(combined, value, negative=negative or field == 'not')
            fields[field] = combined
            continue
        raise _Unsupported('Repeated field cannot be flattened')
    for field, value in fields.items():
        result[field] = value


def _implied_protocols(value):
    """nft may remove explicit protocol checks when payload fields imply them."""
    protocols = set()
    if isinstance(value, dict):
        protocol = value.get('payload', {}).get('protocol')
        if protocol in NFT_PORT_PROTOCOLS or protocol in ('icmp', 'icmpv6'):
            protocols.add('ipv6-icmp' if protocol == 'icmpv6' else protocol)
        if 'tcp option' in value:
            protocols.add('tcp')
        for child in value.values():
            protocols.update(_implied_protocols(child))
    elif isinstance(value, list):
        for child in value:
            protocols.update(_implied_protocols(child))
    return protocols


def _rule(rule):
    result = {key: value for key, value in rule.items() if key not in ('family', 'table', 'chain', 'expr', 'comment')}
    if 'comment' in rule:
        result.update(_comment(rule['comment'], identifier='number'))

    for index, statement in enumerate(rule.get('expr', [])):
        try:
            fields = _statement(statement, rule['table'])
            # Direct inet ingress rules start with their hook attachment guard.
            # Keep that scope separate from an explicit inbound-interface match:
            # these predicates are intersected, not alternative interfaces.
            if (index == 0 and rule['table'] in firewall_scope.TABLES and
                    rule['chain'] == 'ingress' and str(result.get('number', '')).isdigit() and
                    set(fields) == {'inbound-interface'}):
                fields = {'ingress-interface': fields['inbound-interface']}
            _merge(result, fields)
        except _Unsupported as error:
            result.setdefault('unsupported', []).append({
                'position': index, 'reason': str(error), 'expression': statement,
            })

    protocols = _implied_protocols(rule.get('expr', []))
    if 'protocol' not in result and len(protocols) == 1:
        result['protocol'] = sorted(protocols)
    return result


def _configured_fields(group, configuration):
    """Use exactly the same column ordering as the rendering pipeline."""
    kind, name = _group_identity(group['name'], group['table'])
    if kind in NFT_SINGLETON_GROUPS:
        return [NFT_SINGLETON_GROUPS[kind][0]]
    if kind not in ('map', 'match-group', 'limit-group', 'icmp-group') or configuration is None:
        return None

    family = group['name'].split('_', 1)[0]
    definition = lookup(configuration, ('firewall', 'group', kind, family, name), None)
    if definition is None:
        return None
    if kind == 'icmp-group':
        fields = nft_icmp_group_fields(definition)
    elif kind == 'limit-group':
        fields = definition['per'].split(',')
    else:
        fields = nft_group_fields(definition)
    datatypes = [nft_field_type(field, family)[0] for field in fields]
    native_type = group['type']
    if isinstance(native_type, dict) and 'typeof' in native_type:
        compatible = fields == _fields(native_type['typeof'])
    else:
        compatible = datatypes == _list(native_type)
    if not compatible:
        raise ValueError(f"Configured key fields for {group['name']} do not match its nftables datatypes")
    return fields


def _tcp_group_entries(entries, fields, definition):
    """Fold expanded native keys back into their documented logical entry."""
    index = fields.index('tcp-flags')
    mask = nft_group_tcp_mask(definition)
    configured = definition.get('entry', {})
    allowed = {
        name: set(tcp_flag_values(setting['tcp-flags'], mask))
        for name, setting in configured.items() if 'tcp-flags' in setting
    }
    combined = {}
    result = []
    for entry in entries:
        if 'unsupported' in entry or entry.get('default'):
            result.append(entry)
            continue

        value = entry['key'][index]
        setting = configured.get(entry.get('name'), {}).get('tcp-flags')
        if setting is None or value not in allowed[entry['name']]:
            entry['key'][index] = tcp_flag_expression(mask, value)
            result.append(entry)
            continue

        entry['key'][index] = setting
        identity = (entry['name'], repr(entry['key']), repr(entry.get('result')))
        if identity not in combined:
            combined[identity] = entry
            result.append(entry)
            continue

        previous = combined[identity]
        for field in ('packets', 'bytes'):
            if field in entry.get('counter', {}):
                previous.setdefault('counter', {})[field] = previous.get('counter', {}).get(field, 0) + entry['counter'][field]
        if 'last-used' in entry:
            times = [time for time in (previous.get('last-used'), entry['last-used']) if time is not None]
            previous['last-used'] = min(times) if times else None
        if 'expires' in entry:
            previous['expires'] = min(previous.get('expires', entry['expires']), entry['expires'])
    return result


def _group(group, *, mapping, configuration):
    excluded = ('family', 'table', 'type', 'map', 'elem', 'stmt', 'comment')
    result = {key: value for key, value in group.items() if key not in excluded}
    if group['table'] in firewall_scope.TABLES and group['name'] in {
            f'{family}_zone_{hook}' for family in ('ipv4', 'ipv6') for hook in ('input', 'output', 'forward')}:
        result['zone-hook'] = group['name'].split('_')[-1]
    native_type = group['type']
    if isinstance(native_type, dict) and 'typeof' in native_type:
        native_fields = _fields(native_type['typeof'])
        family = group['name'].split('_', 1)[0]
        result['key-datatypes'] = [nft_field_type(field, family)[0] or field for field in native_fields]
        result['match-fields'] = native_fields
    else:
        result['key-datatypes'] = _list(native_type)
    kind, name = _group_identity(group['name'], group['table'])
    if kind:
        result.update({'group-kind': kind, 'group-name': name})
    fields = _configured_fields(group, configuration)
    if fields is not None:
        result['match-fields'] = fields
    if kind == 'limit-group' and configuration is not None:
        family = group['name'].split('_', 1)[0]
        definition = lookup(configuration, ('firewall', 'group', kind, family, name), {})
        # A dynamic set stores active keys; its rate lives in the updating rules.
        # Keep configured bucket parameters explicitly separate from kernel state.
        result['configured-limit'] = {
            key: deepcopy(value) for key, value in definition.items()
            if key not in {'description', 'size', 'timeout'}
        }
    if 'comment' in group:
        result['description'] = group['comment']
    if mapping:
        result['result-datatypes'] = _list(group['map'])

    for statement in group.get('stmt', []):
        if statement == {'counter': None}:
            result['counter'] = True
        elif statement == {'last': None}:
            result['last-used'] = True
        else:
            result.setdefault('unsupported', []).append(statement)

    # An omitted elem property can also mean a terse listing; do not claim empty.
    if 'elem' in group:
        result['entries'] = []
        for element in _list(group['elem']):
            try:
                key, value = element if mapping else (element, None)
                entry = _element(key, group['table'], result['key-datatypes'], result.get('match-fields', ()))
                if mapping:
                    entry['result'] = _map_result(value, result['result-datatypes'], group['table'])
                if 'zone-hook' in result:
                    if result['zone-hook'] == 'output':
                        zones = lookup(configuration or {}, ('firewall', 'zone'), {})
                        entry['from-zone'] = next(
                            (name for name, options in zones.items() if 'local-zone' in options), None)
                    elif result['zone-hook'] == 'input':
                        entry['from-zone'] = entry.get('comment')
                    else:
                        entry['from-zone'] = entry.get('comment', '').split(' to ', 1)[0]
                result['entries'].append(entry)
            except _Unsupported as error:
                result['entries'].append({'unsupported': element, 'reason': str(error)})
        if fields and 'tcp-flags' in fields and configuration is not None:
            family = group['name'].split('_', 1)[0]
            definition = lookup(configuration, ('firewall', 'group', kind, family, name), {})
            result['entries'] = _tcp_group_entries(result['entries'], fields, definition)
    return result


def _source_validation_interfaces(table):
    """Expand installed private sets, retaining references in partial chain listings."""
    for chain in table['chains'].values():
        for rule in chain.get('rules', []):
            for matches in (rule, rule.get('not', {})):
                name = matches.get('source-validation-interface-set')
                group = table['sets'].get(name, {})
                if 'entries' not in group or any('unsupported' in entry for entry in group['entries']):
                    continue
                matches['inbound-interface'] = [entry['key'][0] for entry in group['entries']]
                del matches['source-validation-interface-set']


def normalize(document, *, configuration=None):
    """Normalize a decoded full or scoped ``nft -j list ...`` response.

    Objects are indexed as tables[family][table][chains/sets/maps/flowtables].
    Rules stay in kernel order. Missing definitions are not fetched or invented.
    Returned data is independent of the input and remains JSON serializable.
    Optional running configuration labels group key columns using renderer order.
    """
    if not isinstance(document, dict) or not isinstance(document.get('nftables'), list):
        raise ValueError('Expected an nftables JSON listing with an nftables array')
    result = {'metadata': {}, 'tables': {}}
    for record in deepcopy(document['nftables']):
        if not isinstance(record, dict) or len(record) != 1:
            raise ValueError('Each nftables listing record must contain one object')
        kind, data = next(iter(record.items()))
        if kind == 'metainfo':
            result['metadata'] = data
            continue
        if kind not in ('table', 'chain', 'rule', 'set', 'map', 'flowtable', 'counter', 'limit', 'quota', 'ct timeout', 'ct helper'):
            result.setdefault('unsupported', []).append(record)
            continue

        table_name = data['name'] if kind == 'table' else data['table']
        tables = result['tables'].setdefault(data['family'], {})
        table = tables.setdefault(table_name, {'chains': {}, 'sets': {}, 'maps': {}, 'flowtables': {}})
        if kind == 'table':
            table['metadata'] = data
        elif kind == 'rule':
            chain = table['chains'].setdefault(data['chain'], {})
            chain.setdefault('rules', []).append(_rule(data))
        elif kind == 'chain':
            chain = table['chains'].setdefault(data['name'], {})
            chain.update({key: value for key, value in data.items() if key not in ('family', 'table')})
        elif kind in ('set', 'map'):
            try:
                group = _group(data, mapping=kind == 'map', configuration=firewall_scope.for_table(configuration, table_name))
            except _Unsupported as error:
                group = {'name': data['name'], 'unsupported': [
                    {'reason': str(error), 'expression': data},
                ]}
            table[kind + 's'][data['name']] = group
        elif kind in ('counter', 'limit', 'quota', 'ct timeout', 'ct helper'):
            normalized = {key: value for key, value in data.items() if key not in ('family', 'table')}
            group_kind, name = _group_identity(data['name'], table_name)
            if group_kind:
                normalized.update({'group-kind': group_kind, 'group-name': name})
            if 'comment' in normalized:
                normalized['description'] = normalized.pop('comment')
            if kind == 'limit':
                parameters = {key: data[key] for key in ('rate', 'per', 'burst', 'inv', 'rate_unit', 'burst_unit') if key in data}
                normalized = {key: value for key, value in normalized.items() if key not in parameters}
                normalized.update(_limit('limit', parameters)['limit'])
            if kind == 'quota':
                normalized['mode'] = 'over' if normalized.pop('inv', False) else 'until'
                normalized['remaining'] = max(0, normalized['bytes'] - normalized['used'])
                normalized['exhausted'] = normalized['used'] >= normalized['bytes']
            table.setdefault(kind + 's', {})[data['name']] = normalized
        else:
            flowtable = {key: value for key, value in data.items() if key not in ('family', 'table', 'dev')}
            if 'dev' in data:
                flowtable['interface'] = _list(data['dev'])
            table['flowtables'][data['name']] = flowtable

    for tables in result['tables'].values():
        for table in tables.values():
            _source_validation_interfaces(table)
    return result
