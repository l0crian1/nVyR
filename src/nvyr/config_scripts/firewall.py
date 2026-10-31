"""Firewall maps, IPv4/IPv6 filtering and NAT in one nftables transaction."""

import ipaddress

from nvyr.errors import ValidationError, Warning
from nvyr.helpers import domain_groups, geoip, geoip_config, nftables, nftables_lifecycle
from nvyr.helpers import interface_patterns, kernel_settings, nftables_helpers, nftables_timeouts
from nvyr.helpers import nftables_modify
from nvyr.helpers import nftables_zones
from nvyr.helpers import nftables_source_validation as source_validation
from nvyr.helpers.nftables_singletons import verify_group_inclusions
from nvyr.helpers.template import render
from nvyr.helpers.nftables_formatters import (
    NFT_KEYMAP, NFT_FILTER_HOOKS, nft_group_fields, nft_field_type, singleton_groups, limit_refill_seconds,
    nft_group_tcp_mask, nft_present_fields, nft_field_value, NFT_RULE_LIMIT_PATHS,
    NFT_PORT_PROTOCOLS, NFT_NAT_PORT_PROTOCOLS, NFT_FAMILY_FIELDS, nft_map_results,
    nft_interface_contexts, nft_slave_matches,
)
from nvyr.helpers.validators import ICMP_KEYMAP, ICMP_TYPES, limit_amount, DURATION_UNITS, duration_seconds
from nvyr.helpers.validators import tcp_flag_values
from nvyr.tree import lookup
from nvyr.helpers.nftables_connection import verify_connection, verify_connection_group
from nvyr.helpers.validators import connection_quantity


def get_config(context):
    # Ownership determines when this script runs, not which configuration it can read.
    return context.effective


def verify_icmp_group(family, name, configuration):
    """Validate each type's own code selection before creating the native set."""
    path = f'firewall group icmp-group {family} {name}'
    mode = lookup(configuration, ('match',), None)
    # An empty group is allowed, but its lookup structure must be explicit.
    if mode not in {'type', 'type-code'}:
        raise ValidationError(f'{path}: match must be type or type-code')

    numbers = set()
    for typename, options in lookup(configuration, ('type',), {}).items():
        entry = ICMP_KEYMAP[family][typename]
        # Aliases identify the same wire type and cannot create separate members.
        if entry['number'] in numbers:
            raise ValidationError(f'{path}: {typename} duplicates an already configured ICMP type')
        numbers.add(entry['number'])

        codes = lookup(options, ('code',), [])
        # Type-only membership must not silently discard a configured code.
        if mode == 'type' and codes:
            raise ValidationError(f'{path} type {typename}: code requires match type-code')
        # Each type needs at least one code; there is no implicit code or wildcard.
        if mode == 'type-code' and not codes:
            raise ValidationError(f'{path} type {typename}: code is required for match type-code')

        seen_codes = set()
        for code in codes:
            bounds = [int(part) for part in code.split('-')]
            selected = set(range(bounds[0], bounds[-1] + 1))

            # Check the entire interval so ranges cannot include unassigned gaps.
            if not selected <= entry['codes']:
                allowed = ', '.join(str(value) for value in sorted(entry['codes']))
                raise ValidationError(f'{path} type {typename}: invalid code {code!r}; valid codes: {allowed}')

            # Separate elements must not overlap within the same ICMP type.
            if seen_codes & selected:
                raise ValidationError(f'{path} type {typename}: code {code!r} overlaps another configured code or range')
            seen_codes.update(selected)


def verify_icmp_group_reference(rule, path, groups, mapping, match_group, excluded_group):
    """Reject overlapping ICMP inputs and resolve both matching polarities."""
    # Ordinary rules need no group lookup or inherited-field inspection.
    if 'icmp-group' not in rule and 'icmp-group' not in lookup(rule, ('not',), {}):
        return

    definitions = lookup(groups, ('icmp-group', path[1]), {})
    inherited = nftables.match_fields({}, mapping, match_group, excluded_group)
    explicit = (set(rule) | set(lookup(rule, ('not',), {}))) & {'icmp-type', 'icmp-code'}
    for matches in (rule, lookup(rule, ('not',), {})):
        # Rules without an ICMP group retain their existing matching behavior.
        if 'icmp-group' not in matches:
            continue

        name = ' '.join(path)
        target = matches['icmp-group']
        # References must exist in this rule's family, including negative matches.
        if target not in definitions:
            raise ValidationError(f'{name}: icmp-group {target!r} is not configured in {path[1]}')

        fields = {'icmp-type'}
        # A paired group also owns the code field in a compound lookup.
        if definitions[target]['match'] == 'type-code':
            fields.add('icmp-code')
        conflicts = explicit | (fields & inherited)
        # A group owns its fields; explicit type/code cannot redefine its pairs.
        if conflicts:
            raise ValidationError(f'{name}: icmp-group cannot be combined with ' + ', '.join(sorted(conflicts)))


def _group_interval(field, value, family):
    """Normalize one validated key component for duplicate/overlap detection."""
    if field == 'connection-expiration' or field.endswith(('-packets', '-bytes', '-average-packet-size')):
        kind = 'expiration' if field == 'connection-expiration' else 'packets' if field.endswith('-packets') else 'bytes'
        number = connection_quantity(value, kind)
        return number, number

    if field in {'source-address', 'destination-address'} or (field.startswith('connection-') and field.endswith('-address')):
        if '/' in value:
            network = ipaddress.ip_network(value, strict=False)
            return int(network.network_address), int(network.broadcast_address)

        parts = value.split('-')
        return int(ipaddress.ip_address(parts[0])), int(ipaddress.ip_address(parts[-1]))

    if field in {'source-port', 'destination-port', 'packet-mark', 'connection-mark', 'dscp', 'vlan-id', 'vlan-priority'} or (field.startswith('connection-') and field.endswith(('-port', '-zone', '-id'))):
        parts = value.split('-')
        return int(parts[0]), int(parts[-1])

    if field == 'icmp-type':
        number = ICMP_TYPES[family][value]
        return number, number

    if field == 'icmp-code':
        return int(value), int(value)

    if field in {'source-mac', 'destination-mac'}:
        value = value.lower()
    elif field == 'connection-status':
        value = ','.join(sorted(set(value.split(','))))

    return value, value


def verify_map(family, name, configuration, named_chains):
    """Validate lookup keys and map results with shared group checks."""
    _verify_group(family, name, configuration, 'map', named_chains)
    verify_map_nftables_limitations(family, name, configuration)


def verify_map_nftables_limitations(family, name, configuration):
    """Contain temporary nftables 1.1.7 restrictions until upstream fixes are verified."""
    affected_fields = {
        'connection-zone',
        'connection-original-zone',
        'connection-reply-zone',
        'connection-original-packets',
        'connection-reply-packets',
        'connection-total-packets',
        'connection-original-bytes',
        'connection-reply-bytes',
        'connection-total-bytes',
        'connection-original-average-packet-size',
        'connection-reply-average-packet-size',
        'connection-total-average-packet-size',
    }
    fields = nft_group_fields(configuration)
    affected = [field for field in fields if field in affected_fields]

    # Other keys retain their existing map support; these defects were reproduced
    # with conntrack zone/accounting keys, not with every typeof expression.
    if not affected:
        return

    path = f'firewall group map {family} {name}'
    names = ', '.join(' '.join(NFT_KEYMAP[field].path) for field in affected)

    # Native single-field maps byte-swap these keys and fail real packet lookups.
    # Reject even empty maps so later population cannot install incorrect matches.
    if len(fields) == 1:
        raise ValidationError(
            f'{path}: {names} cannot be the only map match field: '
            'nftables 1.1.7 installs this key with incorrect byte order.'
        )

    # Native five-field maps match packets but corrupt the listed keys/type metadata.
    # Keep inspection and export reliable; tested two-to-four-field maps are valid.
    if len(fields) == 5:
        raise ValidationError(
            f'{path}: five-field maps containing {names} are not supported: '
            'nftables 1.1.7 lists their keys incorrectly.'
        )


def verify_match_group(family, name, configuration):
    """Validate the same lookup keys without map results."""
    _verify_group(family, name, configuration, 'match-group', {})
    verify_dynamic_group(family, name, configuration, 'match-group')


def verify_dynamic_group(family, name, configuration, kind):
    """Dynamic groups contain only packet-learned keys."""
    # Static groups retain their existing interval support without dynamic limits.
    if 'dynamic' not in configuration:
        return

    path = f'firewall group {kind} {family} {name}'
    member_node = 'address' if kind == 'address-group' else 'entry'

    # Dynamic groups must not mix configured policy with packet-learned state.
    if lookup(configuration, (member_node,), None):
        raise ValidationError(
            f'{path}: dynamic groups cannot contain configured members. '
            f'Remove {member_node} configuration or disable dynamic.'
        )

    if kind == 'address-group':
        fields = ['source-address']
    else:
        fields = nft_group_fields(configuration)

    # Only fields with a supported packet extraction may form an update key.
    unsupported = [field for field in fields if not NFT_KEYMAP[field].dynamic]
    if unsupported:
        raise ValidationError(f'{path}: dynamic updates do not support ' + ', '.join(unsupported))


def verify_group_update(rule, path, groups, mapping=None, match_group=None):
    """Validate a learning target separately from the rule's packet matches."""
    # Rules without an update statement need no learning target checks.
    if 'add-to-group' not in rule:
        return

    name = ' '.join(path)
    update = rule['add-to-group']
    targets = set(update) & {'source-address', 'destination-address', 'match-group'}
    # One update statement extracts either an address or one concatenated key.
    if len(targets) != 1:
        raise ValidationError(f'{name}: add-to-group requires exactly one source-address, destination-address or match-group target')

    target = next(iter(targets))
    kind = 'match-group' if target == 'match-group' else 'address-group'
    definition = lookup(groups, (kind, path[1], update[target]), None)
    # References must resolve in the same family, including when no entries exist yet.
    if definition is None:
        raise ValidationError(f"{name}: add-to-group target {update[target]!r} is not a configured {path[1]} {kind}")

    # Static sets do not support packet-path learning.
    if 'dynamic' not in definition:
        raise ValidationError(f"{name}: add-to-group target {update[target]!r} requires dynamic")

    fields = set(nft_group_fields(definition)) if kind == 'match-group' else {target}
    # Prerouting cannot extract an outbound interface before the routing decision.
    if path[2:4] == ('prerouting', 'raw') and 'outbound-interface' in fields:
        raise ValidationError(f'{name}: add-to-group cannot extract outbound-interface in prerouting raw')

    # Locally generated packets have no inbound interface to learn in output raw.
    if path[2:4] == ('output', 'raw') and 'inbound-interface' in fields:
        raise ValidationError(f'{name}: add-to-group cannot extract inbound-interface in output raw')

    # Address-only learning needs no transport protocol lookup through map entries.
    protocol_fields = {'source-port', 'destination-port', 'icmp-type', 'icmp-code', 'tcp-flags'}
    protocols = nftables.match_protocols(rule, mapping, match_group, family=path[1]) if fields & protocol_fields else set()
    # The generated update guards extraction with port-bearing protocols. Reject only
    # configured protocol selections that contradict that guard.
    if fields & {'source-port', 'destination-port'} and protocols - NFT_PORT_PROTOCOLS:
        raise ValidationError(f'{name}: add-to-group port fields require a port protocol (tcp, udp, udplite, sctp or dccp)')

    # The update also supplies the family-specific ICMP guard; any configured
    # protocol selection must agree with the header being extracted.
    protocol = 'icmp' if path[1] == 'ipv4' else 'ipv6-icmp'
    if fields & {'icmp-type', 'icmp-code'} and protocols - {protocol}:
        raise ValidationError(f'{name}: add-to-group ICMP fields require protocol {protocol}')

    # TCP flag extraction supplies a TCP guard and cannot use a conflicting protocol.
    if 'tcp-flags' in fields and protocols - {'tcp'}:
        raise ValidationError(f'{name}: add-to-group TCP flags require protocol tcp')


def verify_key_size(fields, family, path):
    """Shared kernel key limits for groups and per-rule meters."""
    # Inet objects must not acquire an implicit IP-family dependency from their keys.
    unsupported = set(fields) & NFT_FAMILY_FIELDS if family == 'inet' else set()
    if unsupported:
        raise ValidationError(f'{path}: inet keys must be family-neutral; cannot use ' + ', '.join(sorted(unsupported)))

    # Limit concatenated lookup keys to five fields.
    if len(fields) > 5:
        raise ValidationError(f'{path}: Flow group has {len(fields)} key fields (maximum 5).')

    # Check the 64-byte key limit, including each field's four-byte alignment.
    sizes = [(field, nft_field_type(field, family)[1]) for field in fields]
    payload_size = sum(size for _, size in sizes)
    storage_size = sum((size + 3) // 4 * 4 for _, size in sizes)
    if storage_size > 64:
        total = payload_size if payload_size > 64 else storage_size
        lines = [f'{path}: Flow group key size is {total} bytes (maximum 64 bytes).',
                 '', 'Parameter sizes:']
        lines.extend(f'  {field:<28} {size:>2} bytes' for field, size in sizes)
        lines.append(f'\nIncluding 4-byte field alignment: {storage_size} bytes.')
        raise ValidationError('\n'.join(lines))


def _verify_group(family, name, configuration, group_kind, named_chains):
    path = f'firewall group {group_kind} {family} {name}'
    fields = nft_group_fields(configuration)
    # A group needs at least one packet field to form its lookup key.
    if not fields:
        raise ValidationError(f'{path}: at least one match field is required')

    # Groups and meter keys obey the same concatenation storage limits.
    verify_key_size(fields, family, path)

    kind = lookup(configuration, ('result-type',), None)
    # Inet maps supply firewall verdicts; NAT results belong to family-specific maps.
    if family == 'inet' and group_kind == 'map' and kind not in {None, 'verdict'}:
        raise ValidationError(f'{path}: inet maps require result-type verdict')

    # Every map must declare the type of result its entries return.
    if group_kind == 'map' and not kind:
        raise ValidationError(f'{path}: result-type is required')

    # A catch-all has no key fields, but must return the same type as ordinary entries.
    if group_kind == 'map' and 'default-result' in configuration:
        _verify_map_result(configuration['default-result'], f'{path} default-result', kind, named_chains, family)

    # ICMP groups must declare a protocol key, even before any entries are added.
    if set(fields) & {'icmp-type', 'icmp-code'} and 'protocol' not in fields:
        raise ValidationError(f'{path}: ICMP matching requires protocol in the {group_kind} match fields')

    # TCP flags require an explicit protocol key even for an empty group.
    if 'tcp-flags' in fields and 'protocol' not in fields:
        raise ValidationError(f'{path}: TCP flags require protocol in the {group_kind} match fields')

    intervals = []
    exact_keys = {}
    tcp_mask = nft_group_tcp_mask(configuration) if 'tcp-flags' in fields else None

    for identifier, entry in lookup(configuration, ('entry',), {}).items():
        entry_path = f'{path} entry {identifier}'
        # Each entry must supply every declared match field and no extra fields.
        supplied = nft_present_fields(entry)
        if supplied != set(fields):
            missing = set(fields) - supplied
            extra = supplied - set(fields)
            detail = []
            if missing:
                detail.append('missing match fields: ' + ', '.join(sorted(missing)))
            if extra:
                detail.append('undeclared match fields: ' + ', '.join(sorted(extra)))
            raise ValidationError(f'{entry_path}: ' + '; '.join(detail))

        # The generated entry-name|description comment must fit in 128 UTF-8 bytes.
        if len((identifier + '|' + lookup(entry, ('description',), '')).encode('utf-8')) > 128:
            raise ValidationError(f'{entry_path}: entry name and description exceed the 128-byte nftables comment limit')

        # Only maps have results; match-groups supply membership tests.
        if group_kind == 'map':
            _verify_map_result(lookup(entry, ('result',), {}), entry_path, kind, named_chains, family)

        # Port keys require an explicit transport with source/destination ports.
        if set(fields) & {'source-port', 'destination-port'} and lookup(entry, ('protocol',), None) not in NFT_PORT_PROTOCOLS:
            raise ValidationError(f'{entry_path}: port lookup requires a port protocol (tcp, udp, udplite, sctp or dccp)')

        # NAT port results retain their independently supported translation protocols.
        if kind in {'port', 'address-port'} and lookup(entry, ('protocol',), None) not in NFT_NAT_PORT_PROTOCOLS:
            raise ValidationError(f'{entry_path}: port result requires protocol tcp or udp')

        # Only TCP packets have the flags described by this entry.
        if 'tcp-flags' in fields and lookup(entry, ('protocol',), None) != 'tcp':
            raise ValidationError(f'{entry_path}: TCP flags require protocol tcp')

        # Scalar group fields must obey the same ICMP protocol constraints as rules.
        if set(fields) & {'icmp-type', 'icmp-code'}:
            icmp_matches = {field: [entry[field]] for field in fields if not NFT_KEYMAP[field].path}
            nftables.verify_icmp(icmp_matches, (*path.split(), 'entry', identifier), family)

        # Apply the same offloaded-connection status restrictions as ordinary rules.
        if 'connection-status' in fields:
            _verify_offload_status([nft_field_value(entry, 'connection-status')], entry_path)

        # Normalize keys so equivalent addresses or status groups count as duplicates.
        flags = tcp_flag_values(entry['tcp-flags'], tcp_mask) if tcp_mask is not None else [None]
        for flag_value in flags:
            key = tuple((flag_value, flag_value) if field == 'tcp-flags' else _group_interval(field, nft_field_value(entry, field), family)
                        for field in fields)
            # Expanded alternatives may not overlap another logical entry's key.
            if key in exact_keys:
                other = exact_keys[key]
                raise ValidationError(f'{path}: entries {other!r} and {identifier!r} have duplicate or overlapping lookup keys')

            exact_keys[key] = identifier
            intervals.append((key, identifier))

    # Exact tuples need only the hash lookup above, even for large maps.
    if all(low == high for key, _ in intervals for low, high in key):
        return

    # Sweep the most varied component to avoid scanning identical interface keys.
    axis = max(range(len(fields)), key=lambda index: len({key[index] for key, _ in intervals}))
    active = []
    for key, identifier in sorted(intervals, key=lambda item: item[0][axis]):
        active = [(prior, name) for prior, name in active if prior[axis][1] >= key[axis][0]]
        for prior, other in active:
            # Two entries conflict only when their ranges overlap in every key field.
            if all(left[0] <= right[1] and right[0] <= left[1] for left, right in zip(prior, key)):
                raise ValidationError(f'{path}: entries {other!r} and {identifier!r} have duplicate or overlapping lookup keys')
        active.append((key, identifier))


def _verify_map_result(result, entry_path, kind, named_chains, family):
    required = {'verdict': {'action'}, 'address': {'address'}, 'port': {'port'},
                'address-port': {'address', 'port'}}[kind]
    # Jump verdicts require a target in addition to the action itself.
    if kind == 'verdict' and lookup(result, ('action',), None) == 'jump':
        required = required | {'jump-target'}

    # Reject missing or extra result fields for the selected result type.
    if set(result) != required:
        raise ValidationError(f'{entry_path}: result-type {kind} requires exactly: ' + ', '.join(sorted(required)))

    # Map jumps must reference a named chain in the map's address family.
    if 'jump-target' in result and result['jump-target'] not in named_chains:
        raise ValidationError(f"{entry_path}: jump-target {result['jump-target']!r} is not a named chain in {family}")


def _verify_offload_status(groups, name):
    for group in groups:
        flags = set(group.split(','))
        # These additional status restrictions apply only to groups containing offload.
        if 'offload' not in flags:
            continue

        # Offloaded connections must also have the confirmed status bit.
        if 'confirmed' not in flags:
            raise ValidationError(f'{name}: connection status {group!r} requires confirmed in the same group when offload is used')

        # Offload cannot coexist with a helper, sequence adjustment, or dying state.
        incompatible = flags & {'helper', 'seq-adjust', 'dying'}
        if incompatible:
            names = ', '.join(sorted(incompatible))
            raise ValidationError(f'{name}: connection status {group!r}: offload cannot be combined with {names}')


def verify_reject(rule, path, match_group=None, hook=None):
    """Validate response selection and the packet context needed for TCP resets."""
    # Other verdicts need no response checks unless an incompatible response is configured.
    if lookup(rule, ('action',), None) != 'reject' and 'reject-response' not in rule:
        return

    name = ' '.join(path)
    response = lookup(rule, ('reject-response',), None)

    # Portable ICMPX responses and TCP reset are the only family-neutral responses.
    if path[1] == 'inet' and response not in {None, 'no-route', 'host-unreachable', 'port-unreachable', 'admin-prohibited', 'tcp-reset'}:
        raise ValidationError(f'{name}: inet rejects require an ICMPX response or tcp-reset')

    # A response only modifies an explicit reject action, never a map or other verdict.
    if response is not None and lookup(rule, ('action',), None) != 'reject':
        raise ValidationError(f'{name}: reject-response requires action reject')

    # Reject must be reachable only from hooks where the kernel can send a response.
    if lookup(rule, ('action',), None) == 'reject' and hook is not None and hook not in {'ingress', 'prerouting', 'input', 'forward', 'output'}:
        raise ValidationError(f'{name}: reject is not supported in the {hook} hook')

    # Resets require an explicit TCP-only match, including a referenced positive group.
    if response == 'tcp-reset' and nftables.match_protocols(rule, match_group=match_group, family=path[1]) != {'tcp'}:
        raise ValidationError(f'{name}: reject-response tcp-reset requires protocol tcp only')


def verify_rule(rule, path, named_chains, flowtables=None, maps=None, match_groups=None, groups=None):
    # Disabled rules are not emitted, so skip their cross-field requirements.
    if 'disable' in rule:
        return

    name = ' '.join(path)
    # An empty VLAN node cannot contribute a packet match.
    if 'vlan' in rule and not rule['vlan']:
        raise ValidationError(f'{name}: vlan requires id or priority')

    selected = None
    if 'map' in rule:
        # Require a verdict map and reject explicit fields or actions it already supplies.
        selected = nftables.verify_map_reference(rule, path, maps or {}, {'verdict'})

    # A match-group must exist and must not duplicate explicit or map-supplied fields.
    group = nftables.verify_match_group_reference(rule, path, match_groups or {}, selected)

    # Singleton references must exist and supply fields not already matched elsewhere.
    nftables.verify_singleton_references(rule, path, path[1], groups or {}, selected, group)
    # Excluded groups still require valid references and obey all hook restrictions.
    excluded_group = nftables.verify_exclusions(rule, path, path[1], groups or {}, match_groups or {})
    # ICMP group references resolve per family and cannot duplicate other inputs.
    verify_icmp_group_reference(rule, path, groups or {}, selected, group, excluded_group)
    fields = nftables.match_fields(rule, selected, group, excluded_group)

    # Check indirect and negated matches too, so inet never selects an IP family.
    if path[1] == 'inet' and fields & NFT_FAMILY_FIELDS:
        raise ValidationError(f'{name}: inet matches must be family-neutral')

    # Only rules with setters need literal, transport and direct-hook checks.
    if 'modify' in rule:
        protocols = set()
        if 'tcp-mss' in rule['modify']:
            protocols = nftables.match_protocols(rule, selected, group, family=path[1])
        nftables_modify.verify(rule, path, protocols, group)

    # Prerouting runs before routing has selected an outbound interface.
    if path[2:4] == ('prerouting', 'raw') and 'outbound-interface' in fields:
        raise ValidationError(f'{name}: rule, map or match-group cannot match outbound-interface in prerouting raw')

    # Maps and groups cannot introduce inbound-interface matches for local output.
    if path[2:4] == ('output', 'raw') and 'inbound-interface' in fields:
        raise ValidationError(f'{name}: rule, map or match-group cannot match inbound-interface in output raw')

    # Learning targets do not count as matching fields or duplicate packet matches.
    if 'add-to-group' in rule:
        verify_group_update(rule, path, groups or {}, selected, group)

    # Limit values and key extraction must be valid even when a map supplies the verdict.
    if 'limit' in rule or 'limit' in lookup(rule, ('connection',), {}):
        verify_limits(rule, path, selected, group, limit_groups=lookup(groups or {}, ('limit-group', path[1]), {}))

    # Timeout assignment must select the group's transport and family.
    if 'timeout-group' in lookup(rule, ('connection',), {}):
        protocols = nftables.match_protocols(rule, selected, group, family=path[1])
        nftables_timeouts.verify_reference(rule, path, lookup(groups or {}, ('timeout-group',), {}), protocols)

    # Quotas must define one allowance or reference an existing shared allowance.
    if 'quota' in rule:
        verify_quota(rule['quota'], (*path, 'quota'), lookup(groups or {}, ('quota-group',), {}))

    # Named counters and logging options obey the same contract in firewall and NAT.
    nftables.verify_rule_statements(rule, path, groups or {})

    # Response selection must be consistent with the action and effective protocol matches.
    verify_reject(rule, path, group)

    if selected is not None:
        _verify_rule_matches(rule, path, selected, group, excluded_group, fields=fields)
        return

    # Enabled rules without a map must specify their own action.
    if 'action' not in rule:
        raise ValidationError(f'{name}: action is required')

    if rule['action'] == 'jump':
        # A jump action must name its destination chain.
        if 'jump-target' not in rule:
            raise ValidationError(f'{name}: action jump requires jump-target')

        # Only named chains in this rule's address family are valid jump targets.
        if rule['jump-target'] not in named_chains:
            raise ValidationError(f"{name}: jump-target {rule['jump-target']!r} is not a named chain in {path[1]}")
    elif 'jump-target' in rule:
        # A target has no meaning unless the rule's action is jump.
        raise ValidationError(f'{name}: jump-target requires action jump')

    if rule['action'] == 'offload':
        # Flow offload is supported only for packets traversing the forward filter.
        if path[2:4] != ('forward', 'filter'):
            raise ValidationError(f'{name}: action offload is only available in the forward filter')

        # An offload action must select a flowtable.
        if 'offload-target' not in rule:
            raise ValidationError(f'{name}: action offload requires offload-target')

        # The selected flowtable must exist in the proposed configuration.
        if rule['offload-target'] not in (flowtables or {}):
            raise ValidationError(f"{name}: offload-target {rule['offload-target']!r} is not a configured flowtable")
    elif 'offload-target' in rule:
        # A flowtable target is valid only with the offload action.
        raise ValidationError(f'{name}: offload-target requires action offload')

    _verify_rule_matches(rule, path, match_group=group, excluded_group=excluded_group, fields=fields)


def _verify_rule_matches(rule, path, mapping=None, match_group=None, excluded_group=None, *, fields=None):
    """Check ordinary matches even when a map supplies the rule's verdict."""
    name = ' '.join(path)
    if fields is None:
        fields = nftables.match_fields(rule, mapping, match_group, excluded_group)

    # FIB queries need a complete, unambiguous lookup and result selection.
    if 'fib' in rule:
        verify_fib(rule['fib'], path)

    # ICMP type/code pairs and explicit protocols must describe the same header.
    if fields & {'icmp-type', 'icmp-code'}:
        nftables.verify_icmp(rule, path, path[1], mapping, match_group, excluded_group)

    connection = lookup(rule, ('connection',), {})
    # Reject connection-status combinations that cannot describe an offloaded flow.
    if 'status' in connection:
        _verify_offload_status(connection['status'], name)

    # Exclusions use the same exact status combinations as positive comparisons.
    if 'status' in lookup(connection, ('not',), {}):
        _verify_offload_status(connection['not']['status'], name)

    # Transport-port matches require an explicit port-bearing protocol selection.
    if fields & {'source-port', 'destination-port'}:
        nftables.verify_ports(rule, path, mapping=mapping, match_group=match_group)

    # A negated transport tuple still reads port headers through its positive guard.
    excluded_fields = set(lookup(excluded_group or {}, ('match',), {}))
    needs_protocol = bool(fields & {'tcp-mss', 'tcp-flags'} or excluded_fields & {'source-port', 'destination-port'})
    protocols = nftables.match_protocols(rule, mapping, match_group, family=path[1]) if needs_protocol else set()
    if excluded_fields & {'source-port', 'destination-port'} and protocols - NFT_PORT_PROTOCOLS:
        raise ValidationError(f'{name}: excluded match-group port fields require a port protocol (tcp, udp, udplite, sctp or dccp)')

    if 'ttl' in rule:
        ttl = rule['ttl']
        # An exact TTL/hop-limit match cannot be combined with range comparisons.
        if 'eq' in ttl and ('lt' in ttl or 'gt' in ttl):
            raise ValidationError(f'{name}: ttl eq cannot be combined with ttl lt or ttl gt')

        # Bounds are exclusive; at least one integer in the packet field must remain.
        minimum = int(ttl['gt']) + 1 if 'gt' in ttl else 0
        maximum = int(ttl['lt']) - 1 if 'lt' in ttl else 255
        if minimum > maximum:
            raise ValidationError(f'{name}: ttl comparisons cannot match any value from 0 to 255')

        excluded_ttl = lookup(ttl, ('not', 'eq'), None)
        # Excluding the sole permitted TTL makes an otherwise valid range impossible.
        if excluded_ttl is not None and (lookup(ttl, ('eq',), None) == excluded_ttl or minimum == maximum == int(excluded_ttl)):
            raise ValidationError(f'{name}: ttl comparisons exclude the only permitted value')

    # A masked IP or MAC match cannot be mixed with other values of that field.
    for address in ('source-address', 'destination-address',
                    'source-mac', 'destination-mac'):
        for part in (rule, lookup(rule, ('not',), {})):
            matches = lookup(part, (address,), {})
            # Each polarity is rendered independently; retain the per-expression mask limit.
            if len(matches) > 1 and any('mask' in match for match in matches.values()):
                raise ValidationError(f'{name}: {address} mask requires exactly one {address} per polarity')

    # TCP MSS matches must not select any non-TCP protocol.
    if 'tcp-mss' in fields and protocols - {'tcp'}:
        raise ValidationError(f'{name}: tcp-mss requires protocol tcp when protocol is configured')

    # TCP flags require a positive TCP restriction or a group's TCP header guard.
    if 'tcp-flags' in fields:
        has_protocol = bool(lookup(rule, ('protocol',), None)) or 'protocol' in nftables.match_fields({}, mapping, match_group)
        has_protocol = has_protocol or 'tcp-flags' in lookup(excluded_group or {}, ('match',), {})
        if not has_protocol or protocols - {'tcp'}:
            raise ValidationError(f'{name}: tcp-flags requires protocol tcp')

        # A flag field must come from one source, rather than competing lookups.
        sources = int('tcp-flags' in rule)
        sources += sum('tcp-flags' in lookup(definition or {}, ('match',), {})
                       for definition in (mapping, match_group, excluded_group))
        if sources > 1:
            raise ValidationError(f'{name}: tcp-flags cannot be combined with the same field in a map or match-group')


def verify_fib(configuration, path, hook=None):
    """Check FIB combinations, and hook availability when a caller is known."""
    name = ' '.join(path) + ' fib'
    fields = set(lookup(configuration, ('lookup',), {}))
    result = lookup(configuration, ('result',), {})
    excluded = lookup(result, ('not',), {})
    result_fields = (set(result) - {'not'}) | set(excluded)

    # The kernel requires exactly one address as the lookup key.
    if len(fields & {'source-address', 'destination-address'}) != 1:
        raise ValidationError(f'{name}: lookup requires exactly one of source-address or destination-address')

    # A FIB lookup cannot use both incoming and outgoing interface constraints.
    if {'inbound-interface', 'outbound-interface'} <= fields:
        raise ValidationError(f'{name}: lookup inbound-interface and outbound-interface are mutually exclusive')

    # Each FIB expression returns either an interface or an address type.
    if len(result_fields) != 1 or not any(lookup(result, (key,), None) or lookup(excluded, (key,), None) for key in result_fields):
        raise ValidationError(f'{name}: result requires either outbound-interface or route-type')

    interface_results = set(lookup(result, ('outbound-interface',), ())) | set(lookup(excluded, ('outbound-interface',), ()))
    # Existence already has a complementary keyword; only named interfaces are negatable.
    if set(lookup(excluded, ('outbound-interface',), ())) & {'exists', 'missing'}:
        raise ValidationError(f'{name}: negate an interface name; use exists or missing directly')
    # Existence tests are alternatives to matching named outgoing interfaces.
    if interface_results & {'exists', 'missing'} and len(interface_results) != 1:
        raise ValidationError(f'{name}: exists and missing cannot be combined with each other or interface names')

    # The kernel only supports an outgoing-interface input for address-type results.
    if 'outbound-interface' in fields and 'route-type' not in result_fields:
        raise ValidationError(f'{name}: lookup outbound-interface requires result route-type')

    allowed = {'prerouting', 'input', 'forward', 'output', 'postrouting'}
    # Interface results and incoming-interface constraints require an ingress hook.
    if 'outbound-interface' in result_fields or 'inbound-interface' in fields:
        allowed &= {'prerouting', 'input', 'forward'}

    # Outgoing-interface constraints require a hook after the routing decision.
    if 'outbound-interface' in fields:
        allowed &= {'forward', 'output', 'postrouting'}

    # Named chains inherit restrictions from every base hook that can reach them.
    if hook is not None and hook not in allowed:
        hooks = ', '.join(sorted(allowed))
        raise ValidationError(f'{name}: this lookup is not supported from the {hook} hook; allowed hooks: {hooks}')


def verify_quota(options, path, groups=None):
    name = ' '.join(path)

    # A named quota owns its threshold and mode; consumers cannot override them.
    if 'group' in options:
        if set(options) != {'group'}:
            raise ValidationError(f'{name}: quota group cannot be combined with inline quota parameters')

        # Referenced allowances must exist in the proposed configuration.
        if options['group'] not in (groups or {}):
            raise ValidationError(f"{name}: quota group {options['group']!r} is not configured")

        return

    # An inline or named quota needs a byte threshold, including an explicit zero.
    if 'bytes' not in options:
        raise ValidationError(f'{name}: quota requires bytes')

    # Over and until describe opposite match directions for the same allowance.
    if 'over' in options and 'until' in options:
        raise ValidationError(f'{name}: quota over and until are mutually exclusive')


def verify_limits(rule, path, mapping=None, match_group=None, *, hook=None, stage=None, family=None, limit_groups=None):
    """Check limit relationships and extraction at the actual calling hook."""
    # Ordinary rules need no limit-specific path or protocol inspection.
    if not any(lookup(rule, suffix, None) is not None for suffix in NFT_RULE_LIMIT_PATHS.values()):
        return

    name = ' '.join(path)
    family = family or path[1]
    # Group definitions have no hook; rules in base chains supply their own hook.
    if path[1] in {'ipv4', 'ipv6', 'inet'} and path[2] != 'name':
        hook, stage = path[2:4]

    for kind, suffix in NFT_RULE_LIMIT_PATHS.items():
        options = lookup(rule, suffix, None)
        # Rules without this kind of limit have no associated state to validate.
        if options is None:
            continue

        kind = ' '.join(suffix)
        # Resolve named allowances before applying the ordinary limit checks.
        if kind == 'limit' and 'group' in options:
            # A shared allowance cannot also own private bucket parameters.
            if set(options) != {'group'}:
                raise ValidationError(f'{name}: limit group cannot be combined with inline limit parameters')

            group_name = options['group']
            # Limit groups must exist in the consuming rule's address family.
            if group_name not in (limit_groups or {}):
                raise ValidationError(f'{name}: limit group {group_name!r} is not configured in {family}')
            options = limit_groups[group_name]

        required = 'rate' if kind == 'limit' else 'over'
        # A configured limit must specify its rate or connection threshold.
        if required not in options:
            raise ValidationError(f'{name}: {kind} requires {required}')

        fields = lookup(options, ('per',), '').split(',') if 'per' in options else []
        # Repeating a field adds no distinction and usually indicates a typo.
        if len(fields) != len(set(fields)):
            raise ValidationError(f'{name}: {kind} per fields must not repeat')

        # Bounded per-key storage is meaningful only when a key is selected.
        if not fields and (set(options) & {'size', 'timeout'}):
            raise ValidationError(f'{name}: {kind} size and timeout require per')

        # Limit keys have the same register and field-count constraints as groups.
        verify_key_size(fields, family, f'{name} {kind}')

        for direction in ('source', 'destination'):
            prefix_option = direction + '-prefix-length'
            # A subnet mask needs the corresponding address in the tracked key.
            if prefix_option in options and direction + '-address' not in fields:
                raise ValidationError(f'{name}: {kind} {prefix_option} requires per {direction}-address')

            # IPv4 and IPv6 addresses have different maximum prefix lengths.
            maximum = 32 if family == 'ipv4' else 128
            if prefix_option in options and int(options[prefix_option]) > maximum:
                raise ValidationError(f'{name}: {kind} {prefix_option} must be between 0 and {maximum}')

        # Named rate groups must obey the same field restrictions as inline keys.
        if hook is not None:
            nftables.verify_hook_fields(fields, hook, path)

        # Interface metadata must exist at every hook that can invoke this rule.
        inbound_fields = set(fields) & {'inbound-interface', 'inbound-link-group'}
        if inbound_fields and hook == 'output':
            raise ValidationError(f'{name}: {kind} cannot use {sorted(inbound_fields)[0]} in output')

        # Input and prerouting cannot supply an outgoing interface for the key.
        outbound_fields = set(fields) & {'outbound-interface', 'outbound-link-group'}
        if outbound_fields and hook in {'input', 'prerouting'}:
            raise ValidationError(f'{name}: {kind} cannot use {sorted(outbound_fields)[0]} in {hook}')

        # Local output has not acquired an Ethernet header at these filter hooks.
        if set(fields) & {'source-mac', 'destination-mac'} and hook == 'output':
            raise ValidationError(f'{name}: {kind} MAC keys require incoming Ethernet packets')

        # Conntrack is not available at the raw priority, including indirect jumps.
        if stage == 'raw' and (kind == 'connection limit' or 'connection-mark' in fields):
            raise ValidationError(f'{name}: {kind} connection tracking is unavailable in raw chains')

        # A rule disabling tracking cannot also count or key on tracked connections.
        if 'notrack' in rule and (kind == 'connection limit' or 'connection-mark' in fields):
            raise ValidationError(f'{name}: {kind} connection tracking cannot be combined with notrack')

        # Port keys are guarded with port-bearing protocols; explicit protocols must agree.
        if set(fields) & {'source-port', 'destination-port'}:
            protocols = nftables.match_protocols(rule, mapping, match_group, family=family)
            if protocols - NFT_PORT_PROTOCOLS:
                raise ValidationError(f'{name}: {kind} port keys require a port protocol (tcp, udp, udplite, sctp or dccp)')

        if kind == 'limit':
            # Each rule uses one bucket type, never both packet and byte rates.
            if len(options['rate']) != 1:
                raise ValidationError(f'{name}: limit rate requires exactly one of packets or bytes')

            unit, rate_value = next(iter(options['rate'].items()))
            # Packet buckets and byte buckets cannot share burst units.
            if 'burst' in options and set(options['burst']) != {unit}:
                raise ValidationError(f'{name}: limit burst must use the same packet or byte units as rate')

            quantity, period = rate_value.split('/')
            rate = limit_amount(quantity)
            byte_rate = unit == 'bytes'
            burst = limit_amount(lookup(options, ('burst', unit), '0' if byte_rate else '5'))
            nsecs = DURATION_UNITS[period] * 10**9
            bucket = nsecs * (rate + burst) if byte_rate else (nsecs // rate) * burst
            # The kernel stores bucket arithmetic in unsigned 64-bit integers.
            if bucket > 2**64 - 1:
                raise ValidationError(f'{name}: limit rate and burst exceed the kernel bucket capacity')

            # Avoid a zero-cost packet limiter at rates above clock resolution.
            if not byte_rate and rate > nsecs:
                raise ValidationError(f'{name}: limit rate exceeds nanosecond timer resolution')

            refill_seconds = limit_refill_seconds(options)
            # The generated idle timeout must fit the same timer range as explicit durations.
            if fields and refill_seconds > 18446744073:
                raise ValidationError(f'{name}: limit refill time exceeds the supported per-key timeout')

            # Expiring a key before refill would allow fresh bursts too early.
            if 'timeout' in options and duration_seconds(options['timeout']) < refill_seconds:
                raise ValidationError(f'{name}: limit timeout must cover the full bucket refill time '
                                      f'({refill_seconds} seconds)')


def _verify_hook_constraints(configuration, family, named_chains, maps, match_groups):
    """Follow direct and verdict-map jumps, including nested and shared chains."""
    from nvyr.helpers.nftables_zones import policy_targets

    map_targets = {}
    for name, mapping in maps.items():
        targets = set()
        for result in nft_map_results(mapping):
            # Only jump verdicts lead from a map to another chain.
            if lookup(result, ('action',), None) == 'jump':
                targets.add(result['jump-target'])
        map_targets[name] = targets

    pending = []
    for hook, target in policy_targets(lookup(configuration, ('firewall',), {}), family):
        path = ('firewall', family, 'name', target)
        pending.append((hook, 'filter', path, named_chains[target]))
    for hook, stage in NFT_FILTER_HOOKS.values():
        path = ('firewall', family, hook, stage)
        pending.append((hook, stage, path, lookup(configuration, path, {})))

    visited = set()
    while pending:
        hook, stage, path, chain = pending.pop()
        identity = (hook, stage, path)
        # Shared targets need one visit per hook; cycles must not loop verification.
        if identity in visited:
            continue
        visited.add(identity)

        # Default rejects have the same hook constraints as numbered rejects.
        verify_reject({'action': lookup(chain, ('default-action',), None)}, (*path, 'default-action'), hook=hook)

        for number, rule in lookup(chain, ('rule',), {}).items():
            # Disabled rules neither query the FIB nor reach another chain.
            if 'disable' in rule:
                continue

            selected = lookup(maps, (lookup(rule, ('map',), None),), None)
            group = lookup(match_groups, (lookup(rule, ('match-group',), None),), None)
            excluded = lookup(match_groups, (lookup(rule, ('not', 'match-group'), None),), None)
            fields = nftables.match_fields(rule, selected, group, excluded)
            update = lookup(rule, ('add-to-group', 'match-group'), None)
            if update in match_groups:
                fields |= set(nft_group_fields(match_groups[update]))

            # Resolve shared key availability against every actual calling hook.
            nftables.verify_hook_fields(fields, hook, (*path, 'rule', number))

            # Nested and map-selected chains must obey every caller's setter restrictions.
            if 'modify' in rule:
                nftables_modify.verify_hook(rule['modify'], (*path, 'rule', number), hook, stage)

            # Ingress must not enroll flows or count connections before tracking.
            if hook == 'ingress' and (lookup(rule, ('action',), None) == 'offload' or 'limit' in lookup(rule, ('connection',), {})):
                raise ValidationError(f"{' '.join((*path, 'rule', number))}: connection-dependent actions and limits are unavailable in ingress")

            # Link groups require the corresponding device at every calling hook.
            if 'inbound-link-group' in fields and hook == 'output':
                raise ValidationError(f"{' '.join((*path, 'rule', number))}: inbound-link-group is unavailable in output")

            # Routing has not selected an output device at INPUT or PREROUTING.
            if 'outbound-link-group' in fields and hook in {'input', 'prerouting'}:
                raise ValidationError(f"{' '.join((*path, 'rule', number))}: outbound-link-group is unavailable in {hook}")

            # Validate reject responses through every direct or nested caller.
            verify_reject(rule, (*path, 'rule', number), lookup(match_groups, (lookup(rule, ('match-group',), None),), None), hook)

            # Check each installed query against the hook that invokes this chain.
            if 'fib' in rule:
                verify_fib(rule['fib'], (*path, 'rule', number), hook)

            # Inline and shared limits obey every caller's interface and conntrack availability.
            if 'limit' in rule or 'limit' in lookup(rule, ('connection',), {}):
                verify_limits(rule, (*path, 'rule', number), selected, group, hook=hook, stage=stage,
                              limit_groups=lookup(configuration, ('firewall', 'group', 'limit-group', family), {}))

            # Timeout assignment must run after tracking through every nested caller.
            if 'timeout-group' in lookup(rule, ('connection',), {}):
                protocols = nftables.match_protocols(rule, selected, group, family=family)
                nftables_timeouts.verify_reference(
                    rule, (*path, 'rule', number),
                    lookup(configuration, ('firewall', 'group', 'timeout-group'), {}),
                    protocols, hook=hook, stage=stage)

            # Connection availability follows every caller through nested jumps.
            verify_connection(
                rule, (*path, 'rule', number), mapping=lookup(maps, (lookup(rule, ('map',), None),), None),
                match_group=lookup(match_groups, (lookup(rule, ('match-group',), None),), None),
                excluded_group=lookup(match_groups, (lookup(rule, ('not', 'match-group'), None),), None),
                update_group=lookup(match_groups, (lookup(rule, ('add-to-group', 'match-group'), None),), None),
                hook=hook, stage=stage,
                accounting='connection-accounting' in lookup(configuration, ('firewall', 'global-options'), {}))

            targets = set()
            # Direct jumps carry the caller's hook restrictions into their target.
            if lookup(rule, ('action',), None) == 'jump':
                targets.add(rule['jump-target'])

            # Every possible verdict-map target is reachable from the caller.
            if 'map' in rule:
                targets.update(map_targets[rule['map']])

            for target in targets:
                target_path = ('firewall', family, 'name', target)
                pending.append((hook, stage, target_path, named_chains[target]))


def warn_zone_defaults(firewall, context):
    """Report permissive hook fallbacks without interrupting verification."""
    hooks = nftables_zones.active_hooks(firewall)
    for family in nftables_zones.FAMILIES:
        for hook in hooks:
            chain = lookup(firewall, (family, hook, 'filter'), None)
            # Existing chains contain schema defaults. Zones also generate absent
            # chains, whose native fallback is accept without a configuration node.
            if chain is None or chain['default-action'] == 'accept':
                root = 'firewall fail-safe' if context.owner == 'firewall_failsafe' else 'firewall'
                context.report(Warning(
                    f'{root} {family} {hook} filter defaults to accept. '
                    'Traffic on interfaces not assigned to a zone may be allowed.'
                ))


def verify(configuration, context):
    """Validate the effective firewall/NAT tree before native object generation.

    Validate standalone groups even when unused, then check rules and transitive
    hook constraints. Flowtable selectors may refer to future interfaces; the
    kernel attaches their hooks when matching devices appear.
    """
    from nvyr.config_scripts import nat

    # Kernel settings need bounded values even when invoked outside the CLI parser.
    kernel_settings.firewall_values(configuration)

    # Validate NAT as part of the same atomic firewall/NAT commit.
    if 'nat' in configuration:
        nat.verify(configuration, context)

    firewall = lookup(configuration, ('firewall',), {})

    # Helper selection must be complete before generating native objects and their map.
    helpers = lookup(configuration, nftables_helpers.PATH, None)
    if helpers is not None:
        nftables_helpers.verify(helpers)

    # Source validation is optional and must have one unambiguous mode per interface.
    if any('source-validation' in lookup(firewall, (family,), {}) for family in source_validation.FAMILIES):
        source_validation.verify(configuration)

    # Zone references and membership must resolve before tracing their policy chains.
    if 'zone' in firewall or 'zone-policy' in firewall:
        nftables_zones.verify_zones(configuration)
        warn_zone_defaults(firewall, context)

    groups = lookup(configuration, ('firewall', 'group'), {})
    accounting = 'connection-accounting' in lookup(configuration, ('firewall', 'global-options'), {})

    # Only shared named chains can need the cross-hook VRF restriction.
    has_named_chains = any(lookup(firewall, (family, 'name'), None) for family in ('ipv4', 'ipv6', 'inet'))
    interface_contexts = nft_interface_contexts(configuration) if has_named_chains else {}
    for (family, name), interface_context in interface_contexts.items():
        # Hooked chains have exactly one calling hook and need no sharing restriction.
        if not name.startswith('name_'):
            continue

        path = ('firewall', family, 'name', name[5:])
        chain = lookup(configuration, path, {})
        # One native named chain cannot use INPUT's slave name and other hooks' input name.
        if len(interface_context['hooks']) > 1 and nft_slave_matches(chain, interface_context):
            raise ValidationError(f"{' '.join(path)}: VRF-aware inbound matches cannot be shared by input and other hooks; use separate named chains")

    # Validate every map against named chains from its own address family.
    maps = lookup(configuration, ('firewall', 'group', 'map'), {})
    match_groups = lookup(configuration, ('firewall', 'group', 'match-group'), {})
    for family in ('ipv4', 'ipv6', 'inet'):
        chains = lookup(configuration, ('firewall', family, 'name'), {})
        for name, definition in lookup(maps, (family,), {}).items():
            verify_map(family, name, definition, chains)
            # Conntrack keys obey their own protocol and accounting constraints.
            verify_connection_group(definition, ('firewall', 'group', 'map', family, name), accounting=accounting)

        # Sets reuse map key checks without requiring a result.
        for name, definition in lookup(match_groups, (family,), {}).items():
            verify_match_group(family, name, definition)
            # Membership keys use the same conntrack semantics as map keys.
            verify_connection_group(definition, ('firewall', 'group', 'match-group', family, name), accounting=accounting)

    # Unused policies must still define a valid transport and state lifetimes.
    for family, definitions in lookup(groups, ('timeout-group',), {}).items():
        for name, definition in definitions.items():
            nftables_timeouts.verify_group(definition, ('firewall', 'group', 'timeout-group', family, name))

    # Validate unused groups too, before any rule resolves their shared allowance.
    for family, definitions in lookup(groups, ('limit-group',), {}).items():
        for name, definition in definitions.items():
            verify_limits({'limit': definition}, ('firewall', 'group', 'limit-group', family, name), family=family)

    # Unused quota groups must also have a complete, unambiguous allowance.
    for name, definition in lookup(groups, ('quota-group',), {}).items():
        verify_quota(definition, ('firewall', 'group', 'quota-group', name))

    # Configured inclusions must be acyclic, bounded and scoped to their type/family.
    verify_group_inclusions(groups)

    # DNS selectors must resolve to at least one configured hostname, including inclusions.
    domain_groups.verify(configuration)

    # Address sets share the same dynamic storage constraints as concatenated sets.
    for kind, family, name, definition in singleton_groups(groups):
        if kind == 'address-group':
            verify_dynamic_group(family, name, definition, kind)
            # GeoIP membership needs a selector and cannot share another source.
            geoip_config.verify(family, name, definition)

    # Validate unused ICMP groups too, so invalid pairs never reach nftables.
    for family, definitions in lookup(groups, ('icmp-group',), {}).items():
        for name, definition in definitions.items():
            verify_icmp_group(family, name, definition)

    flowtables = lookup(configuration, ('firewall', 'flowtable'), {})
    devices = {}
    for name, flowtable in flowtables.items():
        # A flowtable needs at least one ingress interface.
        if not lookup(flowtable, ('interface',), None):
            raise ValidationError(f'firewall flowtable {name}: at least one interface is required')

        for device in interface_patterns.normalize(flowtable['interface']):
            # Equal-priority tables must not claim the same current or future interface.
            for selector, owner in devices.items():
                if owner != name and interface_patterns.overlaps(device, selector):
                    raise ValidationError(f'firewall flowtable {name}: interface {device!r} is already used by '
                                          f'flowtable {owner!r}; flowtables at the same ingress priority cannot share interfaces')

            devices[device] = name

    for family in ('ipv4', 'ipv6', 'inet'):
        ingress = lookup(configuration, ('firewall', family, 'ingress', 'filter'), None)
        # Ingress requires an explicit attachment; nonexistent and wildcard devices are valid.
        if ingress is not None and not lookup(ingress, ('interface',), None):
            raise ValidationError(f'firewall {family} ingress filter: at least one interface is required')

        named_chains = lookup(configuration, ('firewall', family, 'name'), {})
        # Apply rule checks to every configured hooked chain.
        for hook, stage in NFT_FILTER_HOOKS.values():
            path = ('firewall', family, hook, stage, 'rule')

            for number, rule in lookup(configuration, path, {}).items():
                verify_rule(rule, (*path, number), named_chains, flowtables, lookup(maps, (family,), {}), lookup(match_groups, (family,), {}), groups)

        # Named chains must satisfy the same rule checks as hooked chains.
        for name, chain in named_chains.items():
            for number, rule in lookup(chain, ('rule',), {}).items():
                verify_rule(rule, ('firewall', family, 'name', name, 'rule', number), named_chains, flowtables, lookup(maps, (family,), {}), lookup(match_groups, (family,), {}), groups)
                # Unreferenced named chains still need valid connection predicates.
                verify_connection(
                    rule, ('firewall', family, 'name', name, 'rule', number),
                    mapping=lookup(maps, (family, lookup(rule, ('map',), None)), None),
                    match_group=lookup(match_groups, (family, lookup(rule, ('match-group',), None)), None),
                    excluded_group=lookup(match_groups, (family, lookup(rule, ('not', 'match-group'), None)), None),
                    update_group=lookup(match_groups, (family, lookup(rule, ('add-to-group', 'match-group'), None)), None),
                    accounting=accounting)

        # Hook constraints must also hold through indirect named-chain jumps.
        _verify_hook_constraints(configuration, family, named_chains, lookup(maps, (family,), {}), lookup(match_groups, (family,), {}))

    for state, policy in lookup(configuration, ('firewall', 'global-options', 'state-policy'), {}).items():
        # Each configured global connection-state policy must specify a verdict.
        if 'action' not in policy:
            raise ValidationError(f'firewall global-options state-policy {state}: action is required')

    global_options = lookup(configuration, ('firewall', 'global-options'), {})
    target = lookup(global_options, ('flowtable',), None)
    if target is not None:
        # Global enrollment needs a configured native flowtable to reference.
        if target not in flowtables:
            raise ValidationError(f'firewall global-options flowtable: {target!r} is not a configured flowtable')

        # Only enroll flows that the immediately following global policy will accept.
        if lookup(global_options, ('state-policy', 'established', 'action'), None) != 'accept':
            raise ValidationError('firewall global-options flowtable requires state-policy established action accept')


def generate(configuration, context):
    from nvyr.helpers import logging_runtime
    log_groups = {}
    if logging_runtime.groups(configuration):
        log_groups = logging_runtime.nft_groups(configuration, context.state_directory / 'logging')
    return render_rules(configuration, nftables_lifecycle.plan(context, nftables.manager), log_groups=log_groups)


def render_rules(configuration, lifecycle, *, table='nvyr_filter', replace_table=False, log_groups=None):
    """Both firewall owners use the same formatters and native rule ordering."""
    return render('firewall/filter.nft.j2', {
        'configuration': configuration,
        'lifecycle': lifecycle,
        'objects': nftables_lifecycle.object_paths(configuration),
        'interface_contexts': nft_interface_contexts(configuration),
        'log_groups': log_groups or {},
        'table': table,
        'replace_table': replace_table,
    })


def apply(configuration, context):
    """Load rendered rules and external group membership in one native transaction.

    DNS/GeoIP preparation can supply cached or empty membership with warnings.
    Publish the prepared DNS cache only after the native apply succeeds so failed
    commits do not advertise membership that was never installed.
    """
    from nvyr.helpers import logging_runtime
    logging_runtime.prepare_groups(context.effective, context.state_directory / 'logging')
    dns_cache = None
    has_domains = bool(domain_groups.groups(context.effective))
    has_geoip = bool(geoip_config.groups(context.effective))
    if has_domains or has_geoip:
        rebuild = nftables_lifecycle.plan(context, nftables.manager)['rebuild']
        if has_domains:
            statements, dns_cache = domain_groups.manager.prepare(context.effective, context, rebuild)
            configuration += '\n' + statements

    # Keep kernel defaults and nftables under the same compensating apply boundary.
    with kernel_settings.manager.transaction(kernel_settings.firewall_values(context.effective)):
        if has_geoip:
            geoip.manager.apply(configuration, context, rebuild)
        else:
            accounting = 'connection-accounting' in lookup(context.effective, ('firewall', 'global-options'), {})
            nftables.manager.apply(configuration, context.state_directory, accounting=accounting)

        if dns_cache is not None:
            with domain_groups.manager.lock:
                domain_groups.manager.publish(dns_cache, context.report)

        logging_runtime.cleanup(context.effective, context.state_directory / 'logging')
