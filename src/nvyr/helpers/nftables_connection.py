"""Verification for connection metadata shared by rules and compound groups."""

from nvyr.errors import ValidationError
from nvyr.helpers.nftables_formatters import (
    NFT_KEYMAP, nft_field_value, nft_present_fields, nft_group_fields,
    connection_label_plan, NFT_PORT_PROTOCOLS,
)
from nvyr.helpers.validators import connection_quantity, connection_label_mask


ACCOUNTING_FIELDS = {
    name for name, key in NFT_KEYMAP.items()
    if key.path and key.path[-1] in {'packets', 'bytes', 'average-packet-size'}
}
CONNECTION_FIELDS = {name for name, key in NFT_KEYMAP.items() if key.path[:1] == ('connection',)}


def _values(configuration, field, *, entry=False, negative=False):
    value = nft_field_value(configuration, field, negative=negative)
    if value is None:
        return []
    return [value] if entry else value


def _inherited_values(definitions, field, *, include_default=True):
    for definition in definitions:
        fields = nft_group_fields(definition or {})
        if field in fields:
            if include_default and 'default-result' in definition:
                # Defaults do not constrain a field to the explicit entries.
                # Tuple ports still receive the native conntrack protocol guard.
                if field == 'connection-protocol':
                    ports = {name for name in fields if name.startswith('connection-') and name.endswith('-port')}
                    return list(NFT_PORT_PROTOCOLS) if ports else [None]
                return None
            return [nft_field_value(entry, field) for entry in definition.get('entry', {}).values()]
    return None


def verify_connection(configuration, path, *, mapping=None, match_group=None,
                      excluded_group=None, update_group=None, entry=False, accounting=False,
                      hook=None, stage=None):
    """Check stored tuple fields independently from the packet's own headers."""
    name = ' '.join(path)

    # Disabled rules install no connection expressions, including in named chains.
    if 'disable' in configuration:
        return

    # Explicit and group-supplied connection branches are the only conntrack inputs.
    # Presence, rather than truthiness, keeps empty-node validation active.
    if 'connection' not in configuration and not any(
        'connection' in definition.get('match', {})
        for definition in (mapping, match_group, excluded_group, update_group) if definition is not None
    ):
        return

    connection = configuration.get('connection', {})

    # An explicitly configured connection node must contribute a match or operation.
    if 'connection' in configuration and not connection:
        raise ValidationError(f'{name}: connection requires at least one match, limit or timeout-group')

    for direction in ('original', 'reply', 'total'):
        # Empty direction/accounting sections produce no nftables expression,
        # even when another connection section supplies a valid condition.
        if direction in connection and not connection[direction]:
            raise ValidationError(f'{name}: connection {direction} requires at least one match')

    definitions = (mapping, match_group)
    explicit = nft_present_fields(configuration) | nft_present_fields(configuration, negative=True)
    fields = explicit.copy()
    for definition in (*definitions, excluded_group, update_group):
        fields.update(nft_group_fields(definition or {}))
    fields &= CONNECTION_FIELDS

    # Ordinary packet rules have no conntrack-specific constraints.
    if not fields:
        return

    # Reading tracked traffic totals requires accounting on newly created flows.
    if fields & ACCOUNTING_FIELDS and not accounting:
        raise ValidationError(f'{name}: connection accounting matches require firewall global-options connection-accounting')

    # Raw chains execute before conntrack has attached a tracked connection.
    if stage == 'raw' and fields - {'state'}:
        raise ValidationError(f'{name}: connection metadata is unavailable in {hook} raw before connection tracking')

    states = _values(configuration, 'state', entry=entry)
    inherited_states = _inherited_values(definitions, 'state')
    if inherited_states is not None:
        states = inherited_states

    # Before tracking, only invalid/untracked state tests are meaningful.
    if stage == 'raw':
        raw_states = set(states) | set(_inherited_values(definitions, 'state', include_default=False) or [])
        # A fallback does not make explicitly configured tracked states available before tracking.
        if raw_states - {'invalid', 'untracked'}:
            raise ValidationError(f'{name}: tracked connection states are unavailable in {hook} raw')

    # Untracked/invalid packets cannot also satisfy metadata from a tracked flow.
    if states and set(states) <= {'invalid', 'untracked'} and fields - {'state'}:
        raise ValidationError(f'{name}: invalid/untracked connection state cannot be combined with tracked metadata')

    family = next((part for part in path if part in {'ipv4', 'ipv6'}), None)
    families = _values(configuration, 'connection-family', entry=entry)
    inherited_families = _inherited_values(definitions, 'connection-family')
    if inherited_families is not None:
        families = inherited_families

    # The stored tuple's IP family must match the configured firewall family.
    if family and set(families) - {family}:
        raise ValidationError(f'{name}: connection family must be {family}')

    ports = {field for field in fields if field.endswith('-port')}
    # Only port matches need to inspect every inherited protocol value.
    if ports:
        protocols = _values(configuration, 'connection-protocol', entry=entry)
        inherited_protocols = _inherited_values(definitions, 'connection-protocol')
        has_protocol = bool(protocols) or inherited_protocols is not None
        if inherited_protocols is not None:
            protocols = inherited_protocols

        # A negative tuple group still supplies its own positive transport guard.
        if excluded_group and ports <= set(nft_group_fields(excluded_group)):
            has_protocol = True

        # Learned tuple ports also receive the group's native transport guard.
        if update_group and ports <= set(nft_group_fields(update_group)):
            has_protocol = True

        # Conntrack port words are transport ports only for these port-based protocols.
        if not has_protocol or set(protocols) - NFT_PORT_PROTOCOLS:
            raise ValidationError(f'{name}: connection ports require connection protocol tcp, udp, udplite, sctp or dccp')

    for field in explicit & CONNECTION_FIELDS:
        key = NFT_KEYMAP[field]
        value = nft_field_value(configuration, field)
        # Group entries are scalar keys, not rule comparison nodes.
        if not entry and key.comparisons and value is not None:
            _verify_comparison(field, value, name)

    for negative in (False, True):
        labels = _values(configuration, 'connection-label', negative=negative)
        # Label expansion must remain bounded before rendering allocates its set.
        if labels:
            try:
                connection_label_plan(labels)
            except ValueError as error:
                raise ValidationError(f'{name}: {error}') from error

    required = _values(configuration, 'connection-label')
    excluded = _values(configuration, 'connection-label', negative=True)
    # Reject expressions whose every positive alternative implies an exclusion.
    if required and excluded:
        forbidden = [connection_label_mask(value) for value in excluded]
        if all(any(connection_label_mask(value) & mask == mask for mask in forbidden) for value in required):
            raise ValidationError(f'{name}: connection label requirements are all excluded')


def _verify_comparison(field, options, path):
    if field == 'connection-expiration':
        kind, scale, maximum = 'expiration', 1000, (1 << 32) - 1
    else:
        kind = 'packets' if field.endswith('packets') else 'bytes'
        scale, maximum = 1, (1 << 64) - 1

    # Expiration inputs use whole seconds, but the kernel compares milliseconds.
    values = {
        operator: connection_quantity(value, kind) * scale
        for operator, value in options.items() if operator != 'not'
    }

    # An empty comparison node supplies no condition to the generated rule.
    if not values and 'eq' not in options.get('not', {}):
        raise ValidationError(f'{path}: {field} requires eq, lt or gt')

    # Equality supplies the full comparison; mixing it with bounds is ambiguous.
    if 'eq' in values and (set(values) & {'lt', 'gt'}):
        raise ValidationError(f'{path}: {field} eq cannot be combined with lt or gt')

    lower = values.get('gt', -1) + 1
    upper = values.get('lt', maximum + 1) - 1
    if 'eq' in values:
        lower = upper = values['eq']

    # Strict bounds must leave at least one representable integer value.
    if lower > upper:
        raise ValidationError(f'{path}: {field} comparisons cannot match any value')

    excluded = options.get('not', {}).get('eq')
    # Excluding the only possible value makes the whole comparison impossible.
    if excluded is not None and lower == upper == connection_quantity(excluded, kind) * scale:
        raise ValidationError(f'{path}: {field} excludes its only matching value')


def verify_connection_group(definition, path, *, accounting=False):
    # Packet-only groups need no conntrack entry traversal or accounting checks.
    if 'connection' not in definition.get('match', {}):
        return

    fields = set(nft_group_fields(definition))

    # Port fields need their own conntrack protocol key, not the packet protocol.
    if any(field.startswith('connection-') and field.endswith('-port') for field in fields) and 'connection-protocol' not in fields:
        raise ValidationError(f"{' '.join(path)}: connection ports require connection protocol in the group match fields")

    # Validate empty groups' accounting requirements as well as populated groups.
    if fields & ACCOUNTING_FIELDS and not accounting:
        raise ValidationError(f"{' '.join(path)}: connection accounting matches require firewall global-options connection-accounting")

    for identifier, entry in definition.get('entry', {}).items():
        verify_connection(entry, (*path, 'entry', identifier), entry=True, accounting=accounting)
