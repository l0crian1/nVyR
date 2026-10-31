"""Validate and format literal firewall setters independently of packet matches."""

from nvyr.errors import ValidationError
from nvyr.helpers.validators import (
    DSCP_VALUES, TCP_FLAGS, firewall_dscp, firewall_mark, integer_range, tcp_flag_requirements,
)


FIELDS = frozenset({'packet-mark', 'connection-mark', 'dscp', 'ttl', 'tcp-mss'})


def verify_hook(options, path, hook, stage):
    """Check setters against the actual hook, including transitive callers."""
    name = ' '.join(path)
    # Ingress modifications are outside this feature's supported chain set.
    if hook == 'ingress':
        raise ValidationError(f'{name}: modify is unavailable in ingress')

    # Raw chains execute before a tracked connection is available to mark.
    if 'connection-mark' in options and stage == 'raw':
        raise ValidationError(f'{name}: modify connection-mark is unavailable before connection tracking')

    # The kernel restricts route-based MSS calculation to these routed hooks.
    if options.get('tcp-mss') == 'clamp-to-pmtu' and hook not in {'forward', 'output', 'postrouting'}:
        raise ValidationError(f'{name}: modify tcp-mss clamp-to-pmtu requires forward or output')


def verify(rule, path, protocols, match_group=None):
    """Require bounded setters and TCP SYN coverage before modifying an MSS option."""
    options = rule['modify']
    name = ' '.join(path)
    # An empty modifier has no effect and must not silently pass verification.
    if not options:
        raise ValidationError(f'{name}: modify requires at least one setting')

    # Direct verification callers must obey the same supported setter inventory.
    if set(options) - FIELDS:
        raise ValidationError(f'{name}: unknown modify setting')

    # Family-neutral rules cannot write family-specific IP header fields.
    if path[1] == 'inet' and set(options) & {'dscp', 'ttl'}:
        raise ValidationError(f'{name}: inet modify settings must be family-neutral')

    for field, value in options.items():
        valid = isinstance(value, str)
        if valid and field in {'packet-mark', 'connection-mark'}:
            valid = firewall_mark(value)
        elif valid and field == 'dscp':
            valid = firewall_dscp(value)
        elif valid and field == 'ttl':
            valid = integer_range(value, 0, 255)
        elif valid and field == 'tcp-mss':
            valid = value == 'clamp-to-pmtu' or integer_range(value, 1, 65535)

        # Native statements must receive one bounded literal, never an expression.
        if not valid:
            raise ValidationError(f'{name}: invalid modify {field} value {value!r}')

    # Untracked packets have no connection mark, even in a later filter hook.
    if 'connection-mark' in options and 'notrack' in rule:
        raise ValidationError(f'{name}: modify connection-mark cannot be combined with notrack')

    if 'tcp-mss' in options:
        # MSS belongs to TCP; protocol must explicitly restrict every matching packet.
        if protocols != {'tcp'}:
            raise ValidationError(f'{name}: modify tcp-mss requires protocol tcp only')

        flags = rule.get('tcp-flags', [])
        if 'tcp-flags' in (match_group or {}).get('match', {}):
            flags = [entry.get('tcp-flags', '') for entry in match_group.get('entry', {}).values()]

        # Every positive flag alternative must require SYN, allowing SYN-ACK too.
        if not flags or any((tcp_flag_requirements(value)[1] & TCP_FLAGS['syn']) == 0 for value in flags):
            raise ValidationError(f'{name}: modify tcp-mss requires a positive SYN match in every alternative')

    # Direct rules are checked immediately; named rules are checked for every caller.
    if path[2] != 'name':
        verify_hook(options, path, path[2], path[3])


def statements(family, options):
    """Emit setters in a stable order after matches and before the verdict."""
    parts = []
    for field in ('packet-mark', 'connection-mark', 'dscp', 'ttl', 'tcp-mss'):
        if field not in options:
            continue
        value = options[field]
        if field in {'packet-mark', 'connection-mark'}:
            expression = 'meta mark' if field == 'packet-mark' else 'ct mark'
            value = str(int(value, 16 if value.lower().startswith('0x') else 10))
        elif field == 'dscp':
            expression = 'ip dscp' if family == 'ipv4' else 'ip6 dscp'
            value = str(DSCP_VALUES[value] if value in DSCP_VALUES else int(value))
        elif field == 'ttl':
            expression = 'ip ttl' if family == 'ipv4' else 'ip6 hoplimit'
            value = str(int(value))
        else:
            expression = 'tcp option maxseg size'
            value = 'rt mtu' if value == 'clamp-to-pmtu' else str(int(value))
        parts.append(f'{expression} set {value}')
    return parts
