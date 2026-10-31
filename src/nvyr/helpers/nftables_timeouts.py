"""Named conntrack timeout policies and their family-specific native objects."""

import re

from nvyr.errors import ValidationError
from nvyr.helpers.kernel_settings_map import TIMEOUTS
from nvyr.helpers.validators import duration, duration_seconds
from nvyr.tree import lookup


# Public state names follow global settings; nftables uses its own state labels.
STATES = {
    'tcp': {
        'syn-sent': ('syn_sent', 'syn-sent'),
        'syn-received': ('syn_recv', 'syn-received'),
        'established': ('established', 'established'),
        'fin-wait': ('fin_wait', 'fin-wait'),
        'close-wait': ('close_wait', 'close-wait'),
        'last-ack': ('last_ack', 'last-ack'),
        'time-wait': ('time_wait', 'time-wait'),
        'close': ('close', 'close'),
        'unacknowledged': ('unack', 'unacknowledged'),
        'max-retransmissions': ('retrans', 'max-retransmissions'),
    },
    'udp': {'unreplied': ('unreplied', 'unreplied'), 'replied': ('replied', 'stream')},
}
MAX_SECONDS = 2147483


def identity(native):
    """Recover the CLI family and name without confusing an inet suffix with a name."""
    match = re.fullmatch(r'(ipv4|ipv6)_timeout_group_([A-Za-z_][A-Za-z0-9_-]{0,62})', native)
    if match:
        return match.groups()
    match = re.fullmatch(r'inet_timeout_group_([A-Za-z_][A-Za-z0-9_-]{0,62})_ip6?', native)
    if match:
        return 'inet', match[1]
    return None


def native_names(family, name):
    """Keep an inet policy in one CLI namespace while selecting two native objects."""
    prefix = f'{family}_timeout_group_{name}'
    if family == 'inet':
        return {'ip': prefix + '_ip', 'ip6': prefix + '_ip6'}
    return {'ip' if family == 'ipv4' else 'ip6': prefix}


def policy(options, global_options=None):
    """Resolve omitted states explicitly so global changes participate in lifecycle."""
    protocol = options['protocol']
    inherited = lookup(global_options or {}, ('connection-tracking', 'timeout', protocol), {})
    values = {}
    for state, (native, global_state) in STATES[protocol].items():
        default = TIMEOUTS[protocol][global_state][1]
        value = options.get('timeout', {}).get(state, inherited.get(global_state, default))
        values[native] = duration_seconds(value)
    return values


def verify_group(options, path):
    """Require a usable protocol policy even when the group has no consumers."""
    name = ' '.join(path)
    protocol = options.get('protocol')
    # Only protocols with an exposed and tested native state vocabulary are accepted.
    if protocol not in STATES:
        raise ValidationError(f'{name}: protocol tcp or udp is required')

    values = options.get('timeout', {})
    # A named policy must override at least one state, rather than silently do nothing.
    if not values:
        raise ValidationError(f'{name}: at least one timeout is required')

    for state, value in values.items():
        # TCP and UDP timeout states have different meanings and cannot be mixed.
        if state not in STATES[protocol]:
            raise ValidationError(f'{name}: timeout {state} is unavailable for {protocol}')
        # Bound seconds conservatively for all supported kernel timer frequencies.
        if not duration(value, maximum=MAX_SECONDS):
            raise ValidationError(f'{name}: timeout {state} must be 1–{MAX_SECONDS} seconds using s, m, h or d')


def verify_reference(rule, path, groups, protocols, *, hook=None, stage=None):
    """Check family ownership, transport selection and every named-chain caller."""
    target = rule.get('connection', {}).get('timeout-group')
    # Ordinary rules incur no policy lookup or timeout validation.
    if target is None or 'disable' in rule:
        return

    name = ' '.join(path)
    options = groups.get(path[1], {}).get(target)
    # References remain in the rule's family namespace, including inet.
    if options is None:
        raise ValidationError(f'{name}: timeout-group {target!r} is not configured for {path[1]}')
    # Every packet admitted by explicit or inherited protocol matches must agree.
    if protocols != {options.get('protocol')}:
        raise ValidationError(f'{name}: timeout-group {target!r} requires protocol {options.get("protocol")}')
    # Assignment needs conntrack lookup; raw and ingress execute before tracking.
    if hook == 'ingress' or stage == 'raw':
        raise ValidationError(f'{name}: timeout-group is unavailable before connection tracking')


def statement(family, name):
    """Select an inet object's native family without splitting or duplicating rules."""
    names = native_names(family, name)
    if family == 'inet':
        return ('ct timeout set meta nfproto map { '
                f'ipv4 : "{names["ip"]}", ipv6 : "{names["ip6"]}"' + ' }')
    return f'ct timeout set "{next(iter(names.values()))}"'


def definitions(groups, rebuild, global_options=None):
    """Render rebuilt policies before their consumers in the shared transaction."""
    lines = []
    for family, entries in sorted(groups.get('timeout-group', {}).items()):
        for name, options in sorted(entries.items()):
            values = ', '.join(f'{state}: {seconds}' for state, seconds in policy(options, global_options).items())
            for l3proto, native in native_names(family, name).items():
                if ('ct timeout', native) not in rebuild:
                    continue
                lines.extend([f'ct timeout {native} {{', f'    l3proto {l3proto};',
                              f'    protocol {options["protocol"]};', f'    policy = {{ {values} }};'])
                if 'description' in options:
                    lines.append(f'    comment "{options["description"]}";')
                lines.append('}')
    return '\n'.join(lines)
