"""Render reverse-path checks and their private interface sets in existing raw chains."""

from nvyr.errors import ValidationError


FAMILIES = ('ipv4', 'ipv6', 'inet')
SET_KINDS = ('strict', 'loose', 'overrides')


def configuration(firewall, family):
    """Read one family's settings without creating a second configuration model."""
    return firewall.get(family, {}).get('source-validation', {})


def active(firewall, family):
    """Disabled-only settings need no native chain or validation rules."""
    options = configuration(firewall, family)
    return options.get('default', 'disabled') != 'disabled' or any(
        override.get('mode') in ('strict', 'loose')
        for override in options.get('interface', {}).values())


def chain_name(family):
    """Inet uses the base chain; IP families use the existing dispatch targets."""
    return 'prerouting' if family == 'inet' else family + '_prerouting'


def set_name(family, kind):
    """Keep generated sets separate from user-defined firewall groups."""
    return f'source_validation_{family}_{kind}'


def interface_sets(firewall, family, vrfs=()):
    """Group equal overrides and exclude every override from an enabled default."""
    options = configuration(firewall, family)
    default = options.get('default', 'disabled')
    overrides = options.get('interface', {})
    result = {}
    for mode in ('strict', 'loose'):
        members = sorted(name for name, setting in overrides.items() if setting.get('mode') == mode)
        if members and mode != default:
            result[mode] = members

    excluded = set(overrides) | set(vrfs)
    if excluded and default != 'disabled':
        result['overrides'] = sorted(excluded)
    return result


def verify(tree):
    """Keep family selection and interface overrides unambiguous."""
    firewall = tree.get('firewall', {})
    vrfs = tree.get('vrf', {}).get('name', {})
    configured = [family for family in FAMILIES if 'source-validation' in firewall.get(family, {})]

    # Shared and family-specific validation cannot both process the same packet.
    if 'inet' in configured and len(configured) > 1:
        raise ValidationError('firewall inet source-validation cannot be combined with ipv4 or ipv6 source-validation')

    for family in configured:
        options = configuration(firewall, family)
        default = options.get('default', 'disabled')
        for name, override in options.get('interface', {}).items():
            path = f'firewall {family} source-validation interface {name}'
            # VRF devices represent a second pass, not the original receiving interface.
            if name in vrfs:
                raise ValidationError(f'{path}: select a VRF member interface, not the VRF device')

            # An interface entry must specify which behavior replaces the default.
            if 'mode' not in override:
                raise ValidationError(f'{path}: mode is required')

            # Redundant exceptions obscure which interfaces really differ from the default.
            if override['mode'] == default:
                raise ValidationError(f'{path}: mode {default} matches the global default; remove the redundant interface override')


def render_sets(tree, rebuild):
    """Declare only private sets selected by the ordinary nftables lifecycle."""
    lines = []
    firewall = tree.get('firewall', {})
    vrfs = tree.get('vrf', {}).get('name', {})
    for family in FAMILIES:
        for kind, members in interface_sets(firewall, family, vrfs).items():
            name = set_name(family, kind)
            if ('set', name) not in rebuild:
                continue
            elements = ', '.join(f'"{member}"' for member in members)
            lines.append(f'set {name} {{ type ifname; elements = {{ {elements} }}; }}')
    return '\n'.join(lines)


def render_rules(tree, family, entrypoint):
    """Drop failed lookups with at most two rules; passing packets keep traversing raw."""
    firewall = tree.get('firewall', {})
    if entrypoint != 'prerouting' or not active(firewall, family):
        return ''

    options = configuration(firewall, family)
    default = options.get('default', 'disabled')
    # VRF master passes must not reapply the default after a member override.
    sets = interface_sets(firewall, family, tree.get('vrf', {}).get('name', {}))
    lines = []
    for mode in ('strict', 'loose'):
        if mode == default:
            selector = f'iifname != @{set_name(family, "overrides")} ' if 'overrides' in sets else ''
        elif mode in sets:
            selector = f'iifname @{set_name(family, mode)} '
        else:
            continue

        lookup = 'fib saddr . iif oif 0' if mode == 'strict' else 'fib saddr oif 0'
        scope = 'default' if mode == default else 'interface overrides'
        comment = f'source-validation-{mode}|{mode.capitalize()} source validation ({scope})'
        lines.append(f'{selector}{lookup} counter drop comment "{comment}"')
    return '\n'.join(lines)
