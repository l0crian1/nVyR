"""Zone validation and generated verdict maps, without host-state mutations."""

import json

from nvyr.errors import ValidationError
from nvyr.helpers import interface_patterns
from nvyr.tree import lookup


FAMILIES = ('ipv4', 'ipv6')
HOOKS = ('input', 'output', 'forward')


def verify_zones(configuration):
    firewall = configuration.get('firewall', {})
    zones = firewall.get('zone', {})
    local = None
    interfaces = {}
    prefixes = {}
    vrfs = lookup(configuration, ('vrf', 'name'), {})

    def verify_policies(options, path):
        for family in FAMILIES:
            policy = options.get(family + '-policy')
            # Policies must resolve in the selected address family, even when unused.
            if policy is not None and policy not in firewall.get(family, {}).get('name', {}):
                raise ValidationError(f'{path}: {family} policy {policy!r} is not configured')

    for name, zone in zones.items():
        path = f'firewall zone {name}'
        if 'local-zone' in zone:
            # Local traffic has a single identity, not an interface membership list.
            if local is not None:
                raise ValidationError(f'{path}: only one local-zone is allowed (already {local})')
            local = name

            # Local traffic cannot be classified as traffic between zone interfaces.
            if 'interface' in zone or 'intra-zone' in zone:
                raise ValidationError(f'{path}: local-zone cannot have interface or intra-zone settings')
        else:
            # An ordinary zone must identify at least one interface to classify traffic.
            if not zone.get('interface'):
                raise ValidationError(f'{path}: at least one interface is required')

        for interface in zone.get('interface', []):
            # Classify VRF traffic by its member interface using sdifname, never the master.
            if any(interface_patterns.matches(interface, vrf) for vrf in vrfs):
                raise ValidationError(f'{path}: VRF master {interface!r} cannot belong to a zone')

            # Exact duplicate ownership needs no scan of the interface inventory.
            owner = interfaces.get(interface)
            if owner is not None and owner != name:
                raise ValidationError(f'{path}: interface {interface!r} already belongs to zone {owner}')

            # Reject prefix overlap even if matching interfaces do not exist yet.
            candidates = interfaces if interface.endswith('*') else prefixes
            for existing, owner in candidates.items():
                if owner != name and interface_patterns.overlaps(interface, existing):
                    raise ValidationError(f'{path}: interface {interface!r} already belongs to zone {owner} through {existing!r}')
            interfaces[interface] = name
            if interface.endswith('*'):
                prefixes[interface] = name

        verify_policies(zone.get('intra-zone', {}), path + ' intra-zone')

    for source, definition in firewall.get('zone-policy', {}).get('from-zone', {}).items():
        path = f'firewall zone-policy from-zone {source}'
        # A source-zone reference must resolve even when no destination has been entered.
        if source not in zones:
            raise ValidationError(f'{path}: source zone is not configured')

        # Incomplete pairings have no policy to install.
        if not definition.get('to-zone'):
            raise ValidationError(f'{path}: at least one to-zone policy is required')

        for destination, policies in definition['to-zone'].items():
            pair = f'{path} to-zone {destination}'
            # Both ends of a directional pairing must be configured zones.
            if destination not in zones:
                raise ValidationError(f'{pair}: destination zone is not configured')

            # Intra-zone behavior has its own settings and cannot have competing definitions.
            if source == destination:
                raise ValidationError(f'{pair}: use the zone intra-zone settings for same-zone traffic')

            # At least one address family must have an explicit policy in a pairing.
            if not any(family + '-policy' in policies for family in FAMILIES):
                raise ValidationError(f'{pair}: ipv4-policy or ipv6-policy is required')
            verify_policies(policies, pair)


def policy_targets(firewall, family):
    """Yield calling hooks and named targets without expanding interface pairs."""
    zones = firewall.get('zone', {})
    key = family + '-policy'
    for zone in zones.values():
        policy = zone.get('intra-zone', {}).get(key)
        if policy is not None:
            yield 'forward', policy

    for source, definition in firewall.get('zone-policy', {}).get('from-zone', {}).items():
        for destination, policies in definition.get('to-zone', {}).items():
            policy = policies.get(key)
            if policy is None or source not in zones or destination not in zones:
                continue
            if 'local-zone' in zones[destination]:
                hook = 'input'
            elif 'local-zone' in zones[source]:
                hook = 'output'
            else:
                hook = 'forward'
            yield hook, policy


def active_hooks(firewall):
    zones = firewall.get('zone', {})
    if not any(zone.get('interface') for zone in zones.values()):
        return ()
    if any('local-zone' in zone for zone in zones.values()):
        return HOOKS
    return ('forward',)


def map_name(family, hook):
    return f'{family}_zone_{hook}'


def entries(firewall, family, hook):
    """Keep native prefix keys for policies and zone default verdicts."""
    zones = firewall.get('zone', {})
    local = next((name for name, zone in zones.items() if 'local-zone' in zone), None)
    ordinary = sorted(name for name, zone in zones.items() if 'local-zone' not in zone)
    interfaces = {name: interface_patterns.normalize(zones[name].get('interface', [])) for name in ordinary}
    pairings = firewall.get('zone-policy', {}).get('from-zone', {})
    result = []

    if hook == 'input':
        pairs = [(source, local) for source in ordinary] if local else []
    elif hook == 'output':
        pairs = [(local, destination) for destination in ordinary] if local else []
    else:
        pairs = [(source, destination) for source in ordinary for destination in ordinary]

    for source, destination in pairs:
        if source == destination:
            options = zones[source].get('intra-zone', {})
            action = options.get('default-action', 'accept')
        else:
            options = pairings.get(source, {}).get('to-zone', {}).get(destination, {})
            action = zones[destination].get('default-action', 'drop')

        policy = options.get(family + '-policy')
        if policy is not None:
            verdict = f'jump {family}_name_{policy}'
        else:
            verdict = action

        if hook == 'input':
            keys = [(interface,) for interface in interfaces[source]]
            comment = source
        elif hook == 'output':
            keys = [(interface,) for interface in interfaces[destination]]
            comment = destination
        else:
            keys = [(incoming, outgoing)
                    for incoming in interfaces[source]
                    for outgoing in interfaces[destination]]
            comment = f'{source} to {destination}'

        for key in keys:
            result.append((key, verdict, comment))
    return result


def maps(firewall):
    """Synthetic objects have signatures rather than editable configuration paths."""
    return {('map', map_name(family, hook)): entries(firewall, family, hook)
            for family in FAMILIES for hook in active_hooks(firewall)}


def render_maps(firewall, rebuild):
    blocks = []
    for family in FAMILIES:
        for hook in active_hooks(firewall):
            name = map_name(family, hook)
            if ('map', name) not in rebuild:
                continue
            datatype = 'ifname . ifname' if hook == 'forward' else 'ifname'
            members = entries(firewall, family, hook)
            lines = [f'map {name} {{', f'    type {datatype} : verdict']
            if any(interface.endswith('*') for key, _, _ in members for interface in key):
                lines.append('    flags interval;')
            lines.extend(['    counter;', '    elements = {'])
            elements = []
            for key, verdict, comment in members:
                expression = ' . '.join(json.dumps(interface) for interface in key)
                elements.append(f'        {expression} comment {json.dumps(comment)} : {verdict}')
            lines.append(',\n'.join(elements))
            lines.extend(['    }', '}'])
            blocks.append('\n'.join(lines))
    return '\n\n'.join(blocks)


def dispatch(firewall, family, hook):
    if hook not in active_hooks(firewall):
        return []

    lines = []
    if hook == 'output':
        # Permit the preliminary VRF-device pass; the member-interface pass
        # still evaluates the zone map and the normal output default.
        lines.append('meta oifkind "vrf" counter accept comment "vrf-bypass"')

    fields = {'input': ('meta iifname', 'meta sdifname'),
              'output': ('meta oifname',), 'forward': ('meta iifname . meta oifname',)}
    lines.extend(f'{expression} vmap @{map_name(family, hook)} comment "zone-dispatch|{hook}"'
                 for expression in fields[hook])
    return lines
