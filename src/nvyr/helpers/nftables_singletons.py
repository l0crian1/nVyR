"""Validate reusable singleton membership and expand configured inclusions."""

from nvyr.errors import ValidationError


# The canonical field selects a datatype; rules select the packet direction.
NFT_SINGLETON_GROUPS = {
    'interface-group': ('interface', 'inbound-interface'),
    'address-group': ('address', 'source-address'),
    'domain-group': ('address', 'source-address'),
    'mac-group': ('address', 'source-mac'),
    'port-group': ('port', 'source-port'),
}
MAX_INCLUDE_DEPTH = 8


def verify_group_inclusions(groups):
    """Check each type/family independently, including groups without consumers."""
    for kind in NFT_SINGLETON_GROUPS:
        families = ('ipv4', 'ipv6') if kind in ('address-group', 'domain-group') else (None,)
        for family in families:
            definitions = groups.get(kind, {})
            path = ('firewall', 'group', kind)
            # Address groups resolve references within their own address family.
            if family:
                definitions = definitions.get(family, {})
                path += (family,)

            _verify_namespace(definitions, ' '.join(path))


def _verify_namespace(definitions, path):
    longest_paths = {}

    def check_depth(chain):
        # Count inclusion links, so direct members have depth zero.
        if len(chain) - 1 > MAX_INCLUDE_DEPTH:
            raise ValidationError(f'{path}: include-group exceeds {MAX_INCLUDE_DEPTH} levels: '
                                  + ' -> '.join(chain))

    def visit(name, ancestors):
        chain = (*ancestors, name)
        # Reject self-inclusion and indirect cycles with the offending path.
        if name in ancestors:
            raise ValidationError(f'{path}: circular include-group reference: ' + ' -> '.join(chain))

        # Bound traversal before descending, including very long invalid graphs.
        check_depth(chain)
        # A shared subtree may be valid alone but too deep under another parent.
        if name in longest_paths:
            check_depth((*ancestors, *longest_paths[name]))
            return longest_paths[name]

        definition = definitions[name]
        includes = definition.get('include-group', ())
        # Runtime-owned membership cannot also be assembled from static groups.
        if includes and ('dynamic' in definition or 'geoip' in definition):
            raise ValidationError(f'{path} {name}: include-group cannot be combined with dynamic or geoip')

        longest = (name,)
        for child in includes:
            # Resolve only within this group type and address family, even in fail-safe mode.
            if child not in definitions:
                raise ValidationError(f'{path} {name}: included group {child!r} is not configured in {path}')

            source = definitions[child]
            # Copying learned or externally refreshed members would become stale.
            if 'dynamic' in source or 'geoip' in source:
                raise ValidationError(f'{path} {name}: cannot include dynamic or geoip group {child!r}')

            candidate = (name, *visit(child, chain))
            # Retain the deepest branch so cached reuse cannot hide excessive depth.
            if len(candidate) > len(longest):
                longest = candidate

        longest_paths[name] = longest
        return longest

    for name in definitions:
        visit(name, ())


def included_members(definitions, name, member):
    """Union verified configured members without inheriting settings or mutating input."""
    values = set()
    visited = set()
    pending = [name]
    while pending:
        current = pending.pop()
        if current in visited:
            continue
        visited.add(current)

        definition = definitions[current]
        values.update(definition.get(member, ()))
        pending.extend(definition.get('include-group', ()))

    return values
