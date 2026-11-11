"""NAT verification, invoked by the shared firewall commit owner."""

from nvyr.errors import ValidationError
from nvyr.helpers import nftables, cgnat, interface_patterns
from nvyr.helpers.nftables_singletons import included_members, verify_group_inclusions
from nvyr.tree import lookup


def verify_cgnat(configuration):
    pools = lookup(configuration, (*cgnat.PATH, 'pool'), {})
    groups = lookup(configuration, ('firewall', 'group'), {})
    vrfs = lookup(configuration, ('vrf', 'name'), {})
    devices = cgnat.interface_vrfs(configuration)
    occupied = {}
    # Static subscriber groups must resolve safely before their membership is expanded.
    if cgnat.enabled(configuration):
        verify_group_inclusions(groups)

    for name, pool in pools.items():
        path = f'nat cgnat pool {name}'
        # An allocation pool must contain addresses even when not yet referenced.
        if not lookup(pool, ('public-address',), ()):
            raise ValidationError(f'{path}: public-address is required')
        # A block must fit on one public address; a partial final block stays unused.
        if cgnat.slots(pool) == 0:
            raise ValidationError(f'{path}: block-size exceeds the usable port-range')

    for number, rule in cgnat.enabled(configuration):
        path = (*cgnat.PATH, 'rule', number)
        name = ' '.join(path)
        # References and allocation sources are required only for enabled policies.
        if 'pool' not in rule or rule['pool'] not in pools:
            raise ValidationError(f'{name}: a configured pool is required')
        sources = sum(key in rule for key in ('source-address', 'source-address-group'))
        # Negative/dynamic matches cannot define a stable subscriber allocation space.
        if sources != 1:
            raise ValidationError(f'{name}: specify source-address or a static source-address-group')
        if 'source-address-group' in rule:
            definition = lookup(groups, ('address-group', 'ipv4', rule['source-address-group']), None)
            # Imported or learned memberships change independently of allocation commits.
            if definition is None or any(key in definition for key in ('dynamic', 'from-list', 'geoip')):
                raise ValidationError(f'{name}: source-address-group must be a configured static address group')

        matches = {key: value for key, value in rule.items() if key not in ('source-address', 'source-address-group')}
        match_groups = lookup(groups, ('match-group', 'ipv4'), {})
        # Shared match sources must exist and cannot supply the same field twice.
        selected = nftables.verify_match_group_reference(matches, path, match_groups)
        excluded = nftables.verify_exclusions(matches, path, 'ipv4', groups, match_groups)
        nftables.verify_singleton_references(matches, path, 'ipv4', groups, match_group=selected)
        # Named counters and logging groups retain their ordinary rule constraints.
        nftables.verify_rule_statements(rule, path, groups)
        fields = nftables.match_fields(matches, match_group=selected, excluded_group=excluded)
        # Group-supplied fields must be meaningful at postrouting, including transport matches.
        nftables.verify_hook_fields(fields, 'postrouting', path)
        nftables.verify_ports(matches, path, match_group=selected)
        nftables.verify_icmp(matches, path, 'ipv4', match_group=selected, excluded_group=excluded)
        # Every CGN policy must select an external interface, directly or through a group.
        if 'outbound-interface' not in fields:
            raise ValidationError(f'{name}: outbound-interface or outbound-interface-group is required')

        subscriber_ranges = cgnat.subscribers(configuration, rule)
        # Empty static groups cannot define an allocation, even if extra matches are empty.
        if not subscriber_ranges:
            raise ValidationError(f'{name}: subscriber address selection is empty')
        required = int(rule['allocation-offset']) + cgnat.count(subscriber_ranges)
        available = cgnat.capacity(pools[rule['pool']])
        # Check the complete selected address space, including offset, before generating entries.
        if required > available:
            raise ValidationError(f'{name}: allocation requires {required} blocks but pool {rule["pool"]} has {available}')

        vrf = lookup(rule, ('vrf',), 'default')
        # Named VRFs must exist; default is the implicit routing and conntrack domain.
        if vrf != 'default' and vrf not in vrfs:
            raise ValidationError(f'{name}: VRF {vrf!r} is not configured')
        for direction in ('inbound', 'outbound'):
            selectors = list(lookup(rule, (direction + '-interface',), ()))
            group_name = lookup(rule, (direction + '-interface-group',), None)
            if group_name is not None:
                selectors.extend(included_members(lookup(groups, ('interface-group',), {}), group_name, 'interface'))
            for device, device_vrf in devices.items():
                # CGN is scoped within a VRF; cross-VRF routing must happen outside this translation.
                if any(interface_patterns.matches(selector, device) for selector in selectors) and device_vrf != vrf:
                    raise ValidationError(f'{name}: {direction} interface {device} is outside VRF {vrf}')

        for segment in cgnat.segments(configuration, rule):
            public = segment[0]
            for prior_vrf, prior_number, prior_segment in occupied.setdefault(public, []):
                # External ports cannot identify two subscribers; identical repeated allocations are valid.
                intersection = max(segment[1], prior_segment[1]) <= min(segment[2], prior_segment[2])
                if intersection and (prior_vrf != vrf or cgnat.overlaps(segment, prior_segment)):
                    raise ValidationError(f'{name}: public address/port allocation conflicts with CGN rule {prior_number}')
            occupied[public].append((vrf, number, segment))


def verify(configuration, context, *, root='nat', family='ipv4'):
    # CGN shares IPv4 NAT ownership and must be verified in the same commit.
    if root == 'nat' and 'cgnat' in lookup(configuration, ('nat',), {}):
        verify_cgnat(configuration)
    for direction in ('source', 'destination'):
        path = (root, direction, 'rule')

        for number, rule in lookup(configuration, path, {}).items():
            # Disabled rules are not emitted, so skip their translation requirements.
            if 'disable' in rule:
                continue

            # Counter references and logging flags share firewall verification.
            nftables.verify_rule_statements(rule, (*path, number), lookup(configuration, ('firewall', 'group'), {}))

            name = ' '.join((*path, number))
            selected = None
            if 'map' in rule:
                maps = lookup(configuration, ('firewall', 'group', 'map', family), {})
                # Translation maps must not duplicate explicit fields or results.
                selected = nftables.verify_map_reference(rule, (*path, number), maps, {'address', 'port', 'address-port'})

            groups = lookup(configuration, ('firewall', 'group', 'match-group', family), {})
            # All referenced fields must have one source across rule, map and group.
            group = nftables.verify_match_group_reference(rule, (*path, number), groups, selected)

            # Singleton groups must exist and cannot duplicate another match source.
            nftables.verify_singleton_references(
                rule, (*path, number), family, lookup(configuration, ('firewall', 'group'), {}), selected, group)
            fields = nftables.match_fields(rule, selected, group)

            # Shared keys must be available at the NAT hook that consumes them.
            nftables.verify_hook_fields(fields, 'postrouting' if direction == 'source' else 'prerouting', (*path, number))

            # A destination NAT lookup runs before an output device is selected.
            if direction == 'destination' and 'outbound-link-group' in fields:
                raise ValidationError(f'{name}: outbound-link-group is unavailable before routing')

            # Destination NAT cannot use group-supplied outbound interfaces before routing.
            if (direction == 'destination' and 'outbound-interface' in fields
                    and (selected is not None or group is not None or 'outbound-interface-group' in rule)):
                raise ValidationError(f'{name}: destination NAT map or match-group cannot match outbound-interface before routing')

            translation = lookup(rule, ('translation',), {})
            # Port matches need a transport protocol; port translations still require TCP/UDP.
            nftables.verify_ports(rule, (*path, number), mapping=selected, match_group=group, translation=(
                'port' in translation or lookup(translation, ('port-mapping',), 'default') != 'default'))
            # ICMP groups must remain compatible with the other rule matches.
            nftables.verify_icmp(rule, (*path, number), family, selected, group)

            if selected is not None:
                # The rule or either group must constrain this map's NAT interface.
                interface = 'outbound-interface' if direction == 'source' else 'inbound-interface'
                if interface not in fields:
                    raise ValidationError(f'{name}: NAT map, match-group or rule must match {interface}')
                continue

            if 'exclude' in rule:
                # Excluded packets bypass NAT and cannot also request translation.
                if 'translation' in rule:
                    raise ValidationError(f'{name}: exclude cannot be combined with translation; delete the translation subtree')
            elif not ('address' in translation or 'port' in translation):
                # Every non-exclusion rule must translate an address or a port.
                raise ValidationError(f'{name}: translation address or port is required unless exclude is configured')

            # Persistent mappings require an address translation, not just a port.
            if 'persistent' in translation and 'address' not in translation:
                raise ValidationError(f'{name}: translation persistent requires a translation address')

            # Ordinary NAT rules must specify at least one interface match.
            # When neither is present, report the interface expected for the direction.
            if {'inbound-interface', 'outbound-interface'}.isdisjoint(fields):
                if 'source' == direction:
                    raise ValidationError(f'{name}: An outbound-interface must be defined')

                if 'destination' == direction:
                    raise ValidationError(f'{name}: An inbound-interface must be defined')
