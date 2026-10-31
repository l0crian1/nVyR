"""IPv4 NAT verification, invoked by the shared firewall commit owner."""

from nvyr.errors import ValidationError
from nvyr.helpers import nftables
from nvyr.tree import lookup


def verify(configuration, context):
    for direction in ('source', 'destination'):
        path = ('nat', direction, 'rule')

        for number, rule in lookup(configuration, path, {}).items():
            # Disabled rules are not emitted, so skip their translation requirements.
            if 'disable' in rule:
                continue

            # Counter references and logging flags share firewall verification.
            nftables.verify_rule_statements(rule, (*path, number), lookup(configuration, ('firewall', 'group'), {}))

            name = ' '.join((*path, number))
            selected = None
            if 'map' in rule:
                maps = lookup(configuration, ('firewall', 'group', 'map', 'ipv4'), {})
                # Translation maps must not duplicate explicit fields or results.
                selected = nftables.verify_map_reference(rule, (*path, number), maps, {'address', 'port', 'address-port'})

            groups = lookup(configuration, ('firewall', 'group', 'match-group', 'ipv4'), {})
            # All referenced fields must have one source across rule, map and group.
            group = nftables.verify_match_group_reference(rule, (*path, number), groups, selected)

            # Singleton groups must exist and cannot duplicate another match source.
            nftables.verify_singleton_references(
                rule, (*path, number), 'ipv4', lookup(configuration, ('firewall', 'group'), {}), selected, group)
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
            nftables.verify_icmp(rule, (*path, number), 'ipv4', selected, group)

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
