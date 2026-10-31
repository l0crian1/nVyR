"""IPv4/IPv6 static routes reconciled through the shared FRR reload pipeline.

Lifecycle input is {route_vrf: static_subtree}. Script registrations identify the
routing instances; only get_config() knows their CLI paths.
"""

import ipaddress

from nvyr.errors import ValidationError
from nvyr.helpers import frr_reload, frr_static, interfaces
from nvyr.helpers.template import render
from nvyr.tree import lookup

ROOT = ('protocols', 'static')
DEFAULT_VRF = 'default'


def get_config(context):
    configuration = {DEFAULT_VRF: lookup(context.effective, ROOT, {})}
    for vrf in context.scripts.get('static', {}).get('vrf', ()):
        if vrf != DEFAULT_VRF:
            configuration[vrf] = lookup(context.effective, ('vrf', 'name', vrf, *ROOT), {})

    return configuration


def _verify_paths(route, vrf, path, local):
    """Check relationships between enabled paths, not schema-validated values."""
    identities = set()
    preferences = {}
    gateways = False
    entries = [('next-hop', address, values) for address, values in lookup(route, ('next-hop',), {}).items()]
    entries.extend(('interface', name, values) for name, values in lookup(route, ('interface',), {}).items())
    entries.extend((kind, '', route[kind]) for kind in ('blackhole', 'reject') if kind in route)

    for kind, name, values in entries:
        if 'disable' in values:
            continue

        location = f'{path} {kind}' + (f' {name}' if name else '')
        discard = kind in ('blackhole', 'reject')
        resolution_vrf = lookup(values, ('vrf',), vrf)
        interface = name if kind == 'interface' else lookup(values, ('interface',), '')
        address = ipaddress.ip_address(name) if kind == 'next-hop' else None

        if kind == 'next-hop':
            # On-link resolution needs an explicit egress interface.
            if 'onlink' in values and not interface:
                raise ValidationError(f'{location}: onlink requires an interface')
            # IPv6 link-local addresses are meaningful only within an interface scope.
            if address.version == 6 and address.is_link_local and not interface:
                raise ValidationError(f'{location}: an IPv6 link-local next hop requires an interface')

            gateways = True
            if local is not None:
                if resolution_vrf not in local:
                    local[resolution_vrf] = interfaces.local_addresses(vrf=resolution_vrf)
                # A next hop cannot resolve to the router itself in the selected VRF.
                if address in local[resolution_vrf]:
                    raise ValidationError(f'{location}: next hop is an IP address assigned to the local system in VRF {resolution_vrf}')

        # Both discard actions have the same FRR key; canonical IP spellings can
        # also collapse different CLI tags into a single native next hop.
        identity = ('discard' if discard else kind, resolution_vrf, str(address) if address else '', interface)
        if identity in identities:
            raise ValidationError(f'{location}: duplicates another enabled forwarding identity (blackhole and reject are mutually exclusive)')

        identities.add(identity)
        preference = (int(lookup(values, ('distance',), 1)), int(lookup(values, ('metric',), 0)))
        # FRR cannot mix discard and forwarding next hops in one ECMP preference group.
        if preference in preferences and preferences[preference] != discard:
            raise ValidationError(f'{location}: forwarding and discard paths cannot share distance {preference[0]} '
                                  f'and metric {preference[1]}; give the fallback a different preference')
        preferences[preference] = discard

    return bool(identities), gateways


def verify(configuration, context):
    """Validate enabled routes in the VRF-keyed effective configuration.

    Destination/source identities must be unique and each enabled route must have
    a usable forwarding or discard path. Live next-hop checks are deferred during
    commit check; ordinary commits cache those observations separately per VRF.
    """
    # None skips host queries during commit check; normal commits cache per VRF.
    local = None if context.check_only else {}
    skipped = False

    for vrf, routes in configuration.items():
        identities = set()

        for family in ('route', 'route6'):
            for prefix, route in lookup(routes, (family,), {}).items():
                if 'disable' in route:
                    continue

                path = f'VRF {vrf}: protocols static {family} {prefix}'
                sources = lookup(route, ('source-specific', 'from'), {})
                groups = [(None, route), *sources.items()]
                enabled = False

                for source, values in groups:
                    if 'disable' in values:
                        continue

                    location = path if source is None else f'{path} source-specific from {source}'
                    has_paths, has_gateways = _verify_paths(values, vrf, location, local)
                    skipped |= context.check_only and has_gateways

                    if not has_paths:
                        # A destination can exist solely to contain source-specific routes.
                        if source is not None:
                            raise ValidationError(f'{location}: at least one enabled next-hop, interface, blackhole or reject is required')
                        continue

                    identity = (family, str(ipaddress.ip_network(prefix)),
                                str(ipaddress.ip_network(source)) if source is not None else '::/0')
                    # Canonical prefixes and an explicit ::/0 source must not duplicate a route.
                    if identity in identities:
                        raise ValidationError(f'{location}: duplicates another destination/source route')

                    identities.add(identity)
                    enabled = True

                # An enabled destination needs at least one enabled forwarding or discard path.
                if not enabled:
                    raise ValidationError(f'{path}: at least one enabled next-hop, interface, blackhole or reject is required; '
                                          'disable the prefix to withdraw all its paths')

    if skipped:
        context.report('Static routing: skipped next-hop host address checks; they run during commit.\n')


def generate(configuration, context):
    generated = {}
    for vrf, routes in sorted(configuration.items()):
        text = render('frr/static.conf.j2', {'vrf': vrf, 'configuration': routes})
        generated[vrf] = sorted(text.strip().splitlines())

    return generated


def apply(generated, context):
    frr_reload.manager.apply('static', generated, context.state_directory,
                             adapter=frr_static.adapter, daemons=('staticd', 'zebra'),
                             recovery=context.recovery)
