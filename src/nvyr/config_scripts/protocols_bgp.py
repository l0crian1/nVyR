"""Unicast BGP instances applied through the shared FRR reload transaction."""

import ipaddress
from collections.abc import Mapping

from nvyr.errors import ValidationError
from nvyr.helpers import bgp_parameters, bgp_peer, frr_bgp, frr_reload, interfaces
from nvyr.helpers.interfaces import local_addresses
from nvyr.helpers.template import render
from nvyr.tree import lookup


ROOT = ('protocols', 'bgp')


def get_config(context):
    """Collect default and registered VRF instances without scanning unrelated VRFs."""
    configuration = {}
    default = lookup(context.effective, ROOT, None)
    if default is not None:
        configuration['default'] = default

    for vrf in context.scripts.get('bgp', {}).get('vrf', ()):
        if vrf != 'default':
            values = lookup(context.effective, ('vrf', 'name', vrf, *ROOT), None)
            if values is not None:
                configuration[vrf] = values

    # Address inventory is only needed when configured neighbors can self-peer.
    configured_interfaces = {}
    if any(lookup(instance, ('neighbor',), None) for instance in configuration.values()):
        configured_interfaces = dict(interfaces.configured(context.effective))

    return {
        'instances': configuration,
        'policies': lookup(context.effective, ('policy',), {}),
        'interfaces': configured_interfaces,
    }


def inherited(group, neighbor):
    """Resolve nested peer settings for verification without changing configuration."""
    result = dict(group)
    for key, value in neighbor.items():
        if isinstance(value, Mapping) and isinstance(lookup(result, (key,), None), Mapping):
            result[key] = inherited(result[key], value)
        else:
            result[key] = value
    if 'disable' in neighbor:
        return dict(neighbor)
    return result


def verify_timers(timers, defaults, path):
    # An absent override leaves FRR's inherited timer pair unchanged.
    if 'keepalive' not in timers and 'holdtime' not in timers:
        return

    keepalive = int(lookup(timers, ('keepalive',), lookup(defaults, ('keepalive',), 60)))
    holdtime = int(lookup(timers, ('holdtime',), lookup(defaults, ('holdtime',), 180)))
    # Do not silently let FRR clamp an unusable keepalive/hold-time pair.
    if (holdtime == 0 and keepalive != 0) or (holdtime and not 0 < keepalive <= holdtime // 3):
        raise ValidationError(f'{path}: keepalive must be positive and at most one third of holdtime; '
                              'use keepalive 0 and holdtime 0 to disable timers')


def verify_references(values, policies, family, path):
    """Walk only policy-bearing nodes in one already family-scoped subtree."""
    kinds = {'route-map': 'route-map', 'prefix-list': 'prefix-list', 'access-list': 'access-list',
             'as-path-list': 'as-path-list', 'advertise-map': 'route-map', 'exist-map': 'route-map',
             'non-exist-map': 'route-map', 'suppress-map': 'route-map', 'unsuppress-map': 'route-map'}
    for kind, provider in kinds.items():
        reference = lookup(values, (kind,), None)
        if reference is None:
            continue
        names = reference.values() if isinstance(reference, Mapping) else (reference,)
        available = lookup(policies, (provider,), {})
        if provider in ('prefix-list', 'access-list'):
            available = lookup(available, (family,), {})
        for name in names:
            # Dependency declarations protect deletion; verification also rejects missing providers.
            if name not in available:
                raise ValidationError(f'{path}: {kind} {name!r} is not configured')

    for key, child in values.items():
        if key not in kinds and isinstance(child, Mapping):
            verify_references(child, policies, family, f'{path} {key}')


def verify_parameters(parameters, instance, vrf):
    path = f'BGP VRF {vrf} parameters'

    confederation = lookup(parameters, ('confederation',), {})
    # A confederation's public identity must differ from its member AS.
    if 'identifier' in confederation and int(confederation['identifier']) == int(instance['local-as']):
        raise ValidationError(f'{path}: confederation identifier must differ from local-as')

    # Confederation peers identify other member ASes, never this instance or its public AS.
    reserved = {int(instance['local-as']), int(lookup(confederation, ('identifier',), 0))}
    if any(int(peer) in reserved for peer in lookup(confederation, ('peers',), ())):
        raise ValidationError(f'{path}: confederation peers cannot contain local-as or the confederation identifier')

    # Peers without a confederation identity cannot establish the intended AS relationship.
    if lookup(confederation, ('peers',), None) and 'identifier' not in confederation:
        raise ValidationError(f'{path}: confederation peers require identifier')

    # A delay has no effect unless suppression itself is enabled.
    if 'suppress-fib-pending-delay' in parameters and not bgp_parameters.enabled(parameters, 'suppress-fib-pending'):
        raise ValidationError(f'{path}: suppress-fib-pending-delay requires suppress-fib-pending enable')

    keepalive = lookup(parameters, ('tcp-keepalive',), None)
    # FRR takes one complete TCP keepalive tuple, not partial independent overrides.
    if keepalive is not None and set(keepalive) != {'idle', 'interval', 'probes'}:
        raise ValidationError(f'{path}: tcp-keepalive requires idle, interval and probes')

    startup = lookup(parameters, ('max-med', 'on-startup'), None)
    # Startup MED needs a duration; the MED value alone cannot activate it.
    if startup is not None and 'time' not in startup:
        raise ValidationError(f'{path}: max-med on-startup requires time')

    as_path = lookup(parameters, ('bestpath', 'as-path'), {})
    # AS_SET generation is a modifier of relaxed AS-path multipath selection.
    if bgp_parameters.enabled(as_path, 'multipath-relax-as-set') and not bgp_parameters.enabled(as_path, 'multipath-relax'):
        raise ValidationError(f'{path}: multipath-relax-as-set requires multipath-relax enable')

    # FRR's route-map rescan timer is shared across every instance in the daemon.
    if vrf != 'default' and 'route-map' in parameters:
        raise ValidationError(f'{path}: route-map delay-timer is daemon-wide; configure it under protocols bgp parameters')

    dampening = lookup(parameters, ('dampening',), {})
    # FRR documents route-flap dampening as unsupported per VRF in this release.
    if bgp_parameters.enabled(dampening, 'state') and vrf != 'default':
        raise ValidationError(f'{path}: dampening is supported only in the default VRF by FRR 10.7.1')

    # Reuse must be below suppression so a suppressed route can recover predictably.
    if bgp_parameters.enabled(dampening, 'state') and int(lookup(dampening, ('reuse',), 750)) >= int(lookup(dampening, ('suppress',), 2000)):
        raise ValidationError(f'{path}: dampening reuse must be less than suppress')

    # Maximum suppression cannot be shorter than the penalty half-life.
    if bgp_parameters.enabled(dampening, 'state') and int(lookup(dampening, ('max-suppress-time',), 60)) < int(lookup(dampening, ('half-life',), 15)):
        raise ValidationError(f'{path}: dampening max-suppress-time must be at least half-life')

    groups = lookup(instance, ('peer-group',), {})
    prefixes = set()
    for prefix, listener in lookup(parameters, ('listen', 'range'), {}).items():
        canonical = str(ipaddress.ip_network(prefix))

        # Equivalent prefixes cannot create competing dynamic-neighbor definitions.
        if canonical in prefixes:
            raise ValidationError(f'{path}: duplicate listen range {canonical}')
        prefixes.add(canonical)

        name = lookup(listener, ('peer-group',), None)
        # Listening requires an existing group with a remote AS and active address family.
        if name not in groups or 'remote-as' not in groups[name]:
            raise ValidationError(f'{path}: listen range {prefix} requires a configured peer-group with remote-as')

        group = groups[name]
        # Dynamic neighbors need at least one explicitly or implicitly activated family.
        if not any('disable' not in settings for settings in bgp_parameters.families(parameters, group).values()):
            raise ValidationError(f'{path}: listen peer-group {name} requires an active address-family')


def verify_peer_options(options, internal_peer, path):
    alternate = lookup(options, ('local-as',), None)
    # An alternate identity needs a number; modifiers alone cannot identify this router.
    if alternate is not None and 'number' not in alternate:
        raise ValidationError(f'{path}: local-as requires number')
    # FRR only permits alternate local AS identities on external sessions.
    if alternate is not None and internal_peer:
        raise ValidationError(f'{path}: local-as requires an external neighbor')

    role = lookup(options, ('role',), None)
    # Strict role negotiation must name the local relationship being negotiated.
    if role is not None and 'type' not in role:
        raise ValidationError(f'{path}: role requires type')
    # BGP roles describe external relationships, not internal peers.
    if role is not None and internal_peer:
        raise ValidationError(f'{path}: role requires an external neighbor')

    capability = lookup(options, ('capability',), {})
    # Strict matching and overriding capability mismatches express opposing policies.
    if 'strict-match' in capability and 'override' in capability:
        raise ValidationError(f'{path}: capability strict-match and override are mutually exclusive')
    # Disabling negotiation would suppress the other explicitly requested capabilities.
    if 'disable-negotiation' in capability and len(capability) > 1:
        raise ValidationError(f'{path}: capability disable-negotiation cannot be combined with other capabilities')


def verify_peer_family(options, internal_peer, path):
    # A disabled family cannot also request active-family behavior.
    if 'disable' in options and len(options) > 1:
        raise ValidationError(f'{path}: disable cannot be combined with address-family settings')

    allowed = lookup(options, ('allowas-in',), None)
    # Choose a bounded occurrence count or origin matching, never both.
    if allowed is not None and ('count' in allowed) == ('origin' in allowed):
        raise ValidationError(f'{path}: allowas-in requires exactly one of count or origin')
    private = lookup(options, ('remove-private-as',), {})
    # The nested all/replace branch already selects replacement; two branches are ambiguous.
    if 'replace' in private and 'all' in private:
        raise ValidationError(f'{path}: use remove-private-as all replace for replacement of all private AS numbers')
    # These export transformations operate on external AS boundaries.
    if internal_peer and any(key in options for key in ('allowas-in', 'as-override', 'remove-private-as', 'route-server-client')):
        raise ValidationError(f'{path}: allowas-in, AS override, private-AS removal and route-server-client require an external neighbor')
    # Route-server and reflector behavior require incompatible peer relationships.
    if 'route-server-client' in options and 'route-reflector-client' in options:
        raise ValidationError(f'{path}: route-server-client and route-reflector-client are mutually exclusive')

    soft = lookup(options, ('soft-reconfiguration',), None)
    # An empty grouping node does not enable storage of received routes.
    if soft is not None and 'inbound' not in soft:
        raise ValidationError(f'{path}: soft-reconfiguration requires inbound')
    limit = lookup(options, ('maximum-prefix',), None)
    # A prefix limit needs an actual limit rather than modifiers alone.
    if limit is not None and 'limit' not in limit:
        raise ValidationError(f'{path}: maximum-prefix requires limit')
    if limit is not None:
        # Warning-only never closes the session, so a restart timer would be meaningless.
        if 'warning-only' in limit and 'restart' in limit:
            raise ValidationError(f'{path}: maximum-prefix warning-only and restart are mutually exclusive')
        # Counting rejected routes requires FRR to retain the unmodified inbound routes.
        if 'force' in limit and 'inbound' not in (soft or {}):
            raise ValidationError(f'{path}: maximum-prefix force requires soft-reconfiguration inbound')

    conditional = lookup(options, ('conditional-advertisement',), None)
    # Conditional advertisement needs its output selector and exactly one existence condition.
    if conditional is not None and ('advertise-map' not in conditional or
                                    ('exist-map' in conditional) == ('non-exist-map' in conditional)):
        raise ValidationError(f'{path}: conditional-advertisement requires advertise-map and exactly one of exist-map or non-exist-map')

    addpath = lookup(options, ('addpath',), {})
    # FRR stores one transmit strategy per peer/family.
    if 'transmit' in addpath and len(addpath['transmit']) != 1:
        raise ValidationError(f'{path}: addpath transmit requires exactly one strategy')
    # A receive limit is ineffective if reception is explicitly disabled.
    if 'disable-receive' in addpath and 'receive-limit' in addpath:
        raise ValidationError(f'{path}: addpath disable-receive and receive-limit are mutually exclusive')
    # The native bare command means all attributes; require explicit fields in our CLI.
    if 'attribute-unchanged' in options and not options['attribute-unchanged']:
        raise ValidationError(f'{path}: attribute-unchanged requires as-path, next-hop or med')


def verify_peer(options, instance, policies, path, *, require_remote):
    remote = lookup(options, ('remote-as',), None)
    # Every actual neighbor needs a remote AS, directly or through its peer-group.
    if require_remote and remote is None:
        raise ValidationError(f'{path}: remote-as is required, directly or through a peer-group')

    # Multihop and GTSM configure incompatible outgoing TTL behavior in FRR.
    if 'ebgp-multihop' in options and 'ttl-security' in options:
        raise ValidationError(f'{path}: ebgp-multihop and ttl-security are mutually exclusive')

    # An empty TTL-security node has no executable native meaning.
    if 'ttl-security' in options and 'hops' not in options['ttl-security']:
        raise ValidationError(f'{path}: ttl-security requires hops')

    internal = bgp_peer.internal(remote, instance['local-as'])
    verify_peer_options(options, internal, path)
    # An alternate AS equal to the instance AS has no external identity to substitute.
    if 'local-as' in options and int(options['local-as']['number']) == int(instance['local-as']):
        raise ValidationError(f'{path}: alternate local-as must differ from the instance local-as')
    # eBGP multihop is an external-session setting, not an iBGP timer.
    if internal and 'ebgp-multihop' in options:
        raise ValidationError(f'{path}: ebgp-multihop requires an external neighbor')

    parameters = lookup(instance, ('parameters',), {})
    confederation_peers = lookup(parameters, ('confederation', 'peers'), ())
    confederation_peer = str(remote).isdecimal() and int(remote) in {int(peer) for peer in confederation_peers}
    verify_timers(lookup(options, ('timers',), {}), lookup(parameters, ('timers',), {}), path)
    for family, settings in bgp_parameters.families(parameters, options).items():
        verify_peer_family(settings, internal, f'{path} {family}')
        # An explicitly deactivated family needs no import or export policy.
        if 'disable' in settings:
            continue
        for direction, route_map_direction in (('in', 'import'), ('out', 'export')):
            # Native distribute-list and prefix-list cannot occupy the same filter slot.
            if direction in lookup(settings, ('access-list',), {}) and direction in lookup(settings, ('prefix-list',), {}):
                raise ValidationError(f'{path} {family}: access-list and prefix-list are mutually exclusive for {direction}')

            filtered = any(route_map_direction in lookup(settings, (kind,), {}) for kind in ('route-map', 'as-path-list')) or any(
                direction in lookup(settings, (kind,), {}) for kind in ('prefix-list', 'access-list'))
            # Policy enforcement is opt-in for external sessions, excluding confederation members.
            if (bgp_parameters.enabled(parameters, 'ebgp-requires-policy')
                    and require_remote and not internal and not confederation_peer and 'shutdown' not in options
                    and not bgp_parameters.enabled(parameters, 'shutdown')
                    and not bgp_parameters.enabled(parameters, 'default shutdown')
                    and not filtered):
                raise ValidationError(f'{path} {family}: external neighbors require an explicit {route_map_direction} policy')

        # Route reflection applies only to neighbors inside the same autonomous system.
        if 'route-reflector-client' in settings and remote is not None and not internal:
            raise ValidationError(f'{path} {family}: route-reflector-client requires an internal neighbor')

        verify_references(settings, policies, family.split('-')[0], f'{path} {family}')


def verify(configuration, context):
    """Validate VRF instances, inherited peer settings and referenced policies.

    Instances and cross-feature dependencies are gathered by get_config.
    Host-dependent address checks are deferred during commit check and run when
    prior interface owners have applied their changes.
    """
    instances = configuration['instances']
    policies = configuration['policies']
    configured_addresses = {}
    for values in configuration['interfaces'].values():
        vrf = lookup(values, ('vrf',), 'default')
        addresses = configured_addresses.setdefault(vrf, set())
        addresses.update(ipaddress.ip_interface(value).ip for value in lookup(values, ('address',), ()) if value != 'dhcp')

    skipped_host_check = False
    for vrf, instance in instances.items():
        path = f'BGP VRF {vrf}'
        # A native router instance cannot exist without its autonomous-system identity.
        if 'local-as' not in instance:
            raise ValidationError(f'{path}: local-as is required')

        parameters = lookup(instance, ('parameters',), {})
        verify_parameters(parameters, instance, vrf)
        verify_timers(lookup(parameters, ('timers',), {}), {}, path)
        groups = lookup(instance, ('peer-group',), {})
        dynamic_groups = {lookup(listener, ('peer-group',), None) for listener in lookup(parameters, ('listen', 'range'), {}).values()}
        for name, group in groups.items():
            verify_peer(group, instance, policies, f'{path} peer-group {name}', require_remote=name in dynamic_groups)

        identities = set()
        local = configured_addresses.get(vrf, set()).copy()
        # Query once per populated VRF, including runtime addresses absent from configuration.
        if lookup(instance, ('neighbor',), None):
            # A check-only run may describe interfaces and VRFs that do not exist yet.
            if context.check_only:
                skipped_host_check = True
            else:
                local.update(local_addresses(vrf=vrf))

        for address, neighbor in lookup(instance, ('neighbor',), {}).items():
            neighbor_address = bgp_peer.address(address)
            canonical = bgp_peer.name(address)
            # Interface selectors are only needed for addressed peers, not interface keys.
            if neighbor_address is None and 'interface' in neighbor:
                raise ValidationError(f'{path} neighbor {address}: interface is only valid for an addressed peer')
            # IPv6-only modifies unnumbered peer discovery, not addressed transport.
            if neighbor_address is not None and 'ipv6-only' in neighbor:
                raise ValidationError(f'{path} neighbor {address}: ipv6-only requires an interface neighbor')
            # A link-local address has no routing scope without its peer-facing interface.
            if (neighbor_address is not None and neighbor_address.version == 6
                    and neighbor_address.is_link_local and 'interface' not in neighbor):
                raise ValidationError(f'{path} neighbor {address}: a link-local neighbor requires interface')
            # A peer must not connect back to this router in the same routing domain.
            if neighbor_address in local:
                raise ValidationError(f'{path} neighbor {address}: neighbor address is assigned to the local system in VRF {vrf}')

            # Different IPv6 spellings must not create competing definitions of one native peer.
            if canonical in identities:
                raise ValidationError(f'{path}: duplicate neighbor address {canonical}')
            identities.add(canonical)

            group = lookup(neighbor, ('peer-group',), None)
            # Peer-group names are local to this routing instance, not global across VRFs.
            if group is not None and group not in groups:
                raise ValidationError(f'{path} neighbor {address}: peer-group {group!r} is not configured')

            options = inherited(lookup(groups, (group,), {}), neighbor)
            # A group with a fixed remote AS cannot have a member in a different AS.
            if (group is not None and 'remote-as' in groups[group] and 'remote-as' in neighbor
                    and str(groups[group]['remote-as']).isdecimal()
                    and str(neighbor['remote-as']) != str(groups[group]['remote-as'])):
                raise ValidationError(f'{path} neighbor {address}: remote-as conflicts with peer-group {group}')

            for family, settings in lookup(neighbor, ('address-family',), {}).items():
                inherited_family = lookup(groups, (group, 'address-family', family), {})
                # FRR 10.7.1 ignores attempts to re-enable a community class disabled by the group.
                if ('send-community' in settings and 'send-community' in inherited_family
                        and not set(settings['send-community']).issubset(inherited_family['send-community'])):
                    raise ValidationError(f'{path} neighbor {address}: configure send-community on peer-group {group}; '
                                          'FRR cannot override its disabled community classes on a member')

            # Transport source addresses must use the neighbor's transport family; NLRI families are independent.
            source = lookup(options, ('update-source',), None)
            if source:
                try:
                    source_address = ipaddress.ip_address(source)
                except ValueError:
                    source_address = None
                # An address source and transport destination must be usable on the same IP socket.
                if source_address is not None and neighbor_address is not None and source_address.version != neighbor_address.version:
                    raise ValidationError(f'{path} neighbor {address}: update-source address family must match the neighbor')

            verify_peer(options, instance, policies, f'{path} neighbor {address}', require_remote=True)

        for family, values in lookup(instance, ('address-family',), {}).items():
            for prefix, aggregate in lookup(values, ('aggregate-address',), {}).items():
                # Summary-only suppresses everything and would make a selective suppress-map ineffective.
                if 'summary-only' in aggregate and 'suppress-map' in aggregate:
                    raise ValidationError(f'{path} {family} aggregate-address {prefix}: summary-only and suppress-map are mutually exclusive')
            verify_references(values, policies, family.split('-')[0], f'{path} {family}')

    if skipped_host_check:
        context.report('BGP: skipped live local-address checks; configured addresses were checked. Live checks run during commit.\n')


def generate(configuration, context):
    return frr_bgp.adapter.desired(render('frr/bgp.conf.j2', {'configuration': configuration['instances']}))


def apply(generated, context):
    frr_reload.manager.apply('bgp', generated, context.state_directory, adapter=frr_bgp.adapter,
                             daemons=('zebra', 'bgpd'), recovery=context.recovery)
