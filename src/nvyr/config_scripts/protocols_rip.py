"""RIP and RIPng configuration through the shared FRR transaction."""

from nvyr.errors import ValidationError
from nvyr.helpers import frr_reload, frr_rip, interfaces
from nvyr.helpers.template import render
from nvyr.tree import lookup


def get_config(context):
    protocol = context.owner
    instances = {}
    default = lookup(context.effective, ('protocols', protocol), None)
    if default is not None:
        instances['default'] = default

    for vrf in lookup(context.scripts, (protocol, 'vrf'), ()):
        if vrf != 'default':
            settings = lookup(context.effective, ('vrf', 'name', vrf, 'protocols', protocol), None)
            if settings is not None:
                instances[vrf] = settings

    return {'protocol': protocol, 'instances': instances,
            'policies': lookup(context.effective, ('policy',), {}),
            'interfaces': dict(interfaces.configured(context.effective))}


def verify_filters(settings, policies, family, path):
    for direction, filters in lookup(settings, ('distribute-list',), {}).items():
        # FRR can apply an access-list and prefix-list together, but an empty direction has no meaning.
        if not filters:
            raise ValidationError(f'{path} distribute-list {direction}: select an access-list or prefix-list')
        for kind, name in filters.items():
            # New references must resolve as well as being protected against later deletion.
            if name not in lookup(policies, (kind, family), {}):
                raise ValidationError(f'{path}: {kind} {name!r} is not configured for {family}')

    for direction, offset in lookup(settings, ('offset-list',), {}).items():
        # Both operands belong to one native offset-list command.
        if 'access-list' not in offset or 'metric' not in offset:
            raise ValidationError(f'{path} offset-list {direction}: access-list and metric are required')

        # Offsets use the access-list for this protocol's address family.
        if offset['access-list'] not in lookup(policies, ('access-list', family), {}):
            raise ValidationError(f'{path}: access-list {offset["access-list"]!r} is not configured for {family}')


def verify(configuration, context):
    protocol = configuration['protocol']
    family = 'ipv4' if protocol == 'rip' else 'ipv6'
    policies = configuration['policies']
    assigned = {}
    for vrf, settings in configuration['instances'].items():
        path = f'protocols {protocol}' if vrf == 'default' else f'vrf name {vrf} protocols {protocol}'
        verify_filters(settings, policies, family, path)
        references = [entry['route-map'] for entry in lookup(settings, ('redistribute',), {}).values()
                      if 'route-map' in entry]

        for prefix, entry in lookup(settings, ('source-distance',), {}).items():
            # A source selector alone cannot specify a distance override.
            if 'distance' not in entry:
                raise ValidationError(f'{path} source-distance {prefix}: distance is required')

            # The optional ACL filters destinations for this source-specific distance.
            if 'access-list' in entry and entry['access-list'] not in lookup(policies, ('access-list', family), {}):
                raise ValidationError(f'{path}: access-list {entry["access-list"]!r} is not configured')

        for name, interface in lookup(settings, ('interface',), {}).items():
            where = f'{path} interface {name}'
            configured = lookup(configuration, ('interfaces', name), {})
            assigned_vrf = lookup(configured, ('vrf',), 'default')
            # Interface commands belong to the routing instance containing that link.
            if configured and assigned_vrf != vrf:
                raise ValidationError(f'{where}: interface belongs to VRF {assigned_vrf}')

            # One native interface cannot participate in two instances of this protocol.
            if name in assigned and assigned[name] != vrf:
                raise ValidationError(f'{where}: interface is also configured under VRF {assigned[name]}')
            assigned[name] = vrf

            # RIPng requires IPv6 link-local transport on participating interfaces.
            if protocol == 'ripng' and 'disable' in lookup(configured, ('ipv6',), {}):
                raise ValidationError(f'{where}: IPv6 is disabled')

            split = lookup(interface, ('split-horizon',), {})
            # Disabling split horizon and advertising poisoned reverse are exclusive modes.
            if 'disable' in split and 'poisoned-reverse' in split:
                raise ValidationError(f'{where} split-horizon: disable and poisoned-reverse are mutually exclusive')

            verify_filters(interface, policies, family, where)
            references.extend(lookup(interface, ('route-map',), {}).values())
            authentication = lookup(interface, ('authentication',), None)
            if authentication is not None:
                # Authentication needs one explicit mode and one source of key material.
                if 'mode' not in authentication or sum(key in authentication for key in ('password', 'key-chain')) != 1:
                    raise ValidationError(f'{where} authentication: mode and exactly one of password or key-chain are required')

                # Authentication-length compatibility only applies to MD5 packets.
                if 'md5-auth-length' in authentication and authentication['mode'] != 'md5':
                    raise ValidationError(f'{where} authentication: md5-auth-length requires mode md5')

                if 'key-chain' in authentication:
                    chain = lookup(policies, ('key-chain', authentication['key-chain']), None)
                    # Keychain references must exist; RIP carries an eight-bit MD5 key ID.
                    if chain is None:
                        raise ValidationError(f'{where}: key-chain {authentication["key-chain"]!r} is not configured')

                    # Shared keychains may contain IDs wider than the RIP MD5 field.
                    if authentication['mode'] == 'md5' and any(int(key) > 255 for key in lookup(chain, ('key',), {})):
                        raise ValidationError(f'{where}: RIP MD5 key IDs must fit in 0-255')

        for name in references:
            # Route-map names in interface and redistribution policies use the shared policy tree.
            if name not in lookup(policies, ('route-map',), {}):
                raise ValidationError(f'{path}: route-map {name!r} is not configured')


def generate(configuration, context):
    text = render('frr/rip.conf.j2', {'configuration': configuration})
    return frr_rip.adapters[configuration['protocol']].desired(text)


def apply(generated, context):
    protocol = context.owner
    frr_reload.manager.apply(protocol, generated, context.state_directory,
                             adapter=frr_rip.adapters[protocol], daemons=('zebra', protocol + 'd'),
                             recovery=context.recovery)
