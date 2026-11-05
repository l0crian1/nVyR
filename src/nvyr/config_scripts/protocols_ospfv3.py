"""OSPFv3 IPv6 routing configuration applied through the shared FRR transaction."""

from nvyr.errors import ValidationError
from nvyr.helpers import frr_ospf, frr_reload, interfaces
from nvyr.helpers.ospf_formatters import area_id
from nvyr.helpers.template import render
from nvyr.tree import lookup


def get_config(context):
    instances = {}
    default = lookup(context.effective, ('protocols', 'ospfv3'), None)
    if default is not None:
        instances['default'] = default
    for vrf in lookup(context.scripts, ('ospfv3', 'vrf'), ()):
        if vrf != 'default':
            values = lookup(context.effective, ('vrf', 'name', vrf, 'protocols', 'ospfv3'), None)
            if values is not None:
                instances[vrf] = values

    return {'instances': instances, 'policies': lookup(context.effective, ('policy',), {}),
            'interfaces': dict(interfaces.configured(context.effective))}


def verify_authentication(values, policies, path):
    # A manually specified key and a rotating keychain select different authentication sources.
    if len(values) != 1:
        raise ValidationError(f'{path}: select key or key-chain')
    if 'key-chain' in values:
        chain = lookup(policies, ('key-chain', values['key-chain']), None)
        # Dependency guards protect deletion; new references also need an existing chain.
        if chain is None:
            raise ValidationError(f'{path}: key-chain {values["key-chain"]!r} is not configured')
        for identifier in lookup(chain, ('key',), {}):
            # The authentication trailer has a sixteen-bit security association identifier.
            if not 1 <= int(identifier) <= 65535:
                raise ValidationError(f'{path}: OSPFv3 key IDs must be between 1 and 65535')
    keys = lookup(values, ('key',), {})
    # FRR supports one manual key at a time; rotating keys belong in a keychain.
    if 'key' in values and len(keys) != 1:
        raise ValidationError(f'{path} key: configure exactly one key, or use a key-chain')
    for identifier, key in keys.items():
        # Both operands are required by the authentication trailer command.
        if 'secret' not in key or 'algorithm' not in key:
            raise ValidationError(f'{path} key {identifier}: secret and algorithm are required')


def verify_references(settings, policies, path):
    references = []
    for source, values in lookup(settings, ('redistribute',), {}).items():
        entries = values.values() if source in ('table', 'table-direct') else (values,)
        for entry in entries:
            if 'route-map' in entry:
                references.append((entry['route-map'], ('route-map',)))
    default = lookup(settings, ('default-information', 'originate'), {})
    if 'route-map' in default:
        references.append((default['route-map'], ('route-map',)))
    for area in lookup(settings, ('area',), {}).values():
        for key in ('import-list', 'export-list'):
            if key in area:
                references.append((area[key], ('access-list', 'ipv6')))
        for name in lookup(area, ('filter-list',), {}).values():
            references.append((name, ('prefix-list', 'ipv6')))
    for interface in lookup(settings, ('interface',), {}).values():
        for values in (interface, *lookup(interface, ('address',), {}).values()):
            if 'advertise-prefix-list' in values:
                references.append((values['advertise-prefix-list'], ('prefix-list', 'ipv6')))
    for values in lookup(settings, ('distribute-list', 'export'), {}).values():
        # A provider is required even for an otherwise empty export-list entry.
        if 'access-list' not in values:
            raise ValidationError(f'{path} distribute-list export: access-list is required')
        references.append((values['access-list'], ('access-list', 'ipv6')))

    for name, provider in references:
        # Validate only actual reference positions, never user-chosen tag names.
        if name not in lookup(policies, provider, {}):
            raise ValidationError(f'{path}: {" ".join(provider)} {name!r} is not configured')


def verify(configuration, context):
    policies = configuration['policies']
    for vrf, settings in configuration['instances'].items():
        path = 'protocols ospfv3' if vrf == 'default' else f'vrf name {vrf} protocols ospfv3'
        verify_references(settings, policies, path)
        spf = lookup(settings, ('timers', 'spf'), None)
        if spf is not None:
            # Native SPF throttling needs all three delays in a single command.
            if set(spf) != {'delay', 'initial-hold', 'maximum-hold'}:
                raise ValidationError(f'{path} timers spf: delay, initial-hold, and maximum-hold are required')
            # The adaptive hold time cannot start above its configured ceiling.
            if int(spf['initial-hold']) > int(spf['maximum-hold']):
                raise ValidationError(f'{path} timers spf: initial-hold must not exceed maximum-hold')
        seen = set()
        for identifier, area in lookup(settings, ('area',), {}).items():
            canonical = area_id(identifier)
            # Decimal and dotted decimal spellings identify the same native area.
            if canonical in seen:
                raise ValidationError(f'{path}: area {canonical} is configured under more than one spelling')
            seen.add(canonical)
            # The backbone is a normal area; stub and NSSA are mutually exclusive elsewhere.
            if ('stub' in area and 'nssa' in area) or (canonical == '0.0.0.0' and ('stub' in area or 'nssa' in area)):
                raise ValidationError(f'{path} area {identifier}: choose stub or nssa only for non-backbone areas')
            for section in (area, lookup(area, ('nssa',), {})):
                for prefix, summary in lookup(section, ('range',), {}).items():
                    # Suppressed summaries have no advertised cost.
                    if 'no-advertise' in summary and 'cost' in summary:
                        raise ValidationError(f'{path} area {identifier} range {prefix}: no-advertise excludes cost')
        for name, interface in lookup(settings, ('interface',), {}).items():
            configured = lookup(configuration, ('interfaces', name), {})
            assigned_vrf = lookup(configured, ('vrf',), 'default')
            # A configured link cannot join another routing instance's OSPF process.
            if configured and assigned_vrf != vrf:
                raise ValidationError(f'{path} interface {name}: interface belongs to VRF {assigned_vrf}')
            # Disabling IPv6 also prevents the link-local transport required by OSPFv3.
            if 'disable' in lookup(configured, ('ipv6',), {}):
                raise ValidationError(f'{path} interface {name}: IPv6 is disabled')
            if 'authentication' in interface:
                verify_authentication(interface['authentication'], policies, f'{path} interface {name} authentication')
            # Static neighbors and these controls only apply to point-to-point or multipoint links.
            if ('neighbor-options' in interface or 'neighbor' in interface) and lookup(interface, ('network',), '') not in ('point-to-point', 'point-to-multipoint'):
                raise ValidationError(f'{path} interface {name}: neighbor settings require a point-to-point or point-to-multipoint network')


def generate(configuration, context):
    text = render('frr/ospf.conf.j2', {'configuration': configuration, 'version': 3})
    return frr_ospf.ipv6.desired(text)


def apply(generated, context):
    frr_reload.manager.apply('ospfv3', generated, context.state_directory,
                            adapter=frr_ospf.ipv6, daemons=('zebra', 'ospf6d'), recovery=context.recovery)
