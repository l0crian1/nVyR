"""OSPFv2 configuration, including named VRFs, through the shared FRR transaction."""

from nvyr.errors import ValidationError
from nvyr.helpers import frr_ospf, frr_reload, interfaces
from nvyr.helpers.ospf_formatters import area_id
from nvyr.helpers.template import render
from nvyr.tree import lookup


def get_config(context):
    instances = {}
    default = lookup(context.effective, ('protocols', 'ospf'), None)
    if default is not None:
        instances['default'] = default
    for vrf in lookup(context.scripts, ('ospf', 'vrf'), ()):
        if vrf != 'default':
            values = lookup(context.effective, ('vrf', 'name', vrf, 'protocols', 'ospf'), None)
            if values is not None:
                instances[vrf] = values

    return {'instances': instances, 'policies': lookup(context.effective, ('policy',), {}),
            'interfaces': dict(interfaces.configured(context.effective))}


def verify_authentication(values, policies, path):
    # Authentication modes select incompatible wire formats and cannot coexist.
    if len(values) != 1:
        raise ValidationError(f'{path}: select exactly one authentication mode')
    if 'key-chain' in values:
        chain = lookup(policies, ('key-chain', values['key-chain']), None)
        # Dependency guards protect deletion; creation also needs an existing chain.
        if chain is None:
            raise ValidationError(f'{path}: key-chain {values["key-chain"]!r} is not configured')
        for identifier, key in lookup(chain, ('key',), {}).items():
            # OSPFv2 carries an eight-bit key ID even though shared keychains allow larger IDs.
            if not 1 <= int(identifier) <= 255:
                raise ValidationError(f'{path}: OSPFv2 key IDs must be between 1 and 255')
    for identifier, key in lookup(values, ('md5', 'key'), {}).items():
        # A digest key without a secret would install unusable authentication.
        if 'secret' not in key:
            raise ValidationError(f'{path} md5 key {identifier}: secret is required')
    # An empty MD5 mode has no usable transmit or receive key.
    if 'md5' in values and not lookup(values, ('md5', 'key'), {}):
        raise ValidationError(f'{path} md5: at least one key is required')


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
                references.append((area[key], ('access-list', 'ipv4')))
        for name in lookup(area, ('filter-list',), {}).values():
            references.append((name, ('prefix-list', 'ipv4')))
    for interface in lookup(settings, ('interface',), {}).values():
        for values in (interface, *lookup(interface, ('address',), {}).values()):
            if 'neighbor-filter' in values:
                references.append((values['neighbor-filter'], ('prefix-list', 'ipv4')))
    for values in lookup(settings, ('distribute-list', 'export'), {}).values():
        # A provider is required even for an otherwise empty export-list entry.
        if 'access-list' not in values:
            raise ValidationError(f'{path} distribute-list export: access-list is required')
        references.append((values['access-list'], ('access-list', 'ipv4')))

    for name, provider in references:
        # Validate only actual reference positions, never user-chosen tag names.
        if name not in lookup(policies, provider, {}):
            raise ValidationError(f'{path}: {" ".join(provider)} {name!r} is not configured')


def verify_interface(values, policies, path):
    if 'authentication' in values:
        verify_authentication(values['authentication'], policies, path + ' authentication')
    network = lookup(values, ('network',), {})
    # A link has exactly one OSPF network type.
    if 'network' in values and len(network) != 1:
        raise ValidationError(f'{path} network: select exactly one network type')
    multipoint = lookup(network, ('point-to-multipoint',), {})
    # Native point-to-multipoint modifiers select alternative behaviors.
    if len(multipoint) > 1:
        raise ValidationError(f'{path}: non-broadcast and delay-reflood are mutually exclusive')
    # Fast hello fixes the dead interval at one second and replaces ordinary hello timing.
    if 'fast-hello' in values and ('hello-interval' in values or 'dead-interval' in values):
        raise ValidationError(f'{path}: fast-hello cannot accompany hello-interval or dead-interval')
    for address, settings in lookup(values, ('address',), {}).items():
        verify_interface(settings, policies, f'{path} address {address}')


def verify(configuration, context):
    policies = configuration['policies']
    for vrf, settings in configuration['instances'].items():
        path = 'protocols ospf' if vrf == 'default' else f'vrf name {vrf} protocols ospf'
        verify_references(settings, policies, path)
        spf = lookup(settings, ('timers', 'spf'), None)
        if spf is not None:
            # Native SPF throttling requires all three delays in a single command.
            if set(spf) != {'delay', 'initial-hold', 'maximum-hold'}:
                raise ValidationError(f'{path} timers spf: delay, initial-hold, and maximum-hold are required')
            # The adaptive hold time cannot start above its configured ceiling.
            if int(spf['initial-hold']) > int(spf['maximum-hold']):
                raise ValidationError(f'{path} timers spf: initial-hold must not exceed maximum-hold')
        buffers = lookup(settings, ('socket', 'buffer'), {})
        # The all operand sets both sizes and would overwrite direction-specific values.
        if 'all' in buffers and len(buffers) > 1:
            raise ValidationError(f'{path} socket buffer: all excludes send and receive')
        seen = set()
        for identifier, area in lookup(settings, ('area',), {}).items():
            canonical = area_id(identifier)
            # Decimal and dotted decimal spellings identify the same native area.
            if canonical in seen:
                raise ValidationError(f'{path}: area {canonical} is configured under more than one spelling')
            seen.add(canonical)
            # Stub and NSSA are alternative area types; neither can describe the backbone.
            if ('stub' in area and 'nssa' in area) or (canonical == '0.0.0.0' and ('stub' in area or 'nssa' in area)):
                raise ValidationError(f'{path} area {identifier}: choose stub or nssa only for non-backbone areas')
            # Default cost applies to the injected default in stub and NSSA areas.
            if 'default-cost' in area and not ('stub' in area or 'nssa' in area):
                raise ValidationError(f'{path} area {identifier}: default-cost requires stub or nssa')
            for section in (area, lookup(area, ('nssa',), {})):
                for prefix, summary in lookup(section, ('range',), {}).items():
                    # A suppressed summary has no advertised cost or substitute prefix.
                    if 'no-advertise' in summary and ('cost' in summary or 'substitute' in summary):
                        raise ValidationError(f'{path} area {identifier} range {prefix}: no-advertise excludes cost and substitute')
        for prefix, summary in lookup(settings, ('summary-address',), {}).items():
            # The suppress form has no tag operand in native OSPFv2 syntax.
            if 'no-advertise' in summary and 'tag' in summary:
                raise ValidationError(f'{path} summary-address {prefix}: no-advertise excludes tag')
        for name, interface in lookup(settings, ('interface',), {}).items():
            configured = lookup(configuration, ('interfaces', name), {})
            assigned_vrf = lookup(configured, ('vrf',), 'default')
            # A configured interface cannot participate in another VRF's OSPF process.
            if configured and assigned_vrf != vrf:
                raise ValidationError(f'{path} interface {name}: interface belongs to VRF {assigned_vrf}')
            verify_interface(interface, policies, f'{path} interface {name}')


def generate(configuration, context):
    text = render('frr/ospf.conf.j2', {'configuration': configuration, 'version': 2})
    return frr_ospf.ipv4.desired(text)


def apply(generated, context):
    frr_reload.manager.apply('ospf', generated, context.state_directory,
                            adapter=frr_ospf.ipv4, daemons=('zebra', 'ospfd'), recovery=context.recovery)
