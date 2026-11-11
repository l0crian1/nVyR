"""IS-IS configuration through the shared FRR transaction."""

from nvyr.errors import ValidationError
from nvyr.helpers import frr_isis, frr_reload, interfaces
from nvyr.helpers.template import render
from nvyr.helpers.verification import require_fields
from nvyr.tree import lookup


def get_config(context):
    instances = {}
    default = lookup(context.effective, ('protocols', 'isis'), None)
    if default is not None:
        instances['default'] = default
    for vrf in lookup(context.scripts, ('isis', 'vrf'), ()):
        if vrf != 'default':
            settings = lookup(context.effective, ('vrf', 'name', vrf, 'protocols', 'isis'), None)
            if settings is not None:
                instances[vrf] = settings
    return {'instances': instances, 'policies': lookup(context.effective, ('policy',), {}),
            'interfaces': dict(interfaces.configured(context.effective))}


def verify_authentication(settings, path):
    authentication = lookup(settings, ('authentication',), None)
    # Both the wire format and the secret are required to configure authentication.
    if authentication is not None:
        require_fields(authentication, ('mode', 'password'), path + ' authentication')


def verify(configuration, context):
    assigned = {}
    policies = configuration['policies']
    for vrf, settings in configuration['instances'].items():
        path = 'protocols isis' if vrf == 'default' else f'vrf name {vrf} protocols isis'
        nets = lookup(settings, ('net',), ())
        # An operational IS-IS instance needs a NET; all area addresses share its system ID.
        if not nets or len({value.replace('.', '').lower()[-14:-2] for value in nets}) != 1:
            raise ValidationError(f'{path}: configure NET addresses with one consistent system ID')
        # FRR's NET list supports at most three area addresses per instance.
        if len(nets) > 3:
            raise ValidationError(f'{path}: at most three NET addresses are supported')

        options = lookup(settings, ('options',), {})
        metric_style = lookup(options, ('metric-style',), 'wide')
        process_level = lookup(options, ('level',), 'level-1-2')
        references = []
        for level, values in lookup(settings, ('level',), {}).items():
            verify_authentication(values, f'{path} level {level}')
            timers = lookup(values, ('timers',), {})
            generation = int(lookup(timers, ('lsp-generation',), '30'))
            refresh = int(lookup(timers, ('lsp-refresh',), '900'))
            lifetime = int(lookup(timers, ('lsp-lifetime',), '1200'))
            # FRR requires refresh after generation and a 300-second expiry margin.
            if refresh <= generation or refresh > lifetime - 300:
                raise ValidationError(f'{path} level {level}: LSP refresh must exceed generation and be at least 300 seconds below lifetime')
            for index, rule in lookup(values, ('fast-reroute', 'tiebreaker'), {}).items():
                # A tiebreaker index without a criterion has no native meaning.
                require_fields(rule, ('type',), f'{path} level {level} fast-reroute tiebreaker {index}')

        delay = lookup(settings, ('spf', 'delay'), None)
        # The native IETF backoff command takes all five timer operands together.
        if delay is not None:
            require_fields(delay, ('initial', 'short', 'long', 'hold-down', 'time-to-learn'), path + ' spf delay')
        for priority, values in lookup(settings, ('spf', 'prefix-priority'), {}).items():
            # Prefix priority requires an IPv4 ACL reference, including when it is created in this commit.
            require_fields(values, ('access-list',), f'{path} spf prefix-priority {priority}')
            if values['access-list'] not in lookup(policies, ('access-list', 'ipv4'), {}):
                raise ValidationError(f'{path}: IPv4 access-list {values["access-list"]!r} is not configured')

        # Multi-topology reachability is encoded in extended TLVs, not narrow metrics.
        if lookup(settings, ('topology',), {}) and metric_style != 'wide':
            raise ValidationError(f'{path}: additional topologies require wide metrics')
        for family in lookup(settings, ('address-family',), {}).values():
            for level, values in lookup(family, ('level',), {}).items():
                # FRR cannot originate or redistribute into a disabled routing level.
                if values and process_level not in ('level-1-2', level):
                    raise ValidationError(f'{path}: address-family {level} requires that routing level on the process')
                entries = [lookup(values, ('default-originate',), {})]
                for source, redistribution in lookup(values, ('redistribute',), {}).items():
                    entries.extend(redistribution.values() if source == 'table' else [redistribution])
                references.extend(entry['route-map'] for entry in entries if 'route-map' in entry)

        for name, values in lookup(settings, ('interface',), {}).items():
            where = f'{path} interface {name}'
            configured = lookup(configuration, ('interfaces', name), {})
            actual_vrf = lookup(configured, ('vrf',), 'default')
            # The circuit must belong to its routing instance, including across simultaneous VRFs.
            if (configured and actual_vrf != vrf) or (name in assigned and assigned[name] != vrf):
                raise ValidationError(f'{where}: interface belongs to another VRF')
            assigned[name] = vrf
            families = lookup(values, ('address-family',), ())
            # A circuit must explicitly carry at least one address family.
            if not families:
                raise ValidationError(f'{where}: select at least one address-family')
            # IPv6 routing requires IPv6 to be enabled on the participating interface.
            if 'ipv6-unicast' in families and 'disable' in lookup(configured, ('ipv6',), {}):
                raise ValidationError(f'{where}: IPv6 is disabled')
            verify_authentication(values, where)
            for level, per_level in lookup(values, ('level',), {}).items():
                # FRR restricts narrow metrics to the six-bit legacy metric field.
                if metric_style == 'narrow' and int(lookup(per_level, ('metric',), '10')) > 63:
                    raise ValidationError(f'{where} level {level}: narrow metrics cannot exceed 63')
            for topology, mode in lookup(values, ('topology',), {}).items():
                # Enabling an additional circuit topology requires the process to advertise it.
                if topology != 'standard' and 'disable' not in mode and topology not in lookup(settings, ('topology',), {}):
                    raise ValidationError(f'{where}: topology {topology} must also be configured on the IS-IS process')
        for name in references:
            # Redistribution and origination policies must resolve before FRR receives them.
            if name not in lookup(policies, ('route-map',), {}):
                raise ValidationError(f'{path}: route-map {name!r} is not configured')


def generate(configuration, context):
    return frr_isis.adapter.desired(render('frr/isis.conf.j2', {'configuration': configuration}))


def apply(generated, context):
    frr_reload.manager.apply('isis', generated, context.state_directory, adapter=frr_isis.adapter,
                             daemons=('zebra', 'isisd'), recovery=context.recovery)
