"""Instance parameter rendering and FRR 10.7.1 traditional-profile defaults."""

from nvyr.tree import lookup


# CLI path, native command, native default, nVyR default.
SWITCHES = (
    ('allow-martian-nexthop', 'allow-martian-nexthop', False, False),
    ('client-to-client reflection', 'client-to-client reflection', True, True),
    ('ebgp-connected-route-check', 'disable-ebgp-connected-route-check', False, True),
    ('ebgp-requires-policy', 'ebgp-requires-policy', True, False),
    ('enforce-first-as', 'enforce-first-as', True, True),
    ('fast-convergence', 'fast-convergence', False, False),
    ('fast-external-failover', 'fast-external-failover', True, True),
    ('graceful-shutdown', 'graceful-shutdown', False, False),
    ('hard-administrative-reset', 'hard-administrative-reset', True, True),
    ('ipv6-auto-ra', 'ipv6-auto-ra', True, True),
    ('log-neighbor-changes', 'log-neighbor-changes', False, False),
    ('reject-as-sets', 'reject-as-sets', True, False),
    ('shutdown', 'shutdown', False, False),
    ('suppress-duplicates', 'suppress-duplicates', True, True),
    ('default ipv4-unicast', 'default ipv4-unicast', True, False),
    ('default ipv6-unicast', 'default ipv6-unicast', False, False),
    ('default show-hostname', 'default show-hostname', False, False),
    ('default show-nexthop-hostname', 'default show-nexthop-hostname', False, False),
    ('default dynamic-capability', 'default dynamic-capability', False, False),
    ('default link-local-capability', 'default link-local-capability', False, False),
    ('default shutdown', 'default shutdown', False, False),
    ('network import-check', 'network import-check', True, False),
    ('route-reflector allow-outbound-policy', 'route-reflector allow-outbound-policy', False, False),
    ('bestpath aigp', 'bestpath aigp', False, False),
    ('bestpath compare-routerid', 'bestpath compare-routerid', False, False),
    ('bestpath as-path ignore', 'bestpath as-path ignore', False, False),
    ('bestpath as-path confed', 'bestpath as-path confed', False, False),
    ('bestpath peer-type multipath-relax', 'bestpath peer-type multipath-relax', False, False),
    ('graceful-restart notification', 'graceful-restart notification', True, True),
    ('graceful-restart preserve-fw-state', 'graceful-restart preserve-fw-state', False, False),
    ('graceful-restart end-of-rib', 'graceful-restart disable-eor', False, True),
)

INVERTED = {'ebgp-connected-route-check', 'graceful-restart end-of-rib'}

# Scalar defaults that FRR suppresses from its configuration writer.
NUMBERS = {
    'conditional-advertisement timer': 60,
    'default local-preference': 100,
    'default subgroup-pkt-queue-max': 40,
    'graceful-restart restart-time': 120,
    'graceful-restart stalepath-time': 360,
    'graceful-restart select-defer-time': 120,
    'graceful-restart rib-stale-time': 500,
    'long-lived-graceful-restart stale-time': 0,
    'listen limit': 100,
    'minimum-holdtime': 0,
}


def enabled(parameters, path, default=False):
    return lookup(parameters, tuple(path.split()), 'enable' if default else 'disable') == 'enable'


def commands(parameters):
    """Render explicit switch states; normalization accounts for omitted native defaults."""
    result = []
    for path, native, _, default in SWITCHES:
        state = enabled(parameters, path, default)
        if path in INVERTED:
            state = not state
        result.append(('bgp ' if state else 'no bgp ') + native)

    for path, default in NUMBERS.items():
        value = lookup(parameters, tuple(path.split()), default)
        if int(value) != default:
            result.append(f'bgp {path} {int(value)}')

    for name in ('router-id', 'cluster-id'):
        if name in parameters:
            result.append(f'bgp {name} {parameters[name]}')

    confederation = parameters.get('confederation', {})
    if 'identifier' in confederation:
        result.append(f'bgp confederation identifier {int(confederation["identifier"])}')
    if confederation.get('peers'):
        peers = ' '.join(str(value) for value in sorted({int(value) for value in confederation['peers']}))
        result.append('bgp confederation peers ' + peers)

    restart = parameters.get('graceful-restart', {}).get('mode', 'helper')
    if restart == 'restart':
        result.append('bgp graceful-restart')
    elif restart == 'disable':
        result.append('bgp graceful-restart-disable')

    software = parameters.get('default', {}).get('software-version-capability', 'disable')
    if software != 'disable':
        result.append('bgp default software-version-capability')

    bestpath = parameters.get('bestpath', {})
    as_path = bestpath.get('as-path', {})
    if enabled(as_path, 'multipath-relax'):
        suffix = ' as-set' if enabled(as_path, 'multipath-relax-as-set') else ''
        result.append('bgp bestpath as-path multipath-relax' + suffix)
    med = bestpath.get('med', {})
    comparisons = [name for name in ('confed', 'missing-as-worst') if enabled(med, name)]
    if comparisons:
        result.append('bgp bestpath med ' + ' '.join(comparisons))
    bandwidth = bestpath.get('bandwidth', 'ecmp')
    if bandwidth != 'ecmp':
        result.append('bgp bestpath bandwidth ' + bandwidth)

    maxmed = parameters.get('max-med', {})
    if 'administrative' in maxmed:
        value = int(maxmed['administrative'])
        suffix = '' if value == 4294967294 else ' ' + str(value)
        result.append('bgp max-med administrative' + suffix)
    startup = maxmed.get('on-startup', {})
    if startup:
        value = int(startup.get('med', 4294967294))
        suffix = '' if value == 4294967294 else ' ' + str(value)
        result.append(f'bgp max-med on-startup {int(startup["time"])}' + suffix)

    if enabled(parameters, 'suppress-fib-pending'):
        delay = int(parameters.get('suppress-fib-pending-delay', 1000))
        suffix = '' if delay == 1000 else ' ' + str(delay)
        result.append('bgp suppress-fib-pending' + suffix)

    keepalive = parameters.get('tcp-keepalive', {})
    if keepalive:
        values = [str(int(keepalive[key])) for key in ('idle', 'interval', 'probes')]
        result.append('bgp tcp-keepalive ' + ' '.join(values))
    return [' ' + line for line in result]


def normalize(lines):
    """Remove only verified native defaults, preserving explicit non-default negations."""
    for _, native, default, _ in SWITCHES:
        prefix = 'bgp ' if default else 'no bgp '
        lines.discard(prefix + native)
    for path, default in NUMBERS.items():
        lines.discard(f'bgp {path} {default}')


def families(parameters, options):
    """Include implicit family activation when verifying and rendering a peer."""
    result = dict(options.get('address-family', {}))
    for family in ('ipv4-unicast', 'ipv6-unicast'):
        if enabled(parameters, 'default ' + family):
            result.setdefault(family, {})
    return result


def dampening_command(parameters):
    values = parameters.get('dampening', {})
    if not enabled(values, 'state'):
        return None
    defaults = (15, 750, 2000, 60)
    keys = ('half-life', 'reuse', 'suppress', 'max-suppress-time')
    numbers = tuple(int(values.get(key, default)) for key, default in zip(keys, defaults))
    suffix = '' if numbers == defaults else ' ' + ' '.join(str(number) for number in numbers)
    return '  bgp dampening' + suffix
