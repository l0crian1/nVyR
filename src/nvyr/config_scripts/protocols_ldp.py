"""LDP configuration, validated here and rendered into FRR's shared transaction."""

from nvyr.errors import ValidationError
from nvyr.helpers import frr_ldp, frr_reload, interfaces
from nvyr.helpers.template import render
from nvyr.tree import lookup


def get_config(context):
    return {'ldp': lookup(context.effective, ('protocols', 'ldp'), None),
            'mpls': lookup(context.effective, ('protocols', 'mpls'), None),
            'interfaces': dict(interfaces.configured(context.effective)),
            'policies': lookup(context.effective, ('policy',), {})}


def verify_access_lists(settings, policies, family, path):
    for key, value in settings.items():
        if key.endswith('access-list') or key == 'access-list':
            peer_filter = path.endswith('label local advertise') and key == 'to-access-list'
            peer_filter |= path.endswith('label remote accept') and key == 'from-access-list'
            selected_family = 'ipv4' if peer_filter else family
            # Peer policies match IPv4 LSR IDs; other policies match this AF's addresses.
            if value not in lookup(policies, ('access-list', selected_family), {}):
                raise ValidationError(f'{path} {key}: {value!r} is not a configured {selected_family} access-list')
        elif hasattr(value, 'items'):
            verify_access_lists(value, policies, family, path + ' ' + key)


def verify(configuration, context):
    settings = configuration['ldp']
    if settings is None:
        return

    # LDP installs labels into the kernel table managed by protocols mpls.
    if configuration['mpls'] is None:
        raise ValidationError('protocols ldp requires protocols mpls')

    for name, neighbor in lookup(settings, ('neighbor',), {}).items():
        security = lookup(neighbor, ('ttl-security',), {})
        # A disabled TTL check cannot simultaneously impose a hop limit.
        if 'disable' in security and 'hops' in security:
            raise ValidationError(f'protocols ldp neighbor {name}: ttl-security disable and hops are mutually exclusive')

    for family, values in lookup(settings, ('address-family',), {}).items():
        path = f'protocols ldp address-family {family}'
        verify_access_lists(values, configuration['policies'], family, path)
        allocation = lookup(values, ('label', 'local', 'allocate'), {})
        # FRR chooses either host routes or an ACL for allocation, not both.
        if 'host-routes' in allocation and 'access-list' in allocation:
            raise ValidationError(f'{path}: label allocation host-routes and access-list are mutually exclusive')

        for name in lookup(values, ('interface',), {}):
            # Discovery on a data-plane link must also enable labeled packet reception.
            if name not in lookup(configuration['mpls'], ('interface',), ()):
                raise ValidationError(f'{path} interface {name}: enable it under protocols mpls interface')
            interface = lookup(configuration['interfaces'], (name,), {})
            # This FRR version has one LDP instance in the default routing domain.
            if lookup(interface, ('vrf',), 'default') != 'default':
                raise ValidationError(f'{path} interface {name}: LDP requires the default VRF')
            # IPv6 discovery uses link-local multicast and cannot run with IPv6 disabled.
            if family == 'ipv6' and 'disable' in lookup(interface, ('ipv6',), {}):
                raise ValidationError(f'{path} interface {name}: IPv6 is disabled')


def generate(configuration, context):
    return frr_ldp.adapter.desired(render('frr/ldp.conf.j2', {'configuration': configuration}))


def apply(generated, context):
    frr_reload.manager.apply('ldp', generated, context.state_directory,
                             adapter=frr_ldp.adapter, daemons=('zebra', 'ldpd'), recovery=context.recovery)
