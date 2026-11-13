"""MPLS forwarding: kernel controls in netlinkd and native label routes in FRR."""

import ipaddress

from nvyr.errors import ValidationError
from nvyr.helpers import frr_mpls, frr_reload, interfaces
from nvyr.helpers.template import render
from nvyr.tree import lookup


def get_config(context):
    return lookup(context.effective, ('protocols', 'mpls'), None)


def verify(configuration, context):
    if configuration is None:
        return

    labels = set()
    for label, settings in lookup(configuration, ('lsp',), {}).items():
        value = int(label)
        path = f'protocols mpls lsp {label}'
        # Numeric aliases must not configure the same native incoming label twice.
        if value in labels:
            raise ValidationError(f'{path}: duplicate incoming label')
        labels.add(value)
        hops = lookup(settings, ('next-hop',), {})
        # A static label without a forwarding action cannot be installed.
        if not hops:
            raise ValidationError(f'{path}: at least one next-hop is required')
        addresses = set()
        for address, hop in hops.items():
            parsed = ipaddress.ip_address(address)
            # Canonical IPv6 aliases identify the same FRR next hop.
            if parsed in addresses:
                raise ValidationError(f'{path}: duplicate next-hop address {address}')
            addresses.add(parsed)
            # FRR's static LSP grammar has no interface scope for a link-local gateway.
            if parsed.version == 6 and parsed.is_link_local:
                raise ValidationError(f'{path}: link-local next hops require an interface scope unsupported by FRR static LSPs')
            # Each next hop needs a swap or pop operation.
            if 'outgoing-label' not in hop:
                raise ValidationError(f'{path} next-hop {address}: outgoing-label is required')


def generate(configuration, context):
    kernel = {'interfaces': [], 'label-table-size': 0, 'ip-ttl-propagate': 1, 'default-ttl': 255}
    if configuration is not None:
        kernel = {'interfaces': sorted(lookup(configuration, ('interface',), ())),
                  'label-table-size': 1048575,
                  'ip-ttl-propagate': int('disable-ttl-propagation' not in configuration),
                  'default-ttl': int(configuration['default-ttl'])}
    text = render('frr/mpls.conf.j2', {'configuration': configuration})
    return {'kernel': kernel, 'frr': frr_mpls.adapter.select(text, ('global',))}


def apply(generated, context):
    interfaces.manager.request('replace-mpls', values=generated['kernel'])
    frr_reload.manager.apply('mpls', generated['frr'], context.state_directory,
                             adapter=frr_mpls.adapter, daemons=('zebra',), recovery=context.recovery)
