"""Native MPLS/static label configuration and deletion in private FRR processes.

The shared fixture creates one isolated namespace for this module. Packet and
MTU checks belong to the shared routed functional suite, not these round trips.
"""

import os
import json

import pytest

from nvyr.config_scripts import protocols_mpls, protocols_static
from nvyr.helpers import frr_mpls, frr_static
from tests.test_bgp_lu_native import native
from smoketests.support import wait_for


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_LU_NATIVE') != '1', reason='requires disposable FRR')


def settings(**extra):
    return {'default-ttl': '255', **extra}


def apply(native, configuration):
    manager, state = native
    manager.run(['sysctl', '-qw', 'net.mpls.platform_labels=1048575'])
    desired = protocols_mpls.generate(configuration, None)['frr']
    manager.apply('mpls', desired, state, adapter=frr_mpls.adapter, daemons=('zebra',))
    assert frr_mpls.adapter.select(manager.snapshot(), desired) == desired


def test_mpls_controls_changes_and_removal(native):
    configuration = settings(fec={'nexthop-resolution': {}}, lsp={
        '16000': {'next-hop': {'192.0.2.2': {'outgoing-label': '17000'}}},
        '16001': {'next-hop': {'192.0.2.2': {'outgoing-label': 'implicit-null'}}},
        '16002': {'next-hop': {'2001:db8::2': {'outgoing-label': 'explicit-null'}}}})
    apply(native, configuration)
    configuration['lsp']['16000']['next-hop']['192.0.2.2']['outgoing-label'] = '18000'
    apply(native, configuration)
    apply(native, None)


def test_ldp_first_allocation_respects_fixed_startup_block(native):
    manager, state = native
    data = json.loads(manager.run(['vtysh', '-c', 'show debugging label-table json']))
    assert data['dynamicBlock'] == {'lowerBound': 100000, 'upperBound': 1048574}
    chunks = [chunk for chunk in data['chunks'] if chunk['protocol'] == 'ldp']
    assert chunks
    assert all(100000 <= chunk['start'] <= chunk['end'] <= 1048574 for chunk in chunks)


@pytest.mark.parametrize('family,prefix,hop', [
    ('route', '198.51.100.0/24', '192.0.2.2'),
    ('route6', '2001:db8:100::/64', '2001:db8::2'),
])
def test_static_label_stack_readback_and_removal(native, family, prefix, hop):
    manager, state = native
    configuration = {'default': {family: {prefix: {'next-hop': {hop: {'label': '17000/18000'}}}}}}
    for stack in ('17000/18000', '19000', None):
        entry = configuration['default'][family][prefix]['next-hop'][hop]
        if stack is None:
            entry.pop('label')
        else:
            entry['label'] = stack
        desired = protocols_static.generate(configuration, None)
        manager.apply('static', desired, state, adapter=frr_static.adapter, daemons=('staticd', 'zebra'))
        assert frr_static.adapter.select(manager.snapshot(), desired) == desired
    manager.apply('static', {'default': []}, state, adapter=frr_static.adapter, daemons=('staticd', 'zebra'))


@pytest.mark.parametrize('family,prefix,hop', [
    ('route', '198.51.100.0/24', '192.0.2.2'),
    ('route6', '2001:db8:100::/64', '2001:db8::2'),
])
def test_label_stack_with_other_path_options(native, family, prefix, hop):
    manager, state = native
    path = {'label': '17000/18000', 'interface': 'dum31', 'tag': '15', 'distance': '20',
            'metric': '30', 'weight': '2', 'onlink': {}}
    desired = protocols_static.generate({'default': {family: {prefix: {'next-hop': {hop: path}}}}}, None)
    manager.apply('static', desired, state, adapter=frr_static.adapter, daemons=('staticd', 'zebra'))
    assert frr_static.adapter.select(manager.snapshot(), desired) == desired
    manager.apply('static', {'default': []}, state, adapter=frr_static.adapter, daemons=('staticd', 'zebra'))


def test_static_ipv6_lsp_survives_more_specific_nexthop_route(native):
    manager, _ = native
    interface = 'mplscheck0'
    address = '2001:db8:32::1/64'
    host = '2001:db8:32::2/128'
    manager.run(['ip', 'link', 'add', interface, 'type', 'dummy'])
    try:
        manager.run(['ip', 'link', 'set', interface, 'up'])
        manager.run(['ip', 'address', 'add', address, 'dev', interface, 'nodad'])
        apply(native, settings(lsp={'16032': {'next-hop': {'2001:db8:32::2': {'outgoing-label': '17032'}}}}))

        def installed():
            return json.loads(manager.run(['ip', '-j', '-f', 'mpls', 'route', 'show']))

        def has_label(routes):
            return any(str(route.get('dst')) == '16032' for route in routes)

        wait_for(installed, has_label, description='static IPv6 LSP through connected subnet')
        # OSPFv3 advertises adjacent interface /128s via their link-local next hop.
        # A more-specific RIB entry must not hide the underlying connected /64.
        manager.run(['ip', '-6', 'route', 'add', host, 'via', 'fe80::2', 'dev', interface])
        wait_for(lambda: json.loads(manager.run(['vtysh', '-c', f'show ipv6 route {host} json'])),
                 lambda routes: any(route['protocol'] == 'kernel' for route in routes.get(host, [])),
                 description='more-specific next-hop route in Zebra')
        # Reapplying a changed label forces a fresh reachability evaluation.
        apply(native, settings(lsp={'16032': {'next-hop': {'2001:db8:32::2': {'outgoing-label': '17033'}}}}))
        wait_for(installed, lambda routes: any(str(route.get('dst')) == '16032' and str(route.get('to')) == '17033'
                                              for route in routes),
                 description='static LSP remains usable beneath more-specific route')
        manager.run(['ip', '-6', 'route', 'del', host])
        wait_for(installed, has_label, description='static LSP after host-route withdrawal')
        manager.run(['ip', 'address', 'del', address, 'dev', interface])
        wait_for(installed, lambda routes: not has_label(routes),
                 description='static LSP withdrawn when connected subnet disappears')
    finally:
        apply(native, None)
        manager.run(['ip', 'link', 'del', interface])
