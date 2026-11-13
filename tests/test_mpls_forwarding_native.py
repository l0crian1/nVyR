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
