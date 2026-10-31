"""Opt-in static reload tests against disposable FRR 10.7.1 daemons.

Run only in an isolated privileged container with zebra, mgmtd, staticd and bgpd.
"""

import json
import os
from pathlib import Path
import subprocess
import time

import pytest

from nvyr.config_scripts import protocols_static as static
from nvyr.config_scripts import policy
from nvyr.errors import RouterError
from nvyr.helpers.frr_reload import Manager
from nvyr.helpers.frr_static import adapter
from nvyr.helpers.frr_policy import adapter as policy_adapter

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_RELOAD_TEST') != '1',
                                reason='requires disposable FRR daemons')


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def wait_for(predicate):
    deadline = time.monotonic() + 10
    while not predicate():
        assert time.monotonic() < deadline, 'FRR/kernel state did not converge'
        time.sleep(0.05)


@pytest.fixture
def native(tmp_path):
    assert Path('/.dockerenv').exists(), 'native tests must not run on a shared router'
    manager = Manager()
    state = tmp_path / 'state'
    before = adapter.select(manager.snapshot(), ['default', 'RELOADBLUE', 'RELOADRED'])
    run('ip', 'link', 'add', 'RELOADBLUE', 'type', 'vrf', 'table', '501')
    run('ip', 'link', 'add', 'RELOADRED', 'type', 'vrf', 'table', '502')
    run('ip', 'link', 'add', 'reload0', 'type', 'dummy')
    run('ip', 'link', 'set', 'reload0', 'up')
    yield manager, state
    manager.apply('static', before, state, adapter=adapter, recovery=True)
    run('ip', 'link', 'del', 'reload0')
    run('ip', 'link', 'del', 'RELOADBLUE')
    run('ip', 'link', 'del', 'RELOADRED')


def apply(native, configuration):
    manager, state = native
    desired = static.generate(configuration, None)
    manager.apply('static', desired, state, adapter=adapter, daemons=('staticd', 'zebra'))
    assert adapter.select(manager.snapshot(), desired) == desired
    return desired


def test_native_ipv4_all_path_attributes_and_changes(native):
    """Round-trip every IPv4 path attribute, multipath and fallback preference."""
    configuration = {'default': {'route': {'192.0.2.0/24': {
        'next-hop': {
            '198.51.100.1': {'interface': 'reload0', 'distance': '10', 'metric': '50',
                           'tag': '123', 'weight': '20', 'onlink': {}},
            '198.51.100.2': {'distance': '11', 'weight': '30'},
        },
        'interface': {'reload0': {'distance': '12', 'metric': '51', 'tag': '124', 'weight': '31'}},
        'blackhole': {'distance': '254', 'metric': '100', 'tag': '456'},
    }}}}
    apply(native, configuration)
    configuration['default']['route']['192.0.2.0/24']['next-hop']['198.51.100.1'] = {'interface': 'reload0'}
    apply(native, configuration)
    apply(native, {'default': {}})


def test_native_ipv6_source_specific_and_cross_family_gateway(native):
    """Preserve source-specific IPv6, link-local gateways and IPv4-over-IPv6."""
    apply(native, {'default': {
        'route': {'192.0.2.0/24': {'next-hop': {'fe80::1': {'interface': 'reload0', 'onlink': {}}}}},
        'route6': {'2001:db8:100::/64': {
            'next-hop': {'2001:db8::1': {'interface': 'reload0', 'weight': '12', 'metric': '4'}},
            'source-specific': {'from': {
                '2001:db8:200::/64': {'reject': {'distance': '11', 'tag': '123'}},
                '2001:db8:300::/64': {'interface': {'reload0': {'distance': '12'}}},
            }},
        }},
    }})


def test_native_vrf_routes_leaking_and_deletion(native):
    """Deleting a VRF's routes retains the protocol instance and other VRFs."""
    routes = {'route': {'192.0.2.0/24': {'next-hop': {
        '198.51.100.1': {'vrf': 'default', 'interface': 'reload0', 'onlink': {}},
    }}}}
    desired = apply(native, {'default': {}, 'RELOADBLUE': routes, 'RELOADRED': routes})
    apply(native, {'default': {}, 'RELOADRED': routes})
    manager, _ = native
    assert adapter.select(manager.snapshot(), ['RELOADBLUE']) == {'RELOADBLUE': []}
    assert adapter.select(manager.snapshot(), ['RELOADRED'])['RELOADRED'] == desired['RELOADRED']
    apply(native, {'default': {}, 'RELOADBLUE': routes, 'RELOADRED': routes})


def test_native_repeated_last_route_removal_does_not_disconnect_staticd(native):
    """Exercise the old last-instance crash path through native CLI deletion."""
    configuration = {'RELOADBLUE': {'route': {
        '192.0.2.0/24': {'blackhole': {}}, '198.51.100.0/24': {'blackhole': {}},
    }}}
    pid = Path('/run/frr/staticd.pid').read_text()
    for _ in range(3):
        apply(native, configuration)
        apply(native, {'RELOADBLUE': {}})
        output = run('vtysh', '-c', 'show mgmt backend-adapter all')
        assert 'staticd' in output
        assert Path('/run/frr/staticd.pid').read_text() == pid
    datastore = json.loads(run('vtysh', '-c', 'show mgmt datastore-contents running json'))
    protocols = datastore['frr-routing:routing']['control-plane-protocols']['control-plane-protocol']
    blue = next(item for item in protocols if item['vrf'] == 'RELOADBLUE')
    assert not blue.get('frr-staticd:staticd', {}).get('route-list')


def test_native_disabled_prefix_and_individual_paths(native):
    """Disabling withdraws routes and re-enabling restores the same commands."""
    route = {'blackhole': {}, 'next-hop': {'fe80::1': {'disable': {}}}}
    configuration = {'default': {'route': {'192.0.2.0/24': route}}}
    desired = apply(native, configuration)
    route['disable'] = {}
    assert apply(native, configuration) == {'default': []}
    del route['disable']
    assert apply(native, configuration) == desired


def test_native_backend_rejection_discards_candidate_and_restores_before_image(native):
    """Backend rejection must not leave staged state that poisons the next commit."""
    manager, state = native
    before = apply(native, {'default': {'route': {'192.0.2.0/24': {'blackhole': {}}}}})
    reload = manager.reload
    observed = []

    def observe_failure(target):
        try:
            reload(target)
        except RouterError:
            observed.append(json.loads(run('vtysh', '-c', 'show mgmt datastore-contents candidate json')))
            raise

    manager.reload = observe_failure
    with pytest.raises(RouterError, match='previous configuration restored'):
        manager.apply('static', {
            'default': ['ip route 198.51.100.0/24 blackhole'],
            # Valid CLI grammar, but the backend rejects explicit tables in a
            # device-based VRF. FRR can retain the rejected candidate afterward.
            'RELOADBLUE': ['ip route 203.0.113.0/24 blackhole table 999'],
        }, state, adapter=adapter)
    assert adapter.select(manager.snapshot(), ['default']) == before
    running = json.loads(run('vtysh', '-c', 'show mgmt datastore-contents running json'))
    assert observed and observed[0] != running
    assert json.loads(run('vtysh', '-c', 'show mgmt datastore-contents candidate json')) == running
    apply(native, {'default': {'route': {'198.51.100.0/24': {'reject': {}}}}})


def test_native_lost_success_response_restores_previous_configuration(native):
    """An uncertain subprocess response triggers verified reconciliation back."""
    manager, state = native
    before = apply(native, {'default': {}})
    reload = manager.reload

    def lose_reply(target):
        manager.reload = reload
        reload(target)
        raise ConnectionError('lost successful reload reply')

    manager.reload = lose_reply
    with pytest.raises(RouterError, match='previous configuration restored'):
        manager.apply('static', {'default': ['ip route 192.0.2.0/24 reject']}, state, adapter=adapter)
    assert adapter.select(manager.snapshot(), ['default']) == before


def test_native_policy_destinations_survive_static_reload(native, tmp_path):
    """Keep generic and BGP policies while reloading routes."""
    policies = Manager()
    empty = policy.generate({}, None)
    desired = policy.generate({'route-map': {'RELOAD_KEEP': {'rule': {'10': {
        'action': 'permit', 'set': {'metric': '50', 'local-preference': '200'},
    }}}}}, None)
    policies.apply('policy', desired, tmp_path / 'policy', adapter=policy_adapter)
    try:
        before = run('vtysh', '-c', 'show route-map RELOAD_KEEP')
        apply(native, {'default': {'route': {'192.0.2.0/24': {'blackhole': {}}}}})
        apply(native, {'default': {}})
        assert run('vtysh', '-c', 'show route-map RELOAD_KEEP') == before
    finally:
        policies.apply('policy', empty, tmp_path / 'policy', adapter=policy_adapter, recovery=True)


def test_native_reload_does_not_write_saved_frr_config(native):
    """Runtime commits must not change FRR's boot file or invoke write memory."""
    path = Path('/etc/frr/frr.conf')
    before = path.read_bytes()
    apply(native, {'default': {'route6': {'2001:db8::/64': {'reject': {}}}}})
    assert path.read_bytes() == before


def test_native_ipv4_rib_and_kernel_routes(native):
    """A successful CLI reload must actually install and withdraw IPv4 routes."""
    apply(native, {'default': {'route': {'192.0.2.0/24': {'blackhole': {}}}}})
    wait_for(lambda: '192.0.2.0/24' in json.loads(run('vtysh', '-c', 'show ip route static json')))
    wait_for(lambda: any(item.get('dst') == '192.0.2.0/24' and item.get('type') == 'blackhole'
                         for item in json.loads(run('ip', '-j', 'route', 'show', '192.0.2.0/24'))))
    apply(native, {'default': {}})
    wait_for(lambda: not json.loads(run('ip', '-j', 'route', 'show', '192.0.2.0/24')))


def test_native_ipv6_rib_and_kernel_routes(native):
    """Verify IPv6 rejection in both FRR and the actual kernel forwarding table."""
    apply(native, {'default': {'route6': {'2001:db8::/64': {'reject': {}}}}})
    wait_for(lambda: '2001:db8::/64' in json.loads(run('vtysh', '-c', 'show ipv6 route static json')))
    wait_for(lambda: any(item.get('dst') == '2001:db8::/64' and item.get('type') == 'unreachable'
                         for item in json.loads(run('ip', '-6', '-j', 'route', 'show', '2001:db8::/64'))))
    apply(native, {'default': {}})
    wait_for(lambda: not json.loads(run('ip', '-6', '-j', 'route', 'show', '2001:db8::/64')))


def test_native_vrf_kernel_table_isolation(native):
    """Identical prefixes remain separate in the two Linux VRF routing tables."""
    apply(native, {
        'RELOADBLUE': {'route': {'192.0.2.0/24': {'blackhole': {}}}},
        'RELOADRED': {'route': {'192.0.2.0/24': {'reject': {}}}},
    })
    wait_for(lambda: any(item.get('type') == 'blackhole' for item in
                         json.loads(run('ip', '-j', 'route', 'show', 'table', '501'))))
    wait_for(lambda: any(item.get('type') == 'unreachable' for item in
                         json.loads(run('ip', '-j', 'route', 'show', 'table', '502'))))
    apply(native, {'RELOADRED': {'route': {'192.0.2.0/24': {'reject': {}}}}})
    wait_for(lambda: not json.loads(run('ip', '-j', 'route', 'show', 'table', '501')))
    assert any(item.get('type') == 'unreachable' for item in
               json.loads(run('ip', '-j', 'route', 'show', 'table', '502')))
