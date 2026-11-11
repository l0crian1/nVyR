"""IS-IS native readback, reload and removal using disposable FRR daemons.

Default and named-VRF processes share a stable pair of interfaces for all cases.
Options that change packet formats/authentication are tested independently; these
must not run against a router carrying unrelated IS-IS configuration.
"""

from contextlib import ExitStack
from copy import deepcopy
import os
import json
from pathlib import Path
import subprocess

import pytest

from nvyr.config_scripts import protocols_isis
from nvyr.helpers import frr_isis
from nvyr.helpers.frr_reload import Manager
from smoketests.support import wait_for

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_ISIS_NATIVE') != '1',
                                reason='requires disposable FRR daemons')


def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True).stdout


@pytest.fixture(scope='module')
def native(tmp_path_factory):
    assert Path('/.dockerenv').exists()
    with ExitStack() as cleanup:
        run('ip', 'link', 'add', 'ISISBLUE', 'type', 'vrf', 'table', '507')
        cleanup.callback(run, 'ip', 'link', 'del', 'ISISBLUE')
        run('ip', 'link', 'set', 'ISISBLUE', 'up')
        for number in (0, 1):
            name = f'isisnative{number}'
            run('ip', 'link', 'add', name, 'type', 'dummy')
            cleanup.callback(run, 'ip', 'link', 'del', name)
            if number == 1:
                run('ip', 'link', 'set', name, 'master', 'ISISBLUE')
            run('ip', 'link', 'set', name, 'up')
        manager = Manager()
        state = tmp_path_factory.mktemp('isis-native')
        before = manager.snapshot()
        scopes = ['router isis nvyr', 'router isis nvyr vrf ISISBLUE',
                  'interface isisnative0', 'interface isisnative1']
        cleanup.callback(manager.apply, 'isis', frr_isis.adapter.select(before, scopes),
                         state, adapter=frr_isis.adapter, recovery=True)
        yield manager, state


def apply(native, extra=None, interface=None):
    manager, state = native
    instances = {}
    for vrf, number in [('default', 0), ('ISISBLUE', 1)]:
        settings = {'net': [f'49.0001.0000.0000.000{number+1}.00'], **deepcopy(extra or {})}
        settings['interface'] = {f'isisnative{number}': {'address-family': ['ipv4-unicast', 'ipv6-unicast'], **deepcopy(interface or {})}}
        instances[vrf] = settings
    desired = protocols_isis.generate({'instances': instances}, None)
    manager.apply('isis', desired, state, adapter=frr_isis.adapter, daemons=('zebra', 'isisd'))
    assert frr_isis.adapter.select(manager.snapshot(), desired) == desired
    return desired


@pytest.mark.parametrize('extra', [
    {},
    {'options': {'level': 'level-1'}},
    {'options': {'level': 'level-2'}},
    {'options': {'metric-style': 'narrow'}},
    {'options': {'metric-style': 'transition'}},
    {'options': {'disable-dynamic-hostname': True, 'advertise-high-metrics': True, 'advertise-passive-only': True,
                'overload': {'administrative': True, 'on-startup': '15'}, 'attached-bit': {'send': True, 'ignore': True},
                'purge-originator': True, 'lsp-mtu': '1400', 'log-adjacency-changes': True, 'log-pdu-drops': True}},
    {'level': {'level-1': {'authentication': {'mode': 'plaintext', 'password': 'native', 'snp': 'send-only'}},
              'level-2': {'authentication': {'mode': 'md5', 'password': 'native2', 'snp': 'validate'}}}},
    {'level': {'level-1': {'timers': {'lsp-generation': '15', 'lsp-refresh': '500', 'lsp-lifetime': '900', 'spf-interval': '2'}},
              'level-2': {'timers': {'lsp-generation': '20', 'lsp-refresh': '600', 'lsp-lifetime': '1000', 'spf-interval': '3'}}}},
    {'spf': {'delay': {'initial': '50', 'short': '100', 'long': '500', 'hold-down': '1000', 'time-to-learn': '500'}}},
    {'topology': {'ipv6-unicast': {'overload': True}, 'ipv4-management': {}, 'ipv6-management': {}, 'ipv4-multicast': {}, 'ipv6-multicast': {}, 'ipv6-dstsrc': {}}},
    {'level': {'level-1': {'fast-reroute': {'priority-limit': 'high', 'disable-load-sharing': True, 'tiebreaker': {'1': {'type': 'downstream'}, '2': {'type': 'lowest-backup-metric'}}}}}},
    {'address-family': {af: {'level': {'level-2': {'default-originate': {'always': True, 'metric': '20'}, 'redistribute': {'connected': {'metric': '10'}, 'static': {}, 'local': {}, 'table': {'500': {'metric': '30'}}}}}} for af in ['ipv4-unicast', 'ipv6-unicast']}},
])
def test_process_options_and_removal(native, extra):
    apply(native, extra)
    apply(native)


@pytest.mark.parametrize('interface', [
    {'passive': {}}, {'passive': {'disable': True}},
    {'network': 'point-to-point'}, {'network': 'broadcast'},
    {'circuit-type': 'level-1'}, {'circuit-type': 'level-2'},
    {'authentication': {'mode': 'plaintext', 'password': 'native'}},
    {'authentication': {'mode': 'md5', 'password': 'native'}},
    {'hello-padding': 'disabled', 'disable-three-way-handshake': True},
    {'hello-padding': 'during-adjacency-formation'},
    {'level': {'level-1': {'metric': '25', 'priority': '40', 'timers': {'hello-interval': '5', 'hello-multiplier': '4', 'csnp-interval': '15', 'psnp-interval': '3'}},
              'level-2': {'metric': '30', 'priority': '45', 'timers': {'hello-interval': '6', 'hello-multiplier': '5', 'csnp-interval': '16', 'psnp-interval': '4'}}}},
    {'level': {'level-2': {'fast-reroute': {'lfa': {'exclude-interface': ['lo']}}}}},
])
def test_interface_options_and_removal(native, interface):
    apply(native, interface=interface)
    apply(native)


def test_process_deletion_and_recreation(native):
    apply(native)
    manager, state = native
    manager.apply('isis', {}, state, adapter=frr_isis.adapter)
    assert not frr_isis.adapter.desired(manager.snapshot())
    apply(native)


def test_table_redistribution_edit_and_last_entry_removal(native):
    for metric in ('20', '30', '0'):
        apply(native, {'address-family': {
            family: {'level': {'level-2': {'redistribute': {'table': {'500': {'metric': metric}, '501': {}}}}}}
            for family in ('ipv4-unicast', 'ipv6-unicast')
        }})
    apply(native)
    # Hidden empty table parents previously survived readback and blocked this.
    apply(native, {'options': {'level': 'level-1'}})
    apply(native)


def test_policy_references_and_defaults(native):
    run('vtysh', '-c', 'configure terminal', '-c', 'route-map ISISNATIVE permit 10')
    try:
        for family in ('ipv4-unicast', 'ipv6-unicast'):
            apply(native, {'address-family': {family: {'level': {'level-2': {
                'default-originate': {'always': True, 'metric': '20', 'route-map': 'ISISNATIVE'},
                'redistribute': {'static': {'metric': '0', 'route-map': 'ISISNATIVE'}}
            }}}}})
        apply(native)
    finally:
        run('vtysh', '-c', 'configure terminal', '-c', 'no route-map ISISNATIVE')


@pytest.mark.parametrize('families', [['ipv4-unicast'], ['ipv6-unicast']])
def test_single_family_circuit(native, families):
    apply(native, interface={'address-family': families})
    apply(native)


def test_interface_topology_overrides(native):
    process = {'topology': {'ipv6-unicast': {}}}
    apply(native, process, {'topology': {'ipv6-unicast': {}}})
    apply(native, process, {'topology': {'ipv6-unicast': {'disable': True}}})
    apply(native)


def test_table_redistribution_runtime(native):
    """Table metric/map edits must change advertised routes, not just readback."""
    manager, state = native
    prefixes = [('ip', '-4', '198.19.240.0/24'), ('ipv6', '-6', '2001:db8:240::/64')]

    def configure(metric, policy=None, enabled=True):
        instances = {}
        for vrf, number in [('default', 2), ('ISISBLUE', 3)]:
            settings = {
                'net': [f'49.0001.0000.0000.000{number}.00'],
                'options': {'level': 'level-2'},
                'level': {'level-2': {'timers': {'lsp-generation': '1', 'spf-interval': '1'}}},
                'topology': {'ipv6-unicast': {}},
                'interface': {f'isisnative{number}': {
                    'address-family': ['ipv4-unicast', 'ipv6-unicast'], 'network': 'point-to-point',
                    'level': {'level-2': {'metric': '10', 'timers': {'hello-interval': '1'}}},
                }},
            }
            if vrf == 'default' and enabled:
                entry = {'metric': str(metric)}
                if policy:
                    entry['route-map'] = policy
                settings['address-family'] = {
                    family: {'level': {'level-2': {'redistribute': {'table': {'242': dict(entry)}}}}}
                    for family in ('ipv4-unicast', 'ipv6-unicast')
                }
            instances[vrf] = settings
        desired = protocols_isis.generate({'instances': instances}, None)
        manager.apply('isis', desired, state, adapter=frr_isis.adapter)

    def learned(family, prefix):
        return json.loads(run('vtysh', '-c', f'show {family} route vrf ISISBLUE {prefix} json'))

    with ExitStack() as cleanup:
        run('ip', 'link', 'add', 'isisnative2', 'type', 'veth', 'peer', 'name', 'isisnative3')
        cleanup.callback(run, 'ip', 'link', 'del', 'isisnative2')
        run('ip', 'link', 'set', 'isisnative3', 'master', 'ISISBLUE')
        for number, address in [(2, '192.0.2.1/30'), (3, '192.0.2.2/30')]:
            run('ip', 'address', 'add', address, 'dev', f'isisnative{number}')
            run('ip', 'link', 'set', f'isisnative{number}', 'up')
        for family, flag, prefix in prefixes:
            run('ip', flag, 'route', 'add', 'blackhole', prefix, 'table', '242')
            cleanup.callback(run, 'ip', flag, 'route', 'del', 'blackhole', prefix, 'table', '242')
            run('vtysh', '-c', 'configure terminal', '-c', f'{family} import-table 242')
            cleanup.callback(run, 'vtysh', '-c', 'configure terminal', '-c', f'no {family} import-table 242')
        run('vtysh', '-c', 'configure terminal', '-c', 'route-map ISISDENY deny 10')
        cleanup.callback(run, 'vtysh', '-c', 'configure terminal', '-c', 'no route-map ISISDENY')
        cleanup.callback(run, 'vtysh', '-c', 'configure terminal', '-c', 'no route-map ISISLATE')
        cleanup.callback(apply, native)

        # A commit can create the redistribution reference before its policy.
        # Creating, deleting and recreating that policy must refresh the pointer.
        configure(20, 'ISISLATE')
        for family, flag, prefix in prefixes:
            wait_for(lambda: learned(family, prefix), lambda routes: prefix not in routes,
                     description=f'{family} unresolved map excludes routes', timeout=10)
        for enabled in (True, False, True):
            command = 'route-map ISISLATE permit 10' if enabled else 'no route-map ISISLATE'
            run('vtysh', '-c', 'configure terminal', '-c', command)
            for family, flag, prefix in prefixes:
                wait_for(lambda: learned(family, prefix), lambda routes: (prefix in routes) == enabled,
                         description=f'{family} late policy present={enabled}', timeout=10)

        for metric in (20, 30):
            configure(metric)
            for family, flag, prefix in prefixes:
                wait_for(lambda: learned(family, prefix),
                         lambda routes: any(route.get('protocol') == 'isis' and route.get('metric') == metric + 10
                                            for route in routes.get(prefix, [])),
                         description=f'{family} table route with metric {metric}', timeout=20)
        configure(30, 'ISISDENY')
        for family, flag, prefix in prefixes:
            wait_for(lambda: learned(family, prefix), lambda routes: prefix not in routes,
                     description=f'{family} table route-map withdrawal', timeout=10)
        configure(40)
        for family, flag, prefix in prefixes:
            wait_for(lambda: learned(family, prefix), lambda routes: prefix in routes,
                     description=f'{family} table route restored', timeout=10)
        configure(40, enabled=False)
        for family, flag, prefix in prefixes:
            wait_for(lambda: learned(family, prefix), lambda routes: prefix not in routes,
                     description=f'{family} table removal withdrawal', timeout=10)


def test_level_change_with_origination(native):
    for level in ('level-1', 'level-2', 'level-1'):
        apply(native, {'options': {'level': level}, 'address-family': {
            'ipv4-unicast': {'level': {level: {'default-originate': {'always': True},
                                              'redistribute': {'static': {}}}}}
        }})
    apply(native)
