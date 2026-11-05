"""Opt-in RIP/RIPng readback and reload against disposable FRR 10.7.1.

One VRF, dummy link and veth pair are retained throughout the module. Authentication
modes, passive defaults and split-horizon variants change in place. Native packet
checks exercise the renderer independently of the full routed functional scenario.
"""

from copy import deepcopy
import os
from pathlib import Path
import subprocess

import pytest

from nvyr.config_scripts import protocols_rip, policy
from nvyr.helpers import frr_rip, frr_policy
from nvyr.helpers.frr_reload import Manager
from smoketests.support import wait_for

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_RIP_NATIVE') != '1',
                                reason='requires disposable FRR daemons')


def run(*arguments):
    return subprocess.run(arguments, capture_output=True, text=True, check=True).stdout


@pytest.fixture(scope='module')
def native(tmp_path_factory):
    assert Path('/.dockerenv').exists(), 'native tests must not run on a shared router'
    manager = Manager()
    state = tmp_path_factory.mktemp('rip-state')
    before = manager.snapshot()
    run('ip', 'link', 'add', 'RIPNATIVE', 'type', 'vrf', 'table', '506')
    run('ip', 'link', 'set', 'RIPNATIVE', 'up')
    run('ip', 'link', 'add', 'ripnative0', 'type', 'dummy')
    run('ip', 'link', 'set', 'ripnative0', 'master', 'RIPNATIVE')
    run('ip', 'link', 'set', 'ripnative0', 'up')
    run('ip', 'address', 'add', '192.0.2.100/32', 'dev', 'ripnative0')
    run('ip', '-6', 'address', 'add', '2001:db8:506::100/128', 'dev', 'ripnative0')
    run('ip', 'link', 'add', 'ripnative1', 'type', 'veth', 'peer', 'name', 'ripnative2')
    run('ip', 'link', 'set', 'ripnative2', 'master', 'RIPNATIVE')
    for name, number in [('ripnative1', 1), ('ripnative2', 2)]:
        run('ip', 'address', 'add', f'198.18.254.{number}/30', 'dev', name)
        run('ip', '-6', 'address', 'add', f'2001:db8:ff06::{number}/64', 'dev', name)
        run('ip', 'link', 'set', name, 'up')
    yield manager, state
    policy_scopes = [scope for scope in frr_policy.adapter.desired(manager.snapshot()) if 'RIPNATIVE' in scope]
    manager.apply('policy', frr_policy.adapter.select(before, policy_scopes), state,
                  adapter=frr_policy.adapter, recovery=True)
    for protocol, adapter in frr_rip.adapters.items():
        scopes = [f'router {protocol}', f'router {protocol} vrf RIPNATIVE',
                  'interface ripnative0', 'interface ripnative1', 'interface ripnative2']
        manager.apply(protocol, adapter.select(before, scopes), state, adapter=adapter, recovery=True)
    run('ip', 'link', 'del', 'ripnative0')
    run('ip', 'link', 'del', 'ripnative1')
    run('ip', 'link', 'del', 'RIPNATIVE')


def apply(native, protocol, settings):
    manager, state = native
    configuration = {'protocol': protocol, 'instances': settings}
    desired = protocols_rip.generate(configuration, None)
    adapter = frr_rip.adapters[protocol]
    manager.apply(protocol, desired, state, adapter=adapter, daemons=(protocol + 'd', 'zebra'))
    assert adapter.select(manager.snapshot(), desired) == desired
    return desired


@pytest.mark.parametrize('protocol', ['rip', 'ripng'])
def test_common_options_and_removal(native, protocol):
    prefix = '192.0.2.0/24' if protocol == 'rip' else '2001:db8:506::/64'
    settings = {'maximum-paths': '4', 'default-metric': '5', 'default-information': {'originate': True},
                'route': [prefix], 'network': [prefix], 'timers': {'update': '5', 'timeout': '20', 'garbage-collection': '10'},
                'redistribute': {'connected': {'metric': '3'}, 'local': {}, 'static': {}},
                'interface': {'ripnative0': {'passive': {}, 'split-horizon': {'poisoned-reverse': True}}}}
    if protocol == 'ripng':
        settings['aggregate-address'] = ['2001:db8:506::/48']
    apply(native, protocol, {'default': {'maximum-paths': '2'}, 'RIPNATIVE': settings})
    changed = deepcopy(settings)
    changed['interface']['ripnative0'] = {'passive': {'disable': True}, 'split-horizon': {'disable': True}}
    changed['timers'] = {'update': '30'}
    changed['default-metric'] = '1'
    apply(native, protocol, {'RIPNATIVE': changed})
    apply(native, protocol, {'RIPNATIVE': {'interface': {'ripnative0': {'split-horizon': {}}}}})
    apply(native, protocol, {})


@pytest.mark.parametrize('mode,length', [('text', None), ('md5', None), ('md5', 'rfc'), ('md5', 'old-ripd')])
def test_ipv4_authentication_versions_and_passive(native, mode, length):
    auth = {'mode': mode, 'password': 'rip-native'}
    if length:
        auth['md5-auth-length'] = length
    settings = {'version': '2', 'neighbor': ['192.0.2.2'], 'distance': '120', 'passive-default': True,
                'log-neighbor-changes': True, 'source-distance': {'192.0.2.0/24': {'distance': '125'}},
                'interface': {'ripnative0': {'passive': {'disable': True}, 'authentication': auth,
                                             'send-version': 'both', 'receive-version': 'none', 'v2-broadcast': True}}}
    apply(native, 'rip', {'RIPNATIVE': settings})
    apply(native, 'rip', {'RIPNATIVE': {'interface': {'ripnative0': {}}}})


@pytest.mark.parametrize('protocol', ['rip', 'ripng'])
def test_native_operational_scope(native, protocol):
    apply(native, protocol, {'default': {}, 'RIPNATIVE': {}})
    family = 'ip' if protocol == 'rip' else 'ipv6'
    for suffix in ('', ' vrf RIPNATIVE', ' vrf all'):
        for action in ('', ' status'):
            output = run('vtysh', '-c', f'show {family} {protocol}{suffix}{action}')
            assert 'Unknown command' not in output
    for suffix in (' vrf default', ' vrf RIPNATIVE', ''):
        output = run('vtysh', '-c', f'clear {family} {protocol}{suffix}')
        assert 'error' not in output.lower()
        assert 'No RIP' not in output


@pytest.mark.parametrize('protocol', ['rip', 'ripng'])
def test_native_filters_offsets_redistribution_and_keychain(native, protocol):
    manager, state = native
    family = 'ipv4' if protocol == 'rip' else 'ipv6'
    prefix = '192.0.2.0/24' if protocol == 'rip' else '2001:db8:506::/64'
    lists = {family: {'RIPNATIVE': {'rule': {'10': {'action': 'permit', 'prefix': prefix}}}}}
    policies = {'access-list': lists, 'prefix-list': deepcopy(lists),
                'route-map': {'RIPNATIVE': {'rule': {'10': {'action': 'permit', 'set': {'metric': '3'}}}}},
                'key-chain': {'RIPNATIVE': {'key': {'1': {'secret': 'native-rip', 'algorithm': 'md5'}}}}}
    manager.apply('policy', policy.generate(policies, None), state, adapter=frr_policy.adapter)
    filters = {'in': {'access-list': 'RIPNATIVE', 'prefix-list': 'RIPNATIVE'},
               'out': {'access-list': 'RIPNATIVE', 'prefix-list': 'RIPNATIVE'}}
    offsets = {direction: {'access-list': 'RIPNATIVE', 'metric': '2'} for direction in ('in', 'out')}
    interface = {'distribute-list': filters, 'offset-list': offsets,
                 'route-map': {'in': 'RIPNATIVE', 'out': 'RIPNATIVE'}}
    if protocol == 'rip':
        interface['authentication'] = {'mode': 'md5', 'key-chain': 'RIPNATIVE'}
    sources = ['kernel', 'connected', 'local', 'static', 'ospf' if protocol == 'rip' else 'ospfv3',
               'isis', 'bgp', 'nhrp', 'babel', 'openfabric']
    if protocol == 'rip':
        sources.append('eigrp')
    settings = {'distribute-list': filters, 'offset-list': offsets,
                'redistribute': {source: {'metric': '2', 'route-map': 'RIPNATIVE'} for source in sources},
                'interface': {'ripnative0': interface}}
    if protocol == 'rip':
        settings['source-distance'] = {prefix: {'distance': '122', 'access-list': 'RIPNATIVE'}}
    apply(native, protocol, {'RIPNATIVE': settings})
    apply(native, protocol, {'RIPNATIVE': {'interface': {'ripnative0': {}}}})


@pytest.mark.parametrize('protocol', ['rip', 'ripng'])
def test_native_exchange_forwarding_and_withdrawal(native, protocol):
    manager, state = native
    family = '-4' if protocol == 'rip' else '-6'
    prefix = '192.0.2.100/32' if protocol == 'rip' else '2001:db8:506::100/128'
    destination = prefix.split('/')[0]
    left = {'timers': {'update': '2', 'timeout': '8', 'garbage-collection': '4'},
            'interface': {'ripnative1': {'passive': {'disable': True}}}}
    right = {'timers': dict(left['timers']), 'interface': {
        'ripnative2': {'passive': {'disable': True}}, 'ripnative0': {'passive': {}}}}
    if protocol == 'rip':
        for settings, name in [(left, 'ripnative1'), (right, 'ripnative2')]:
            settings.update({'version': '2', 'passive-default': True})
            settings['interface'][name]['authentication'] = {
                'mode': 'md5', 'password': 'rip-packet', 'md5-auth-length': 'rfc',
            }
    apply(native, protocol, {'default': left, 'RIPNATIVE': right})
    wait_for(lambda: run('ip', family, 'route', 'show', prefix), lambda output: 'ripnative1' in output,
             description=f'{protocol} native route exchange', timeout=20)
    run('ping', family, '-c', '1', '-W', '2', destination)
    right['interface'].pop('ripnative0')
    apply(native, protocol, {'default': left, 'RIPNATIVE': right})
    wait_for(lambda: run('ip', family, 'route', 'show', prefix), lambda output: not output.strip(),
             description=f'{protocol} native route withdrawal', timeout=20)

    # Exercise the routed scenario's export policy and inbound filter together.
    # Denying the inbound prefix may discard poison, requiring route expiry.
    policy_family = 'ipv4' if protocol == 'rip' else 'ipv6'
    entry = {'action': 'permit', 'prefix': prefix}
    policies = {'prefix-list': {policy_family: {'RIPNATIVE': {'rule': {'10': entry}}}},
                'route-map': {'RIPNATIVE': {'rule': {'10': {'action': 'permit',
                    'match': {policy_family: {'prefix-list': 'RIPNATIVE'}}}}}}}
    manager.apply('policy', policy.generate(policies, None), state, adapter=frr_policy.adapter)
    left['interface']['ripnative1']['distribute-list'] = {'in': {'prefix-list': 'RIPNATIVE'}}
    right['redistribute'] = {'connected': {'route-map': 'RIPNATIVE'}}
    apply(native, protocol, {'default': left, 'RIPNATIVE': right})
    wait_for(lambda: run('ip', family, 'route', 'show', prefix), lambda output: 'ripnative1' in output,
             description=f'{protocol} filtered redistribution', timeout=20)
    entry['action'] = 'deny'
    manager.apply('policy', policy.generate(policies, None), state, adapter=frr_policy.adapter)
    wait_for(lambda: run('ip', family, 'route', 'show', prefix), lambda output: not output.strip(),
             description=f'{protocol} policy withdrawal', timeout=20)


def test_passive_default_transitions_preserve_explicit_modes(native):
    active = {'interface': {'ripnative0': {'passive': {'disable': True}}}}
    passive = {'interface': {'ripnative0': {'passive': {}}}}
    for settings in (active, dict(active, **{'passive-default': True}),
                     dict(passive, **{'passive-default': True}), passive, active):
        apply(native, 'rip', {'RIPNATIVE': settings})
