"""Opt-in reload checks against disposable FRR 10.7.1 daemons.

Requires zebra, mgmtd, staticd and bgpd in ordinary CLI mode. These tests create
no BGP neighbors and are excluded from the ordinary build suite.
"""

import json
import os
from pathlib import Path

import pytest

from nvyr.config_scripts import policy
from nvyr.errors import RouterError
from nvyr.helpers import frr_reload
from nvyr.helpers.frr_policy import adapter
from nvyr.storage import atomic_json


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_POLICY_TEST') != '1',
                                reason='requires isolated FRR policy daemons')


def running(daemon):
    """Inspect native policy commands independently in Zebra and BGP."""
    return frr_reload.run(['vtysh', '-d', daemon, '-c', 'show running-config'])


def apply(native, configuration, *, recovery=False):
    manager, state = native
    desired = policy.generate(configuration, None)
    manager.apply('policy', desired, state, adapter=adapter,
                  daemons=('zebra', 'bgpd'), recovery=recovery)
    return desired


@pytest.fixture
def native(tmp_path):
    assert Path('/.dockerenv').exists(), 'never run native policy tests on a shared router'
    manager = frr_reload.Manager()
    yield manager, tmp_path
    # A fresh manager also cleans up after tests inject a failed/lost reload reply.
    apply((frr_reload.Manager(), tmp_path), {}, recovery=True)


def test_native_ipv4_filters_update_and_remove(native):
    """Replace same-sequence ACL/prefix entries and remove their last objects."""
    configuration = {'access-list': {'ipv4': {'RELOAD_POLICY': {'description': 'ACL description', 'rule': {
        '2': {'action': 'permit', 'address': '10.0.20.0', 'wildcard-mask': '0.0.255.0'},
        '10': {'action': 'permit', 'prefix': '192.0.2.0/24', 'exact-match': {}},
        '20': {'action': 'deny', 'any': {}},
    }}}}, 'prefix-list': {'ipv4': {'RELOAD_POLICY': {'description': 'Prefix description', 'rule': {
        '10': {'action': 'permit', 'prefix': '10.0.0.0/8', 'ge': '8', 'le': '24'},
    }}}}}
    desired = apply(native, configuration)
    for daemon in ('zebra', 'bgpd'):
        assert adapter.select(running(daemon), desired) == desired

    configuration['access-list']['ipv4']['RELOAD_POLICY']['rule']['2']['action'] = 'deny'
    configuration['prefix-list']['ipv4']['RELOAD_POLICY']['rule']['10']['le'] = '28'
    desired = apply(native, configuration)
    for daemon in ('zebra', 'bgpd'):
        assert adapter.select(running(daemon), desired) == desired

    apply(native, {})
    for daemon in ('zebra', 'bgpd'):
        assert 'RELOAD_POLICY' not in running(daemon)


def test_native_ipv6_filters_update_and_remove(native):
    """IPv6 ACLs and prefix-lists retain their independent family and bounds."""
    configuration = {'access-list': {'ipv6': {'RELOAD_POLICY': {'rule': {
        '10': {'action': 'permit', 'prefix': '2001:db8::/32', 'exact-match': {}},
        '20': {'action': 'deny', 'any': {}},
    }}}}, 'prefix-list': {'ipv6': {'RELOAD_POLICY': {'rule': {
        '10': {'action': 'permit', 'prefix': '2001:db8::/32', 'ge': '48', 'le': '128'},
    }}}}}
    desired = apply(native, configuration)
    for daemon in ('zebra', 'bgpd'):
        assert adapter.select(running(daemon), desired) == desired

    configuration['prefix-list']['ipv6']['RELOAD_POLICY']['rule']['10']['action'] = 'deny'
    desired = apply(native, configuration)
    for daemon in ('zebra', 'bgpd'):
        assert adapter.select(running(daemon), desired) == desired


def test_native_route_map_all_setters_and_removal(native):
    """Round-trip every setter, descriptions and duplicate ASNs, then remove setters."""
    rule = {'action': 'permit', 'description': ' Policy   rule ', 'set': {
        'metric': '50', 'local-preference': '200', 'weight': '100', 'origin': 'igp',
        'ipv4': {'next-hop': {'address': '192.0.2.1'}}, 'ipv6': {'next-hop': {'global': '2001:db8::1'}},
        'as-path': {'prepend': '65001 65002 65001'},
        'community': ['100:1', '2:1', 'additive'],
        'large-community': ['100:1:2', '2:1:2', 'additive'],
    }}
    configuration = {'route-map': {'RELOAD_POLICY': {'rule': {'10': rule}}}}
    desired = apply(native, configuration)
    assert adapter.select(running('bgpd'), desired) == desired

    rule['action'] = 'deny'
    rule['description'] = 'Changed description'
    rule['set'] = {'metric': '70'}
    desired = apply(native, configuration)
    assert adapter.select(running('bgpd'), desired) == desired
    assert 'set local-preference' not in running('bgpd')


def test_native_bgp_lists_update_type_and_remove(native):
    """Change a list's representation without stale rules or lost ownership claims."""
    configuration = {'as-path-list': {'RELOAD_POLICY': {'rule': {
        '10': {'action': 'permit', 'regex': '_65000_'}}}},
        'community-list': {'standard': {'RELOAD_POLICY': {'rule': {
            '10': {'action': 'permit', 'community': ['65000:1', 'no-export']}}}}}}
    desired = apply(native, configuration)
    assert adapter.select(running('bgpd'), desired) == desired

    configuration['community-list'] = {'expanded': {'RELOAD_POLICY': {'rule': {
        '10': {'action': 'permit', 'regex': '^65000:'},
        '20': {'action': 'deny', 'regex': '.*'}}}}}
    configuration['as-path-list']['RELOAD_POLICY']['rule']['10']['regex'] = '^65001$'
    desired = apply(native, configuration)
    assert adapter.select(running('bgpd'), desired) == desired

    manager, _ = native
    manager.reload = lambda target: pytest.fail('unchanged BGP lists caused a reload')
    apply(native, configuration)


def test_native_bgp_list_lost_reply_restores_previous_values(native):
    """A failed policy transaction restores AS-path and both community list families."""
    manager, state = native
    configuration = {'as-path-list': {'RELOAD_POLICY': {'rule': {
        '10': {'action': 'permit', 'regex': '_65000_'}}}},
        'community-list': {'standard': {'RELOAD_POLICY': {'rule': {
            '10': {'action': 'permit', 'community': ['65000:1']}}}}},
        'large-community-list': {'standard': {'RELOAD_POLICY': {'rule': {
            '10': {'action': 'permit', 'community': ['65000:1:1']}}}}}}
    before = apply(native, configuration)
    reload = manager.reload
    failed = False

    def lose_reply(target):
        nonlocal failed
        reload(target)
        if not failed:
            failed = True
            raise ConnectionError('injected lost BGP list reload reply')

    manager.reload = lose_reply
    configuration['as-path-list']['RELOAD_POLICY']['rule']['10']['regex'] = '_65001_'
    configuration['community-list']['standard']['RELOAD_POLICY']['rule']['10']['community'] = ['65001:1']
    configuration['large-community-list']['standard']['RELOAD_POLICY']['rule']['10']['community'] = ['65001:1:1']
    with pytest.raises(RouterError, match='previous configuration restored'):
        apply(native, configuration)
    assert adapter.select(running('bgpd'), before) == before


def test_native_unchanged_policy_does_not_reload(native):
    """FRR writer ordering must not cause repeat reloads for unchanged policies."""
    manager, _ = native
    configuration = {'route-map': {'RELOAD_POLICY': {'rule': {
        '2': {'action': 'permit', 'match': {'metric': '10', 'tag': '20'}, 'set': {'metric': '30'}},
        '10': {'action': 'deny'},
    }}}}
    apply(native, configuration)
    manager.reload = lambda target: pytest.fail('unchanged policy caused a reload')
    apply(native, configuration)


def test_native_partial_apply_is_restored(native):
    """Undo an applied filter change when a later part of the reload fails."""
    manager, state = native
    before = apply(native, {'prefix-list': {'ipv4': {'RELOAD_POLICY': {'rule': {
        '10': {'action': 'permit', 'prefix': '10.0.0.0/8'},
    }}}}})
    reload = manager.reload
    failed = False

    def partial_reload(target):
        nonlocal failed
        if not failed:
            failed = True
            partial = {'ip prefix-list RELOAD_POLICY': [
                'ip prefix-list RELOAD_POLICY seq 10 deny 192.0.2.0/24',
            ]}
            reload(adapter.replace(manager.snapshot(), partial))
            raise ConnectionError('injected failure after prefix-list update')
        reload(target)

    manager.reload = partial_reload
    desired = before | {'route-map RELOAD_POLICY': ['route-map RELOAD_POLICY permit 10']}
    with pytest.raises(RouterError, match='previous configuration restored'):
        manager.apply('policy', desired, state, adapter=adapter, daemons=('zebra', 'bgpd'))

    expected = before | {'route-map RELOAD_POLICY': []}
    for daemon in ('zebra', 'bgpd'):
        assert adapter.select(running(daemon), expected) == expected


def test_native_lost_success_reply_is_restored(native):
    """Restore all created policies even when a successful reload reply was lost."""
    manager, state = native
    reload = manager.reload
    lost = False

    def lose_reply(target):
        nonlocal lost
        reload(target)
        if not lost:
            lost = True
            raise ConnectionError('lost successful reload reply')

    manager.reload = lose_reply
    with pytest.raises(RouterError, match='previous configuration restored'):
        apply(native, {'route-map': {'RELOAD_POLICY': {'rule': {
            '10': {'action': 'permit', 'set': {'local-preference': '200'}},
        }}}})

    assert lost
    for daemon in ('zebra', 'bgpd'):
        assert 'RELOAD_POLICY' not in running(daemon)
    assert 'pending' not in json.loads((state / 'frr-reload/policy.json').read_text())


def test_native_interrupted_reload_recovery(native):
    """Startup uses durable claims to remove unpublished policy objects."""
    manager, state = native
    desired = policy.generate({'route-map': {'RELOAD_POLICY': {'rule': {
        '10': {'action': 'permit', 'set': {'weight': '100'}},
    }}}}, None)
    before = {scope: [] for scope in desired}
    atomic_json(state / 'frr-reload/policy.json', {
        'scopes': list(desired), 'pending': {'before': before, 'target': desired},
    })
    manager.directory.mkdir(exist_ok=True)
    manager.reload(adapter.replace(manager.snapshot(), desired))
    assert 'RELOAD_POLICY' in running('bgpd')

    apply((frr_reload.Manager(), state), {}, recovery=True)
    for daemon in ('zebra', 'bgpd'):
        assert 'RELOAD_POLICY' not in running(daemon)


def test_native_unmanaged_policy_and_saved_file_preserved(native, tmp_path):
    """Named ownership preserves foreign policies and never writes frr.conf."""
    foreign = (frr_reload.Manager(), tmp_path / 'foreign')
    configuration = {'prefix-list': {'ipv4': {'FOREIGN_POLICY': {'rule': {
        '10': {'action': 'deny', 'prefix': '192.0.2.0/24'},
    }}}}}
    expected = apply(foreign, configuration)
    saved = Path('/etc/frr/frr.conf').read_bytes()
    try:
        apply(native, {'route-map': {'RELOAD_POLICY': {'rule': {'10': {'action': 'permit'}}}}})
        apply(native, {})
        for daemon in ('zebra', 'bgpd'):
            assert adapter.select(running(daemon), expected) == expected
        assert Path('/etc/frr/frr.conf').read_bytes() == saved
    finally:
        apply(foreign, {})


def test_native_wildcard_edge_masks_and_well_known_communities(native):
    """Native canonical spellings must agree with host masks and numeric communities."""
    configuration = {
        'access-list': {'ipv4': {'RELOAD_POLICY': {'rule': {
            '10': {'action': 'permit', 'address': '192.0.2.1', 'wildcard-mask': '0.0.0.0'},
            '20': {'action': 'deny', 'address': '192.0.2.1', 'wildcard-mask': '255.255.255.255'},
        }}}},
        'route-map': {'RELOAD_POLICY': {'rule': {'10': {
            'action': 'permit', 'set': {'community': ['65535:65281', '65535:666', '0:0']},
        }}}},
    }
    desired = apply(native, configuration)
    assert adapter.select(running('bgpd'), desired) == desired
    native[0].reload = lambda target: pytest.fail('canonical writer output caused a reload')
    apply(native, configuration)


def test_native_rejected_command_restores_existing_policy(native):
    """A native command rejection reports failure and retains the original policy."""
    manager, state = native
    before = apply(native, {'route-map': {'RELOAD_POLICY': {'rule': {
        '10': {'action': 'permit', 'set': {'weight': '100'}},
    }}}})
    invalid = {'route-map RELOAD_POLICY': ['route-map RELOAD_POLICY permit 10\n set weight not-a-number']}
    with pytest.raises(RouterError, match='previous configuration restored'):
        manager.apply('policy', invalid, state, adapter=adapter, daemons=('zebra', 'bgpd'))
    assert adapter.select(running('bgpd'), before) == before


def test_native_all_route_map_match_conditions(native):
    """Preserve independent ACL/prefix-list conditions, including both next-hop families."""
    configuration = {
        'access-list': {
            'ipv4': {'RELOAD_POLICY': {'rule': {'10': {'action': 'permit', 'any': {}}}}},
            'ipv6': {'RELOAD_POLICY': {'rule': {'10': {'action': 'permit', 'any': {}}}}},
        },
        'prefix-list': {
            'ipv4': {'RELOAD_POLICY': {'rule': {'10': {'action': 'permit', 'prefix': '10.0.0.0/8'}}}},
            'ipv6': {'RELOAD_POLICY': {'rule': {'10': {'action': 'permit', 'prefix': '2001:db8::/32'}}}},
        },
        'route-map': {'RELOAD_POLICY': {'rule': {'10': {'action': 'permit', 'match': {
            'ipv4': {
                'access-list': 'RELOAD_POLICY', 'prefix-list': 'RELOAD_POLICY',
                'next-hop': {'access-list': 'RELOAD_POLICY', 'prefix-list': 'RELOAD_POLICY'},
            },
            'ipv6': {
                'access-list': 'RELOAD_POLICY', 'prefix-list': 'RELOAD_POLICY',
                'next-hop': {'access-list': 'RELOAD_POLICY', 'prefix-list': 'RELOAD_POLICY'},
            },
            'interface': 'lo', 'metric': '100', 'tag': '200',
        }}}}},
    }
    desired = apply(native, configuration)
    # MGMTd owns Zebra's route-map config writer; Zebra itself prints the lists.
    scope = 'route-map RELOAD_POLICY'
    for daemon in ('mgmtd', 'bgpd'):
        assert adapter.select(running(daemon), [scope]) == {scope: desired[scope]}
