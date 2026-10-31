"""Interface prefixes retain native matching and unambiguous ownership."""

from copy import deepcopy

import pytest

from nvyr.errors import ValidationError
from nvyr.helpers import interface_patterns, interfaces
from nvyr.helpers.validators import interface_match
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


@pytest.mark.parametrize('value', ['eth0', 'wg*', 'eth0.*', 'a' * 15, 'a' * 15 + '*'])
def test_interface_selector_accepts_exact_names_and_prefixes(value):
    assert interface_match(value)


@pytest.mark.parametrize('value', ['*', '*eth', 'eth*0', 'eth**', 'eth?', 'eth[01]', '', 'a' * 16 + '*'])
def test_interface_selector_rejects_shell_globs_and_overlong_names(value):
    assert not interface_match(value)


def test_prefix_normalization_preserves_disjoint_members():
    assert interface_patterns.normalize(['wg0', 'wg*', 'wg1*', 'eth1', 'eth2*', 'eth2']) == ['eth1', 'eth2*', 'wg*']
    assert interface_patterns.overlaps('wg*', 'wg10*')
    assert interface_patterns.overlaps('wg1', 'wg*')
    assert not interface_patterns.overlaps('wg0*', 'wg1*')


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_rule_prefixes_negation_groups_and_zone_maps(family):
    config = {'firewall': {
        'group': {'interface-group': {
            'BASE': {'interface': ['wg*']},
            'ALL': {'interface': ['wg0', 'eth*'], 'include-group': ['BASE'], 'counter': True, 'last-used': True},
        }},
        'zone': {'VPN': {'interface': ['wg*', 'wg0']}, 'LAN': {'interface': ['eth*']}, 'LOCAL': {'local-zone': True}},
        family: {'forward': {'filter': {'rule': {
            '10': {'action': 'accept', 'inbound-interface': ['wg*', 'wg0'], 'not': {'outbound-interface': ['eth*', 'eth0']}},
            '20': {'action': 'accept', 'inbound-interface-group': 'ALL'},
        }}}},
    }}
    text = rendered(config)
    assert 'iifname { "wg*" } oifname != { "eth*" }' in text
    assert '"wg*" . "eth*" comment "VPN to LAN"' in text
    assert '"wg0"' not in text
    assert text.count('flags interval;') == 8  # Two groups and six generated zone maps.
    assert 'counter;\n' in text and 'last;' in text


@pytest.mark.parametrize('other', ['wg0', 'wg1*', 'w*'])
def test_zones_reject_cross_zone_overlap_before_interfaces_exist(other):
    config = {'firewall': {'zone': {'VPN': {'interface': ['wg*']}, 'OTHER': {'interface': [other]}}}}
    with pytest.raises(ValidationError, match='already belongs to zone'):
        rendered(config)


def test_zone_prefix_cannot_claim_configured_vrf_master():
    config = {'vrf': {'name': {'BLUE': {'table': '100'}}},
              'firewall': {'zone': {'VPN': {'interface': ['BL*']}}}}
    with pytest.raises(ValidationError, match='VRF master'):
        rendered(config)


def test_flowtable_prefix_does_not_require_existing_devices(controller, session, monkeypatch):
    def must_not_query_prefix(name):
        raise AssertionError(f'Attempted concrete-device lookup for {name}')

    monkeypatch.setattr(interfaces, 'exists', must_not_query_prefix)
    controller.execute('set firewall flowtable FAST interface wg*', session)
    text = rendered({'firewall': {'flowtable': {'FAST': {'interface': ['wg*', 'wg0', 'wg1*']}}}})

    assert 'devices = { "wg*" }' in text


@pytest.mark.parametrize('other', ['wg0', 'wg1*', 'w*'])
def test_flowtables_reject_overlapping_future_devices(other):
    config = {'firewall': {'flowtable': {
        'FIRST': {'interface': ['wg*']}, 'SECOND': {'interface': [other]},
    }}}
    with pytest.raises(ValidationError, match='same ingress priority cannot share interfaces'):
        rendered(config)


@pytest.mark.parametrize('kind', ['map', 'match-group'])
@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_user_group_keys_remain_exact_only(kind, family, controller, session):
    with pytest.raises(ValidationError):
        controller.execute(f'set firewall group {kind} {family} EXACT entry one inbound-interface wg*', session)


def test_nat_rule_prefixes_use_same_matching_as_firewall():
    config = {'nat': {'source': {'rule': {'10': {
        'outbound-interface': ['eth*'], 'translation': {'address': 'masquerade'},
    }}}}}
    assert 'oifname { "eth*" } masquerade' in rendered(config)


def test_vrf_member_prefix_rebuilds_input_expression():
    before = {'interfaces': {'dummy': {'dum0': {}}}, 'vrf': {'name': {'BLUE': {'table': '100'}}},
              'firewall': {'ipv4': {'input': {'filter': {'rule': {
                  '10': {'action': 'accept', 'inbound-interface': ['dum*']},
              }}}}}}
    after = deepcopy(before)
    after['interfaces']['dummy']['dum0']['vrf'] = 'BLUE'
    text = rendered(after, before)
    assert 'meta sdifname { "dum*" }' in text
    assert destroyed(text) == {'ipv4_input', 'input'}


def test_prefix_reference_reapplies_for_vrf_membership_without_pinning_interface(controller, engine, session):
    controller.execute('set vrf name BLUE table 100', session)
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('set firewall ipv4 input filter rule 10 inbound-interface dum* action accept', session)
    engine.commit(session)

    controller.execute('set interfaces dummy dum0 vrf BLUE', session)
    assert list(engine.commit(session)['results']) == ['vrf_conntrack', 'dummy', 'firewall']

    # Removing a wildcard-covered member is allowed, and restores iifname matching.
    controller.execute('delete interfaces dummy dum0', session)
    assert list(engine.commit(session)['results']) == ['vrf_conntrack', 'dummy', 'firewall']


def test_delete_one_negative_prefix_preserves_other_exclusions(controller, engine, session):
    controller.execute('set firewall ipv4 forward filter rule 10 inbound-interface not wg* action accept', session)
    controller.execute('set firewall ipv4 forward filter rule 10 inbound-interface not eth1.*', session)
    controller.execute('delete firewall ipv4 forward filter rule 10 inbound-interface not wg*', session)

    rule = engine.view(session)['firewall']['ipv4']['forward']['filter']['rule']['10']
    assert rule['not']['inbound-interface'] == ['eth1.*']


def test_fail_safe_accepts_prefixes_without_interfaces(controller, engine, session):
    controller.execute('set firewall fail-safe ipv4 input filter rule 10 inbound-interface eth* action accept', session)
    controller.execute('set firewall fail-safe group interface-group VPN interface wg*', session)
    # Normal commits verify the fail-safe and let the main firewall remove its table.
    assert engine.commit(session)['results'] == {
        'firewall_failsafe': {'success': True},
        'firewall': {'success': True},
    }
