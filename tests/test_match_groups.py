"""Concatenated set membership, shared map checks, and three-source conflicts."""

from copy import deepcopy
from types import SimpleNamespace
import json

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import RouterError
from nvyr.helpers import nftables
from nvyr.helpers.nftables_formatters import nft_match_group
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree
from tests.test_firewall_maps import rendered
from tests.test_firewall_matches import PATHS, configured


def group_definition(family='ipv4'):
    address = '192.0.2.0/24' if family == 'ipv4' else '2001:db8::/64'
    return {'match': {'source-address': True}, 'description': 'Trusted sources',
            'entry': {'TRUSTED': {'source-address': address, 'description': 'Office'}}}


def with_group(rule, path=('ipv4', 'forward', 'filter'), group=None):
    tree = configured(rule, path)
    tree['firewall']['group'] = {'match-group': {path[0]: {'G': group or group_definition(path[0])}}}
    return tree


@pytest.mark.parametrize('path', PATHS + [('ipv4', 'name', 'CUSTOM'), ('ipv6', 'name', 'CUSTOM')])
def test_group_on_every_rule_path(path):
    tree = with_group({'match-group': 'G', 'action': 'accept'}, path)
    text = rendered(tree)
    assert f'set {path[0]}_match_group_G' in text
    assert f'== @{path[0]}_match_group_G accept' in text


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_cli_anchor_suggestions_and_dependency_registration(controller, engine, session, family):
    controller.execute('set interfaces dummy dum9', session)
    controller.execute(f'set firewall group match-group {family} G match source-address inbound-interface', session)
    address = '192.0.2.0/24' if family == 'ipv4' else '2001:db8::/64'
    controller.execute(f'set firewall group match-group {family} G entry OFFICE source-address {address} inbound-interface dum9', session)
    controller.execute(f'set firewall {family} forward filter rule 10 match-group G action accept', session)

    assert 'G' in dict(controller.completion(f'set firewall {family} forward filter rule 20 match-group ', session)['candidates'])
    other = 'ipv6' if family == 'ipv4' else 'ipv4'
    assert 'G' not in dict(controller.completion(f'set firewall {other} forward filter rule 20 match-group ', session)['candidates'])
    for command in [f'delete firewall group match-group {family} G', 'delete interfaces dummy dum9']:
        with pytest.raises(RouterError, match='referenced'):
            controller.execute(command, session)

    assert engine.commit(session)['results']['firewall']['success']


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('flags', [{}, {'counter': True}, {'last-used': True}, {'counter': True, 'last-used': True}])
def test_group_comments_global_tracking_and_immutability(family, flags):
    definition = group_definition(family)
    original = deepcopy(definition)
    text = nft_match_group(family, 'G', ReadOnlyTree(definition), flags)
    assert 'comment "Trusted sources";' in text
    assert 'comment "TRUSTED|Office"' in text
    assert 'flags interval;' in text
    assert text.count('counter;') == int('counter' in flags)
    assert text.count('last;') == int('last-used' in flags)
    assert ' : ' not in text
    assert definition == original


def test_rule_map_and_match_group_can_supply_distinct_matches():
    tree = with_group({'match-group': 'G', 'map': 'M', 'outbound-interface': ['eth0'], 'counter': {}})
    tree['firewall']['group']['map'] = {'ipv4': {'M': {
        'match': {'destination-address': True}, 'result-type': 'verdict',
        'entry': {'A': {'destination-address': '203.0.113.1', 'result': {'action': 'drop'}}}}}}
    text = rendered(tree)
    rule = next(line for line in text.splitlines() if 'vmap @ipv4_map_M' in line)
    assert rule.index('oifname') < rule.index('== @ipv4_match_group_G') < rule.index('counter') < rule.index('vmap')


@pytest.mark.parametrize('explicit,map_field,group_field,message', [
    ({'source-address': {'192.0.2.1': {}}}, 'destination-address', 'source-address', 'match-group duplicates.*rule: source-address'),
    ({}, 'source-address', 'source-address', 'match-group duplicates.*map: source-address'),
    ({'destination-address': {'203.0.113.1': {}}}, 'destination-address', 'source-address', 'map cannot be combined with destination-address'),
])
def test_three_sources_reject_every_pairwise_overlap(explicit, map_field, group_field, message):
    rule = {'map': 'M', 'match-group': 'G', **explicit}
    mapping = {'match': {map_field: True}, 'result-type': 'verdict'}
    group = {'match': {group_field: True}}
    with pytest.raises(RouterError, match=message):
        firewall.verify_rule(rule, ('firewall', 'ipv4', 'forward', 'filter', 'rule', '10'), {},
                             maps={'M': mapping}, match_groups={'G': group})


def test_protocol_from_group_controls_explicit_port_and_mss_checks():
    group = {'match': {'protocol': True}, 'entry': {'TCP': {'protocol': 'tcp'}}}
    tree = with_group({'match-group': 'G', 'destination-port': ['443'], 'tcp-mss': ['1460'], 'action': 'accept'}, group=group)
    rendered(tree)
    group['entry']['TCP']['protocol'] = 'udp'
    with pytest.raises(RouterError, match='tcp-mss requires protocol tcp'):
        rendered(tree)
    group['entry']['TCP']['protocol'] = 'icmp'
    with pytest.raises(RouterError, match='requires an explicit port protocol'):
        rendered(tree)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_icmp_group_requires_protocol_and_checks_combined_type_code(family):
    group = {'match': {'icmp-code': True}, 'entry': {'A': {'icmp-code': '0'}}}
    with pytest.raises(RouterError, match='requires protocol'):
        firewall.verify_match_group(family, 'G', group)
    group['match']['protocol'] = True
    group['entry']['A']['protocol'] = 'icmp' if family == 'ipv4' else 'ipv6-icmp'
    tree = with_group({'match-group': 'G', 'icmp-type': ['echo-request'], 'action': 'accept'}, (family, 'input', 'filter'), group)
    rendered(tree)
    tree['firewall'][family]['input']['filter']['rule']['10']['icmp-type'].append('echo-reply')
    with pytest.raises(RouterError, match='exactly one'):
        rendered(tree)


@pytest.mark.parametrize('edit,message', [
    (lambda g: g.pop('match'), 'match field'),
    (lambda g: g['entry']['TRUSTED'].pop('source-address'), 'missing match'),
    (lambda g: g['entry']['TRUSTED'].update({'protocol': 'tcp'}), 'undeclared match'),
    (lambda g: g['entry'].update({'OTHER': {'source-address': '192.0.2.1'}}), 'overlapping'),
    (lambda g: g['entry']['TRUSTED'].update(description='x' * 128), 'comment limit'),
])
def test_groups_reuse_key_verification(edit, message):
    group = group_definition()
    edit(group)
    with pytest.raises(RouterError, match=message):
        firewall.verify_match_group('ipv4', 'G', group)


@pytest.mark.parametrize('fields,message', [
    (['source-address', 'destination-address', 'inbound-interface', 'outbound-interface', 'destination-port'], '66 bytes'),
    (['source-address', 'destination-address', 'protocol', 'source-port', 'destination-port', 'state'], 'maximum 5'),
])
def test_groups_share_map_key_size_limits(fields, message):
    matches = dict.fromkeys(fields, True)
    if 'state' in matches:
        del matches['state']
        matches['connection'] = {'state': True}
    with pytest.raises(RouterError, match=message):
        firewall.verify_match_group('ipv6', 'G', {'match': matches})


@pytest.mark.parametrize('extra', [{'result-type': 'verdict'}, {'entry': {'A': {'result': {'action': 'accept'}}}}])
def test_group_schema_has_no_results(extra):
    tree = {'firewall': {'group': {'match-group': {'ipv4': {'G': extra}}}}}
    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration(tree)


def test_groups_do_not_supply_an_action_and_must_exist():
    path = ('firewall', 'ipv4', 'forward', 'filter', 'rule', '10')
    with pytest.raises(RouterError, match='not configured'):
        firewall.verify_rule({'match-group': 'G', 'action': 'accept'}, path, {})
    with pytest.raises(RouterError, match='action is required'):
        firewall.verify_rule({'match-group': 'G'}, path, {}, match_groups={'G': group_definition()})


@pytest.mark.parametrize('direction,interface', [('source', 'outbound-interface'), ('destination', 'inbound-interface')])
@pytest.mark.parametrize('use_map', [False, True])
def test_nat_group_can_supply_interface_alongside_translation_or_map(direction, interface, use_map):
    group = {'match': {interface: True}, 'entry': {'A': {interface: 'eth0'}}}
    rule = {'match-group': 'G', 'protocol': ['tcp']}
    tree = {'firewall': {'group': {'match-group': {'ipv4': {'G': group}}}},
            'nat': {direction: {'rule': {'10': rule}}}}
    if use_map:
        rule['map'] = 'M'
        tree['firewall']['group']['map'] = {'ipv4': {'M': {'match': {'destination-address': True},
            'result-type': 'address', 'entry': {'A': {'destination-address': '203.0.113.10',
                                                      'result': {'address': '10.0.0.10'}}}}}}
    else:
        rule['translation'] = {'address': '10.0.0.10'}
    text = rendered(tree)
    assert '== @ipv4_match_group_G' in text
    assert ('snat' if direction == 'source' else 'dnat') + ' ip to ' in text


def test_deleted_group_is_destroyed_after_consumers_and_before_recreation():
    before = with_group({'match-group': 'G', 'action': 'accept'})
    text = rendered({}, before)
    assert text.index('flush chain inet nvyr_filter ipv4_forward') < text.index('destroy set inet nvyr_filter ipv4_match_group_G')
    assert 'set ipv4_match_group_G {' not in text


def test_recovery_discovers_unpublished_match_groups(monkeypatch):
    monkeypatch.setattr(nftables, 'manager', SimpleNamespace(
        rule_limits=lambda: [], named_state=lambda: [], maps=lambda: [], flowtables=lambda: [], named_chains=lambda: [],
        icmp_groups=lambda: [], singleton_groups=lambda: [], match_groups=lambda: [('ipv6', 'ORPHAN')]))
    assert 'destroy set inet nvyr_filter ipv6_match_group_ORPHAN' in rendered({}, recovery=True)


def test_set_discovery_only_returns_owned_names(monkeypatch):
    entries = [{'family': 'inet', 'table': 'nvyr_filter', 'name': name} for name in
               ['ipv4_match_group_G', 'ipv6_match_group_G', 'ipv4_map_M', 'unmanaged']]
    entries.append({'family': 'inet', 'table': 'other', 'name': 'ipv4_match_group_FOREIGN'})
    monkeypatch.setattr(nftables, 'cmd', lambda argv: json.dumps({'nftables': [{'set': item} for item in entries]}))
    assert nftables.Manager().match_groups() == [('ipv4', 'G'), ('ipv6', 'G')]
