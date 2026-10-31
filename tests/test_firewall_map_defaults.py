"""Catch-all map results share normal validation, dependencies and runtime views."""

from copy import deepcopy

import pytest

from nvyr.errors import RouterError
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.op_scripts import firewall as display
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


def mapping_tree(family='ipv4', result=None):
    """Build an unused map so each test can attach its intended consumer."""
    return {'firewall': {'group': {'map': {family: {'SERVICES': {
        'match': {'protocol': True}, 'result-type': 'verdict',
        'default-result': result if result is not None else {'action': 'drop'},
    }}}}}}


@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
def test_default_result_schema_anchor_suggestion_and_dependency(controller, engine, session, family):
    """Default jumps use the same family-scoped registrar as ordinary results."""
    controller.execute(f'set firewall {family} name FALLBACK default-action drop', session)
    controller.execute(f'set firewall group map {family} SERVICES match protocol', session)
    controller.execute(f'set firewall group map {family} SERVICES result-type verdict', session)
    controller.execute(f'set firewall group map {family} SERVICES default-result action jump jump-target FALLBACK', session)
    choices = dict(controller.completion(f'set firewall group map {family} SERVICES default-result jump-target ', session)['candidates'])
    assert 'FALLBACK' in choices
    assert f'* comment "default|" : jump {family}_name_FALLBACK' in rendered(engine.view(session))

    with pytest.raises(RouterError, match='referenced'):
        controller.execute(f'delete firewall {family} name FALLBACK', session)
    controller.execute(f'delete firewall group map {family} SERVICES default-result', session)
    controller.execute(f'delete firewall {family} name FALLBACK', session)
    assert '* comment' not in rendered(engine.view(session))


@pytest.mark.parametrize('family,address', [('ipv4', '10.0.0.10'), ('ipv6', '2001:db8::10')])
@pytest.mark.parametrize('kind', ['address', 'port', 'address-port'])
def test_default_translation_results_use_declared_type(family, address, kind):
    """A map may contain only its default, including a concatenated result."""
    tree = mapping_tree(family)
    mapping = tree['firewall']['group']['map'][family]['SERVICES']
    mapping['result-type'] = kind
    mapping['default-result'] = {}
    if 'address' in kind:
        mapping['default-result']['address'] = address
    if 'port' in kind:
        mapping['default-result']['port'] = '8443'
    result = ' . '.join(mapping['default-result'].values())
    assert '* comment "default|" : ' + result in rendered(tree)


@pytest.mark.parametrize('result', [{}, {'port': '22'}, {'action': 'jump'}, {'action': 'accept', 'jump-target': 'FALLBACK'}])
def test_invalid_default_shape_is_rejected(result):
    """Empty defaults and fields for another result type cannot reach generation."""
    with pytest.raises(RouterError, match='default-result: result-type verdict requires exactly'):
        rendered(mapping_tree(result=result))


def test_default_target_must_exist():
    """Verification protects scoped fail-safe rendering as well as registrar clients."""
    with pytest.raises(RouterError, match='is not a named chain'):
        rendered(mapping_tree(result={'action': 'jump', 'jump-target': 'MISSING'}))


def test_default_jump_rebuilds_nested_consumers():
    """Changing the default target rebuilds its map and callers through nested jumps."""
    before = mapping_tree('inet', {'action': 'jump', 'jump-target': 'INNER'})
    before['firewall']['inet'] = {
        'name': {'INNER': {'default-action': 'drop'}, 'OUTER': {'rule': {'10': {'map': 'SERVICES'}}}},
        'input': {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'OUTER'}}}},
    }
    after = deepcopy(before)
    after['firewall']['inet']['name']['INNER']['default-action'] = 'accept'
    text = rendered(after, before)
    assert destroyed(text) == {'inet_name_INNER', 'inet_name_OUTER', 'input'}
    assert destroyed(text, 'map') == {'inet_map_SERVICES'}


def test_default_jump_cannot_bypass_ingress_restrictions():
    """Hook traversal follows a fallback jump even when the map has no entries."""
    tree = mapping_tree('inet', {'action': 'jump', 'jump-target': 'TRACKED'})
    tree['firewall']['inet'] = {
        'name': {'TRACKED': {'rule': {'10': {'action': 'accept', 'connection': {'state': ['established']}}}}},
        'ingress': {'filter': {'interface': ['future*'], 'rule': {'10': {'map': 'SERVICES'}}}},
    }
    with pytest.raises(RouterError, match='unavailable in ingress'):
        rendered(tree)


def test_default_jump_uses_vrf_input_context():
    """A fallback policy still selects sdifname for VRF members in INPUT."""
    tree = mapping_tree('inet', {'action': 'jump', 'jump-target': 'MEMBER'})
    tree['vrf'] = {'name': {'BLUE': {'table': '101'}}}
    tree['interfaces'] = {'dummy': {'dum0': {'vrf': 'BLUE'}}}
    tree['firewall']['inet'] = {
        'name': {'MEMBER': {'rule': {'10': {'inbound-interface': ['dum0'], 'action': 'accept'}}}},
        'input': {'filter': {'rule': {'10': {'map': 'SERVICES'}}}},
    }
    assert 'meta sdifname { "dum0" }' in rendered(tree)
    tree['firewall']['inet']['forward'] = {'filter': {'rule': {'10': {'map': 'SERVICES'}}}}
    with pytest.raises(RouterError, match='cannot be shared by input and other hooks'):
        rendered(tree)


def test_fallback_does_not_claim_a_tcp_only_map():
    """Unlisted protocols reach a default, so a separate port predicate is unsafe."""
    tree = mapping_tree()
    mapping = tree['firewall']['group']['map']['ipv4']['SERVICES']
    mapping['entry'] = {'TCP': {'protocol': 'tcp', 'result': {'action': 'accept'}}}
    tree['firewall']['ipv4'] = {'input': {'filter': {'rule': {'10': {'map': 'SERVICES', 'destination-port': ['443']}}}}}
    with pytest.raises(RouterError, match='explicit port protocol'):
        rendered(tree)
    del mapping['default-result']
    assert 'th dport { 443 }' in rendered(tree)


@pytest.mark.parametrize('family,protocol', [('ipv4', 'icmp'), ('ipv6', 'ipv6-icmp')])
def test_default_icmp_map_retains_its_native_header_guard(family, protocol):
    """A catch-all matches any ICMP type, but cannot reinterpret other protocols."""
    tree = mapping_tree(family)
    tree['firewall']['group']['map'][family]['SERVICES']['match']['icmp-type'] = True
    tree['firewall'][family] = {'input': {'filter': {'rule': {'10': {'map': 'SERVICES'}}}}}
    assert f'meta l4proto {protocol} ' in rendered(tree)


def test_default_connection_protocol_does_not_constrain_explicit_ports():
    """A tuple-protocol fallback cannot validate a separate tuple-port match."""
    tree = mapping_tree()
    mapping = tree['firewall']['group']['map']['ipv4']['SERVICES']
    mapping['match'] = {'connection': {'protocol': True}}
    mapping['entry'] = {'TCP': {'connection': {'protocol': 'tcp'}, 'result': {'action': 'accept'}}}
    tree['firewall']['ipv4'] = {'input': {'filter': {'rule': {'10': {
        'map': 'SERVICES', 'connection': {'original': {'destination-port': ['443']}},
    }}}}}
    with pytest.raises(RouterError, match='connection ports require'):
        rendered(tree)

    # Moving the port into the map supplies the native tuple protocol guard.
    del tree['firewall']['ipv4']['input']['filter']['rule']['10']['connection']
    mapping['match']['connection']['original'] = {'destination-port': True}
    mapping['entry']['TCP']['connection']['original'] = {'destination-port': '443'}
    assert 'ct protocol {' in rendered(tree)


def test_default_connection_state_is_not_an_entry_only_constraint():
    """A fallback can reach tracked packets despite an explicit untracked key."""
    tree = mapping_tree()
    mapping = tree['firewall']['group']['map']['ipv4']['SERVICES']
    mapping['match'] = {'connection': {'state': True}}
    mapping['entry'] = {'UNTRACKED': {'connection': {'state': 'untracked'}, 'result': {'action': 'drop'}}}
    tree['firewall']['ipv4'] = {'input': {'filter': {'rule': {'10': {
        'map': 'SERVICES', 'connection': {'mark': ['1']},
    }}}}}
    assert 'ct mark' in rendered(tree)

    # Raw hooks must still reject explicitly selected tracked states.
    mapping['entry']['UNTRACKED']['connection']['state'] = 'established'
    tree['firewall']['ipv4'] = {'prerouting': {'raw': {'rule': {'10': {'map': 'SERVICES'}}}}}
    with pytest.raises(RouterError, match='tracked connection states are unavailable'):
        rendered(tree)


def test_default_normalization_and_tabulated_tracking(capsys):
    """Catch-all metadata is retained without pretending it has a typed tuple key."""
    native = {'family': 'inet', 'table': 'nvyr_filter', 'name': 'inet_map_SERVICES',
              'type': ['inet_proto', 'inet_service'], 'map': 'verdict',
              'stmt': [{'counter': None}, {'last': None}], 'elem': [[{'elem': {
                  'val': '*', 'comment': 'default|', 'counter': {'packets': 3, 'bytes': 180}, 'last': {'used': 500},
              }}, {'drop': None}]]}
    group = normalize({'nftables': [{'map': native}]})['tables']['inet']['nvyr_filter']['maps']['inet_map_SERVICES']
    entry = group['entries'][0]
    assert entry['default'] is True and entry['key'] == []
    assert entry['counter'] == {'packets': 3, 'bytes': 180}
    assert entry['result'] == {'action': 'drop'}
    assert entry['last-used'] == 0.5
    display._show_group(group, False, False)
    output = capsys.readouterr().out
    assert 'default' in output and 'drop' in output and '180' in output
    assert '[incomplete]' not in output
