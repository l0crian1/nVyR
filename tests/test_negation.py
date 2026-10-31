"""Negated values use the ordinary configuration lifecycle and value grammar."""

import json
from copy import deepcopy

import pytest

from build_tools.schema_builder import SchemaBuildError, _normalize_callbacks
from nvyr.errors import RouterError
from nvyr.lexer import lex
from nvyr.render import set_commands, diff_commands
from nvyr.schema import Schema
from nvyr.tree import lookup, MISSING
from nvyr.config_scripts import firewall
from nvyr.helpers.nftables_formatters import nft_rule
from nvyr.helpers.strip_private import ConfigurationMasker
from tests.test_firewall_matches import configured
from tests.test_nftables_normalizer import rule_document, rules


RULE = 'firewall ipv4 forward filter rule 10'
PATH = tuple(RULE.split())


def test_mixed_values_and_anchor_round_trip(controller, engine, session):
    controller.execute(f'set {RULE} source-address 10.0.0.0/8 source-address not 10.20.0.0/16 '
                       'destination-port 80 destination-port not 443 protocol tcp action accept', session)
    rule = lookup(engine.view(session), PATH)
    assert rule['source-address'] == {'10.0.0.0/8': {}}
    assert rule['not'] == {'source-address': {'10.20.0.0/16': {}}, 'destination-port': ['443']}

    configuration = engine.view(session)
    commands = list(set_commands(engine.schema, configuration))
    assert f'set {RULE} source-address not 10.20.0.0/16' in commands
    assert f'set {RULE} destination-port not 443' in commands
    assert not controller.load(session, '\n'.join(commands), set_format=True, replace=True)
    assert engine.view(session) == configuration
    engine.schema.validate_configuration(configuration)


def test_negated_masks_joined_values_and_edit(controller, engine, session):
    controller.execute(f'edit {RULE}', session)
    controller.execute('set source-address not 10.1.2.3 mask 255.0.255.0', session)
    controller.execute('set connection status not confirmed and snat and dnat', session)
    controller.execute('set connection status not assured', session)
    before = engine.view(session)

    controller.execute('delete connection status not confirmed and snat and dnat', session)
    commands = list(diff_commands(engine.schema, before, engine.view(session)))
    assert commands == [f'delete {RULE} connection status not confirmed and snat and dnat']
    controller.execute('delete source-address not 10.1.2.3', session)
    assert lookup(engine.view(session), PATH + ('not', 'source-address')) is MISSING


@pytest.mark.parametrize('suffix', ['source-address not', 'source-address not nope',
                                    'connection status not confirmed and', 'protocol not typo'])
def test_invalid_negation_is_atomic(controller, session, suffix):
    before = list(session.mutations)
    with pytest.raises(RouterError):
        controller.execute(f'set {RULE} counter {suffix}', session)
    assert list(session.mutations) == before


def test_completion_keeps_values_hints_and_joining(controller, session):
    result = controller.completion(f'set {RULE} source-address ', session, explicit=True)
    assert 'not' in dict(result['candidates'])
    assert result['hints']

    result = controller.completion(f'set {RULE} source-address not ', session, explicit=True)
    assert 'not' not in dict(result['candidates'])
    assert '<Enter>' not in dict(result['candidates'])
    assert result['hints']
    result = controller.completion(f'set {RULE} source-address not 10.0.0.1 ', session, explicit=True)
    assert {'mask', '<Enter>'} <= dict(result['candidates']).keys()

    result = controller.completion(f'set {RULE} connection status not confirmed and ', session, explicit=True)
    assert 'snat' in dict(result['candidates'])
    assert 'not' not in dict(result['candidates'])


@pytest.mark.parametrize('node', [
    {'kind': 'node', 'negatable': True},
    {'kind': 'leaf_node', 'negatable': 'true'},
    {'kind': 'leaf_node', 'negatable': True, 'valueless': True},
])
def test_invalid_metadata_fails_at_build_and_runtime(node):
    with pytest.raises(SchemaBuildError, match='negatable'):
        _normalize_callbacks(node)
    with pytest.raises(ValueError, match='negatable'):
        Schema({'kind': 'node', 'children': {'value': node}})


def test_nested_negatable_nodes_resolve_their_own_variants():
    schema = Schema({'kind': 'node', 'children': {
        'object': {'kind': 'tag_node', 'negatable': True, 'children': {
            'value': {'kind': 'leaf_node', 'negatable': True},
        }},
    }})

    cursor = schema.resolve(lex('object not example value not excluded'))
    assert cursor.path == ('not', 'object', 'example', 'not', 'value')
    assert cursor.value == 'excluded'
    assert schema.resolve(cursor.path).node is cursor.node

    # A quoted literal name survives export and internal storage-path resolution.
    tree = {'object': {'not': {'value': 'literal'}}}
    assert list(set_commands(schema, tree)) == ["set object 'not' value literal"]
    assert schema.resolve(lex("object 'not' value literal")).path == ('object', 'not', 'value')
    assert schema.resolve(('object', 'not', 'value')).expect == 'value'
    assert list(diff_commands(schema, tree, {'object': {}})) == ["delete object 'not'"]


def test_dependency_deletion_and_reference_inspection_include_exclusions(controller, engine, session):
    controller.execute('set firewall group address-group ipv4 EXCLUDED address 10.0.0.1', session)
    controller.execute(f'set {RULE} source-address-group not EXCLUDED action accept', session)

    output = controller.execute('show references firewall group address-group ipv4 EXCLUDED', session)
    assert 'source-address-group not EXCLUDED' in output['text']
    with pytest.raises(RouterError, match='source-address-group not'):
        controller.execute('delete firewall group address-group ipv4 EXCLUDED', session)

    controller.execute(f'delete {RULE} source-address-group not EXCLUDED', session)
    controller.execute('delete firewall group address-group ipv4 EXCLUDED', session)
    assert 'not' not in lookup(engine.view(session), PATH)


def test_delete_whole_field_removes_both_polarities(controller, engine, session):
    controller.execute(f'set {RULE} source-address 10.0.0.1 source-address not 10.0.0.2', session)
    controller.execute(f'delete {RULE} source-address', session)
    assert lookup(engine.view(session), PATH) == {}


@pytest.mark.parametrize('field,included,excluded', [
    ('destination-port', '80', ['443', '8080', '8443']),
    ('source-address', '10.0.0.0/8', ['10.1.0.0/16', '10.2.0.0/16', '10.3.0.0/16']),
    ('connection status', 'confirmed', ['assured', 'confirmed and snat', 'confirmed and dnat']),
])
def test_delete_one_exclusion_preserves_other_values(controller, engine, session, field, included, excluded):
    # Commit several exclusions so deletion must work against running plus candidate mutations.
    controller.execute(f'set {RULE} protocol tcp action accept {field} {included}', session)
    for value in excluded:
        controller.execute(f'set {RULE} {field} not {value}', session)
    engine.commit(session)
    before = engine.view(session)

    controller.execute(f'delete {RULE} {field} not {excluded[1]}', session)
    after = engine.view(session)
    assert list(diff_commands(engine.schema, before, after)) == [
        f'delete {RULE} {field} not {excluded[1]}',
    ]

    # Only the selected exclusion disappears; positive and other negative values survive.
    commands = list(set_commands(engine.schema, after))
    assert f'set {RULE} {field} {included}' in commands
    assert f'set {RULE} {field} not {excluded[0]}' in commands
    assert f'set {RULE} {field} not {excluded[1]}' not in commands
    assert f'set {RULE} {field} not {excluded[2]}' in commands
    engine.schema.validate_configuration(after)

    # Text export and replacement load must preserve the remaining exclusions exactly.
    assert not controller.load(session, '\n'.join(commands), set_format=True, replace=True)
    assert engine.view(session) == after


def test_copy_load_privacy_and_scoped_commands(controller, engine, session):
    controller.execute(f'set {RULE} source-address not 10.1.2.3 mask 255.255.255.0 action accept', session)
    controller.execute('copy firewall ipv4 forward filter rule 10 to firewall ipv4 forward filter rule 20', session)
    configuration = engine.view(session)
    assert lookup(configuration, PATH) == lookup(configuration, PATH[:-1] + ('20',))

    assert not controller.load(session, json.dumps(configuration), replace=True)
    assert engine.view(session) == configuration
    masked = ConfigurationMasker(engine.schema).tree(configuration)
    assert '10.1.2.3' not in str(masked)

    output = controller.execute(f'show {RULE} source-address not 10.1.2.3 | commands', session)
    assert 'set mask 255.255.255.0' in output['text']


@pytest.mark.parametrize('field,included,excluded', [
    ('destination-port', '80', '443'),
    ('source-address', '10.0.0.0/8', '10.1.0.0/16'),
    ('packet-type', 'host', 'other'),
])
def test_replace_can_remove_positive_values_and_retain_exclusions(controller, engine, session, field, included, excluded):
    controller.execute(f'set {RULE} protocol tcp action accept {field} {included} {field} not {excluded}', session)
    engine.commit(session)
    replacement = deepcopy(engine.view(session))
    del lookup(replacement, PATH)[field]

    assert not controller.load(session, json.dumps(replacement), replace=True)
    assert engine.view(session) == replacement
    assert field in lookup(engine.running, PATH)


def test_quoted_not_is_a_literal_reference(controller, engine, session):
    controller.execute(f"set {RULE} source-address-group 'not'", session)
    assert lookup(engine.view(session), PATH)['source-address-group'] == 'not'
    assert list(set_commands(engine.schema, engine.view(session))) == [
        f"set {RULE} source-address-group 'not'"]


def test_notrack_abbreviation_and_scalar_consumption(controller, session):
    controller.execute('set firewall ipv4 prerouting raw rule 10 not action accept', session)
    prefix = f'set {RULE} packet-type host '
    assert 'packet-type' in dict(controller.completion(prefix, session)['candidates'])
    assert 'packet-type' not in dict(controller.completion(prefix + 'packet-type not other ', session)['candidates'])


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('field,value,expression', [
    ('state', ['new', 'related'], 'ct state != { new, related }'),
    ('connection-status', ['confirmed,snat,dnat'], 'ct status != { confirmed | dnat | snat }'),
    ('packet-type', 'host', 'meta pkttype != host'),
    ('inbound-interface', ['eth0', 'eth1'], 'iifname != { "eth0", "eth1" }'),
    ('outbound-interface', ['eth0'], 'oifname != { "eth0" }'),
    ('source-mac', {'02:11:22:33:44:55': {}}, 'ether saddr != { 02:11:22:33:44:55 }'),
    ('destination-mac', {'02:11:22:33:44:55': {'mask': 'ff:ff:00:ff:00:ff'}},
     'ether daddr & ff:ff:00:ff:00:ff != 02:11:00:33:00:55'),
    ('packet-mark', ['1', '8-16'], 'meta mark != { 1, 8-16 }'),
    ('connection-mark', ['1'], 'ct mark != { 1 }'),
    ('dscp', ['10', '30'], '{family} dscp != { 10, 30 }'),
    ('protocol', ['icmp'], 'meta l4proto != { icmp }'),
    ('source-port', ['80', '443'], 'th sport != { 443, 80 }'),
    ('destination-port', ['8000-9000'], 'th dport != { 8000-9000 }'),
    ('tcp-mss', ['1200', '1460'], 'tcp option maxseg size != { 1200, 1460 }'),
])
def test_negated_match_rendering_and_validation(family, field, value, expression):
    rule = {'action': 'accept', 'not': {field: value}}
    if field in ('state', 'connection-status', 'connection-mark'):
        rule = {'action': 'accept', 'connection': {'not': {field.removeprefix('connection-'): value}}}
    if 'port' in field or field == 'tcp-mss':
        rule['protocol'] = ['tcp']
    tree = configured(rule, (family, 'forward', 'filter'))
    Schema.bundled().validate_configuration(tree)
    firewall.verify(tree, None)
    expected = expression.replace('{family}', 'ip' if family == 'ipv4' else 'ip6')
    assert expected in nft_rule(family, 'forward', '10', rule)


def test_negative_ports_do_not_treat_excluded_protocol_as_positive():
    tree = configured({'action': 'accept', 'not': {'protocol': ['tcp'], 'destination-port': ['80']}})
    with pytest.raises(RouterError, match='requires an explicit port protocol'):
        firewall.verify(tree, None)


def test_negated_icmp_counts_masks_ttl_and_fib_constraints():
    rule = {'action': 'accept', 'protocol': ['icmp'], 'not': {'icmp-type': ['echo-request'], 'icmp-code': ['0']}}
    firewall.verify(configured(rule), None)
    assert 'icmp type != { echo-request }' in nft_rule('ipv4', 'forward', '10', rule)
    rule['not']['icmp-type'].append('echo-reply')
    with pytest.raises(RouterError, match='exactly one of each'):
        firewall.verify(configured(rule), None)

    rule = {'action': 'accept', 'ttl': {'eq': '64', 'not': {'eq': '64'}}}
    with pytest.raises(RouterError, match='only permitted value'):
        firewall.verify(configured(rule), None)

    rule = {'action': 'accept', 'fib': {'lookup': {'source-address': True},
                                      'result': {'not': {'outbound-interface': ['missing']}}}}
    with pytest.raises(RouterError, match='use exists or missing'):
        firewall.verify(configured(rule), None)


def test_positive_and_negative_groups_with_independent_fields():
    groups = {'match-group': {'ipv4': {
        'INCLUDED': {'match': {'source-address': True}, 'entry': {}},
        'EXCLUDED': {'match': {'source-address': True, 'destination-address': True}, 'entry': {}},
    }}, 'address-group': {'ipv4': {'EXTRA': {'address': ['10.0.0.1']}}}}
    rule = {'action': 'accept', 'match-group': 'INCLUDED', 'not': {'match-group': 'EXCLUDED'}}
    tree = configured(rule)
    tree['firewall']['group'] = groups
    firewall.verify(tree, None)
    text = nft_rule('ipv4', 'forward', '10', rule, match_groups=groups['match-group']['ipv4'])
    assert 'ip saddr == @ipv4_match_group_INCLUDED' in text
    assert 'ip saddr . ip daddr != @ipv4_match_group_EXCLUDED' in text

    rule['not'] = {'source-address-group': 'EXTRA'}
    firewall.verify(tree, None)
    assert 'ip saddr != @ipv4_address_group_EXTRA' in nft_rule('ipv4', 'forward', '10', rule, match_groups=groups['match-group']['ipv4'])


def test_map_key_can_have_an_additional_negative_match():
    mapping = {'match': {'source-address': True}, 'result-type': 'verdict',
               'entry': {'one': {'source-address': '10.0.0.0/8', 'result': {'action': 'accept'}}}}
    rule = {'map': 'POLICY', 'not': {'source-address': {'10.1.0.0/16': {}}}}
    tree = configured(rule)
    tree['firewall']['group'] = {'map': {'ipv4': {'POLICY': mapping}}}

    firewall.verify(tree, None)
    text = nft_rule('ipv4', 'forward', '10', rule, maps={'POLICY': mapping})
    assert text.index('ip saddr != { 10.1.0.0/16 }') < text.index('ip saddr vmap @ipv4_map_POLICY')


def test_normalizer_preserves_both_polarities_and_detail_output(capsys):
    from nvyr.op_scripts.firewall import _rule_detail

    document = rule_document(
        {'match': {'op': '==', 'left': {'meta': {'key': 'mark'}}, 'right': 1}},
        {'match': {'op': '!=', 'left': {'meta': {'key': 'mark'}}, 'right': {'set': [2, 3]}}},
        {'match': {'op': '!=', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': '10.0.0.1'}},
        {'accept': None},
    )
    rule = rules(document)['10']
    assert rule['packet-mark'] == [1]
    assert rule['not']['packet-mark'] == [2, 3]
    assert rule['not']['source-address'] == {'10.0.0.1': {}}
    assert 'unsupported' not in rule

    _rule_detail(rule, False)
    output = capsys.readouterr().out
    assert 'Packet mark (not)' in output
    assert 'Source address (not)' in output
