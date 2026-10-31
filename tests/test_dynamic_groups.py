"""Dynamic group defaults, packet update validation and configuration references."""

from copy import deepcopy
from dataclasses import replace

import pytest

from nvyr.errors import RouterError
from nvyr.helpers.nftables_formatters import NFT_KEYMAP, nft_duration
from nvyr.helpers.validators import duration
from nvyr.schema import Schema
from tests.test_firewall_maps import rendered
from tests.test_firewall_matches import PATHS, configured


def dynamic_tree(rule=None, family='ipv4', kind='address-group', definition=None):
    if rule is None:
        rule = {'action': 'accept', 'add-to-group': {'source-address': 'G'}}
    if definition is None:
        definition = {'dynamic': {}}
    tree = configured(rule, (family, 'forward', 'filter'))
    tree['firewall']['group'] = {kind: {family: {'G': definition}}}
    return tree


def test_defaults_are_direct_and_do_not_modify_configuration():
    tree = dynamic_tree()
    original = deepcopy(tree)
    schema = Schema.bundled()
    group = schema.defaults(tree)['firewall']['group']['address-group']['ipv4']['G']
    assert group['dynamic'] == {'timeout': '10m', 'size': '65536', 'gc-interval': '30s'}
    text = rendered(tree)
    assert 'flags dynamic,timeout;' in text
    assert 'timeout 10m;' in text
    assert 'size 65536;' in text
    assert 'gc-interval 30s;' in text
    assert 'update @ipv4_address_group_G { ip saddr } accept' in text
    assert tree == original

    tree['firewall']['group']['address-group']['ipv4']['G'] = {}
    effective = schema.defaults(tree)
    assert 'dynamic' not in effective['firewall']['group']['address-group']['ipv4']['G']


@pytest.mark.parametrize('value,maximum,valid', [
    ('1s', 18446744073, True), ('45m', 18446744073, True),
    ('17h', 18446744073, True), ('123d', 18446744073, True),
    ('18446744073s', 18446744073, True), ('18446744074s', 18446744073, False),
    ('4294967s', 4294967, True), ('4294968s', 4294967, False),
    ('0s', 18446744073, False), ('-1m', 18446744073, False),
    ('1.5h', 18446744073, False), ('1ms', 18446744073, False),
    ('1h30m', 18446744073, False), ('10', 18446744073, False),
    ('1H', 18446744073, False), ('1w', 18446744073, False),
])
def test_duration_bounds_and_units(value, maximum, valid):
    assert duration(value, maximum) is valid


def test_large_durations_use_native_components():
    assert nft_duration('100000000s') == '1157d9h46m40s'
    assert nft_duration('18446744073s') == '213503d23h34m33s'


@pytest.mark.parametrize('path', PATHS + [('ipv4', 'name', 'CUSTOM'), ('ipv6', 'name', 'CUSTOM')])
@pytest.mark.parametrize('target', ['source-address', 'destination-address'])
def test_updates_on_every_firewall_path(path, target):
    tree = configured({'action': 'continue', 'add-to-group': {target: 'G', 'timeout': '2h'}}, path)
    tree['firewall']['group'] = {'address-group': {path[0]: {'G': {'dynamic': {}}}}}
    text = rendered(tree)
    expression = ('ip' if path[0] == 'ipv4' else 'ip6') + (' saddr' if target == 'source-address' else ' daddr')
    assert f'update @{path[0]}_address_group_G {{ {expression} timeout 2h }} continue' in text


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_match_group_updates_extract_declared_fields(family):
    rule = {'protocol': ['tcp'], 'action': 'accept', 'add-to-group': {'match-group': 'G'}}
    definition = {'match': {'destination-port': True, 'protocol': True, 'source-address': True}, 'dynamic': {}}
    tree = dynamic_tree(rule, family, 'match-group', definition)
    text = rendered(tree)
    address = 'ip saddr' if family == 'ipv4' else 'ip6 saddr'
    assert f'update @{family}_match_group_G {{ {address} . meta l4proto . th dport }}' in text


@pytest.mark.parametrize('update,message', [
    ({}, 'exactly one'), ({'timeout': '1m'}, 'exactly one'),
    ({'source-address': 'G', 'destination-address': 'G'}, 'exactly one'),
    ({'source-address': 'missing'}, 'not a configured'),
    ({'match-group': 'G'}, 'not a configured'),
])
def test_invalid_update_targets(update, message):
    with pytest.raises(RouterError, match=message):
        rendered(dynamic_tree({'action': 'accept', 'add-to-group': update}))


def test_static_targets_are_rejected():
    with pytest.raises(RouterError, match='requires dynamic'):
        rendered(dynamic_tree(definition={}))


@pytest.mark.parametrize('member', ['192.0.2.1', '192.0.2.0/24', '192.0.2.1/32', '192.0.2.1-192.0.2.10'])
def test_dynamic_address_groups_reject_configured_members(member):
    with pytest.raises(RouterError, match='dynamic groups cannot contain configured members'):
        rendered(dynamic_tree(definition={'dynamic': {}, 'address': [member]}))


@pytest.mark.parametrize('field,value', [('source-address', '192.0.2.1'), ('source-address', '192.0.2.0/24'), ('destination-port', '10-20'),
                                       ('packet-mark', '1-2'), ('dscp', '10-15')])
def test_dynamic_match_groups_reject_configured_members(field, value):
    definition = {'dynamic': {}, 'match': {field: True, 'protocol': True},
                  'entry': {'A': {field: value, 'protocol': 'tcp'}}}
    tree = dynamic_tree({'action': 'accept'}, kind='match-group', definition=definition)
    with pytest.raises(RouterError, match='dynamic groups cannot contain configured members'):
        rendered(tree)


@pytest.mark.parametrize('family,address', [('ipv4', '192.0.2.1'), ('ipv6', '2001:db8::1')])
@pytest.mark.parametrize('kind', ['address-group', 'match-group'])
def test_configured_members_require_static_groups(family, address, kind):
    definition = {}
    if kind == 'address-group':
        definition['address'] = [address]
    else:
        definition['match'] = {'source-address': True}
        definition['entry'] = {'A': {'source-address': address}}

    tree = dynamic_tree({'action': 'accept'}, family, kind, definition)
    rendered(tree)

    definition['dynamic'] = {}
    with pytest.raises(RouterError, match='dynamic groups cannot contain configured members'):
        rendered(tree)

    definition.pop('dynamic')
    rendered(tree)


def test_unsupported_extraction_is_rejected(monkeypatch):
    monkeypatch.setitem(NFT_KEYMAP, 'source-address', replace(NFT_KEYMAP['source-address'], dynamic=False))
    with pytest.raises(RouterError, match='dynamic updates do not support source-address'):
        rendered(dynamic_tree())


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('field', ['source-port', 'destination-port', 'icmp-type', 'icmp-code'])
def test_update_header_extraction_supplies_protocol_guard(family, field):
    definition = {'dynamic': {}, 'match': {field: True, 'protocol': True}}
    rule = {'action': 'accept', 'add-to-group': {'match-group': 'G'}}
    tree = dynamic_tree(rule, family, 'match-group', definition)
    is_port = field in {'source-port', 'destination-port'}
    protocol = 'tcp' if is_port else ('icmp' if family == 'ipv4' else 'ipv6-icmp')
    guard = 'meta l4proto { dccp, sctp, tcp, udp, udplite }' if is_port else f'meta l4proto {protocol}'
    assert f'{guard} update @{family}_match_group_G' in rendered(tree)
    assert 'protocol' not in rule

    rule['protocol'] = [protocol]
    rendered(tree)
    for protocols in (['gre'], [protocol, 'gre']):
        rule['protocol'] = protocols
        with pytest.raises(RouterError, match='require.*protocol'):
            rendered(tree)


@pytest.mark.parametrize('consumer', ['map', 'match-group'])
def test_update_rejects_contradictory_inherited_protocols(consumer):
    definition = {'dynamic': {}, 'match': {'destination-port': True, 'protocol': True}}
    rule = {'add-to-group': {'match-group': 'G'}, consumer: 'MATCH'}
    if consumer == 'match-group':
        rule['action'] = 'accept'
    tree = dynamic_tree(rule, kind='match-group', definition=definition)
    selection = {'match': {'protocol': True}, 'entry': {'one': {'protocol': 'gre'}}}
    if consumer == 'map':
        selection['result-type'] = 'verdict'
        selection['entry']['one']['result'] = {'action': 'accept'}
    tree['firewall']['group'].setdefault(consumer, {}).setdefault('ipv4', {})['MATCH'] = selection

    with pytest.raises(RouterError, match='require.*protocol'):
        rendered(tree)

    selection['entry']['one']['protocol'] = 'udp'
    assert 'meta l4proto { dccp, sctp, tcp, udp, udplite } update @ipv4_match_group_G' in rendered(tree)


def test_cli_learning_group_does_not_require_rule_protocol(controller, engine, session):
    controller.execute('set firewall group match-group ipv4 test match source-address destination-address destination-port protocol', session)
    controller.execute('set firewall group match-group ipv4 test dynamic', session)
    controller.execute('set firewall ipv4 input filter rule 10 action continue add-to-group match-group test', session)

    text = rendered(engine.view(session))
    assert 'meta l4proto { dccp, sctp, tcp, udp, udplite } update @ipv4_match_group_test' in text
    assert engine.commit(session)['results']['firewall']['success']


def test_prerouting_cannot_learn_outbound_interface():
    tree = configured({'action': 'accept', 'add-to-group': {'match-group': 'G'}}, ('ipv4', 'prerouting', 'raw'))
    tree['firewall']['group'] = {'match-group': {'ipv4': {'G': {
        'dynamic': {}, 'match': {'outbound-interface': True}}}}}
    with pytest.raises(RouterError, match='cannot extract outbound-interface'):
        rendered(tree)


def test_learning_does_not_conflict_with_explicit_or_inherited_matches():
    rule = {'source-address': {'192.0.2.1': {}}, 'add-to-group': {'source-address': 'G'}, 'map': 'M'}
    tree = dynamic_tree(rule)
    tree['firewall']['group']['map'] = {'ipv4': {'M': {
        'match': {'destination-address': True}, 'result-type': 'verdict'}}}
    assert 'update @ipv4_address_group_G' in rendered(tree)


@pytest.mark.parametrize('kind,target', [('address-group', 'source-address'), ('match-group', 'match-group')])
def test_cli_defaults_anchor_suggestors_dependencies_and_scope(controller, engine, session, kind, target):
    path = f'firewall group {kind} ipv4 G'
    if kind == 'match-group':
        controller.execute(f'set {path} match source-address', session)
    controller.execute(f'set {path} dynamic timeout 45m', session)
    controller.execute(f'set {path} dynamic size 100', session)
    controller.execute(f'set {path} dynamic gc-interval 1m', session)
    controller.execute(f'set firewall ipv4 forward filter rule 10 action accept add-to-group {target} G', session)
    controller.execute('set firewall ipv4 forward filter rule 10 add-to-group timeout 2m', session)

    command = f'set firewall ipv4 forward filter rule 20 add-to-group {target} '
    assert 'G' in dict(controller.completion(command, session)['candidates'])
    assert 'G' not in dict(controller.completion(command.replace('ipv4', 'ipv6'), session)['candidates'])
    with pytest.raises(RouterError, match='referenced'):
        controller.execute(f'delete {path}', session)
    with pytest.raises(RouterError):
        controller.execute('set nat source rule 10 add-to-group source-address G', session)
    assert engine.commit(session)['results']['firewall']['success']


@pytest.mark.parametrize('field,value', [('timeout', '18446744074s'), ('timeout', '1w'),
                                        ('gc-interval', '4294968s'), ('size', '0'),
                                        ('size', '4294967296')])
def test_schema_rejects_invalid_dynamic_options(field, value):
    tree = dynamic_tree(definition={'dynamic': {field: value}})
    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration(tree)


def test_rule_timeout_is_validated_by_the_schema():
    rule = {'action': 'accept', 'add-to-group': {'source-address': 'G', 'timeout': '0s'}}
    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration(dynamic_tree(rule))


def test_duration_rejects_excessive_integer_input_without_an_exception():
    assert not duration('9' * 5000 + 's', 18446744073)
