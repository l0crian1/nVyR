"""ICMP names, individual codes, map tuples, and independent consuming matches."""

from copy import deepcopy

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import RouterError
from nvyr.helpers.nftables_formatters import nft_field_type, nft_map, nft_rule
from nvyr.helpers.validators import ICMP_TYPES
from nvyr.schema import Schema
from tests.test_firewall_maps import rendered
from tests.test_firewall_matches import PATHS, configured


@pytest.mark.parametrize('path', PATHS + [('ipv4', 'name', 'CUSTOM'), ('ipv6', 'name', 'CUSTOM')])
def test_icmp_options_on_every_firewall_rule(path):
    protocol = 'icmp' if path[0] == 'ipv4' else 'ipv6-icmp'
    rule = {'action': 'accept', 'protocol': [protocol], 'icmp-type': ['echo-request'], 'icmp-code': ['0']}
    text = rendered(configured(rule, path))
    expression = 'icmp' if path[0] == 'ipv4' else 'icmpv6'
    assert f'{expression} type {{ echo-request }} {expression} code {{ 0 }}' in text

    del rule['protocol']
    with pytest.raises(RouterError, match='requires protocol ' + protocol):
        rendered(configured(rule, path))


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_all_named_types_and_numeric_choice_descriptions(controller, session, family):
    path = f'set firewall {family} input filter rule 10 icmp-type '
    choices = dict(controller.completion(path, session)['candidates'])
    for name, number in ICMP_TYPES[family].items():
        assert f'(type {number})' in choices[name]
        controller.execute(path + name, session)

    rule = controller.engine.view(session)['firewall'][family]['input']['filter']['rule']['10']
    assert set(rule['icmp-type']) == set(ICMP_TYPES[family])


@pytest.mark.parametrize('family,value', [
    ('ipv4', '8'), ('ipv6', '128'), ('ipv4', 'nd-router-solicit'),
    ('ipv6', 'timestamp-request'), ('ipv4', 'echo-reqest'), ('ipv6', 'bogus'),
])
def test_type_validation_rejects_numbers_wrong_family_and_typos(family, value):
    tree = configured({'action': 'accept', 'icmp-type': [value]}, (family, 'input', 'filter'))
    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration(tree)


@pytest.mark.parametrize('value', ['-1', '256', '0-3', 'port-unreachable', '1.5'])
def test_code_validation_accepts_only_individual_bytes(value):
    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration(configured({'icmp-code': [value]}))


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('matches', [
    {'icmp-type': ['echo-request', 'echo-reply']},
    {'icmp-code': ['0', '1', '255']},
    {'icmp-type': ['echo-request'], 'icmp-code': ['0']},
])
def test_rule_lists_and_single_type_code_pair(family, matches):
    protocol = 'icmp' if family == 'ipv4' else 'ipv6-icmp'
    rule = {'action': 'accept', 'protocol': [protocol], **matches}
    original = deepcopy(rule)
    text = rendered(configured(rule, (family, 'forward', 'filter')))
    assert ('icmpv6' if family == 'ipv6' else 'icmp') in text
    assert rule == original


@pytest.mark.parametrize('matches,message', [
    ({'icmp-type': ['echo-request', 'echo-reply'], 'icmp-code': ['0']}, 'exactly one'),
    ({'icmp-type': ['echo-request'], 'icmp-code': ['0', '1']}, 'exactly one'),
    ({'icmp-type': ['echo-request'], 'protocol': ['tcp']}, 'requires protocol'),
    ({'icmp-code': ['0'], 'protocol': ['icmp', 'udp']}, 'requires protocol'),
    ({'icmp-type': ['echo-request'], 'destination-port': ['53']}, 'cannot be combined'),
    ({'icmp-type': ['echo-request'], 'tcp-mss': ['1460']}, 'cannot be combined'),
])
def test_rule_icmp_cross_field_checks(matches, message):
    with pytest.raises(RouterError, match=message):
        rendered(configured({'action': 'accept', **matches}))


@pytest.mark.parametrize('family,protocol', [('ipv4', 'icmp'), ('ipv6', 'ipv6-icmp')])
def test_explicit_icmp_protocol(family, protocol):
    rendered(configured({'action': 'accept', 'protocol': [protocol], 'icmp-code': ['0']},
                        (family, 'input', 'filter')))


def icmp_map(family='ipv4'):
    protocol = 'icmp' if family == 'ipv4' else 'ipv6-icmp'
    return {'match': {'protocol': True, 'icmp-type': True, 'icmp-code': True}, 'result-type': 'verdict',
            'entry': {'ECHO': {'protocol': protocol, 'icmp-type': 'echo-request', 'icmp-code': '0',
                               'result': {'action': 'drop'}}}}


@pytest.mark.parametrize('family,datatype', [('ipv4', 'icmp'), ('ipv6', 'icmpv6')])
def test_map_scalar_fields_native_types_and_unrelated_rule_matches(family, datatype):
    mapping = icmp_map(family)
    rule = {'map': 'M', 'outbound-interface': ['eth0'], 'ttl': {'gt': '1'}, 'counter': {}}
    tree = configured(rule, (family, 'output', 'filter'))
    tree['firewall']['group'] = {'map': {family: {'M': mapping}}}
    text = rendered(tree)

    assert nft_field_type('icmp-type', family) == (datatype + '_type', 1)
    assert nft_field_type('icmp-code', family) == (datatype + '_code', 1)
    assert f'type inet_proto . {datatype}_type . {datatype}_code : verdict;' in text
    assert 'echo-request . 0 comment "ECHO|" : drop' in text
    assert text.index('oifname { "eth0" }') < text.index(f'vmap @{family}_map_M')
    assert 'counter ' in text

    mapping['entry']['ECHO']['icmp-type'] = ['echo-request']
    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration(tree)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_map_protocol_must_agree_with_icmp_fields(family):
    mapping = icmp_map(family)
    mapping['match']['protocol'] = True
    mapping['entry']['ECHO']['protocol'] = 'udp'
    with pytest.raises(RouterError, match='requires protocol'):
        firewall.verify_map(family, 'M', mapping, {})


def test_map_aliases_cannot_create_duplicate_wire_keys():
    mapping = icmp_map('ipv6')
    mapping['entry']['ECHO']['icmp-type'] = 'mld-listener-done'
    mapping['entry']['OTHER'] = deepcopy(mapping['entry']['ECHO'])
    mapping['entry']['OTHER']['icmp-type'] = 'mld-listener-reduction'
    with pytest.raises(RouterError, match='duplicate or overlapping'):
        firewall.verify_map('ipv6', 'M', mapping, {})


@pytest.mark.parametrize('rule,message', [
    ({'ttl': {'gt': '255'}}, 'cannot match'),
    ({'destination-port': ['53']}, 'cannot be combined'),
    ({'protocol': ['tcp']}, 'cannot be combined'),
    ({'tcp-mss': ['1460']}, 'cannot be combined'),
    ({'source-address': {'192.0.2.1': {'mask': '255.255.0.0'}, '192.0.2.2': {}}}, 'exactly one'),
    ({'connection': {'status': ['offload']}}, 'requires confirmed'),
])
def test_map_consumers_still_validate_ordinary_matches(rule, message):
    path = ('firewall', 'ipv4', 'forward', 'filter', 'rule', '10')
    with pytest.raises(RouterError, match=message):
        firewall.verify_rule({'map': 'M', **rule}, path, {}, maps={'M': icmp_map()})


def test_cardinality_accounts_for_type_or_code_from_map():
    mapping = icmp_map()
    del mapping['match']['icmp-type']
    del mapping['entry']['ECHO']['icmp-type']
    rule = {'map': 'M', 'icmp-type': ['echo-request', 'echo-reply']}
    path = ('firewall', 'ipv4', 'forward', 'filter', 'rule', '10')
    with pytest.raises(RouterError, match='exactly one'):
        firewall.verify_rule(rule, path, {}, maps={'M': mapping})

    rule['icmp-type'] = ['echo-request']
    firewall.verify_rule(rule, path, {}, maps={'M': mapping})


def test_numeric_code_rendering_uses_decimal():
    mapping = icmp_map()
    mapping['entry']['ECHO']['icmp-code'] = '010'
    assert 'echo-request . 10 comment' in nft_map('ipv4', 'M', mapping)
    assert 'icmp code { 10 }' in nft_rule('ipv4', 'input', '10', {'action': 'accept', 'icmp-code': ['010']})


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('field,value', [('icmp-type', 'echo-request'), ('icmp-code', '0')])
@pytest.mark.parametrize('protocols', [None, [], ['tcp'], ['icmp', 'ipv6-icmp']])
def test_icmp_rule_requires_only_its_family_protocol(family, field, value, protocols):
    rule = {'action': 'accept', field: [value]}
    if protocols is not None:
        rule['protocol'] = protocols

    path = ('firewall', family, 'input', 'filter', 'rule', '10')
    protocol = 'icmp' if family == 'ipv4' else 'ipv6-icmp'
    with pytest.raises(RouterError, match='requires protocol ' + protocol):
        firewall.verify_rule(rule, path, {})


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('field', ['icmp-type', 'icmp-code'])
@pytest.mark.parametrize('populated', [False, True])
def test_icmp_map_requires_protocol_key_even_when_empty(family, field, populated):
    value = 'echo-request' if field == 'icmp-type' else '0'
    mapping = {'match': {field: True}, 'result-type': 'verdict'}
    if populated:
        mapping['entry'] = {'A': {field: value, 'result': {'action': 'accept'}}}

    with pytest.raises(RouterError, match='requires protocol in the map match fields'):
        firewall.verify_map(family, 'M', mapping, {})


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_empty_icmp_map_with_declared_protocol_key_remains_valid(family):
    mapping = icmp_map(family)
    mapping['entry'].clear()
    firewall.verify_map(family, 'M', mapping, {})
    path = ('firewall', family, 'input', 'filter', 'rule', '10')
    firewall.verify_rule({'map': 'M'}, path, {}, maps={'M': mapping})
