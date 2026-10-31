"""Firewall match schema, cross-field checks, rendering, and CLI integration."""

import copy

import pytest

from nvyr.config_scripts import firewall
from tests.lifecycle import firewall_context
from nvyr.errors import ValidationError
from nvyr.helpers import validators
from nvyr.helpers.nftables_formatters import nft_rule
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree, lookup


PATHS = [('ipv4', 'input', 'filter'), ('ipv4', 'forward', 'filter'),
         ('ipv4', 'output', 'filter'), ('ipv6', 'input', 'filter'),
         ('ipv6', 'forward', 'filter'), ('ipv6', 'output', 'filter'),
         ('ipv4', 'prerouting', 'raw'), ('ipv6', 'prerouting', 'raw'),
         ('ipv4', 'output', 'raw'), ('ipv6', 'output', 'raw')]


def configured(rule, path=('ipv4', 'forward', 'filter')):
    family, hook, stage = path
    return {'firewall': {family: {hook: {stage: {'rule': {'10': rule}}}}}}


@pytest.fixture(scope='module')
def schema():
    return Schema.bundled()


@pytest.mark.parametrize('path', PATHS)
def test_multi_matches_and_masks_available_on_all_firewall_rules(schema, path):
    version = 4 if path[0] == 'ipv4' else 6
    rule = {'action': 'accept', 'packet-mark': ['0', '12-20', '4294967295'], 'connection': {'mark': ['1-8', '42']}, 'dscp': ['0', '8-16', '63'], 'tcp-mss': ['0', '536-1400', '1460', '65535'], 'source-mac': {'ff:ff:ff:ff:ff:ff': {}, '01:00:5e:00:00:01': {}}, 'destination-mac': {'00:11:22:33:44:55': {'mask': 'ff:ff:00:ff:00:ff'}}, 'source-address': {('192.0.2.129' if version == 4 else '2001:db8::1234'):
                               {'mask': '255.0.255.0' if version == 4 else 'ffff:0:ffff::ffff'}}}
    original = copy.deepcopy(rule)
    tree = configured(rule, path)
    schema.validate_configuration(tree)
    effective = ReadOnlyTree(schema.defaults(tree))
    if path[2] == 'raw':
        with pytest.raises(ValidationError, match='before connection tracking'):
            firewall.verify(effective, None)
        return

    firewall.verify(effective, None)
    context = firewall_context(effective, ReadOnlyTree({}), 'firewall', ('firewall',),
                            previous_effective=ReadOnlyTree({}), schema=schema)
    rendered = firewall.generate(effective, context)

    for expression in ('meta mark { 0, 12-20, 4294967295 }', 'ct mark { 1-8, 42 }',
                       ('ip' if version == 4 else 'ip6') + ' dscp { 0, 63, 8-16 }',
                       'tcp option maxseg size { 0, 1460, 536-1400, 65535 }',
                       'ether saddr { 01:00:5e:00:00:01, ff:ff:ff:ff:ff:ff }',
                       'ether daddr & ff:ff:00:ff:00:ff == 00:11:00:33:00:55'):
        assert expression in rendered

    assert 'maxseg size set' not in rendered
    assert rule == original


@pytest.mark.parametrize('field,maximum', [('packet-mark', 4294967295),
    ('connection-mark', 4294967295), ('dscp', 63), ('tcp-mss', 65535)])
def test_numeric_match_validation(schema, field, maximum):
    def rule(value):
        matches = {'connection': {'mark': value}} if field == 'connection-mark' else {field: value}
        return configured({'action': 'accept', **matches})

    for value in ['0', str(maximum), f'0-{maximum}', '1-1']:
        schema.validate_configuration(rule([value]))

    for value in ['-1', str(maximum + 1), f'0-{maximum + 1}', '2-1', '1-', '-2',
                  '1-2-3', '1.5', '1; drop', '01', '0-01', '-0', '0x10']:
        with pytest.raises(ValidationError):
            schema.validate_configuration(rule([value]))

    with pytest.raises(ValidationError):
        schema.validate_configuration(rule('1'))


@pytest.mark.parametrize('field', ['source-address', 'destination-address',
                                 'source-mac', 'destination-mac'])
@pytest.mark.parametrize('path', PATHS)
def test_each_mask_requires_exactly_one_corresponding_address(field, path):
    address = ('00:11:22:33:44:55' if 'mac' in field else
               '192.0.2.1' if path[0] == 'ipv4' else '2001:db8::1')
    mask = ('ff:ff:ff:00:00:00' if 'mac' in field else
            '255.255.255.0' if path[0] == 'ipv4' else 'ffff:ffff:ffff:ffff::')
    other = ('00:11:22:33:44:66' if 'mac' in field else
             '192.0.2.2' if path[0] == 'ipv4' else '2001:db8::2')
    rule = {'action': 'accept', field: {address: {'mask': mask}}}
    firewall.verify(ReadOnlyTree(configured(rule, path)), None)

    for matches in ({address: {'mask': mask}, other: {}},
                    {other: {}, address: {'mask': mask}},
                    {address: {'mask': mask}, other: {'mask': mask}}):
        rule[field] = matches

        with pytest.raises(ValidationError, match=f'{field} mask requires exactly one {field}') as error:
            firewall.verify(ReadOnlyTree(configured(rule, path)), None)

        assert 'firewall ' + ' '.join(path) + ' rule 10:' in str(error.value)

    rule[field] = {address: {}, other: {}}
    firewall.verify(ReadOnlyTree(configured(rule, path)), None)
    rendered = nft_rule(path[0], path[1], '10', rule)

    assert '{ ' + ', '.join(sorted((address, other))) + ' }' in rendered

    rule[field][address]['mask'] = mask
    rule['disable'] = True
    firewall.verify(ReadOnlyTree(configured(rule, path)), None)

    assert nft_rule(path[0], path[1], '10', rule) == ''


@pytest.mark.parametrize('field,values', [
    ('source-address', {'192.0.2.1': {'mask': '2001:db8::'}}),
    ('destination-address', {'192.0.2.1': {'mask': '255.255.255.0/24'}}),
    ('source-mac', {'00:11:22:33:44:55': {'mask': 'ffff'}}),
    ('destination-mac', {'invalid': {}}),
    ('source-address', {'mask': '255.255.255.0'}),
])
def test_invalid_masks_and_addresses_rejected(schema, field, values):
    with pytest.raises(ValidationError):
        schema.validate_configuration(configured({'action': 'accept', field: values}))


def test_reusable_validators_preserve_existing_constraints():
    assert validators.integer_range('-3--1', -10, 10, allow_range=True)
    assert not validators.integer_range('1-2', 0, 10)
    assert validators.integer_range('01', 0, 10)

    for address in ['ff:ff:ff:ff:ff:ff', '01:00:5e:00:00:01', '00:00:00:00:00:00']:
        assert validators.mac(address, unicast=False)
        assert not validators.mac(address)

    assert validators.mac('02:00:00:00:00:01')


@pytest.mark.parametrize('family,address,mask,expected', [
    ('ipv4', '192.0.2.129', '255.0.255.0', 'ip saddr & 255.0.255.0 == 192.0.2.0'),
    ('ipv4', '192.0.2.129/24', '255.255.0.255', 'ip saddr & 255.255.0.0 == 192.0.0.0'),
    ('ipv6', '2001:db8::1234', 'ffff:0:ffff::ffff', 'ip6 saddr & ffff:0:ffff::ffff == 2001::1234'),
    ('ipv6', '2001:db8::1234/64', 'ffff:0:ffff::ffff', 'ip6 saddr & ffff:0:ffff:: == 2001::'),
])
def test_mask_normalization_and_prefix_intersection(family, address, mask, expected):
    rule = {'action': 'drop', 'source-address': {address: {'mask': mask}}}

    assert nft_rule(family, 'forward', '10', rule) == expected + ' drop comment "10|"'


def test_tcp_mss_protocol_dependency():
    for protocols in ([], ['tcp']):
        firewall.verify_rule({'action': 'accept', 'tcp-mss': ['1460'], 'protocol': protocols}, ('rule', '10'), {})

    for protocols in (['udp'], ['icmp'], ['ipv6-icmp'], ['tcp', 'udp']):
        with pytest.raises(ValidationError, match='tcp-mss requires protocol tcp'):
            firewall.verify_rule({'action': 'accept', 'tcp-mss': ['1460'], 'protocol': protocols}, ('rule', '10'), {})


def test_cli_anchoring_completion_and_failed_mask_commit(controller, engine, session):
    prefix = 'firewall ipv4 forward filter rule 10'
    controller.execute('set ' + prefix + ' action accept packet-mark 10 packet-mark 20-30 dscp 8-16 tcp-mss 1460', session)
    options = dict(controller.completion('set ' + prefix + ' ', session, explicit=True)['candidates'])

    assert {'packet-mark', 'connection', 'dscp', 'tcp-mss', 'source-address',
            'destination-mac'} <= options.keys()
    assert not any(name.endswith('-mask') or name.endswith('-mac-address') for name in options)
    assert engine.commit(session)['results']['firewall']['success']

    path = tuple(prefix.split())

    assert lookup(engine.running, (*path, 'packet-mark')) == ['10', '20-30']

    controller.execute('set ' + prefix + ' source-address 192.0.2.1 mask 255.255.255.0 source-address 192.0.2.2', session)
    result = engine.commit(session)

    assert 'source-address mask requires exactly one source-address' in result['results']['firewall']['error']
    assert 'source-address' not in lookup(engine.running, path)

    controller.execute('delete ' + prefix + ' source-address 192.0.2.2', session)

    assert engine.commit(session)['results']['firewall']['success']
    assert lookup(engine.running, (*path, 'source-address')) == {'192.0.2.1': {'mask': '255.255.255.0'}}

    options = dict(controller.completion('set ' + prefix + ' source-address 192.0.2.1 ', session, explicit=True)['candidates'])

    assert 'mask' in options

    controller.execute('delete ' + prefix + ' source-address 192.0.2.1 mask', session)

    assert engine.commit(session)['results']['firewall']['success']
    assert lookup(engine.running, (*path, 'source-address')) == {'192.0.2.1': {}}

    controller.execute('delete ' + prefix + ' source-address 192.0.2.1', session)

    assert engine.commit(session)['results']['firewall']['success']
    assert lookup(engine.running, (*path, 'source-address')) == {}

    effective = ReadOnlyTree(engine.schema.defaults(engine.running))
    context = firewall_context(effective, ReadOnlyTree({}), 'firewall', ('firewall',),
                            previous_effective=ReadOnlyTree({}), schema=engine.schema)

    assert 'saddr' not in firewall.generate(effective, context)


@pytest.mark.parametrize('path', PATHS)
def test_protocol_all_removed_from_firewall(schema, path):
    with pytest.raises(ValidationError, match="Invalid value 'all'"):
        schema.validate_configuration(configured({'action': 'accept', 'protocol': ['all']}, path))


@pytest.mark.parametrize('direction', ['source', 'destination'])
def test_protocol_all_removed_from_nat(schema, direction):
    with pytest.raises(ValidationError, match="Invalid value 'all'"):
        schema.validate_configuration({'nat': {direction: {'rule': {'10': {
            'exclude': True, 'protocol': ['all']}}}}})


@pytest.mark.parametrize('field', ['source-address', 'destination-address', 'source-mac', 'destination-mac'])
def test_empty_address_collection_has_no_match_expression(field):
    assert nft_rule('ipv4', 'input', '10', {'action': 'accept', field: {}}) == 'accept comment "10|"'


@pytest.mark.parametrize('family,field,address,mask', [
    ('ipv4', 'source-address', '192.0.2.1', '255.255.255.0'),
    ('ipv6', 'destination-address', '2001:db8::1', 'ffff:ffff:ffff:ffff::'),
    ('ipv4', 'source-mac', '11:22:33:44:55:66', 'ff:ff:ff:00:00:00'),
    ('ipv6', 'destination-mac', '11:22:33:44:55:66', 'ff:ff:ff:00:00:00'),
])
def test_address_tags_in_edit_context_completion_and_private_output(controller, engine, session,
                                                                    family, field, address, mask):
    prefix = f'firewall {family} input filter rule 10'
    controller.execute('set ' + prefix + ' action accept', session)
    controller.execute('edit ' + prefix, session)
    controller.execute(f'set {field} {address} mask {mask} log', session)

    assert lookup(engine.view(session), (*prefix.split(), field, address)) == {'mask': mask}
    assert lookup(engine.view(session), (*prefix.split(), 'log')) == {}

    completion = controller.completion(f'set {field} {address} ', session, explicit=True)

    assert {'mask', 'action', 'log', '<Enter>'} <= dict(completion['candidates']).keys()

    for mode in ({'tab': True}, {'space': True}, {}):
        result = controller.completion(f'set {field} {address} ma', session, **mode)

        assert result['replacement'] == 'mask'

    text = controller.execute('show candidate-configuration | commands', session)['text']

    assert f'set {field} {address} mask {mask}' in text

    private = controller.execute('show candidate-configuration | commands | strip-private', session)['text']

    assert address not in private
    assert lookup(engine.view(session), (*prefix.split(), field, address)) == {'mask': mask}

    before = list(session.mutations)

    with pytest.raises(ValidationError):
        controller.execute(f'set {field} {address} mask action accept', session)

    assert session.mutations == before
