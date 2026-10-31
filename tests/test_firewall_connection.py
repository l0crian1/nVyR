"""Conntrack matches keep packet fields, stored tuples and accounting distinct."""

from copy import deepcopy
from pathlib import Path

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import nftables
from nvyr.helpers.nftables_formatters import (
    connection_label_plan, nft_connection_labels, nft_group_fields,
)
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.helpers.validators import connection_quantity
from tests.test_firewall_maps import rendered


def configuration(connection, *, accounting=False, family='ipv4', hook='forward', stage='filter'):
    tree = {'firewall': {family: {hook: {stage: {'rule': {
        '10': {'action': 'accept', 'connection': connection},
    }}}}}}
    if accounting:
        tree['firewall']['global-options'] = {'connection-accounting': True}
    return tree


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('connection,error', [
    ({}, 'connection requires at least one'),
    ({'original': {}}, 'connection original requires at least one'),
    ({'reply': {}}, 'connection reply requires at least one'),
    ({'total': {}}, 'connection total requires at least one'),
    ({'state': ['established'], 'original': {}}, 'connection original requires at least one'),
    ({'expiration': {}}, 'requires eq, lt or gt'),
])
def test_empty_connection_sections_are_rejected(connection, error, family):
    with pytest.raises(RouterError, match=error):
        rendered(configuration(connection, family=family))


def test_connection_limit_without_other_metadata_is_valid():
    text = rendered(configuration({'limit': {'over': '5'}}))

    assert 'ct count over 5' in text


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('field,error', [
    ('connection', 'connection requires at least one'),
    ('fib', 'lookup requires exactly one'),
])
def test_empty_rule_match_blocks_check_and_commit(controller, engine, session, family, field, error):
    rule_path = f'firewall {family} forward filter rule 10'
    controller.execute(f'set {rule_path} action accept {field}', session)

    for result in (engine.check(session), engine.commit(session)):
        assert result['results']['firewall']['success'] is False
        assert error in result['results']['firewall']['error']

    assert 'firewall' not in engine.running

    # A standalone log node has meaningful behavior and remains valid.
    controller.execute(f'delete {rule_path} {field}', session)
    controller.execute(f'set {rule_path} log', session)
    assert engine.commit(session)['results']['firewall']['success'] is True


def test_connection_cli_anchor_negation_and_individual_delete(controller, engine, session):
    controller.execute('set firewall ipv4 forward filter rule 10 action accept connection '
                       'protocol tcp original destination-address 203.0.113.1 destination-port 443', session)
    controller.execute('set firewall ipv4 forward filter rule 10 connection label 1 and 2', session)
    controller.execute('set firewall ipv4 forward filter rule 10 connection label not 3 and 4', session)
    controller.execute('set firewall ipv4 forward filter rule 10 connection label not 5', session)
    controller.execute('delete firewall ipv4 forward filter rule 10 connection label not 3 and 4', session)

    connection = engine.view(session)['firewall']['ipv4']['forward']['filter']['rule']['10']['connection']
    assert connection['original'] == {'destination-address': ['203.0.113.1'], 'destination-port': ['443']}
    assert connection['label'] == ['1,2']
    assert connection['not']['label'] == ['5']

    completion = controller.completion(
        'set firewall ipv4 forward filter rule 10 connection label 1 and ', session,
        explicit=True)
    assert '0-127' in dict(completion['hints'])


def test_connection_fields_render_without_changing_input():
    connection = {
        'state': ['established'], 'status': ['confirmed'], 'mark': ['10-20'],
        'direction': ['original'], 'family': ['ipv4'], 'protocol': ['tcp'],
        'zone': ['0-2'], 'id': ['100'], 'helper': ['ftp'], 'expiration': {'gt': '30s'},
        'original': {'source-address': ['192.0.2.0/24'], 'destination-port': ['443'],
                     'packets': {'gt': '10'}, 'zone': ['0']},
        'reply': {'not': {'destination-address': ['198.51.100.1']}, 'bytes': {'lt': '1m'}},
        'total': {'average-packet-size': {'eq': '1k'}},
    }
    before = deepcopy(connection)
    text = rendered(configuration(connection, accounting=True))

    for expression in (
        'ct state { established }', 'ct status == { confirmed }', 'ct mark { 10-20 }',
        'ct direction { original }', 'ct l3proto { ipv4 }', 'ct protocol { tcp }',
        'ct zone { 0-2 }', 'ct id { 100 }', 'ct helper { "ftp" }', 'ct expiration > 30s',
        'ct original ip saddr { 192.0.2.0/24 }', 'ct original proto-dst { 443 }',
        'ct original packets > 10', 'ct original zone { 0 }',
        'ct reply ip daddr != { 198.51.100.1 }', 'ct reply bytes < 1048576',
        'ct avgpkt == 1024',
    ):
        assert expression in text
    assert connection == before


@pytest.mark.parametrize('connection,error', [
    ({'original': {'destination-port': ['443']}}, 'connection ports require'),
    ({'protocol': ['icmp'], 'original': {'destination-port': ['443']}}, 'connection ports require'),
    ({'family': ['ipv6']}, 'connection family must be ipv4'),
    ({'state': ['untracked'], 'mark': ['1']}, 'untracked'),
    ({'expiration': {'eq': '10s', 'lt': '20s'}}, 'eq cannot'),
    ({'original': {'bytes': {'gt': '10', 'lt': '11'}}}, 'cannot match'),
    ({'total': {'packets': {'lt': '0'}}}, 'cannot match'),
    ({'total': {'bytes': {'eq': '1k', 'not': {'eq': '1024'}}}}, 'only matching'),
    ({'label': ['1,2'], 'not': {'label': ['1']}}, 'all excluded'),
])
def test_invalid_connection_combinations(connection, error):
    with pytest.raises(RouterError, match=error):
        rendered(configuration(connection, accounting=True))


def test_accounting_is_explicit_and_raw_metadata_is_rejected():
    with pytest.raises(RouterError, match='connection-accounting'):
        rendered(configuration({'total': {'packets': {'gt': '0'}}}))

    with pytest.raises(RouterError, match='before connection tracking'):
        rendered(configuration({'mark': ['1']}, hook='prerouting', stage='raw'))

    assert 'ct state { untracked }' in rendered(
        configuration({'state': ['untracked']}, hook='prerouting', stage='raw'))

    # The lifetime between whole seconds still contains valid millisecond values.
    assert 'ct expiration > 1s' in rendered(configuration({'expiration': {'gt': '1s', 'lt': '2s'}}))


def test_nested_jump_checks_connection_metadata_at_each_entrypoint():
    tree = {'firewall': {'ipv4': {
        'prerouting': {'raw': {'rule': {'1': {'action': 'jump', 'jump-target': 'FIRST'}}}},
        'name': {
            'FIRST': {'rule': {'1': {'action': 'jump', 'jump-target': 'SECOND'}}},
            'SECOND': {'rule': {'1': {'action': 'accept', 'connection': {'mark': ['1']}}}},
        },
    }}}
    with pytest.raises(RouterError, match='before connection tracking'):
        rendered(tree)


@pytest.mark.parametrize('kind,value,expected', [
    ('packets', '18446744073709551615', 2**64 - 1),
    ('bytes', '1g', 1024**3), ('expiration', '1d', 86400),
    ('expiration', '4294967s', 4294967),
])
def test_connection_quantity_boundaries(kind, value, expected):
    assert connection_quantity(value, kind) == expected


@pytest.mark.parametrize('kind,value', [
    ('packets', str(2**64)), ('packets', '1k'), ('bytes', '-1'),
    ('expiration', '4294968s'), ('expiration', '1'), ('bytes', '1;accept'),
])
def test_invalid_connection_quantities(kind, value):
    with pytest.raises(ValueError):
        connection_quantity(value, kind)


def test_labels_allow_unrelated_bits_and_bound_complex_expansion():
    assert nft_connection_labels(['0,127']) == 'ct label & (0 | 127) == (0 | 127)'
    assert nft_connection_labels(['1', '2']) == 'ct label 1,2'
    assert nft_connection_labels(['1', '2'], negative=True) == 'ct label & 1 != 1 ct label & 2 != 2'
    assert connection_label_plan(['0,1', '2']) == ('set', 7, [3, 4, 5, 6, 7])
    assert connection_label_plan(['0', '0,1'])[0] == 'all'

    # Many simple alternatives remain compact; the cap is on expanded values.
    assert connection_label_plan([str(bit) for bit in range(128)])[0] == 'any'
    with pytest.raises(RouterError, match='4096'):
        rendered(configuration({'label': ['0,1', ','.join(str(bit) for bit in range(2, 16))]}))


def test_connection_group_uses_nested_keys_and_typeof_only_when_needed():
    definition = {
        'match': {'connection': {'protocol': True, 'original': {'destination-address': True, 'destination-port': True}}},
        'result-type': 'verdict',
        'entry': {'WEB': {'connection': {'protocol': 'tcp', 'original': {
            'destination-address': '203.0.113.1', 'destination-port': '443',
        }}, 'result': {'action': 'accept'}}},
    }
    tree = {'firewall': {'group': {'map': {'ipv4': {'PUBLIC': definition}}}}}
    assert 'type inet_proto . ipv4_addr . inet_service : verdict' in rendered(tree)
    assert nft_group_fields(definition) == [
        'connection-protocol', 'connection-original-destination-address', 'connection-original-destination-port',
    ]

    definition['match'] = {'connection': {'helper': True, 'id': True}}
    definition['entry']['WEB']['connection'] = {'helper': 'ftp', 'id': '42'}
    assert 'typeof ct helper . ct id : verdict' in rendered(tree)


def test_group_conflicts_only_with_same_connection_fields():
    definition = {'match': {'connection': {'mark': True}}, 'entry': {'ONE': {'connection': {'mark': '1'}}}}
    tree = configuration({'mark': ['1']})
    tree['firewall']['group'] = {'match-group': {'ipv4': {'MARKS': definition}}}
    rule = tree['firewall']['ipv4']['forward']['filter']['rule']['10']
    rule['match-group'] = 'MARKS'
    with pytest.raises(RouterError, match='connection-mark'):
        rendered(tree)

    rule['connection'] = {'direction': ['original']}
    rule['packet-mark'] = ['1']
    assert 'ct mark == @ipv4_match_group_MARKS' in rendered(tree)


def test_normalizer_connection_directions_comparisons_labels():
    expressions = [
        {'match': {'op': '==', 'left': {'ct': {'key': 'ip daddr', 'dir': 'original'}}, 'right': '203.0.113.1'}},
        {'match': {'op': '>', 'left': {'ct': {'key': 'packets', 'dir': 'reply'}}, 'right': 10}},
        {'match': {'op': '<', 'left': {'ct': {'key': 'expiration'}}, 'right': 30}},
        {'match': {'op': '==', 'left': {'&': [{'ct': {'key': 'label'}}, {'|': [0, 1]}]}, 'right': {'|': [0, 1]}}},
    ]
    document = {'nftables': [{'rule': {
        'family': 'inet', 'table': 'nvyr_filter', 'chain': 'ipv4_forward', 'expr': expressions,
    }}]}
    rule = normalize(document)['tables']['inet']['nvyr_filter']['chains']['ipv4_forward']['rules'][0]
    assert rule['connection-original-destination-address'] == ['203.0.113.1']
    assert rule['connection-reply-packets'] == {'gt': 10}
    assert rule['connection-expiration'] == {'lt': '30s'}
    assert rule['connection-label'] == ['0 and 1']
    assert 'unsupported' not in rule


def test_unknown_typeof_field_remains_visible_in_scoped_listing():
    document = {'nftables': [{'set': {
        'family': 'inet', 'table': 'external', 'name': 'CUSTOM',
        'type': {'typeof': {'ct': {'key': 'secmark'}}},
    }}]}
    group = normalize(document)['tables']['inet']['external']['sets']['CUSTOM']
    assert group['name'] == 'CUSTOM'
    assert group['unsupported'][0]['expression'] == document['nftables'][0]['set']


@pytest.mark.parametrize('failure', [None, 'check', 'apply'])
def test_accounting_changes_only_at_apply_and_restores_on_failure(tmp_path, monkeypatch, failure):
    setting = tmp_path / 'accounting'
    setting.write_text('0')
    monkeypatch.setattr(nftables, 'Path', lambda value: (
        setting if str(value) == '/proc/sys/net/netfilter/nf_conntrack_acct' else Path(value)
    ))
    observed = []

    def run(arguments):
        stage = 'check' if '--check' in arguments else 'apply'
        observed.append((stage, setting.read_text()))
        return (1, 'rejected') if stage == failure else (0, '')

    monkeypatch.setattr(nftables, 'rc_cmd', run)
    if failure:
        with pytest.raises(RouterError, match='rejected'):
            nftables.Manager().apply('candidate', tmp_path, accounting=True)
        assert setting.read_text() == '0'
        assert not (tmp_path / 'firewall.nft').exists()
    else:
        nftables.Manager().apply('candidate', tmp_path, accounting=True)
        assert setting.read_text() == '1'
        nftables.Manager().apply('candidate', tmp_path, accounting=False)
        assert setting.read_text() == '0'

    assert observed[0] == ('check', '0')
    if failure != 'check':
        assert observed[1] == ('apply', '1')
