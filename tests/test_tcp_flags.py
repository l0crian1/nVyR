"""TCP requirements retain the same meaning in rules and compound groups."""

from copy import deepcopy

import pytest

from build_tools.schema_builder import SchemaBuildError, _normalize_callbacks
from nvyr.errors import RouterError
from nvyr.helpers.nftables_formatters import nft_group_tcp_mask
from nvyr.helpers.validators import tcp_flag_values, tcp_flags, tcp_flags_mask
from nvyr.lexer import lex
from nvyr.render import set_commands
from nvyr.schema import Schema
from nvyr.tree import lookup
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


RULE = 'firewall ipv4 input filter rule 10'
PATH = tuple(RULE.split())


def group_definition(kind):
    definition = {
        'match': {'protocol': True, 'tcp-flags': True, 'destination-port': True},
        'counter': True, 'last-used': True,
        'entry': {
            'SYN': {'protocol': 'tcp', 'tcp-flags': 'syn,not ack,not rst', 'destination-port': '8000-9000'},
            'RESET': {'protocol': 'tcp', 'tcp-flags': 'rst', 'destination-port': '8000-9000'},
        },
    }
    if kind == 'map':
        definition['result-type'] = 'verdict'
        for entry in definition['entry'].values():
            entry['result'] = {'action': 'continue'}
    return definition


def configured(kind='map', family='ipv4'):
    rule = {kind: 'FLAGS'}
    if kind == 'match-group':
        rule['action'] = 'continue'
    return {'firewall': {'group': {kind: {family: {'FLAGS': group_definition(kind)}}},
                         family: {'output': {'filter': {'rule': {'10': rule}}}}}}


def test_all_flag_values_preserve_dont_care_bits():
    # Check the actual SYN, ACK and RST bit meanings independently of the parser.
    for mask in (22, 255):
        selected = set(tcp_flag_values('syn,not ack,not rst', mask))
        for flags in range(256):
            expected = bool(flags & 2) and not flags & 16 and not flags & 4
            assert ((flags & mask) in selected) == expected

    assert tcp_flags_mask(['syn,not ack', 'rst']) == 22
    assert set(tcp_flag_values('not syn')) == {value for value in range(256) if not value & 2}


@pytest.mark.parametrize('value', ['', 'syyn', 'not', 'not not syn', 'syn,', 'syn,syn', 'syn,not syn', 'not ack,ack'])
def test_invalid_flag_expressions(value):
    assert not tcp_flags(value)


def test_joined_not_completion_serialization_and_single_alternative_deletion(controller, engine, session):
    controller.execute(f'set {RULE} protocol tcp action accept tcp-flags syn and not ack and not fin and not rst', session)
    controller.execute(f'set {RULE} tcp-flags rst', session)
    rule = lookup(engine.view(session), PATH)
    assert rule['tcp-flags'] == ['syn,not ack,not fin,not rst', 'rst']

    for suffix in ('', 'syn and ', 'syn and not '):
        choices = dict(controller.completion(f'set {RULE} tcp-flags ' + suffix, session, explicit=True)['candidates'])
        assert 'ack' in choices
        assert ('not' in choices) == (not suffix.endswith('not '))
        if suffix:
            assert 'syn' not in choices

    commands = list(set_commands(engine.schema, engine.view(session)))
    assert f'set {RULE} tcp-flags syn and not ack and not fin and not rst' in commands
    controller.execute(f'delete {RULE} tcp-flags syn and not ack and not fin and not rst', session)
    assert lookup(engine.view(session), PATH)['tcp-flags'] == ['rst']
    assert engine.commit(session)['results']['firewall']['success']


@pytest.mark.parametrize('suffix', ['not', 'syn and not', 'syn and not syn', 'syn and not not ack', 'syn and typo'])
def test_bad_join_is_atomic(controller, session, suffix):
    before = list(session.mutations)
    with pytest.raises(RouterError):
        controller.execute(f'set {RULE} counter tcp-flags {suffix}', session)
    assert session.mutations == before


@pytest.mark.parametrize('setting', [{'negatable': 'yes'}, {'unknown': True}, {}, {'negatable': True, 'other': True}])
def test_invalid_joinable_settings(setting):
    node = {'kind': 'leaf_node', 'joinable': setting}
    with pytest.raises(SchemaBuildError, match='joinable'):
        _normalize_callbacks(deepcopy(node))
    with pytest.raises(ValueError, match='joinable'):
        Schema({'kind': 'node', 'children': {'value': node}})


def test_generic_join_negation_and_operational_arguments():
    node = {'kind': 'leaf_node', 'joinable': {'negatable': True},
            'choices': {'red': 'Red', 'blue': 'Blue'},
            'command': {'argv': ['example', '@2']}}
    schema = Schema({'kind': 'node', 'children': {'color': node}})
    assert schema.operational(lex('color red and not blue')).value == 'red,not blue'
    with pytest.raises(RouterError, match="after 'not'"):
        schema.operational(lex('color not'))
    with pytest.raises(RouterError, match="after 'not'"):
        schema.configuration_path(lex('color not'), 'delete')


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('kind', ['map', 'match-group'])
def test_group_generation_masks_and_conflicts(kind, family):
    tree = configured(kind, family)
    text = rendered(tree)
    assert 'tcp flags & 22' in text
    assert 'inet_proto . tcp_flag . inet_service' in text
    assert 'tcp . 2 . 8000-9000' in text
    for value in (4, 6, 20, 22):
        assert f'tcp . {value} . 8000-9000' in text

    definition = tree['firewall']['group'][kind][family]['FLAGS']
    definition['entry']['SYN']['tcp-flags'] = 'syn'
    with pytest.raises(RouterError, match='overlapping'):
        rendered(tree)

    definition['entry']['SYN']['tcp-flags'] = 'syn,not rst'
    definition['entry']['RESET']['protocol'] = 'udp'
    with pytest.raises(RouterError, match='TCP flags require protocol tcp'):
        rendered(tree)


@pytest.mark.parametrize('kind', ['map', 'match-group'])
def test_group_protocol_required_even_without_entries(kind):
    tree = configured(kind)
    definition = tree['firewall']['group'][kind]['ipv4']['FLAGS']
    definition['entry'].clear()
    del definition['match']['protocol']
    with pytest.raises(RouterError, match='TCP flags require protocol'):
        rendered(tree)


@pytest.mark.parametrize('kind', ['map', 'match-group'])
def test_group_cli_joined_flags_export_and_reload(controller, engine, session, kind):
    path = f'firewall group {kind} ipv4 FLAGS'
    controller.execute(f'set {path} match protocol tcp-flags', session)
    controller.execute(f'set {path} entry INITIAL protocol tcp tcp-flags syn and not ack and not rst', session)
    if kind == 'map':
        controller.execute(f'set {path} result-type verdict', session)
        controller.execute(f'set {path} entry INITIAL result action accept', session)

    original = engine.view(session)
    commands = list(set_commands(engine.schema, original))
    assert f'set {path} entry INITIAL tcp-flags syn and not ack and not rst' in commands
    controller.execute(f'delete {path}', session)
    for command in commands:
        controller.execute(command, session)
    assert engine.view(session) == original


@pytest.mark.parametrize('protocol', [None, ['udp'], ['tcp', 'udp']])
def test_rule_protocol_is_explicit_and_tcp_only(protocol):
    rule = {'tcp-flags': ['syn'], 'action': 'accept'}
    if protocol is not None:
        rule['protocol'] = protocol
    tree = {'firewall': {'ipv4': {'input': {'filter': {'rule': {'10': rule}}}}}}
    with pytest.raises(RouterError, match='tcp-flags requires protocol tcp'):
        rendered(tree)


@pytest.mark.parametrize('kind', ['map', 'match-group'])
def test_explicit_and_inherited_flag_fields_conflict(kind):
    tree = configured(kind)
    tree['firewall']['ipv4']['output']['filter']['rule']['10']['tcp-flags'] = ['syn']
    with pytest.raises(RouterError, match='tcp-flags'):
        rendered(tree)


def test_group_changes_rebuild_nested_jump_consumers():
    before = configured()
    family = before['firewall']['ipv4']
    family['name'] = {'INNER': family.pop('output')['filter'],
                      'OUTER': {'rule': {'10': {'action': 'jump', 'jump-target': 'INNER'}}}}
    family['input'] = {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'OUTER'}}}}
    after = deepcopy(before)
    after['firewall']['group']['map']['ipv4']['FLAGS']['entry']['SYN']['tcp-flags'] = 'syn,not ack,not rst,not fin'

    text = rendered(after, before)
    assert destroyed(text) == {'ipv4_name_INNER', 'ipv4_name_OUTER', 'ipv4_input', 'input'}
    assert not destroyed(rendered(after, after))


def test_dynamic_flags_use_all_bits_and_reject_configured_members():
    tree = configured('match-group')
    definition = tree['firewall']['group']['match-group']['ipv4']['FLAGS']
    definition['dynamic'] = {'size': '1'}
    for entry in definition['entry'].values():
        entry['destination-port'] = '8080'
    assert nft_group_tcp_mask(definition) == 255
    with pytest.raises(RouterError, match='dynamic groups cannot contain configured members'):
        rendered(tree)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_packet_length_cli_ranges_negation_and_deletion(controller, engine, session, family):
    path = f'firewall {family} input filter rule 10'
    controller.execute(f'set {path} action accept packet-length 40 packet-length 100-200 packet-length not 150', session)
    tree = engine.view(session)
    text = rendered(tree)
    assert 'meta length { 100-200, 40 }' in text
    assert 'meta length != { 150 }' in text
    controller.execute(f'delete {path} packet-length 40', session)
    assert lookup(engine.view(session), tuple(path.split()))['packet-length'] == ['100-200']


@pytest.mark.parametrize('value', ['-1', '4294967296', '100-50', '64k'])
def test_packet_length_invalid_values(controller, session, value):
    with pytest.raises(RouterError):
        controller.execute(f'set {RULE} packet-length {value}', session)
