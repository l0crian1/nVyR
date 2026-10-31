"""Rule setters preserve matches, schema visibility and transitive hook restrictions."""

from copy import deepcopy
import ast
from pathlib import Path

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import RouterError
from nvyr.helpers import nftables_modify
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.lexer import lex
from nvyr.schema import Schema
from nvyr.op_scripts import firewall as display
from tests.test_firewall_maps import rendered


def configuration(family='ipv4', hook='forward', stage='filter', options=None):
    return {'firewall': {family: {hook: {stage: {'rule': {'10': {
        'protocol': ['tcp'], 'tcp-flags': ['syn'], 'action': 'continue',
        'modify': options if options is not None else {'packet-mark': '0x20', 'tcp-mss': '1360'},
    }}}}}}}


@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
@pytest.mark.parametrize('hook,stage,connection,clamp', [
    ('input', 'filter', True, False), ('forward', 'filter', True, True),
    ('output', 'filter', True, True), ('output', 'raw', False, True),
    ('prerouting', 'raw', False, False),
])
def test_schema_and_rendering_per_hook(family, hook, stage, connection, clamp):
    schema = Schema.bundled()
    cursor = schema.resolve(lex(f'firewall {family} {hook} {stage} rule 10 modify'))
    fields = cursor.node['children']
    assert cursor.node['anchor']
    assert ('connection-mark' in fields) is connection
    assert ('dscp' in fields) is (family != 'inet')
    assert ('ttl' in fields) is (family != 'inet')
    assert ('clamp-to-pmtu' in fields['tcp-mss'].get('choices', {})) is clamp

    options = {'packet-mark': '0x20', 'tcp-mss': 'clamp-to-pmtu' if clamp else '1360'}
    if connection:
        options['connection-mark'] = '4294967295'
    if family != 'inet':
        options.update(dscp='ef', ttl='63')
    tree = configuration(family, hook, stage, options)
    text = rendered(tree)
    line = next(line for line in text.splitlines() if 'comment "10|' in line)
    assert 'meta mark set 32' in line
    assert 'tcp option maxseg size set ' + ('rt mtu' if clamp else '1360') in line
    assert line.index('tcp flags') < line.index('meta mark set') < line.index('continue comment')
    if family != 'inet':
        assert ('ip dscp set 46' if family == 'ipv4' else 'ip6 dscp set 46') in line
        assert ('ip ttl set 63' if family == 'ipv4' else 'ip6 hoplimit set 63') in line


@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
def test_ingress_does_not_advertise_modify(family):
    cursor = Schema.bundled().resolve(lex(f'firewall {family} ingress filter rule 10'))
    assert 'modify' not in cursor.node['children']


@pytest.mark.parametrize('options,message', [
    ({}, 'at least one setting'), ({'unknown': '1'}, 'unknown modify'),
    ({'packet-mark': '4294967296'}, 'invalid modify'),
    ({'connection-mark': '0x100000000'}, 'invalid modify'),
    ({'packet-mark': '0xno'}, 'invalid modify'), ({'dscp': '64'}, 'invalid modify'),
    ({'dscp': 'af99'}, 'invalid modify'), ({'ttl': '256'}, 'invalid modify'),
    ({'tcp-mss': '0'}, 'invalid modify'), ({'tcp-mss': '65536'}, 'invalid modify'),
])
def test_direct_verification_rejects_invalid_values(options, message):
    rule = {'action': 'continue', 'modify': options, 'protocol': ['tcp'], 'tcp-flags': ['syn']}
    with pytest.raises(RouterError, match=message):
        firewall.verify_rule(rule, ('firewall', 'ipv4', 'forward', 'filter', 'rule', '10'), {})


@pytest.mark.parametrize('protocol,flags,message', [
    ([], ['syn'], 'requires protocol tcp'), (['udp'], ['syn'], 'requires protocol tcp'),
    (['tcp', 'udp'], ['syn'], 'requires protocol tcp'),
    (['tcp'], [], 'positive SYN'), (['tcp'], ['not syn'], 'positive SYN'),
    (['tcp'], ['syn', 'ack'], 'positive SYN'),
])
def test_mss_requires_tcp_and_syn_in_every_alternative(protocol, flags, message):
    tree = configuration()
    rule = tree['firewall']['ipv4']['forward']['filter']['rule']['10']
    rule['protocol'] = protocol
    rule['tcp-flags'] = flags
    with pytest.raises(RouterError, match=message):
        firewall.verify_rule(rule, ('firewall', 'ipv4', 'forward', 'filter', 'rule', '10'), {})


def test_syn_ack_and_inherited_match_group_flags():
    tree = configuration()
    rule = tree['firewall']['ipv4']['forward']['filter']['rule']['10']
    rule['tcp-flags'] = ['syn,ack', 'syn,not ack']
    assert 'maxseg size set 1360' in rendered(tree)

    del rule['protocol'], rule['tcp-flags']
    rule['match-group'] = 'HANDSHAKE'
    tree['firewall']['group'] = {'match-group': {'ipv4': {'HANDSHAKE': {
        'match': {'protocol': True, 'tcp-flags': True},
        'entry': {'SYN': {'protocol': 'tcp', 'tcp-flags': 'syn'}},
    }}}}
    assert 'maxseg size set 1360' in rendered(tree)


@pytest.mark.parametrize('hook,stage,options,message', [
    ('prerouting', 'raw', {'connection-mark': '1'}, 'before connection tracking'),
    ('output', 'raw', {'connection-mark': '1'}, 'before connection tracking'),
    ('input', 'filter', {'tcp-mss': 'clamp-to-pmtu'}, 'requires forward or output'),
    ('prerouting', 'raw', {'tcp-mss': 'clamp-to-pmtu'}, 'requires forward or output'),
    ('ingress', 'filter', {'packet-mark': '1'}, 'unavailable in ingress'),
])
@pytest.mark.parametrize('mapped', [False, True])
def test_nested_and_map_selected_callers_enforce_hook_restrictions(hook, stage, options, message, mapped):
    tree = configuration(options=options)
    family = tree['firewall']['ipv4']
    rule = family.pop('forward')['filter']['rule']['10']
    family['name'] = {
        'BOTTOM': {'rule': {'10': rule}},
        'TOP': {'rule': {'10': {'action': 'jump', 'jump-target': 'BOTTOM'}}},
    }
    family[hook] = {stage: {'rule': {'10': {'action': 'jump', 'jump-target': 'TOP'}}}}
    if hook == 'ingress':
        family[hook][stage]['interface'] = ['test*']
    if mapped:
        family[hook][stage]['rule']['10'] = {'map': 'DISPATCH'}
        tree['firewall']['group'] = {'map': {'ipv4': {'DISPATCH': {
            'match': {'packet-mark': True}, 'result-type': 'verdict',
            'entry': {'one': {'packet-mark': '0', 'result': {'action': 'jump', 'jump-target': 'TOP'}}},
        }}}}
    with pytest.raises(RouterError, match=message):
        rendered(tree)


def test_disabled_setters_do_not_constrain_callers():
    tree = configuration(options={'connection-mark': '1'})
    rule = tree['firewall']['ipv4'].pop('forward')['filter']['rule']['10']
    rule['disable'] = True
    tree['firewall']['ipv4']['name'] = {'TARGET': {'rule': {'10': rule}}}
    tree['firewall']['ipv4']['output'] = {'raw': {'rule': {'10': {'action': 'jump', 'jump-target': 'TARGET'}}}}
    assert 'ct mark set' not in rendered(tree)


def test_setter_changes_rebuild_only_the_changed_chain():
    tree = configuration()
    tree['firewall']['ipv4']['name'] = {'UNCHANGED': {'default-action': 'drop'}}
    before = deepcopy(tree)
    tree['firewall']['ipv4']['forward']['filter']['rule']['10']['modify']['packet-mark'] = '2'
    text = rendered(tree, previous=before)
    assert 'destroy chain inet nvyr_filter ipv4_forward' in text
    assert 'destroy chain inet nvyr_filter ipv4_name_UNCHANGED' not in text


def test_normalizer_keeps_matches_separate_from_setters(monkeypatch, capsys):
    document = {'nftables': [{'rule': {
        'family': 'inet', 'table': 'nvyr_filter', 'chain': 'ipv4_forward', 'comment': '10|',
        'expr': [
            {'match': {'op': '==', 'left': {'meta': {'key': 'mark'}}, 'right': 1}},
            {'mangle': {'key': {'meta': {'key': 'mark'}}, 'value': 2}},
            {'mangle': {'key': {'ct': {'key': 'mark'}}, 'value': 3}},
            {'mangle': {'key': {'payload': {'protocol': 'ip', 'field': 'dscp'}}, 'value': 'ef'}},
            {'mangle': {'key': {'payload': {'protocol': 'ip', 'field': 'ttl'}}, 'value': 63}},
            {'mangle': {'key': {'tcp option': {'name': 'maxseg', 'field': 'size'}}, 'value': {'rt': {'key': 'mtu'}}}},
            {'continue': None},
        ],
    }}]}
    table = normalize(document)['tables']['inet']['nvyr_filter']
    rule = table['chains']['ipv4_forward']['rules'][0]
    assert 'unsupported' not in rule
    assert rule['packet-mark'] == [1]
    assert rule['modify'] == {'packet-mark': 2, 'connection-mark': 3, 'dscp': 46, 'ttl': 63, 'tcp-mss': 'clamp-to-pmtu'}

    monkeypatch.setattr(display, '_load_table', lambda **kwargs: table)
    display.show(family='ipv4', hook='forward', detail=True)
    output = capsys.readouterr().out
    assert 'Modify' in output and 'clamp-to-pmtu' in output
    assert 'Unsupported' not in output


def test_ordinary_rules_skip_modify_verification(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError('Absent modify node was verified')
    monkeypatch.setattr(nftables_modify, 'verify', unexpected)
    firewall.verify_rule({'action': 'accept'}, ('firewall', 'ipv4', 'forward', 'filter', 'rule', '10'), {})


def test_smoketest_commands_parse_with_nested_anchors():
    """Every installed test command uses actual schema parsing, including and and modify."""
    schema = Schema.bundled()
    path = Path(__file__).resolve().parents[1] / 'smoketests/test_firewall_modify.py'
    for node in ast.walk(ast.parse(path.read_text())):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == 'config'
                and node.func.attr == 'set'):
            command = ast.literal_eval(node.args[0])
            assert schema.set_paths(lex(command)[1:]), command


def test_modify_anchor_and_match_field_are_distinct(controller, engine, session):
    controller.execute('set firewall ipv4 forward filter rule 10 packet-mark 1 modify packet-mark 0x20 dscp ef action continue', session)
    rule = engine.view(session)['firewall']['ipv4']['forward']['filter']['rule']['10']
    assert rule['packet-mark'] == ['1']
    assert rule['modify'] == {'packet-mark': '0x20', 'dscp': 'ef'}
    line = next(line for line in rendered(engine.view(session)).splitlines() if 'comment "10|' in line)
    assert line.index('meta mark { 1 }') < line.index('meta mark set 32') < line.index('continue comment')
