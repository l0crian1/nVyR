"""ICMP group structure, assigned codes, references, lifecycle and display."""

from copy import deepcopy
import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import RouterError
from nvyr.helpers import nftables
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.helpers.validators import ICMP_KEYMAP, ICMP_TYPES
from nvyr.op_scripts import firewall as display
from tests.test_firewall_maps import rendered
from tests.test_firewall_matches import PATHS, configured
from tests.test_nftables_lifecycle import destroyed


def configuration(family='ipv4', mode='type-code', code='0-2', negative=False):
    rule = {'protocol': ['icmp' if family == 'ipv4' else 'ipv6-icmp'], 'action': 'accept'}
    if negative:
        rule['not'] = {'icmp-group': 'G'}
    else:
        rule['icmp-group'] = 'G'
    tree = configured(rule, (family, 'input', 'filter'))
    member = {'code': [code]} if mode == 'type-code' else {}
    tree['firewall']['group'] = {'icmp-group': {family: {'G': {
        'match': mode, 'type': {'destination-unreachable': member}, 'description': 'Errors',
    }}}}
    return tree


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('mode', ['type', 'type-code'])
@pytest.mark.parametrize('negative', [False, True])
def test_group_generation_and_global_tracking(family, mode, negative):
    tree = configuration(family, mode, negative=negative)
    tree['firewall']['global-options'] = {'counter': True, 'last-used': True}
    before = deepcopy(tree)

    text = rendered(tree)
    datatype = 'icmp' if family == 'ipv4' else 'icmpv6'
    assert f'type {datatype}_type' + (f' . {datatype}_code;' if mode == 'type-code' else ';') in text
    expression = f'{datatype} type' + (f' . {datatype} code' if mode == 'type-code' else '')
    assert expression + (' !=' if negative else ' ==') + f' @{family}_icmp_group_G' in text
    if mode == 'type-code':
        assert 'destination-unreachable . 0-2' in text
    else:
        assert 'elements = { destination-unreachable };' in text
    assert 'counter;' in text and 'last;' in text and 'comment "Errors";' in text
    assert tree == before


@pytest.mark.parametrize('path', PATHS + [('ipv4', 'name', 'TEST'), ('ipv6', 'name', 'TEST')])
def test_group_available_on_every_firewall_chain(path):
    tree = configuration(path[0])
    rule = tree['firewall'].pop(path[0])['input']['filter']['rule']['10']
    tree['firewall'].update(configured(rule, path)['firewall'])
    assert f'@{path[0]}_icmp_group_G' in rendered(tree)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_all_keymap_codes_and_rejected_gaps(family):
    assert set(ICMP_KEYMAP[family]) == set(ICMP_TYPES[family])
    for typename, entry in ICMP_KEYMAP[family].items():
        for code in range(256):
            definition = {'match': 'type-code', 'type': {typename: {'code': [str(code)]}}}
            if code in entry['codes']:
                firewall.verify_icmp_group(family, 'G', definition)
            else:
                with pytest.raises(RouterError, match='invalid code'):
                    firewall.verify_icmp_group(family, 'G', definition)

    typename, code = ('router-advertisement', '0-16') if family == 'ipv4' else ('router-renumbering', '1-255')
    with pytest.raises(RouterError, match='valid codes:'):
        firewall.verify_icmp_group(family, 'G', {'match': 'type-code', 'type': {typename: {'code': [code]}}})


@pytest.mark.parametrize('definition,message', [
    ({'type': {}}, 'match must be'),
    ({'match': 'type', 'type': {'echo-request': {'code': ['0']}}}, 'code requires'),
    ({'match': 'type-code', 'type': {'echo-request': {}}}, 'code is required'),
    ({'match': 'type-code', 'type': {'echo-request': {'code': ['1']}}}, 'invalid code'),
])
def test_invalid_unused_groups_fail_verification(definition, message):
    with pytest.raises(RouterError, match=message):
        rendered({'firewall': {'group': {'icmp-group': {'ipv4': {'G': definition}}}}})


def test_duplicate_type_aliases_are_rejected():
    definition = {'match': 'type', 'type': {'mld-listener-done': {}, 'mld-listener-reduction': {}}}
    with pytest.raises(RouterError, match='duplicates'):
        firewall.verify_icmp_group('ipv6', 'G', definition)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_cli_retains_and_deletes_individual_codes(controller, engine, session, family):
    prefix = f'firewall group icmp-group {family} G'
    controller.execute(f'set {prefix} match type-code', session)
    controller.execute(f'set {prefix} type destination-unreachable code 0', session)
    assert engine.commit(session)['results']['firewall']['success']

    # A later command adds a separate element without replacing code zero.
    controller.execute(f'set {prefix} type destination-unreachable code 3', session)
    controller.execute(f'set {prefix} type echo-request code 0', session)
    assert engine.commit(session)['results']['firewall']['success']
    types = engine.running['firewall']['group']['icmp-group'][family]['G']['type']
    assert types['destination-unreachable']['code'] == ['0', '3']
    assert types['echo-request']['code'] == ['0']
    text = rendered(engine.running)
    assert 'destination-unreachable . 0, destination-unreachable . 3' in text
    assert 'destination-unreachable . 0-3' not in text

    # Removing one code preserves its sibling and the other type's membership.
    controller.execute(f'delete {prefix} type destination-unreachable code 0', session)
    assert engine.commit(session)['results']['firewall']['success']
    types = engine.running['firewall']['group']['icmp-group'][family]['G']['type']
    assert types['destination-unreachable']['code'] == ['3']
    assert types['echo-request']['code'] == ['0']


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('codes', [['0', '3-5'], ['0-1', '3', '5-6']])
def test_multiple_codes_and_ranges_form_separate_elements(family, codes):
    tree = configuration(family)
    tree['firewall']['group']['icmp-group'][family]['G']['type']['destination-unreachable']['code'] = codes

    text = rendered(tree)
    for code in codes:
        assert f'destination-unreachable . {code}' in text
    assert 'flags interval;' in text


@pytest.mark.parametrize('codes', [['0-3', '2'], ['0-3', '3-5'], ['0', '0-0'], ['0', '0']])
def test_overlapping_code_elements_are_rejected(codes):
    definition = {'match': 'type-code', 'type': {'destination-unreachable': {'code': codes}}}
    with pytest.raises(RouterError, match='overlaps another'):
        firewall.verify_icmp_group('ipv4', 'G', definition)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('negative', [False, True])
def test_cli_completion_dependencies_and_commit(controller, engine, session, family, negative):
    controller.execute(f'set firewall group icmp-group {family} G match type-code type destination-unreachable code 0-2', session)
    protocol = 'icmp' if family == 'ipv4' else 'ipv6-icmp'
    exclusion = 'not ' if negative else ''
    prefix = f'set firewall {family} input filter rule 10 '
    controller.execute(prefix + f'protocol {protocol} action accept icmp-group {exclusion}G', session)

    candidates = controller.completion(prefix + 'icmp-group ' + exclusion, session)['candidates']
    assert 'G' in dict(candidates)
    with pytest.raises(RouterError, match='referenced'):
        controller.execute(f'delete firewall group icmp-group {family} G', session)
    assert engine.commit(session)['results']['firewall']['success']

    controller.execute(f'delete firewall {family} input filter rule 10 icmp-group {exclusion}G', session)
    controller.execute(f'delete firewall group icmp-group {family} G', session)
    assert engine.commit(session)['results']['firewall']['success']


@pytest.mark.parametrize('suffix', ['match code', 'type 3', 'type echo-request code 2-0',
                                    'type echo-request code 256', 'type echo-request code 0,1',
                                    'type echo-request code 0 and 1'])
def test_schema_rejects_invalid_syntax(controller, session, suffix):
    with pytest.raises(RouterError):
        controller.execute('set firewall group icmp-group ipv4 G ' + suffix, session)


@pytest.mark.parametrize('field,value', [('icmp-type', ['echo-request']), ('icmp-code', ['0'])])
@pytest.mark.parametrize('negative', [False, True])
@pytest.mark.parametrize('source', ['rule', 'not', 'map', 'match-group', 'excluded-group'])
def test_overlapping_fields_are_rejected(field, value, negative, source):
    tree = configuration(negative=negative)
    rule = tree['firewall']['ipv4']['input']['filter']['rule']['10']
    if source in ('rule', 'not'):
        target = rule if source == 'rule' else rule.setdefault('not', {})
        target[field] = value
    else:
        kind = 'match-group' if source == 'excluded-group' else source
        group = {'match': {field: True, 'protocol': True}, 'entry': {}}
        tree['firewall']['group'][kind] = {'ipv4': {'OTHER': group}}
        target = rule.setdefault('not', {}) if source == 'excluded-group' else rule
        target[kind] = 'OTHER'
        if source != 'excluded-group':
            rule.pop('protocol')
        if kind == 'map':
            rule.pop('action')
            group['result-type'] = 'verdict'
    with pytest.raises(RouterError, match='icmp-group cannot be combined'):
        rendered(tree)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('negative', [False, True])
def test_protocol_and_transport_checks(family, negative):
    tree = configuration(family, negative=negative)
    rule = tree['firewall'][family]['input']['filter']['rule']['10']
    for protocols in ([], ['tcp'], ['icmp', 'ipv6-icmp']):
        rule['protocol'] = protocols
        if not protocols:
            rule.pop('protocol')
        with pytest.raises(RouterError, match='requires protocol'):
            rendered(tree)
    rule['protocol'] = ['icmp' if family == 'ipv4' else 'ipv6-icmp']
    rule['destination-port'] = ['22']
    with pytest.raises(RouterError, match='ICMP matching cannot be combined'):
        rendered(tree)


@pytest.mark.parametrize('source', ['rule', 'map', 'match-group'])
def test_independent_fields_and_protocol_sources_remain_usable(source):
    tree = configuration()
    rule = tree['firewall']['ipv4']['input']['filter']['rule']['10']
    rule['inbound-interface'] = ['eth0']
    rule['source-address'] = {'192.0.2.1': {}}
    if source != 'rule':
        rule.pop('protocol')
        rule[source] = 'OTHER'
        definition = {'match': {'protocol': True}, 'entry': {'ICMP': {'protocol': 'icmp'}}}
        if source == 'map':
            rule.pop('action')
            definition['result-type'] = 'verdict'
            definition['entry']['ICMP']['result'] = {'action': 'accept'}
        tree['firewall']['group'][source] = {'ipv4': {'OTHER': definition}}

    text = rendered(tree)
    assert 'icmp type . icmp code == @ipv4_icmp_group_G' in text
    assert 'iifname' in text and '192.0.2.1' in text


def test_tracking_change_rebuilds_group_and_consumers():
    before = configuration()
    after = deepcopy(before)
    after['firewall']['global-options'] = {'counter': True, 'last-used': True}

    text = rendered(after, before)
    assert destroyed(text, 'set') == {'ipv4_icmp_group_G'}
    assert destroyed(text) == {'ipv4_input', 'input'}


@pytest.mark.parametrize('negative', [False, True])
def test_changed_group_rebuilds_nested_jump_consumers_only(negative):
    before = configuration(negative=negative)
    family = before['firewall']['ipv4']
    family['name'] = {'INNER': family.pop('input')['filter'],
                      'OUTER': {'rule': {'10': {'action': 'jump', 'jump-target': 'INNER'}}},
                      'UNRELATED': {'default-action': 'drop'}}
    family['forward'] = {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'OUTER'}}}}
    after = deepcopy(before)
    after['firewall']['group']['icmp-group']['ipv4']['G']['type']['destination-unreachable']['code'] = ['3']

    text = rendered(after, before)
    assert destroyed(text) == {'ipv4_name_INNER', 'ipv4_name_OUTER', 'ipv4_forward', 'forward'}
    assert destroyed(text, 'set') == {'ipv4_icmp_group_G'}
    assert 'UNRELATED' not in text
    assert not destroyed(rendered(before, before), 'set')


def test_family_resolution_empty_sets_and_recovery(monkeypatch):
    tree = configuration()
    tree['firewall']['group']['icmp-group'] = {'ipv6': {'G': {'match': 'type'}}}
    with pytest.raises(RouterError, match='not configured in ipv4'):
        rendered(tree)

    monkeypatch.setattr(nftables.manager, 'icmp_groups', lambda: [('ipv4', 'ORPHAN')])
    assert 'destroy set inet nvyr_filter ipv4_icmp_group_ORPHAN' in rendered({}, recovery=True)
    assert 'elements' not in rendered({'firewall': {'group': {'icmp-group': {'ipv4': {'G': {'match': 'type'}}}}}})


@pytest.mark.parametrize('mode', ['type', 'type-code'])
@pytest.mark.parametrize('detail', [False, True])
def test_normalized_partial_listing_and_opmode(mode, detail, monkeypatch, capsys, controller):
    tree = configuration(mode=mode)
    datatypes = ['icmp_type', 'icmp_code'] if mode == 'type-code' else 'icmp_type'
    key = {'concat': ['destination-unreachable', {'range': [0, 2]}]} if mode == 'type-code' else 'echo-request'
    document = {'nftables': [{'set': {'family': 'inet', 'table': 'nvyr_filter',
        'name': 'ipv4_icmp_group_G', 'type': datatypes, 'elem': [key]}}]}
    table = normalize(document, configuration=tree)['tables']['inet']['nvyr_filter']
    group = table['sets']['ipv4_icmp_group_G']
    assert group['match-fields'] == (['icmp-type', 'icmp-code'] if mode == 'type-code' else ['icmp-type'])
    assert 'unsupported' not in group['entries'][0]
    monkeypatch.setattr(display, '_load_table', lambda *, failsafe=False: table)

    display.show(section='group', family='ipv4', group_kind='icmp-group', group_name='G', detail=detail)
    text = capsys.readouterr().out
    assert 'IPv4 icmp-group G' in text and 'ICMP type' in text
    assert ('ICMP code' in text) == (mode == 'type-code')
    assert (' | ' in text) == detail
    assert 'icmp-group' in dict(controller.completion('show firewall group ', explicit=True)['candidates'])
