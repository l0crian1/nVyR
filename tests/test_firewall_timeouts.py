"""Timeout policies preserve family ownership, references and whole-object lifecycle."""

from copy import deepcopy

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import nftables_timeouts as timeouts
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.helpers.process import operational_argv
from nvyr.lexer import lex
from nvyr.op_scripts import firewall as display
from nvyr.schema import Schema
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


def configuration(family='ipv4', protocol='udp'):
    """Build a policy and consumer with separate, deliberately unchanged chains."""
    state = 'unreplied' if protocol == 'udp' else 'established'
    return {'firewall': {
        'group': {'timeout-group': {family: {'APP': {
            'protocol': protocol, 'timeout': {state: '10s'}, 'description': 'Application tracking',
        }}}},
        family: {
            'output': {'filter': {'rule': {'10': {
                'protocol': [protocol], 'destination-port': ['5300'], 'action': 'accept',
                'connection': {'timeout-group': 'APP'},
            }}}},
            'name': {'UNCHANGED': {'default-action': 'drop'}},
        },
    }}


@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
@pytest.mark.parametrize('protocol', ['tcp', 'udp'])
def test_policy_rendering_and_global_inheritance(family, protocol):
    """All families emit explicit native timeouts, including global inherited states."""
    tree = configuration(family, protocol)
    tree['firewall']['global-options'] = {'connection-tracking': {'timeout': {
        'udp': {'stream': '4m'}, 'tcp': {'close': '20s'},
    }}}
    text = rendered(tree)
    for native in timeouts.native_names(family, 'APP').values():
        assert f'ct timeout {native} {{' in text
        assert f'"{native}"' in text
    assert ('replied: 240' if protocol == 'udp' else 'close: 20') in text
    assert ('unreplied: 10' if protocol == 'udp' else 'established: 10') in text
    assert text.index('ct timeout set') < text.index('accept comment "10|"')
    if family == 'inet':
        assert 'ct timeout set meta nfproto map {' in text
        assert text.count('accept comment "10|"') == 1


@pytest.mark.parametrize('options, message', [
    ({}, 'protocol tcp or udp is required'),
    ({'protocol': 'udp'}, 'at least one timeout'),
    ({'protocol': 'udp', 'timeout': {'established': '1m'}}, 'unavailable for udp'),
    ({'protocol': 'tcp', 'timeout': {'replied': '1m'}}, 'unavailable for tcp'),
    ({'protocol': 'udp', 'timeout': {'unreplied': '0s'}}, '1–2147483'),
    ({'protocol': 'tcp', 'timeout': {'established': '25d'}}, '1–2147483'),
])
def test_invalid_unused_policy(options, message):
    """Direct verify callers receive the same state and duration restrictions as CLI."""
    with pytest.raises(RouterError, match=message):
        timeouts.verify_group(options, ('firewall', 'group', 'timeout-group', 'ipv4', 'BAD'))


@pytest.mark.parametrize('protocols', [[], ['tcp'], ['udp', 'tcp']])
def test_rule_must_select_the_policy_transport(protocols):
    """Unconstrained or mixed transport traffic cannot receive a UDP-only policy."""
    tree = configuration()
    rule = tree['firewall']['ipv4']['output']['filter']['rule']['10']
    if protocols:
        rule['protocol'] = protocols
    else:
        del rule['protocol']
    with pytest.raises(RouterError, match='requires protocol udp'):
        rendered(tree)


def test_inherited_protocol_from_match_group():
    """A compound group can provide the transport instead of an explicit rule leaf."""
    tree = configuration()
    tree['firewall']['group']['match-group'] = {'ipv4': {'SERVICES': {
        'match': {'protocol': True, 'destination-port': True},
        'entry': {'DNS': {'protocol': 'udp', 'destination-port': '5300'}},
    }}}
    rule = tree['firewall']['ipv4']['output']['filter']['rule']['10']
    del rule['protocol'], rule['destination-port']
    rule['match-group'] = 'SERVICES'
    assert 'ct timeout set "ipv4_timeout_group_APP"' in rendered(tree)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
@pytest.mark.parametrize('hook, stage', [('prerouting', 'raw'), ('output', 'raw'), ('ingress', 'filter')])
def test_pretracking_schema_has_no_assignment(family, hook, stage):
    """Unsupported hooks do not advertise the timeout assignment leaf."""
    schema = Schema.bundled()
    roots = ('firewall',) if hook == 'ingress' else ('firewall', 'firewall fail-safe')
    for root in roots:
        cursor = schema.resolve(lex(f'{root} {family} {hook} {stage} rule 10'))
        children = cursor.node['children'].get('connection', {}).get('children', {})
        assert 'timeout-group' not in children


@pytest.mark.parametrize('hook, stage', [('prerouting', 'raw'), ('output', 'raw'), ('ingress', 'filter')])
def test_nested_jump_cannot_bypass_hook_checks(hook, stage):
    """A reusable policy chain is checked against every caller, including raw/ingress."""
    tree = configuration()
    family = tree['firewall']['ipv4']
    rule = family['output']['filter']['rule']['10']
    del family['output']
    family['name']['BOTTOM'] = {'rule': {'10': rule}}
    family['name']['TOP'] = {'rule': {'10': {'action': 'jump', 'jump-target': 'BOTTOM'}}}
    family[hook] = {stage: {'rule': {'10': {'action': 'jump', 'jump-target': 'TOP'}}}}
    if hook == 'ingress':
        family[hook][stage]['interface'] = ['test*']
    with pytest.raises(RouterError, match='timeout-group is unavailable before connection tracking'):
        rendered(tree)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6', 'inet'])
def test_policy_change_rebuilds_consumers_and_preserves_unrelated_chains(family):
    """Both halves of inet groups participate in dependency-driven replacement."""
    before = configuration(family)
    after = deepcopy(before)
    after['firewall']['group']['timeout-group'][family]['APP']['timeout']['unreplied'] = '20s'
    text = rendered(after, before)
    assert destroyed(text, 'ct timeout') == set(timeouts.native_names(family, 'APP').values())
    assert family + '_name_UNCHANGED' not in text
    assert text.index('flush chain') < text.index('destroy ct timeout') < text.index('ct timeout set')


def test_global_timeout_changes_rebuild_only_inherited_policies():
    """Explicit group values are independent of changes to their global defaults."""
    before = configuration('inet')
    after = deepcopy(before)
    after['firewall']['global-options'] = {'connection-tracking': {'timeout': {'udp': {'stream': '3m'}}}}
    text = rendered(after, before)
    assert len(destroyed(text, 'ct timeout')) == 2
    assert 'replied: 180' in text

    before['firewall']['group']['timeout-group']['inet']['APP']['timeout']['replied'] = '1m'
    after['firewall']['group']['timeout-group']['inet']['APP']['timeout']['replied'] = '1m'
    assert not destroyed(rendered(after, before), 'ct timeout')


def test_nested_policy_consumers_are_rebuilt_together():
    """Changing one inet policy propagates through every nested jump caller."""
    before = configuration('inet')
    family = before['firewall']['inet']
    assignment = family['output']['filter']['rule']['10']
    family['name']['BOTTOM'] = {'rule': {'10': assignment}}
    family['name']['TOP'] = {'rule': {'10': {'action': 'jump', 'jump-target': 'BOTTOM'}}}
    family['output']['filter']['rule']['10'] = {'action': 'jump', 'jump-target': 'TOP'}
    after = deepcopy(before)
    after['firewall']['group']['timeout-group']['inet']['APP']['timeout']['unreplied'] = '20s'

    text = rendered(after, before)

    for chain in ('inet_name_BOTTOM', 'inet_name_TOP', 'output'):
        assert f'flush chain inet nvyr_filter {chain}' in text
    assert 'inet_name_UNCHANGED' not in text


def test_timeout_operational_dispatch(controller):
    """The family/name selector and detail option reach the common firewall display."""
    for family in ('inet', 'ipv4', 'ipv6'):
        for suffix in ('', ' DNS', ' DNS detail', ' detail'):
            line = f'show firewall group timeout-group {family}{suffix}'
            cursor = controller.operational.operational(lex(line))
            argv = operational_argv(cursor.node['command'], lex(line), line,
                                    omitted_positions=cursor.omitted_positions)
            assert argv[:5] == ['firewall.nvyr.op', 'show', '--section', 'group', '--group_kind']
            assert argv[argv.index('--family') + 1] == family
            assert ('--detail' in argv) == suffix.endswith('detail')
            assert ('--group_name' in argv) == ('DNS' in suffix)


def test_cli_completion_and_reference_protection(controller, session, engine):
    """Anchored policies complete in-family and cannot be removed while referenced."""
    controller.execute('set firewall group timeout-group inet DNS protocol udp timeout unreplied 10s replied 30s', session)
    controller.execute('set firewall inet output filter rule 10 protocol udp connection timeout-group DNS action accept', session)
    command = 'set firewall inet input filter rule 10 connection timeout-group '
    assert 'DNS' in dict(controller.completion(command, session)['candidates'])
    assert 'DNS' not in dict(controller.completion(command.replace('inet', 'ipv4'), session)['candidates'])
    with pytest.raises(RouterError, match='referenced'):
        controller.execute('delete firewall group timeout-group inet DNS', session)
    assert engine.commit(session)['results']['firewall']['success']


def test_timeout_display_normalizes_both_native_families(monkeypatch, capsys):
    """One public inet policy displays both installed halves and rule references."""
    names = timeouts.native_names('inet', 'DNS_ip')
    records = []
    for l3proto, name in names.items():
        records.append({'ct timeout': {'family': 'inet', 'table': 'nvyr_filter', 'name': name,
                                      'protocol': 'udp', 'l3proto': l3proto,
                                      'policy': {'unreplied': 10, 'replied': 30}, 'comment': 'DNS'}})
    records.append({'rule': {'family': 'inet', 'table': 'nvyr_filter', 'chain': 'output',
                            'comment': '10|', 'expr': [{'ct timeout': {'map': {
                                'key': {'meta': {'key': 'nfproto'}},
                                'data': {'set': [['ipv4', names['ip']], ['ipv6', names['ip6']]]},
                            }}}, {'accept': None}]}})
    table = normalize({'nftables': records})['tables']['inet']['nvyr_filter']
    assert table['chains']['output']['rules'][0]['connection-timeout-group'] == 'DNS_ip'
    monkeypatch.setattr(display, '_load_table', lambda **kwargs: table)
    display.show(section='group', group_kind='timeout-group', family='inet', group_name='DNS_ip')
    text = capsys.readouterr().out
    assert text.count('inet timeout-group DNS_ip') == 1
    assert 'IPv4' in text and 'IPv6' in text
    assert '10s' in text and '30s' in text


def test_failsafe_uses_separate_table_and_no_cross_scope_reference():
    """Fail-safe policies use the existing isolated renderer and verification scope."""
    from nvyr.config_scripts import firewall_failsafe
    from tests.lifecycle import firewall_context
    from nvyr.tree import ReadOnlyTree

    tree = {'firewall': {'fail-safe': configuration()['firewall']}}
    schema = Schema.bundled()
    effective = ReadOnlyTree(schema.defaults(tree))
    context = firewall_context(effective, {}, 'firewall_failsafe', ('firewall', 'fail-safe'),
                               True, previous_effective={}, schema=schema)
    scoped = firewall_failsafe.get_config(context)
    firewall_failsafe.verify(scoped, context)
    text = firewall_failsafe.generate(scoped, context)
    assert 'table inet nvyr_filter_failsafe' in text
    assert 'ct timeout ipv4_timeout_group_APP' in text
