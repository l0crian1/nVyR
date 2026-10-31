"""Firewall display, shared formatting, and command-tree dispatch."""

from copy import deepcopy
import json
from pathlib import Path

import pytest

from nvyr import opmode
from nvyr.errors import OperationalError, ParseError
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.helpers.output import detailed_output
from nvyr.helpers.process import operational_argv
from nvyr.lexer import lex
from nvyr.op_scripts import firewall


@pytest.fixture
def installed(monkeypatch):
    path = Path(__file__).parent / 'fixtures/nftables/listings.json'
    document = json.loads(path.read_text())['ruleset']
    groups = {'map': {'ipv4': {}}, 'match-group': {'ipv4': {}}}
    groups['map']['ipv4']['POLICY'] = {'match': {'source-address': {}, 'destination-port': {}}}
    groups['map']['ipv4']['NAT'] = {'match': {'destination-address': {}, 'destination-port': {}}}
    groups['match-group']['ipv4']['PAIR'] = {'match': {'source-address': {}, 'destination-port': {}}}
    configuration = {'firewall': {'group': groups}}
    table = normalize(document, configuration=configuration)['tables']['inet']['nvyr_filter']
    monkeypatch.setattr(firewall, '_load_table', lambda **kwargs: table)
    return table


def test_summary_preserves_kernel_order_and_tracking(installed, capsys):
    installed['chains']['ipv4_forward']['rules'].append({'number': 'default', 'action': 'drop'})
    firewall.show(family='ipv4', hook='forward')
    output = capsys.readouterr().out

    assert 'IPv4 forward filter' in output
    assert 'Packets' in output and 'Bytes' in output
    assert 'Never' in output and '2s ago' in output
    assert 'jump TARGET' in output and 'map POLICY' in output
    assert output.index('states') < output.index('ports') < output.index('default')
    assert 'ipv4_nat' not in output and 'Entry' not in output
    assert '=' * 72 + '\nIPv4 forward filter' in output


def test_rule_detail_and_masking_do_not_modify_data(installed, capsys):
    original = deepcopy(installed)
    firewall.show(family='ipv4', hook='forward', rule='20', detail=True)
    output = capsys.readouterr().out
    assert 'Source address' in output and '192.0.2.0/24' in output
    assert '11:22:33:00:00:00 mask ff:ff:ff:00:00:00' in output
    assert ' | ' in output
    assert 'transport' not in output

    firewall.show(family='ipv4', hook='forward', rule='20', strip_private=True, detail=True)
    masked = capsys.readouterr().out
    assert '<ipv4>' in masked and '<mac> mask <mac>' in masked
    assert '192.0.2' not in masked and '11:22:33' not in masked
    assert installed == original


def test_rule_detail_displays_fib_query(installed, capsys):
    rule = next(rule for rule in installed['chains']['ipv4_forward']['rules'] if rule.get('number') == '20')
    rule['fib'] = {'lookup': {'source-address': True, 'inbound-interface': True},
                   'result': {'outbound-interface': ['missing']}}

    firewall.show(family='ipv4', hook='forward', rule='20', detail=True)
    output = capsys.readouterr().out
    assert 'FIB' in output
    assert 'source-address: Enabled' in output
    assert 'outbound-interface: missing' in output
    assert 'Unsupported expressions' not in output


def test_connection_detail_and_group_columns_mask_addresses(installed, capsys):
    rule = next(rule for rule in installed['chains']['ipv4_forward']['rules'] if rule.get('number') == '20')
    rule.update({
        'connection-original-destination-address': ['203.0.113.10'],
        'connection-reply-packets': {'gt': 10},
        'connection-label': ['1 and 127'],
    })
    group = installed['maps']['ipv4_map_POLICY']
    group['match-fields'] = ['connection-original-destination-address', 'connection-original-destination-port']
    group['entries'][0]['key'] = ['203.0.113.10', 443]
    original = deepcopy(installed)

    firewall.show(family='ipv4', hook='forward', rule='20', detail=True, strip_private=True)
    output = capsys.readouterr().out
    assert 'Connection original destination address' in output
    assert 'Connection reply packets' in output and 'gt: 10' in output
    assert '1 and 127' in output
    assert '203.0.113.10' not in output and '<ipv4>' in output

    firewall.show(section='group', family='ipv4', group_kind='map', group_name='POLICY', strip_private=True)
    output = capsys.readouterr().out
    assert 'Connection original destination port' in output
    assert '203.0.113.10' not in output and '<ipv4>' in output
    assert installed == original


def test_map_columns_follow_renderer_and_keep_leading_zero_ids(installed, capsys):
    group = installed['maps']['ipv4_map_POLICY']
    group['entries'][0]['name'] = '001'
    firewall.show(section='group', family='ipv4', group_kind='map', group_name='POLICY')
    output = capsys.readouterr().out

    assert output.index('Source address') < output.index('Destination port') < output.index('Result')
    assert 'jump TARGET' in output and '001' in output
    assert 'Policy' in output and 'entry' in output
    assert 'LEARNED' not in output

    firewall.show(section='group', family='ipv4', group_kind='map', group_name='POLICY', strip_private=True)
    masked = capsys.readouterr().out
    assert '192.0.2.1' not in masked and '<ipv4>' in masked
    assert '<private>' in masked


def test_dynamic_group_and_flowtable(installed, capsys):
    installed['flowtables']['flowtable_FAST'] = {'interface': ['eth0', 'eth1'], 'hook': 'ingress', 'prio': 0}
    firewall.show(section='group', group_kind='address-group', group_name='LEARNED')
    output = capsys.readouterr().out
    assert 'GC interval' in output and '30s' in output
    assert 'Expires' in output and 'Last used' in output
    assert '192.0.2.1' in output

    firewall.show(section='flowtable')
    output = capsys.readouterr().out
    assert 'Flowtable' in output and 'Interface' in output


@pytest.mark.parametrize('detail', [False, True])
def test_unsupported_rule_and_group_remain_visible(installed, capsys, detail):
    installed['chains']['ipv4_forward']['rules'][0]['unsupported'] = [{'reason': 'unknown'}]
    installed['sets']['ipv4_address_group_LEARNED']['entries'].append({'unsupported': {'private': 'secret'}})
    firewall.show(detail=detail)
    output = capsys.readouterr().out

    if not detail:
        assert '[incomplete]' in output
    assert 'unsupported expressions' in output
    assert 'unsupported group data' in output
    assert 'secret' not in output


def test_missing_and_empty_scopes(installed, capsys, monkeypatch):
    with pytest.raises(OperationalError, match='Rule 999 is not installed'):
        firewall.show(family='ipv4', hook='forward', rule='999')
    with pytest.raises(OperationalError, match='not installed'):
        firewall.show(family='ipv4', named=True, chain_name='MISSING')

    monkeypatch.setattr(firewall, '_load_table', lambda **kwargs: {})
    firewall.show()
    assert 'No firewall objects installed' in capsys.readouterr().out


def test_named_scope_excludes_other_chains(installed, capsys):
    installed['chains']['ipv4_name_CUSTOM'] = {'rules': [{'number': '1', 'action': 'return'}]}
    firewall.show(family='ipv4', named=True, chain_name='CUSTOM')
    output = capsys.readouterr().out
    assert 'name CUSTOM' in output and 'return' in output
    assert 'forward filter' not in output and 'Entry' not in output


@pytest.mark.parametrize('hook', [None, 'input', 'forward', 'output'])
@pytest.mark.parametrize('detail', [False, True])
def test_state_policy_scope_preserves_counters_and_excludes_other_tables(installed, capsys, hook, detail):
    for policy_hook in ('input', 'forward', 'output'):
        installed['chains'][policy_hook] = {'rules': [
            {'verdict-map': {'fields': ['state'], 'entries': [
                {'key': ['established'], 'result': {'action': 'accept'},
                 'counter': {'packets': 58, 'bytes': 9008}},
                {'key': ['invalid'], 'result': {'action': 'drop'},
                 'counter': {'packets': 0, 'bytes': 0}},
            ]}},
            {'verdict-map': {'fields': ['address-family'], 'entries': [
                {'key': ['ipv4'], 'result': {'action': 'jump', 'jump-target': 'ipv4_' + policy_hook}},
            ]}},
        ]}
    original = deepcopy(installed)

    firewall.show(section='state-policy', hook=hook, detail=detail)
    output = capsys.readouterr().out

    for policy_hook in ('input', 'forward', 'output'):
        assert (f'State policy ({policy_hook})' in output) == (hook is None or hook == policy_hook)
    assert 'established' in output and 'invalid' in output
    assert '58' in output and '9008' in output
    assert (' | ' in output) == detail
    assert 'jump' not in output and 'POLICY' not in output and 'LEARNED' not in output
    assert 'IPv4 forward filter' not in output
    assert installed == original


def test_state_policy_empty_scope(installed, capsys):
    firewall.show(section='state-policy', hook='output')
    assert capsys.readouterr().out == 'No firewall objects installed in this scope.\n'


def test_state_policy_hook_completion(controller, session):
    for prefix, mode in [('', None), ('run ', session)]:
        result = controller.completion(prefix + 'show firewall state-policy ', mode, explicit=True)
        assert {'input', 'forward', 'output', 'detail', '<Enter>'} <= dict(result['candidates']).keys()


def test_unlabelled_group_does_not_guess_packet_fields(installed, capsys):
    installed['maps']['ipv4_map_POLICY'].pop('match-fields')
    firewall.show(section='group', group_name='POLICY')
    output = capsys.readouterr().out
    assert 'Key 1 (ipv4_addr)' in output
    assert 'Configured match fields unavailable' in output


def test_load_uses_read_only_rpc_and_one_ruleset_query(monkeypatch):
    requests = []

    class Client:
        def __init__(self, path):
            assert path == '/run/nvyr/configd.sock'

        def request(self, operation, **arguments):
            requests.append((operation, arguments))
            return {'text': '{}'}

        def close(self):
            requests.append('closed')

    def command(argv):
        assert argv == ['nft', '-j', 'list', 'ruleset']
        return '{"nftables": []}'

    monkeypatch.setattr(firewall, 'Client', Client)
    monkeypatch.setattr(firewall, 'cmd', command)
    assert firewall._load_table() == {}
    assert requests == [('execute', {'text': 'show running-configuration'}), 'closed']

    monkeypatch.setattr(firewall, 'cmd', lambda argv: 'not json')
    with pytest.raises(OperationalError, match='Cannot interpret firewall data'):
        firewall._load_table()


@pytest.mark.parametrize(('line', 'options'), [
    ('show firewall', []),
    ('show firewall state-policy', ['--section', 'state-policy']),
    ('show firewall state-policy input', ['--section', 'state-policy', '--hook', 'input']),
    ('show firewall state-policy forward', ['--section', 'state-policy', '--hook', 'forward']),
    ('show firewall state-policy output', ['--section', 'state-policy', '--hook', 'output']),
    ('show firewall ipv4', ['--family', 'ipv4']),
    ('show firewall ipv6 input filter', ['--family', 'ipv6', '--hook', 'input', '--stage', 'filter']),
    ('show firewall ipv4 prerouting raw rule 10', ['--family', 'ipv4', '--hook', 'prerouting', '--stage', 'raw', '--rule', '10']),
    ('show firewall ipv6 prerouting raw rule 10', ['--family', 'ipv6', '--hook', 'prerouting', '--stage', 'raw', '--rule', '10']),
    ('show firewall ipv4 output raw rule 10', ['--family', 'ipv4', '--hook', 'output', '--stage', 'raw', '--rule', '10']),
    ('show firewall ipv6 output raw rule 10', ['--family', 'ipv6', '--hook', 'output', '--stage', 'raw', '--rule', '10']),
    ('show firewall ipv6 output filter rule 10', ['--family', 'ipv6', '--hook', 'output', '--stage', 'filter', '--rule', '10']),
    ('show firewall ipv4 name', ['--family', 'ipv4', '--named']),
    ('show firewall ipv4 name CUSTOM rule 20', ['--family', 'ipv4', '--named', '--chain_name', 'CUSTOM', '--rule', '20']),
    ('show firewall group map ipv4 POLICY', ['--section', 'group', '--group_kind', 'map', '--family', 'ipv4', '--group_name', 'POLICY']),
    ('show firewall group match-group ipv6', ['--section', 'group', '--group_kind', 'match-group', '--family', 'ipv6']),
    ('show firewall group icmp-group', ['--section', 'group', '--group_kind', 'icmp-group']),
    ('show firewall group icmp-group ipv4 ERRORS', ['--section', 'group', '--group_kind', 'icmp-group', '--family', 'ipv4', '--group_name', 'ERRORS']),
    ('show firewall group icmp-group ipv6', ['--section', 'group', '--group_kind', 'icmp-group', '--family', 'ipv6']),
    ('show firewall group port-group WEB', ['--section', 'group', '--group_kind', 'port-group', '--group_name', 'WEB']),
    ('show firewall group counter-group TOTAL', ['--section', 'group', '--group_kind', 'counter-group', '--group_name', 'TOTAL']),
    ('show firewall group limit-group ipv4 LOGIN', ['--section', 'group', '--group_kind', 'limit-group', '--family', 'ipv4', '--group_name', 'LOGIN']),
    ('show firewall group limit-group ipv6', ['--section', 'group', '--group_kind', 'limit-group', '--family', 'ipv6']),
    ('show firewall flowtable FAST', ['--section', 'flowtable', '--group_name', 'FAST']),
    ('show firewall zone', ['--section', 'zone']),
    ('show firewall zone ipv4', ['--section', 'zone', '--family', 'ipv4']),
    ('show firewall zone ipv6', ['--section', 'zone', '--family', 'ipv6']),
    ('show firewall zone ipv4 A', ['--section', 'zone', '--family', 'ipv4', '--zone_name', 'A']),
    ('show firewall zone ipv6 A', ['--section', 'zone', '--family', 'ipv6', '--zone_name', 'A']),
])
@pytest.mark.parametrize('detail', [False, True])
def test_schema_dispatch(controller, line, options, detail):
    if detail:
        line += ' detail'
        options = [*options, '--detail']
    cursor = controller.operational.operational(lex(line))
    argv = operational_argv(cursor.node['command'], lex(line), line,
                            omitted_positions=cursor.omitted_positions)
    assert argv == ['firewall.nvyr.op', 'show', *options]


@pytest.mark.parametrize('detail', [False, True])
def test_named_counter_and_limit_display(monkeypatch, capsys, detail):
    document = {'nftables': [
        {'counter': {'family': 'inet', 'table': 'nvyr_filter', 'name': 'counter_group_TOTAL',
                     'packets': 42, 'bytes': 4200, 'comment': 'Shared counter'}},
        {'limit': {'family': 'inet', 'table': 'nvyr_filter', 'name': 'ipv4_limit_group_LOGIN',
                   'rate': 10, 'per': 'minute', 'burst': 5, 'inv': True}},
        {'rule': {'family': 'inet', 'table': 'nvyr_filter', 'chain': 'ipv4_input', 'comment': '10|',
                  'expr': [{'limit': 'ipv4_limit_group_LOGIN'}, {'counter': 'counter_group_TOTAL'}, {'drop': None}]}},
    ]}
    table = normalize(document)['tables']['inet']['nvyr_filter']
    monkeypatch.setattr(firewall, '_load_table', lambda **kwargs: table)

    firewall.show(section='group', group_kind='counter-group', group_name='TOTAL', detail=detail)
    output = capsys.readouterr().out
    assert 'counter-group TOTAL' in output
    assert '42' in output and '4200' in output
    assert (' | ' in output) == detail

    firewall.show(section='group', group_kind='limit-group', family='ipv4', detail=detail)
    output = capsys.readouterr().out
    assert 'IPv4 limit-group LOGIN' in output and '10/m' in output

    firewall.show(family='ipv4', hook='input', detail=True)
    output = capsys.readouterr().out
    assert 'TOTAL' in output and 'LOGIN' in output
    assert '4200' not in output


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('detail', [False, True])
def test_raw_and_filter_display_scopes(installed, capsys, family, detail):
    for native in ('output', 'output_raw', 'prerouting'):
        installed['chains'][family + '_' + native] = {'rules': [
            {'number': '10', 'action': 'continue', 'description': native},
            {'number': 'default', 'action': 'accept'},
        ]}
    installed['chains']['output_raw'] = {'rules': []}
    installed['chains']['prerouting'] = {'rules': []}

    for hook, stage in [('output', 'filter'), ('output', 'raw'), ('prerouting', 'raw')]:
        firewall.show(family=family, hook=hook, stage=stage, rule='10', detail=detail)
        output = capsys.readouterr().out
        assert f'{family.replace("ip", "IP")} {hook} {stage}' in output
        assert 'default' in output and '10' in output
        assert (' | ' in output) == detail
        assert ('output filter' in output) == (stage == 'filter')
        assert ('output raw' in output) == (hook == 'output' and stage == 'raw')

    firewall.show(family=family, hook='output')
    output = capsys.readouterr().out
    assert 'output raw' in output and 'output filter' in output

    firewall.show()
    output = capsys.readouterr().out
    assert 'State policy (output_raw)' not in output
    assert 'State policy (prerouting)' not in output


def test_rule_requires_a_number(controller):
    with pytest.raises(ParseError):
        controller.execute('show firewall ipv4 forward filter rule')


@pytest.mark.parametrize('detail', [False, True])
def test_selected_rule_keeps_default_action_only(installed, capsys, detail):
    installed['chains']['ipv4_forward']['rules'].append({'number': 'default', 'action': 'drop'})

    firewall.show(family='ipv4', hook='forward', rule='20', detail=detail)
    output = capsys.readouterr().out

    assert 'default' in output and 'masks' in output
    assert 'states' not in output and 'ports' not in output
    assert ('Source address' in output) == detail
    assert (' | ' in output) == detail
    assert ('Rule 20' in output) == detail


def test_detail_applies_to_whole_chain_and_named_chain(installed, capsys):
    installed['chains']['ipv4_name_CUSTOM'] = installed['chains']['ipv4_forward']

    for options in ({'hook': 'forward'}, {'named': True, 'chain_name': 'CUSTOM'}):
        firewall.show(family='ipv4', detail=True, **options)
        output = capsys.readouterr().out
        assert 'Rule 10' in output and 'Rule 20' in output and 'Rule 97' in output
        assert 'Source address' in output and ' | ' in output


@pytest.mark.parametrize('detail', [False, True])
def test_groups_only_use_detail_when_requested_and_omit_tracking_flags(installed, capsys, detail):
    firewall.show(section='group', detail=detail)
    output = capsys.readouterr().out
    assert (' | ' in output) == detail
    assert 'Enabled' not in output
    assert 'Packets' in output and 'Bytes' in output and 'Last used' in output


@pytest.mark.parametrize('detail', [False, True])
def test_flowtables_only_use_detail_when_requested(installed, capsys, detail):
    installed['flowtables']['flowtable_FAST'] = {'interface': ['eth0', 'eth1'], 'hook': 'ingress', 'prio': 0}

    firewall.show(section='flowtable', detail=detail)
    output = capsys.readouterr().out
    assert (' | ' in output) == detail
    assert 'eth0' in output and 'eth1' in output


@pytest.mark.parametrize('scope', [
    'show firewall', 'show firewall ipv4', 'show firewall ipv4 forward',
    'show firewall state-policy', 'show firewall state-policy output',
    'show firewall ipv4 forward filter', 'show firewall ipv4 forward filter rule 10',
    'show firewall ipv4 name CUSTOM', 'show firewall ipv4 name CUSTOM rule 20',
    'show firewall group', 'show firewall group map ipv4 test',
    'show firewall group interface-group WAN', 'show firewall flowtable test',
    'show firewall zone', 'show firewall zone ipv4', 'show firewall zone ipv6 A',
])
def test_detail_completion_in_both_modes(controller, session, scope):
    for prefix, mode in [('', None), ('run ', session)]:
        result = controller.completion(prefix + scope + ' ', mode, explicit=True)
        assert 'detail' in dict(result['candidates'])
        result = controller.completion(prefix + scope + ' det', mode, tab=True)
        assert result['replacement'] == 'detail'


def test_required_nested_rule_tag_is_suggested(controller):
    result = controller.completion('show firewall ipv4 name CUSTOM ', explicit=True)
    assert 'rule' in dict(result['candidates'])


def test_completion_and_execution_from_both_modes(controller, session, monkeypatch):
    controller.engine.running['firewall'] = {'group': {'port-group': {'WEB': {'port': ['443']}}}}
    calls = []

    def command(argv, **options):
        calls.append(argv)
        return 'Firewall display\n'

    monkeypatch.setattr('nvyr.controller.cmd', command)
    for prefix, mode in [('', None), ('run ', session)]:
        result = controller.completion(prefix + 'show firewall group port-group ', mode, explicit=True)
        assert 'WEB' in dict(result['candidates'])
        result = controller.execute(prefix + 'show firewall ipv4 forward filter rule 10', mode)
        assert result['text'] == 'Firewall display\n'
    assert calls[0] == calls[1]


def test_opmode_error_has_no_traceback(installed, capsys):
    with pytest.raises(SystemExit):
        opmode.run(['show', '--named', '--chain_name', 'MISSING'], namespace=vars(firewall))
    error = capsys.readouterr().err
    assert 'not installed' in error and 'Traceback' not in error


def test_missing_named_chain_value_has_clear_error(installed):
    with pytest.raises(OperationalError, match='Specify a named chain'):
        firewall.show(family='ipv4', named=True, rule='10')


@pytest.mark.parametrize('role', ['read-only', 'net-admin', 'sys-admin'])
def test_display_is_available_to_every_role(controller, monkeypatch, role):
    from tests.test_login import as_role

    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: 'Firewall display\n')
    with as_role(role):
        assert controller.execute('show firewall')['text'] == 'Firewall display\n'
        assert controller.execute('show firewall ipv4 forward filter | count')['text'] == '1\n'


def test_strip_private_flag_reaches_script(controller, monkeypatch):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')

    controller.execute('show firewall ipv4 forward filter rule 10 | strip-private')

    assert calls == [['firewall.nvyr.op', 'show', '--strip-private',
                      '--family', 'ipv4', '--hook', 'forward', '--stage', 'filter', '--rule', '10']]


def test_shared_detail_helper(capsys):
    from nvyr.op_scripts.interfaces import detailed_output as interfaces_output

    assert interfaces_output is detailed_output
    detailed_output([['eth0', 'up'], ['dum0', 'down']], ['Interface', 'State'])
    output = capsys.readouterr().out
    assert 'Interface | eth0' in output
    assert '\n\n' in output and 'dum0' in output
