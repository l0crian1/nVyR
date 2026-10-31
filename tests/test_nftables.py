import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from nvyr.config_scripts import firewall as firewall
from nvyr.errors import RouterError, RecoveryError
from nvyr.helpers import nftables
from nvyr.helpers.process import CommandError
from nvyr.helpers.nftables_formatters import (nft_rule, nft_family_dispatch, nft_state_policy, nft_log_prefix,
                                   nft_active_hooks, nft_chain_body)
from nvyr.schema import Schema
from tests.lifecycle import firewall_context
from nvyr.tree import ReadOnlyTree


def generated(configuration, previous=None):
    schema = Schema.bundled()
    tree = {'firewall': configuration}
    schema.validate_configuration(tree)
    effective = ReadOnlyTree(schema.defaults(tree))
    firewall.verify(effective, None)
    before = {'firewall': previous} if previous is not None else {}
    context = firewall_context(effective, ReadOnlyTree(before), 'firewall', ('firewall',),
                               previous_effective=ReadOnlyTree(schema.defaults(before)), schema=schema)

    return firewall.generate(effective, context)


def test_rendering_compiles_schema_once(monkeypatch):
    """Construct lifecycle snapshots using the schema already loaded by the caller."""
    bundled = Schema.bundled
    calls = []

    def load(*args, **kwargs):
        calls.append(True)
        return bundled(*args, **kwargs)

    monkeypatch.setattr(Schema, 'bundled', load)
    text = generated({'ipv4': {'forward': {'filter': {'rule': {'10': {'action': 'accept'}}}}}})

    assert 'accept comment "10|"' in text
    assert len(calls) == 1


def test_keymap_order_sets_and_comment_are_independent_of_input_order():
    rule = {
        'action': 'accept',
        'connection': {'state': ['related', 'established']},
        'source-address': {'1.1.1.1': {}},
        'destination-address': {'2.2.2.2': {}},
        'destination-port': ['23', '22'],
        'protocol': ['tcp'],
        'counter': {},
        'last-used': True,
    }
    expected = ('ct state { established, related } ip saddr { 1.1.1.1 } ip daddr { 2.2.2.2 } '
                'meta l4proto { tcp } th dport { 22, 23 } counter last accept comment "10|"')

    assert nft_rule('ipv4', 'forward', '10', rule) == expected
    assert nft_rule('ipv4', 'forward', '10', dict(reversed(list(rule.items())))) == expected

    rule.update({'source-port': ['53'], 'description': 'DNS \\ admin'})

    assert 'th sport { 53 }' in nft_rule('ipv4', 'forward', '10', rule)
    assert nft_rule('ipv4', 'forward', '10', rule).endswith('comment "10|DNS \\ admin"')


@pytest.mark.parametrize('flags', [(), ('counter',), ('last-used',), ('counter', 'last-used')])
def test_global_tracking_applies_only_to_enabled_numbered_firewall_rules(flags):
    rules = {'10': {'action': 'accept'},
             '20': {'action': 'drop', 'counter': {}, 'last-used': True},
             '30': {'action': 'drop', 'disable': True}}
    config = {family: {
        **{hook: {'filter': {'rule': deepcopy(rules)}} for hook in ('input', 'output', 'forward')},
        'name': {'CUSTOM': {'rule': deepcopy(rules)}},
    } for family in ('ipv4', 'ipv6')}
    config['ipv4']['prerouting'] = {'raw': {'rule': deepcopy(rules)}}
    config['global-options'] = dict.fromkeys(flags, True) | {
        'state-policy': {'established': {'action': 'accept'}}}
    original = deepcopy(config)

    text = generated(config)
    prefix = ''.join({'counter': 'counter ', 'last-used': 'last '}[flag] for flag in flags)

    assert text.count(prefix + 'accept comment "10|"') == 9
    assert text.count('counter last drop comment "20|"') == 9
    assert 'comment "30|' not in text
    assert text.count('counter accept comment "default|default-action accept"') == 9
    assert text.count('ct state vmap { established counter : accept }') == 3
    assert config == original

    numbered = [line.strip() for line in text.splitlines() if 'comment "10|' in line]

    assert numbered == [prefix + 'accept comment "10|"'] * 9

    config['global-options'] = {}
    without_globals = generated(config)

    assert without_globals.count('\n        accept comment "10|"') == 9
    assert without_globals.count('counter last drop comment "20|"') == 9
    assert 'chain ' not in generated({'global-options': dict.fromkeys(flags, True)}).split('table inet nvyr_filter {')[1]


def test_global_tracking_cli_completion_and_no_implicit_configuration(controller, engine, session):
    options = dict(controller.completion('set firewall global-options ', session, explicit=True)['candidates'])

    assert {'counter', 'last-used', 'state-policy'} <= options.keys()

    controller.execute('set firewall ipv4 forward filter rule 10 action accept', session)
    controller.execute('set firewall global-options counter', session)
    controller.execute('set firewall global-options last-used', session)
    config = engine.view(session)
    effective = engine.schema.defaults(config)

    for tree in (config, effective):
        assert tree['firewall']['ipv4']['forward']['filter']['rule']['10'] == {'action': 'accept'}

    assert 'counter last accept comment "10|"' in generated(config['firewall'])

    for flag in ('counter', 'last-used'):
        with pytest.raises(RouterError):
            engine.schema.validate_configuration({'firewall': {'global-options': {flag: False}}})


@pytest.mark.parametrize('owner', ['firewall', 'nat'])
def test_last_used_replaces_old_schema_key(owner):
    rule = {'action': 'accept'} if owner == 'firewall' else {'exclude': True}

    def configuration(flag):
        rules = {'rule': {'10': rule | {flag: True}}}
        return ({'firewall': {'ipv4': {'input': {'filter': rules}}}} if owner == 'firewall'
                else {'nat': {'source': rules}})

    schema = Schema.bundled()
    schema.validate_configuration(configuration('last-used'))

    with pytest.raises(RouterError):
        schema.validate_configuration(configuration('last'))


def test_global_tracking_is_render_only_and_does_not_affect_nat():
    from nvyr.helpers.nftables_formatters import nft_nat_rule

    rule = ReadOnlyTree({'action': 'accept'})
    options = ReadOnlyTree({'counter': True, 'last-used': True})

    assert nft_rule('ipv4', 'input', '10', rule, options) == 'counter last accept comment "10|"'
    assert dict(rule) == {'action': 'accept'}
    assert dict(options) == {'counter': True, 'last-used': True}
    assert nft_nat_rule('source', '10', {'exclude': True}) == 'return comment "10|"'


def test_ipv6_protocol_prefixes_ports_ranges_and_singleton_sets():
    rule = {
        'action': 'drop',
        'protocol': ['ipv6-icmp'],
        'source-address': {'2001:0db8::1/64': {}},
        'connection': {'state': ['new']},
        'description': 'a' * 121,
    }

    assert nft_rule('ipv6', 'forward', '999999', rule).startswith(
        'ct state { new } ip6 saddr { 2001:0db8::1/64 } meta l4proto { ipv6-icmp } drop')
    assert 'th dport { 22, 80, 8000-8100 }' in nft_rule('ipv4', 'forward', '1',
        {'action': 'accept', 'protocol': ['tcp'], 'destination-port': ['8000-8100', '80', '22']})
    assert nft_rule('ipv4', 'forward', '2', {'action': 'accept'}) == 'accept comment "2|"'
    assert 'th dport { 22-85, 80, 84-90, 91 }' in nft_rule('ipv4', 'forward', '1', {'action': 'accept',
        'protocol': ['tcp'], 'destination-port': ['80', '22-85', '84-90', '91']})


@pytest.mark.parametrize('family,addresses', [
    ('ipv4', ['10.0.1.0/25', '10.0.1.128/25', '10.0.1.1', '10.0.1.0/25']),
    ('ipv6', ['2001:db8::/65', '2001:db8:0:0:8000::/65', '2001:db8::1', '2001:db8::/65']),
])
def test_sets_are_sorted_but_left_for_nftables_to_normalize(family, addresses):
    ports = ['100-200', '150-250', '251-300', '80', '80', '200-260', '150']
    rule = {'action': 'accept', 'protocol': ['tcp'], 'source-address': {address: {} for address in addresses},
            'destination-port': ports}
    text = nft_rule(family, 'forward', '10', rule)

    assert 'saddr { ' + ', '.join(sorted(set(addresses))) + ' }' in text
    assert 'th dport { ' + ', '.join(sorted(ports)) + ' }' in text

    reordered = dict(reversed(list(rule.items())))
    reordered.update({'source-address': {address: {} for address in reversed(addresses)}, 'destination-port': list(reversed(ports))})

    assert nft_rule(family, 'forward', '10', reordered) == text


@pytest.mark.parametrize('family,number,rule', [
    ('unsupported', '1', {'action': 'drop'}), ('ipv4', '0', {'action': 'drop'}),
    ('ipv4', '1', {'action': 'drop; flush ruleset'}),
    ('ipv4', '1', {'action': 'accept', 'protocol': ['tcp; drop']}),
    ('ipv4', '1', {'action': 'accept', 'description': '"; flush ruleset; #'}),
    ('ipv4', '1', {'action': 'accept', 'description': '\n'}),
    ('ipv4', '1', {'action': 'accept', 'counter': False}),
    ('ipv4', '1', {'action': 'accept', 'connection': {'state': 'new'}}),
    ('ipv4', '1', {'action': 'accept', 'destination-port': ['22; drop']}),
    ('ipv4', '1', {'action': 'accept', 'source-address': {'1.1.1.1; drop': {}}}),
    ('ipv4', '1', {'action': 'accept', 'unknown': True}),
])
def test_schema_rejects_unsafe_or_unsupported_values_before_rendering(family, number, rule):
    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration({
            'firewall': {family: {'forward': {'filter': {'rule': {number: rule}}}}}})


def test_only_configured_filters_create_chains_and_direct_defaults():
    assert 'chain forward {' not in generated({'description': 'not a filter', 'ipv4': {'forward': {}}})

    text = generated({'ipv4': {'forward': {'filter': {}}}})

    assert 'chain forward {' in text and 'chain ipv4_forward {' in text
    assert 'chain input {' not in text and 'chain output {' not in text and 'chain ipv6_forward {' not in text
    assert 'meta nfproto vmap { ipv4 : jump ipv4_forward }' in text
    assert 'counter accept comment "default|default-action accept"' in text
    assert 'ct state vmap' not in text and '\n        log\n' not in text
    assert text.index('add table inet nvyr_filter') < text.index('chain ipv4_forward {')
    assert 'destroy chain' not in text  # Initial creation has no previous objects to replace.
    replacement = generated({'ipv4': {'forward': {'filter': {}}}},
                            previous={'ipv6': {'forward': {'filter': {}}}})
    assert replacement.index('destroy chain inet nvyr_filter forward') < replacement.index('chain forward {')
    assert 'destroy chain inet nvyr_filter ipv6_forward' in replacement
    assert 'destroy chain inet nvyr_filter ipv4_forward' not in replacement
    assert 'delete chain' not in text and 'flush ruleset' not in text


def test_all_hooks_families_numeric_rule_order_and_global_state_policies():
    rules = {'100': {'action': 'drop'}, '2': {'action': 'accept'}, '10': {'action': 'reject'}}
    config = {'ipv4': {hook: {'filter': {'rule': rules}} for hook in ('input', 'forward', 'output')},
              'ipv6': {'forward': {'filter': {}}},
              'global-options': {'state-policy': {'related': {'action': 'accept'},
                  'established': {'action': 'accept'}, 'invalid': {'action': 'drop'}}}}
    text = generated(config)

    assert text.count('ct state vmap { established counter : accept, invalid counter : drop, related counter : accept }') == 3
    assert 'chain state_reject {' not in text
    assert 'meta nfproto vmap { ipv4 : jump ipv4_forward, ipv6 : jump ipv6_forward }' in text
    assert text.index('comment "2|"') < text.index('comment "10|"') < text.index('comment "100|"')

    for hook in ('input', 'forward', 'output'):
        chain = text.split('chain ' + hook + ' {', 1)[1]

        assert chain.index('ct state vmap') < chain.index('meta nfproto vmap')

    assert 'chain ' not in generated({'global-options': config['global-options']}).split('table inet nvyr_filter {')[1]


@pytest.mark.parametrize('family,protocol', [('ipv4', 'icmp'), ('ipv6', 'ipv6-icmp')])
@pytest.mark.parametrize('field', ['source-port', 'destination-port'])
@pytest.mark.parametrize('hook', ['input', 'forward', 'output'])
def test_ports_require_port_protocol_for_each_family_hook(family, protocol, field, hook):
    rule = {'action': 'accept', field: ['22']}

    for invalid in (None, protocol):
        if invalid:
            rule['protocol'] = [invalid]

        with pytest.raises(RouterError, match=f'{field} requires an explicit port protocol'):
            generated({family: {hook: {'filter': {'rule': {'10': rule}}}}})

    for valid in ('tcp', 'udp', 'udplite', 'sctp', 'dccp'):
        rule['protocol'] = [valid]

        assert 'th ' in generated({family: {hook: {'filter': {'rule': {'10': rule}}}}})


@pytest.mark.parametrize('command', [
    'rule 0 action accept', 'rule 1000000 action accept', 'rule 0000001 action accept',
    'rule 1 description ' + 'a' * 122, 'rule 1 description ' + 'é' * 61,
    'rule 1 destination-port 0', 'rule 1 destination-port 65536',
    'rule 1 destination-port 90-80', 'rule 1 source-port 1-65536',
    'rule 1 source-port 1:2', 'rule 1 source-port -1',
    'rule 1 source-port 080', 'rule 1 destination-port 1-0080',
    'rule 1 source-address 2001:db8::1',
])
def test_firewall_limits_and_types_use_schema_validation(engine, session, command):
    from nvyr.lexer import lex

    with pytest.raises(RouterError):
        engine.mutate(session, 'set', lex('firewall ipv4 forward filter ' + command))


def test_global_policy_requires_an_action_and_missing_rule_action_is_contextual():
    with pytest.raises(RouterError, match='state-policy invalid: action is required'):
        generated({'global-options': {'state-policy': {'invalid': {}}}})

    with pytest.raises(RouterError, match='firewall ipv6 input filter rule 42: action is required'):
        generated({'ipv6': {'input': {'filter': {'rule': {'42': {}}}}}})


def test_nft_loader_checks_then_atomically_loads_one_file_and_publishes(tmp_path, monkeypatch):
    calls = []
    text = generated({'ipv4': {'forward': {'filter': {}}}})

    def run(argv, **kwargs):
        calls.append(argv)

        assert Path(argv[-1]).read_text() == text
        assert not (tmp_path / 'firewall.nft').exists()

        return 0, ''

    monkeypatch.setattr(nftables, 'rc_cmd', run)
    nftables.Manager().apply(text, tmp_path)

    assert [argv[:-1] for argv in calls] == [['nft', '--check', '--file'], ['nft', '--file']]
    assert calls[0][-1] == calls[1][-1]
    assert (tmp_path / 'firewall.nft').read_text() == text
    assert list(tmp_path.iterdir()) == [tmp_path / 'firewall.nft']


@pytest.mark.parametrize('stage', ['check', 'apply'])
def test_rejected_nft_transaction_keeps_last_file(tmp_path, monkeypatch, stage):
    import sys

    bindir, state = tmp_path/'bin', tmp_path/'state'
    bindir.mkdir()
    state.mkdir()
    executable = bindir/'nft'
    executable.write_text('#!' + sys.executable + '\nimport sys\n'
                          f'raise SystemExit(1 if ("--check" in sys.argv) == {stage == "check"!r} else 0)\n')
    executable.chmod(0o755)
    monkeypatch.setenv('PATH', str(bindir))  # Never execute the host packet filter.
    destination = state/'firewall.nft'
    destination.write_text('previous')

    with pytest.raises(RouterError, match="nftables"):
        nftables.Manager().apply('candidate', state)

    assert destination.read_text() == 'previous'
    assert list(state.iterdir()) == [destination]


def test_check_only_never_applies_or_publishes(tmp_path, monkeypatch):
    """Inactive fail-safe validation must not change accounting or the saved artifact."""
    destination = tmp_path / 'firewall_failsafe.nft'
    destination.write_text('previous')
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        assert '--check' in argv
        return 0, ''

    monkeypatch.setattr(nftables, 'rc_cmd', run)
    nftables.Manager().apply('candidate', tmp_path, owner='firewall_failsafe',
                            accounting=True, check_only=True)
    assert len(calls) == 1
    assert destination.read_text() == 'previous'
    assert list(tmp_path.iterdir()) == [destination]


def test_table_inventory_checks_family_and_propagates_query_errors(monkeypatch):
    monkeypatch.setattr(nftables, 'cmd', lambda argv: '{"nftables": ['
                        '{"table": {"family": "ip", "name": "nvyr_filter_failsafe"}},'
                        '{"table": {"family": "inet", "name": "nvyr_filter"}}]}')
    manager = nftables.Manager()
    assert not manager.table_exists('nvyr_filter_failsafe')
    assert manager.table_exists('nvyr_filter')

    def fail(argv):
        raise RouterError('nft inventory failed')

    monkeypatch.setattr(nftables, 'cmd', fail)
    with pytest.raises(RouterError, match='inventory failed'):
        manager.table_exists('nvyr_filter_failsafe')


def test_uncertain_nft_load_requires_engine_recovery(tmp_path, monkeypatch):
    def run(argv, **kwargs):
        if '--check' not in argv:
            raise CommandError('timeout') from subprocess.TimeoutExpired(argv, 15)

        return 0, ''

    monkeypatch.setattr(nftables, 'rc_cmd', run)

    with pytest.raises(RecoveryError, match='outcome is uncertain'):
        nftables.Manager().apply('candidate', tmp_path)


def test_nft_post_apply_persistence_failure_requires_recovery(tmp_path, monkeypatch):
    monkeypatch.setattr(nftables, 'rc_cmd', lambda argv, **kwargs: (0, ''))
    monkeypatch.setattr(nftables, 'sync_directory', lambda path: (_ for _ in ()).throw(OSError('disk error')))

    with pytest.raises(RecoveryError, match='could not be published'):
        nftables.Manager().apply('candidate', tmp_path)


def test_multi_addresses_protocols_and_nonexistent_interface_names():
    rule = {'action': 'accept', 'protocol': ['udp', 'tcp'], 'destination-port': ['53'],
            'source-address': {'192.0.2.1': {}, '192.0.2.0/24': {}, '198.51.100.1': {}},
            'destination-address': {'203.0.113.1': {}},
            'inbound-interface': ['future1', 'future0'], 'outbound-interface': ['later0']}
    text = generated({'ipv4': {'forward': {'filter': {'rule': {'10': rule}}}}})

    assert 'iifname { "future0", "future1" } oifname { "later0" }' in text
    assert 'ip saddr { 192.0.2.0/24, 192.0.2.1, 198.51.100.1 } ip daddr { 203.0.113.1 }' in text
    assert 'meta l4proto { tcp, udp } th dport { 53 }' in text

    with pytest.raises(RouterError):
        generated({'ipv4': {'forward': {'filter': {'rule': {'10': {'action': 'accept', 'protocol': ['all']}}}}}})


@pytest.mark.parametrize('protocols', [[], ['all'], ['tcp', 'icmp'], ['tcp', 'all'], ['udp', 'icmp']])
def test_port_validation_rejects_any_non_transport_protocol(protocols):
    rule = {'action': 'accept', 'protocol': protocols, 'source-port': ['53']}

    with pytest.raises(RouterError, match='source-port requires an explicit port protocol'):
        firewall.verify_rule(rule, ('firewall', 'ipv4', 'forward', 'filter', 'rule', '10'), {})


@pytest.mark.parametrize('name', ['bad/name', 'bad name', 'eth*0', 'x' * 16, 'x";drop'])
def test_interface_match_syntax_validation(name):
    with pytest.raises(RouterError):
        generated({'ipv4': {'forward': {'filter': {'rule': {'10': {'action': 'accept', 'inbound-interface': [name]}}}}}})


def test_dispatch_helper_default_log_and_restricted_actions(controller, session):
    config = {'ipv4': {'input': {'filter': {}}}, 'ipv6': {'input': {'filter': {}}}}

    assert nft_family_dispatch(config, 'input') == 'meta nfproto vmap { ipv4 : jump ipv4_input, ipv6 : jump ipv6_input }'
    assert nft_family_dispatch(config, 'forward') == ''

    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration({'firewall': {'ipv4': {'input; drop': {'filter': {}}}}})

    text = generated({'ipv4': {'input': {'filter': {'default-log': True}}}})

    assert '        counter log prefix "[ipv4-INP-filter-default-A]" accept comment "default|default-action accept"' in text

    for action in ('return', 'continue'):
        with pytest.raises(RouterError):
            controller.execute('set firewall ipv4 input filter default-action ' + action, session)

    with pytest.raises(RouterError):
        controller.execute('set firewall ipv4 input filter log', session)

    with pytest.raises(RouterError):
        controller.execute('set firewall global-options state-policy invalid action return', session)

    options = dict(controller.completion('set firewall ipv4 input filter ', session, explicit=True)['candidates'])

    assert 'default-log' in options and 'log' not in options

    options = dict(controller.completion('set firewall global-options state-policy invalid action ', session, explicit=True)['candidates'])

    assert set(options) == {'accept', 'drop', 'reject'}


def test_firewall_follows_interface_owners_on_commit_and_recovery(engine, controller, session, monkeypatch):
    from tests.lifecycle import LifecycleStub

    calls = []

    class Recorded(LifecycleStub):
        def apply(self, generated, context):
            calls.append(context.owner)

    for owner in engine.modules:
        monkeypatch.setitem(engine.modules, owner, Recorded())

    interface_owners = [owner for owner, (path, _) in engine.schema.owners.items() if path[0] == 'interfaces']

    assert interface_owners
    assert all(engine.schema.owners['firewall'][1] > engine.schema.owners[owner][1] for owner in interface_owners)

    for command in ('set interfaces ethernet eth0', 'set interfaces dummy dum0',
                    'set firewall ipv4 forward filter'):
        controller.execute(command, session)

    engine.commit(session)

    assert calls == ['dummy', 'ethernet', 'firewall']

    calls.clear()
    engine._run_recovery(engine.running, engine.running, set(engine.schema.owners))

    assert calls.index('firewall') > max(calls.index(owner) for owner in interface_owners)


def test_show_firewall_uses_existing_operational_execution(controller, session, monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return 'table inet nvyr_filter {\n}\n'

    monkeypatch.setattr('nvyr.controller.cmd', run)

    for command, context in [('show firewall', None), ('run show firewall', session)]:
        assert 'table inet nvyr_filter' in controller.execute(command, context)['text']

    assert calls == [['firewall.nvyr.op', 'show']] * 2


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('hook,label', [('input', 'INP-filter'), ('output', 'OUT-filter'), ('forward', 'FWD-filter'), ('prerouting', 'PRE-raw'), ('output_raw', 'OUT-raw')])
@pytest.mark.parametrize('action,letter', [('accept', 'A'), ('drop', 'D'), ('reject', 'R'), ('continue', 'C')])
def test_log_prefix_context(family, hook, label, action, letter):
    assert nft_log_prefix(family, hook, '500', action) == f'"[{family}-{label}-500-{letter}]"'


def test_default_log_is_on_the_default_rule_and_rule_logs_include_context():
    text = generated({'ipv4': {'input': {'filter': {'default-log': True, 'default-action': 'drop',
        'rule': {'10': {'action': 'accept', 'log': {}}, '20': {'action': 'reject', 'log': {}}}}}}})

    assert 'log prefix "[ipv4-INP-filter-10-A]" accept comment "10|"' in text
    assert 'log prefix "[ipv4-INP-filter-20-R]" reject comment "20|"' in text
    assert 'counter log prefix "[ipv4-INP-filter-default-D]" drop comment "default|default-action drop"' in text
    assert '\n        log\n' not in text

    plain = generated({'ipv6': {'output': {'filter': {'default-action': 'drop'}}}})

    assert 'counter drop comment "default|default-action drop"' in plain and 'log prefix' not in plain


def test_state_policy_helper_is_sorted_counted_and_scoped():
    assert nft_state_policy({'related': {'action': 'accept'}, 'invalid': {'action': 'drop'},
                             'established': {'action': 'accept'}}) == (
        'ct state vmap { established counter : accept, invalid counter : drop, related counter : accept }')
    assert nft_state_policy({}) == ''

    for invalid in ({'new': {'action': 'accept'}}, {'invalid': {'action': 'return'}}):
        with pytest.raises(RouterError):
            Schema.bundled().validate_configuration({'firewall': {'global-options': {'state-policy': invalid}}})


def test_raw_scope_shared_fields_and_disabled_rules(controller, engine, session):
    prefix = 'firewall ipv4 prerouting raw'
    controller.execute('set ' + prefix + ' rule 10 action continue notrack log counter inbound-interface future0', session)
    controller.execute('set ' + prefix + ' rule 20 disable', session)
    controller.execute('set firewall ipv4 input filter rule 30 action drop disable', session)
    controller.execute('set firewall global-options state-policy invalid action drop', session)
    tree = engine.view(session)
    text = generated(tree['firewall'])

    assert 'type filter hook prerouting priority raw; policy accept;' in text
    assert 'meta nfproto vmap { ipv4 : jump ipv4_prerouting }' in text
    assert 'iifname { "future0" } log prefix "[ipv4-PRE-raw-10-C]" counter notrack continue comment "10|"' in text
    assert '20|' not in text and '30|' not in text
    assert text.count('ct state vmap') == 1  # Input only, never prerouting raw.
    assert 'state_reject' not in text and 'chain ipv6_prerouting {' not in text
    removed = generated({}, previous=tree['firewall'])
    assert 'destroy chain inet nvyr_filter prerouting' in removed
    assert 'destroy chain inet nvyr_filter ipv4_prerouting' in removed
    assert 'chain prerouting {' not in removed
    assert nft_rule('ipv4', 'prerouting', '20', {'disable': True}) == ''

    engine.commit(session)
    engine.save(session)

    assert engine.store.read('boot.json')['firewall']['ipv4']['prerouting']['raw']['rule']['20'] == {'disable': True}

    controller.execute('delete ' + prefix + ' rule 20 disable', session)
    result = engine.commit(session)['results']['firewall']

    assert not result['success'] and 'prerouting raw rule 20: action is required' in result['error']


@pytest.mark.parametrize('suffix', ['outbound-interface eth0', 'notrack true'])
def test_raw_schema_rejects_unavailable_fields(controller, session, suffix):
    with pytest.raises(RouterError):
        controller.execute('set firewall ipv4 prerouting raw rule 10 ' + suffix, session)


def test_notrack_is_raw_only_and_raw_port_checks_are_contextual(controller, session):
    with pytest.raises(RouterError):
        controller.execute('set firewall ipv4 input filter rule 10 notrack', session)

    with pytest.raises(RouterError):
        controller.execute('set firewall ipv6 output filter rule 10 notrack', session)

    with pytest.raises(RouterError, match='prerouting raw rule 10: destination-port requires'):
        generated({'ipv4': {'prerouting': {'raw': {'rule': {'10': {'action': 'accept', 'destination-port': ['53']}}}}}})

    possibilities = dict(controller.completion('set firewall ipv4 prerouting raw rule 10 ', session, explicit=True)['candidates'])

    assert {'notrack', 'disable', 'inbound-interface'} <= possibilities.keys()
    assert 'outbound-interface' not in possibilities


@pytest.mark.parametrize('configuration,expected', [
    ({}, []),
    ({'global-options': {'state-policy': {'established': {'action': 'accept'}}}}, []),
    ({'ipv4': {'name': {'CUSTOM': {}}}, 'flowtable': {'FAST': {}}}, []),
    ({'ipv6': {'forward': {'filter': {}}}}, ['forward']),
    ({'ipv4': {'output': {'filter': {}}, 'input': {'filter': {}},
               'prerouting': {'raw': {}}, 'forward': {'filter': {}}}},
     ['input', 'forward', 'output', 'prerouting']),
    ({'ipv6': {'prerouting': {'raw': {}}}}, ['prerouting']),
])
def test_active_hooks_select_configured_chains_without_rendering(configuration, expected, monkeypatch):
    def unexpected_render(*args):
        raise AssertionError('Hook selection must not render a dispatch expression')

    monkeypatch.setattr('nvyr.helpers.nftables_formatters._nft_dispatch', unexpected_render)
    assert nft_active_hooks(ReadOnlyTree(configuration)) == expected


@pytest.mark.parametrize('family,hook', [('ipv4', 'forward'), ('ipv6', 'name_CUSTOM'), ('ipv4', 'prerouting')])
def test_chain_body_orders_rules_skips_disabled_and_preserves_configuration(family, hook):
    chain = {
        'rule': {'10': {'action': 'drop'}, '2': {'action': 'accept'},
                 '1': {'disable': True}},
        'default-action': 'drop',
        'default-log': True,
    }
    original = deepcopy(chain)
    global_options = {'counter': True, 'last-used': True}

    lines = nft_chain_body(family, hook, ReadOnlyTree(chain), global_options).splitlines()

    assert lines[:2] == [
        'counter last accept comment "2|"',
        'counter last drop comment "10|"',
    ]
    prefix = nft_log_prefix(family, hook, 'default', 'drop')
    assert lines[2] == f'counter log prefix {prefix} drop comment "default|default-action drop"'
    assert chain == original
    assert global_options == {'counter': True, 'last-used': True}


def test_chain_body_without_rules_still_renders_default():
    assert nft_chain_body('ipv4', 'input', {'default-action': 'accept'}) == (
        'counter accept comment "default|default-action accept"'
    )
