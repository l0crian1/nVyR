"""Family-neutral rules share base chains, dependencies and operational views."""

from copy import deepcopy

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import RouterError
from nvyr.helpers.log_reader import select
from nvyr.helpers.nftables_formatters import nft_flowtable
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.helpers.process import operational_argv
from nvyr.lexer import lex
from nvyr.op_scripts import firewall as display
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


def inet_tree():
    """A neutral chain can coexist with both family-specific dispatch targets."""
    return {'firewall': {
        'inet': {'input': {'filter': {'rule': {'10': {
            'action': 'accept', 'inbound-interface': ['inside0'], 'counter': {},
        }}}}},
        'ipv4': {'input': {'filter': {'default-action': 'drop'}}},
        'ipv6': {'input': {'filter': {'default-action': 'drop'}}},
    }}


def test_inet_rules_follow_global_processing_and_precede_dispatch():
    """Shared rules execute without an extra jump or a terminating default."""
    tree = inet_tree()
    tree['firewall']['global-options'] = {'state-policy': {'established': {'action': 'accept'}}}
    text = rendered(tree)
    base = text[text.index('    chain input {'):]

    assert base.index('ct state') < base.index('iifname') < base.index('meta nfproto')
    assert 'chain inet_input' not in text
    assert 'default|' not in base
    assert text.count('default|default-action drop') == 2


def test_inet_only_hook_and_deletion_preserve_family_chains():
    """Removing neutral rules rebuilds dispatch without destroying IP policies."""
    before = inet_tree()
    after = deepcopy(before)
    del after['firewall']['inet']
    text = rendered(after, before)

    assert destroyed(text) == {'input'}
    assert 'meta nfproto vmap' in text
    assert 'inside0' not in text

    only = {'firewall': {'inet': before['firewall']['inet']}}
    assert 'type filter hook input' in rendered(only)
    assert destroyed(rendered({}, only)) == {'input'}


def test_inet_schema_keeps_neutral_matches_and_rejects_family_fields(controller, engine, session):
    """Unsupported inputs are absent from completions and rejected immediately."""
    controller.execute('set firewall inet input filter rule 10 action accept protocol tcp destination-port 22', session)
    choices = dict(controller.completion('set firewall inet input filter rule 10 ', session, explicit=True)['candidates'])
    assert {'connection', 'fib', 'map', 'match-group', 'limit', 'quota', 'tcp-flags', 'packet-length'} <= choices.keys()
    assert not {'source-address', 'destination-address', 'icmp-type', 'icmp-code', 'icmp-group', 'ttl', 'dscp'} & choices.keys()

    for option in ('source-address 192.0.2.1', 'source-address-group TEST', 'connection family ipv4',
                   'connection original destination-address 192.0.2.1', 'limit per source-address',
                   'connection limit per destination-address', 'reject-response net-unreachable'):
        with pytest.raises(RouterError):
            controller.execute('set firewall inet input filter rule 10 ' + option, session)
    with pytest.raises(RouterError):
        controller.execute('set firewall inet input filter default-action drop', session)

    assert 'meta l4proto { tcp } th dport { 22 } accept' in rendered(engine.view(session))


def test_inet_ingress_bindings_do_not_expand_ip_family_scope():
    """Direct rules are guarded when other families add devices to the same hook."""
    tree = {'firewall': {
        'inet': {'ingress': {'filter': {'interface': ['inside*'], 'rule': {'10': {'action': 'drop'}}}}},
        'ipv4': {'ingress': {'filter': {'interface': ['outside0']}}},
    }}
    text = rendered(tree)
    assert 'devices = { "inside*", "outside0" }' in text
    assert 'iifname { "inside*" } drop comment "10|"' in text
    assert 'meta nfproto ipv4 iifname { "outside0" } jump ipv4_ingress' in text


def test_inet_ingress_schema_and_nested_hook_checks(controller, session):
    """Groups and nested jumps cannot recover leaves removed from ingress."""
    for option in ('connection state new', 'fib lookup source-address', 'outbound-interface eth0',
                   'limit per connection-mark', 'limit per outbound-interface'):
        with pytest.raises(RouterError):
            controller.execute('set firewall inet ingress filter rule 10 ' + option, session)

    tree = {'firewall': {'inet': {
        'ingress': {'filter': {'interface': ['future*'], 'rule': {'10': {'action': 'jump', 'jump-target': 'TOP'}}}},
        'name': {
            'TOP': {'rule': {'10': {'action': 'jump', 'jump-target': 'BOTTOM'}}},
            'BOTTOM': {'rule': {'10': {'action': 'accept', 'connection': {'state': ['established']}}}},
        },
    }}}
    with pytest.raises(RouterError, match='unavailable in ingress'):
        rendered(tree)


def test_inet_ingress_display_preserves_attachment_and_rule_matches(capsys):
    """A wildcard hook guard and a narrower rule predicate remain separate ANDs."""
    document = {'nftables': [{'rule': {
        'family': 'inet', 'table': 'nvyr_filter', 'chain': 'ingress', 'comment': '10|',
        'expr': [
            {'match': {'left': {'meta': {'key': 'iifname'}}, 'op': '==', 'right': 'eth*'}},
            {'match': {'left': {'meta': {'key': 'iifname'}}, 'op': '==', 'right': 'eth1'}},
            {'accept': None},
        ],
    }}]}
    chain = normalize(document)['tables']['inet']['nvyr_filter']['chains']['ingress']
    rule = chain['rules'][0]
    assert rule['ingress-interface'] == ['eth*']
    assert rule['inbound-interface'] == ['eth1']
    assert 'unsupported' not in rule

    display._rule_detail(rule, False)
    output = capsys.readouterr().out
    assert 'Ingress interface' in output
    assert 'Inbound interface' in output


def test_inet_maps_rebuild_nested_consumers_and_preserve_unrelated_chains(controller, engine, session):
    """Inet objects have their own registrar namespace and whole-chain lifecycle."""
    controller.execute('set firewall group map inet SERVICES match protocol destination-port', session)
    controller.execute('set firewall group map inet SERVICES result-type verdict', session)
    controller.execute('set firewall group map inet SERVICES entry SSH protocol tcp destination-port 22 result action jump result jump-target INNER', session)
    controller.execute('set firewall inet name INNER rule 10 action accept', session)
    controller.execute('set firewall inet name OUTER rule 10 map SERVICES', session)
    controller.execute('set firewall inet forward filter rule 10 action jump jump-target OUTER', session)
    controller.execute('set firewall ipv4 input filter rule 10 action accept', session)
    before = engine.view(session)

    suggestions = dict(controller.completion('set firewall inet input filter rule 20 map ', session)['candidates'])
    assert 'SERVICES' in suggestions
    with pytest.raises(RouterError, match='referenced'):
        controller.execute('delete firewall group map inet SERVICES', session)

    after = deepcopy(before)
    after['firewall']['group']['map']['inet']['SERVICES']['description'] = 'Updated'
    text = rendered(after, before)
    assert destroyed(text) == {'inet_name_OUTER', 'forward'}
    assert destroyed(text, 'map') == {'inet_map_SERVICES'}
    assert 'inet_name_INNER' in text
    assert 'chain ipv4_input' not in text

    after = deepcopy(before)
    after['firewall']['inet']['name']['INNER']['rule']['10']['action'] = 'drop'
    assert destroyed(rendered(after, before)) == {'inet_name_INNER', 'inet_name_OUTER', 'forward'}


def test_inet_match_group_and_private_limit_use_neutral_keys():
    """Neutral set lookups and per-key buckets use the same rule/group formatters."""
    tree = {'firewall': {
        'group': {'match-group': {'inet': {'TRUSTED': {
            'match': {'inbound-interface': True}, 'entry': {'LAN': {'inbound-interface': 'inside0'}},
        }}}},
        'inet': {'input': {'filter': {'rule': {'10': {
            'match-group': 'TRUSTED', 'action': 'accept',
            'limit': {'rate': {'packets': '10/s'}, 'per': 'inbound-interface'},
        }}}}},
    }}
    text = rendered(tree)
    assert 'set inet_match_group_TRUSTED' in text
    assert 'set rule_limit_inet_input_10' in text
    assert 'update @rule_limit_inet_input_10' in text
    assert 'iifname == @inet_match_group_TRUSTED' in text


def test_inet_key_and_result_checks_apply_outside_schema():
    """Verify rejects family-dependent keys before looking up their native widths."""
    with pytest.raises(RouterError, match='family-neutral'):
        firewall.verify_key_size(['connection-original-source-address'], 'inet', 'test')
    with pytest.raises(RouterError, match='result-type verdict'):
        firewall.verify_map('inet', 'BAD', {'match': {'protocol': True}, 'result-type': 'address'}, {})


def test_inet_rejects_use_icmpx_and_tcp_reset_requires_tcp():
    """Portable reject responses are emitted without a family match."""
    tree = {'firewall': {'inet': {'input': {'filter': {'rule': {'10': {
        'action': 'reject', 'reject-response': 'admin-prohibited',
    }}}}}}}
    assert 'reject with icmpx type admin-prohibited' in rendered(tree)
    rule = tree['firewall']['inet']['input']['filter']['rule']['10']
    rule['reject-response'] = 'tcp-reset'
    with pytest.raises(RouterError, match='protocol tcp'):
        rendered(tree)
    rule['protocol'] = ['tcp']
    assert 'reject with tcp reset' in rendered(tree)


def test_inet_display_separates_state_policy_and_direct_rules(monkeypatch, capsys):
    """Numbered base-chain rules appear only in inet operational views."""
    table = {'chains': {'input': {'name': 'input', 'rules': [
        {'number': 'global-offload', 'action': 'continue'},
        {'number': '10', 'action': 'accept', 'counter': {'packets': 3, 'bytes': 120}},
    ]}}}
    monkeypatch.setattr(display, '_load_table', lambda **kwargs: table)
    display.show(family='inet', hook='input', stage='filter', rule='10')
    output = capsys.readouterr().out
    assert 'inet input filter' in output and 'accept' in output
    assert 'global-offload' not in output and 'default' not in output

    display.show(section='state-policy', hook='input')
    output = capsys.readouterr().out
    assert 'global-offload' in output and 'accept' not in output


def test_inet_map_normalization_and_log_selection():
    """Installed keys retain their schema names and log scopes retain the inet prefix."""
    configuration = {'firewall': {'group': {'map': {'inet': {'P': {'match': {'inbound-interface': True}}}}}}}
    document = {'nftables': [{'map': {
        'family': 'inet', 'table': 'nvyr_filter', 'name': 'inet_map_P', 'type': 'ifname', 'map': 'verdict',
        'elem': [['inside0', {'accept': None}]],
    }}]}
    group = normalize(document, configuration=configuration)['tables']['inet']['nvyr_filter']['maps']['inet_map_P']
    assert group['match-fields'] == ['inbound-interface']
    assert group['group-name'] == 'P'
    _, pattern = select('firewall', family='inet', hook='input', stage='filter', rule='10')
    assert pattern.search('[inet-INP-filter-10-A]')
    assert not pattern.search('[ipv4-INP-filter-10-A]')


def test_flowtable_counter_is_explicit_and_has_whole_object_lifecycle():
    """Flow accounting is separate from the enrollment rule's counter statement."""
    before = {'firewall': {'flowtable': {'FT': {'interface': ['future*']}}}}
    after = deepcopy(before)
    after['firewall']['flowtable']['FT']['counter'] = True
    text = rendered(after, before)
    assert 'devices = { "future*" }; counter;' in text
    assert destroyed(text, 'flowtable') == {'flowtable_FT'}
    assert 'counter;' not in nft_flowtable('FT', before['firewall']['flowtable']['FT'])


def test_inet_operational_dispatch(controller):
    """Scoped tables, runtime state and logs all pass the inet family to their scripts."""
    commands = [
        'show firewall inet input filter rule 10 detail',
        'show firewall inet forward filter limits',
        'show firewall inet forward filter rule 10 quota',
        'show firewall inet name SHARED rule 20 limit',
        'show firewall group map inet SERVICES',
        'show firewall group match-group inet LOCAL detail',
        'show firewall group limit-group inet SHARED',
        'show log firewall inet input filter rule 10',
    ]
    for line in commands:
        cursor = controller.operational.operational(lex(line))
        argv = operational_argv(cursor.node['command'], lex(line), line,
                                omitted_positions=cursor.omitted_positions)
        assert argv[argv.index('--family') + 1] == 'inet'


def test_inet_dynamic_group_cleanup(controller, engine, monkeypatch):
    """Runtime cleanup uses exact neutral keys and never touches another family's set."""
    from nvyr.helpers import firewall_runtime

    engine.running['firewall'] = {'group': {'match-group': {'inet': {'LEARNED': {
        'dynamic': {}, 'match': {'inbound-interface': True},
    }}}}}
    calls = []
    monkeypatch.setattr(firewall_runtime, 'rc_cmd', lambda argv: (calls.append(argv) or (0, '')))
    firewall_runtime.clear(engine, controller.operational,
                           'clear firewall group match-group inet LEARNED member inbound-interface eth1')
    assert calls == [['nft', 'destroy', 'element', 'inet', 'nvyr_filter', 'inet_match_group_LEARNED', '{', '"eth1"', '}']]


def test_inet_failsafe_uses_shared_pipeline(controller, engine, session, tmp_path):
    """Fail-safe supports inet rules but exposes neither ingress nor flow enrollment."""
    from nvyr.config_scripts import firewall_failsafe
    from tests.test_firewall_failsafe import context

    controller.execute('set firewall fail-safe inet input filter rule 10 action accept protocol tcp destination-port 22', session)
    tree = engine.view(session)
    ctx = context(tree, tmp_path, recovery=True)
    configuration = firewall_failsafe.get_config(ctx)
    firewall_failsafe.verify(configuration, ctx)
    text = firewall_failsafe.generate(configuration, ctx)
    assert 'nvyr_filter_failsafe' in text
    assert 'th dport { 22 } accept' in text

    with pytest.raises(RouterError):
        controller.execute('set firewall fail-safe inet ingress filter interface eth0', session)
    with pytest.raises(RouterError):
        controller.execute('set firewall fail-safe inet forward filter rule 10 action offload', session)


def test_inet_vrf_membership_rebuilds_base_chain():
    """An interface's VRF transition updates the direct INPUT expression."""
    before = inet_tree()
    before['firewall']['inet']['input']['filter']['rule']['10']['inbound-interface'] = ['dum0']
    before['interfaces'] = {'dummy': {'dum0': {}}}
    after = deepcopy(before)
    after['interfaces']['dummy']['dum0']['vrf'] = 'BLUE'
    after['vrf'] = {'name': {'BLUE': {'table': '101'}}}

    text = rendered(after, before)
    assert destroyed(text) == {'input'}
    assert 'meta sdifname { "dum0" }' in text


def test_inet_map_match_group_conflicts_are_rejected():
    """Inherited keys retain the same conflict rules as direct packet matches."""
    tree = {'firewall': {
        'group': {
            'map': {'inet': {'MAP': {'match': {'protocol': True}, 'result-type': 'verdict'}}},
            'match-group': {'inet': {'SET': {'match': {'protocol': True}}}},
        },
        'inet': {'input': {'filter': {'rule': {'10': {'map': 'MAP', 'match-group': 'SET'}}}}},
    }}
    with pytest.raises(RouterError, match='protocol'):
        rendered(tree)
