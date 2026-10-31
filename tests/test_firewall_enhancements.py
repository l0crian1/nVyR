"""Rule actions, additional packet matches, and named flowtable lifecycle."""

from copy import deepcopy
from dataclasses import replace
import json

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import ValidationError
from nvyr.helpers import interfaces, nftables
from nvyr.helpers.nftables_formatters import nft_rule
from tests.lifecycle import firewall_context
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree


STATUS_FLAGS = ('expected', 'seen-reply', 'assured', 'confirmed', 'snat', 'dnat',
                'seq-adjust', 'snat-done', 'dnat-done', 'dying', 'fixed-timeout',
                'helper', 'offload')


RULE_PATHS = [
    (family, hook, 'filter')
    for family in ('ipv4', 'ipv6')
    for hook in ('input', 'forward', 'output')
] + [('ipv4', 'prerouting', 'raw'), ('ipv6', 'prerouting', 'raw'),
     ('ipv4', 'output', 'raw'), ('ipv6', 'output', 'raw'), ('ipv4', 'name', 'CUSTOM'), ('ipv6', 'name', 'CUSTOM')]


def configuration(rule, path=('ipv4', 'forward', 'filter')):
    family, hook, chain = path
    return {'firewall': {family: {hook: {chain: {'rule': {'10': rule}}}}}}


def render(tree, previous=None, recovery=False, state_directory=None):
    schema = Schema.bundled()
    schema.validate_configuration(tree)
    effective = ReadOnlyTree(schema.defaults(tree))
    previous_effective = ReadOnlyTree(schema.defaults(previous or {}))
    context = firewall_context(effective, ReadOnlyTree(previous or {}), 'firewall', ('firewall',),
                            previous_effective=previous_effective, recovery=recovery, schema=schema)
    if state_directory is not None:
        context = replace(context, state_directory=state_directory)
    firewall.verify(effective, context)
    return firewall.generate(effective, context)


@pytest.mark.parametrize('path', RULE_PATHS)
@pytest.mark.parametrize('action', ['continue', 'return'])
def test_rule_verdicts_on_all_hooks_and_named_chains(path, action):
    tree = configuration({'action': action, 'log': {}}, path)
    text = render(tree)

    assert f'{action} comment "10|"' in text
    assert 'log prefix' in text


@pytest.mark.parametrize('packet_type', ['broadcast', 'host', 'multicast', 'other'])
@pytest.mark.parametrize('path', RULE_PATHS)
def test_packet_type_is_a_match_on_all_rule_types(path, packet_type):
    text = render(configuration({'action': 'accept', 'packet-type': packet_type}, path))

    assert f'meta pkttype {packet_type} accept comment "10|"' in text


@pytest.mark.parametrize('ttl', [{'eq': '0'}, {'eq': '255'}, {'gt': '0'}, {'lt': '255'},
                                  {'gt': '63', 'lt': '65'}, {}])
def test_valid_ttl_comparisons(ttl):
    rule = {'action': 'accept', 'ttl': ttl}
    text = render(configuration(rule))

    for operator, symbol in [('eq', '=='), ('lt', '<'), ('gt', '>')]:
        if operator in ttl:
            assert f'ip ttl {symbol} {ttl[operator]}' in text


@pytest.mark.parametrize('path', RULE_PATHS)
def test_ttl_and_status_follow_address_family_and_match_exact_values(path):
    rule = {'action': 'accept', 'ttl': {'gt': '63', 'lt': '65'}, 'connection': {'status': [flag if flag != 'offload' else 'offload,confirmed' for flag in STATUS_FLAGS]}}
    original = deepcopy(rule)
    if path[2] == 'raw':
        with pytest.raises(ValidationError, match='before connection tracking'):
            render(configuration(rule, path))
        return

    text = render(configuration(rule, path))
    expression = 'ip ttl' if path[0] == 'ipv4' else 'ip6 hoplimit'

    assert f'{expression} < 65 {expression} > 63' in text
    assert ('ct status == { 0x2000, assured, confirmed, confirmed | 0x4000, dnat, '
            'dnat-done, dying, expected, fixed-timeout, seen-reply, seq-adjust, snat, snat-done }') in text
    assert rule == original

    del rule['connection']
    assert 'ct status' not in render(configuration(rule, path))


def test_new_match_values_and_flags_reject_invalid_schema_values():
    for rule in [{'packet-type': 'unknown'}, {'packet-type': ['host']},
                 {'connection': {'status': ['unknown']}},
                 {'connection': {'status': {'assured': True}}}]:
        with pytest.raises(ValidationError):
            render(configuration({'action': 'accept', **rule}))


@pytest.mark.parametrize('ttl', [
    {'eq': '64', 'lt': '65'}, {'eq': '64', 'gt': '63'},
    {'lt': '64', 'gt': '64'}, {'lt': '64', 'gt': '63'},
    {'lt': '64', 'gt': '65'}, {'lt': '0'}, {'gt': '255'},
])
def test_impossible_or_exclusive_ttl_comparisons_fail_before_rendering(ttl):
    with pytest.raises(ValidationError, match='firewall ipv4 forward filter rule 10: ttl'):
        render(configuration({'action': 'accept', 'ttl': ttl}))

    text = render(configuration({'action': 'accept', 'ttl': ttl, 'disable': True}))
    assert 'comment "10|' not in text


@pytest.mark.parametrize('value', ['-1', '256', '1.5', '64; accept'])
def test_ttl_values_are_schema_validated(value):
    with pytest.raises(ValidationError):
        render(configuration({'action': 'accept', 'ttl': {'eq': value}}))


def test_flowtable_requires_interface_selectors():
    with pytest.raises(ValidationError, match='at least one interface'):
        render({'firewall': {'flowtable': {'FAST': {}}}})


def test_flowtable_exact_name_does_not_require_existing_device(monkeypatch):
    """Render the native name unchanged even when no link exists yet."""
    def unexpected_lookup(name):
        raise AssertionError(f'Flowtable verification queried host interface {name}')

    monkeypatch.setattr(interfaces, 'exists', unexpected_lookup)
    text = render({'firewall': {'flowtable': {'FAST': {'interface': ['missing0']}}}})

    assert 'devices = { "missing0" }' in text


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_offload_action_and_target_must_be_used_together(family):
    with pytest.raises(ValidationError, match='action offload requires offload-target'):
        render(configuration({'action': 'offload'}, (family, 'forward', 'filter')))

    with pytest.raises(ValidationError, match='not a configured flowtable'):
        render(configuration({'action': 'offload', 'offload-target': 'MISSING'},
                             (family, 'forward', 'filter')))

    with pytest.raises(ValidationError, match='offload-target requires action offload'):
        render(configuration({'action': 'accept', 'offload-target': 'FAST'},
                             (family, 'forward', 'filter')))


@pytest.mark.parametrize('path', [path for path in RULE_PATHS if path[1] != 'forward'])
def test_offload_is_not_available_outside_forward(path):
    schema = Schema.bundled()
    for rule in [{'action': 'offload'}, {'action': 'accept', 'offload-target': 'FAST'}]:
        with pytest.raises(ValidationError):
            schema.validate_configuration(configuration(rule, path))


def test_flowtable_deletion_recovery_and_shared_nat_cleanup(monkeypatch):
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    tree = {'firewall': {'flowtable': {
        'FAST': {'interface': ['eth1', 'eth0'], 'offload': {'software': True}},
        'OTHER': {'interface': ['eth2']},
    }}}
    original = deepcopy(tree)
    text = render(tree)

    assert 'flowtable flowtable_FAST { hook ingress priority 0; devices = { "eth0", "eth1" }; }' in text
    assert 'flags offload' not in text
    assert tree == original

    deleted = render({}, previous=tree)
    assert 'destroy flowtable inet nvyr_filter flowtable_FAST' in deleted
    assert 'destroy flowtable inet nvyr_filter flowtable_OTHER' in deleted
    assert 'hook ingress' not in deleted
    assert 'flush ruleset' not in deleted
    assert [line for line in deleted.splitlines() if line.startswith('destroy table')] == [
        'destroy table inet nvyr_filter_failsafe']
    assert 'destroy chain inet nvyr_filter ipv4_nat_prerouting' not in deleted
    assert 'chain nat_prerouting {' not in deleted

    monkeypatch.setattr(nftables.manager, 'flowtables', lambda: ['ORPHAN'])
    recovered = render({}, recovery=True)
    assert 'destroy flowtable inet nvyr_filter flowtable_ORPHAN' in recovered


def test_flowtable_inventory_only_returns_owned_names(monkeypatch):
    entries = [
        {'family': 'inet', 'table': 'nvyr_filter', 'name': 'flowtable_FAST'},
        {'family': 'ip', 'table': 'nvyr_filter', 'name': 'flowtable_WRONG_FAMILY'},
        {'family': 'inet', 'table': 'other', 'name': 'flowtable_WRONG_TABLE'},
        {'family': 'inet', 'table': 'nvyr_filter', 'name': 'unrelated'},
    ]
    monkeypatch.setattr(nftables, 'cmd', lambda argv: json.dumps({
        'nftables': [{'flowtable': entry} for entry in entries],
    }))

    assert nftables.Manager().flowtables() == ['FAST']


def test_flowtables_cannot_share_devices_at_the_same_ingress_priority(monkeypatch):
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    tree = {'firewall': {'flowtable': {
        'FIRST': {'interface': ['eth0']}, 'SECOND': {'interface': ['eth0']},
    }}}

    with pytest.raises(ValidationError, match="interface 'eth0' is already used by flowtable 'FIRST'"):
        render(tree)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_forward_offload_continues_without_accept_and_destroys_references_first(family, monkeypatch):
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    tree = configuration({'action': 'offload', 'offload-target': 'FAST', 'log': {}},
                         (family, 'forward', 'filter'))
    tree['firewall']['flowtable'] = {'FAST': {'interface': ['eth0', 'eth1']}}
    previous = deepcopy(tree)
    previous['firewall']['flowtable']['FAST']['interface'] = ['eth0']
    text = render(tree, previous=previous)
    rule_line = next(line for line in text.splitlines() if 'comment "10|' in line)

    assert f'log prefix "[{family}-FWD-filter-10-O]" flow add @flowtable_FAST comment "10|"' in rule_line
    assert 'accept' not in rule_line
    assert text.index(f'flush chain inet nvyr_filter {family}_forward') < text.index('destroy flowtable')
    assert text.index('flowtable flowtable_FAST {') < text.index('flow add @flowtable_FAST')

    without = render({}, previous=tree)
    assert 'destroy flowtable inet nvyr_filter flowtable_FAST' in without
    assert 'flow add' not in without


def test_flowtable_cli_multi_interfaces_references_and_forward_only_completion(controller, engine, session, monkeypatch):
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    for command in [
        'set interfaces dummy dum0',
        'set firewall flowtable FAST interface dum0',
        'set firewall flowtable FAST interface eth0',
        'set firewall flowtable FAST offload software',
        'set firewall ipv4 forward filter rule 10 action offload offload-target FAST ttl gt 30 ttl lt 60 connection status assured connection status confirmed',
    ]:
        controller.execute(command, session)

    assert engine.commit(session)['results']['firewall']['success']
    assert engine.running['firewall']['flowtable']['FAST']['interface'] == ['dum0', 'eth0']

    for command in ['delete firewall flowtable FAST', 'delete interfaces dummy dum0']:
        with pytest.raises(ValidationError, match='referenc'):
            controller.execute(command, session)

    for hook in ('forward', 'input', 'output'):
        choices = dict(controller.completion(
            f'set firewall ipv4 {hook} filter rule 10 action ', session, explicit=True)['candidates'])
        assert ('offload' in choices) == (hook == 'forward')
        assert {'continue', 'return'} <= choices.keys()

    controller.execute('delete firewall ipv4 forward', session)
    controller.execute('delete firewall flowtable FAST', session)
    controller.execute('delete interfaces dummy dum0', session)
    assert engine.commit(session)['results']['firewall']['success']


def test_new_flowtable_interface_can_be_created_in_same_commit_and_recovery(controller, engine, session, monkeypatch):
    present = set()
    monkeypatch.setattr(interfaces, 'exists', lambda name: name in present)
    monkeypatch.setattr(engine.modules['dummy'], 'apply', lambda *args: present.add('dum0'))
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('set firewall flowtable FAST interface dum0', session)

    result = engine.commit(session)
    assert result['results']['dummy']['success']
    assert result['results']['firewall']['success']

    present.clear()
    engine._run_recovery(engine.running, engine.running, set(engine.schema.owners))
    assert present == {'dum0'}


def test_flowtable_check_commit_and_recovery_allow_future_device(controller, engine, session, monkeypatch):
    """All lifecycle stages accept an exact selector without querying host links."""
    def unexpected_lookup(name):
        raise AssertionError('flowtable verification should not query host interfaces')

    monkeypatch.setattr(interfaces, 'exists', unexpected_lookup)
    controller.execute('set firewall flowtable FAST interface dum0', session)

    result = engine.check(session)
    assert result['results']['firewall']['success']

    result = engine.commit(session)
    assert result['results']['firewall']['success']

    engine._run_recovery(engine.running, engine.running, set(engine.schema.owners))


@pytest.mark.parametrize('value', ['', ',snat', 'snat,', 'snat,,dnat', 'snat,unknown',
                                  'snat, dnat', '0x30', 'SNAT'])
def test_connection_status_rejects_invalid_groups(value):
    with pytest.raises(ValidationError):
        render(configuration({'action': 'accept', 'connection': {'status': [value]}}))


@pytest.mark.parametrize('path', RULE_PATHS)
def test_connection_status_groups_are_exact_deduplicated_symbolic_expressions(path):
    rule = {'action': 'accept', 'connection': {'status': [
        'offload,confirmed', 'snat,dnat', 'dnat,snat', 'snat,snat,dnat',
    ]}}
    original = deepcopy(rule)
    if path[2] == 'raw':
        with pytest.raises(ValidationError, match='before connection tracking'):
            render(configuration(rule, path))
        return

    text = render(configuration(rule, path))

    assert 'ct status == { confirmed | 0x4000, dnat | snat }' in text
    assert 'ct status &' not in text
    assert rule == original


def test_connection_status_cli_accepts_groups_and_individual_values(controller, engine, session):
    controller.execute(
        'set firewall ipv4 forward filter rule 10 action accept '
        'connection status offload,confirmed connection status snat,dnat', session,
    )
    assert engine.commit(session)['results']['firewall']['success']
    rule = engine.running['firewall']['ipv4']['forward']['filter']['rule']['10']
    assert rule['connection']['status'] == ['offload,confirmed', 'snat,dnat']

    choices = dict(controller.completion(
        'set firewall ipv4 forward filter rule 10 connection status ', session,
        explicit=True,
    )['candidates'])
    assert set(STATUS_FLAGS) <= choices.keys()

    controller.execute(
        'delete firewall ipv4 forward filter rule 10 connection status snat,dnat', session,
    )
    assert engine.commit(session)['results']['firewall']['success']
    rule = engine.running['firewall']['ipv4']['forward']['filter']['rule']['10']
    assert rule['connection']['status'] == ['offload,confirmed']
    assert 'ct status == { confirmed | 0x4000 }' in nft_rule('ipv4', 'forward', '10', rule)


def test_list_validator_optional_separator_preserves_single_value_behavior():
    from nvyr.helpers.validators import prepare_list

    single = prepare_list('snat dnat')
    grouped = prepare_list('snat dnat', separator=',')
    assert single('snat')
    assert not single('snat,dnat')
    assert grouped('snat')
    assert grouped('snat,dnat')
    assert not grouped('snat,')

    for separator in ('', 1):
        with pytest.raises(ValueError, match='separator'):
            prepare_list('snat dnat', separator=separator)


@pytest.mark.parametrize(('group', 'expected'), [
    ('snat,dnat,confirmed', 'confirmed | dnat | snat'),
    ('offload,confirmed,snat,dnat', 'confirmed | dnat | 0x4000 | snat'),
])
def test_connection_status_group_supports_more_than_two_flags(group, expected):
    text = render(configuration({'action': 'accept', 'connection': {'status': [group]}}))
    assert f'ct status == {{ {expected} }}' in text


@pytest.mark.parametrize('value', ['snat,dantt', 'offlaod', 'snat,,dnat'])
def test_connection_status_cli_reports_invalid_value_and_path(controller, session, value):
    with pytest.raises(ValidationError) as caught:
        controller.execute(
            f'set firewall ipv4 forward filter rule 10 connection status {value}', session,
        )

    message = str(caught.value)
    assert value in message
    assert 'firewall ipv4 forward filter rule 10 connection status' in message


@pytest.mark.parametrize('group', ['offload', 'offload,snat', 'offload,offload'])
def test_offload_status_requires_confirmed_in_its_exact_group(group):
    with pytest.raises(ValidationError, match='requires confirmed in the same group'):
        render(configuration({'action': 'accept', 'connection': {'status': [group, 'confirmed']}}))


@pytest.mark.parametrize('flag', ['helper', 'seq-adjust', 'dying'])
@pytest.mark.parametrize('path', RULE_PATHS)
def test_offload_status_rejects_incompatible_flags(flag, path):
    group = f'confirmed,offload,{flag}'
    with pytest.raises(ValidationError, match=f'offload cannot be combined with {flag}'):
        render(configuration({'action': 'accept', 'connection': {'status': [group]}}, path))


def test_offload_status_restrictions_do_not_cross_alternatives():
    text = render(configuration({'action': 'accept', 'connection': {'status': ['offload,confirmed', 'helper', 'seq-adjust', 'dying']}}))
    assert 'ct status == { 0x2000, confirmed | 0x4000, dying, seq-adjust }' in text


def test_disabled_rule_defers_offload_status_consistency_checks():
    text = render(configuration({'action': 'accept', 'disable': True, 'connection': {'status': ['offload,helper']}}))
    assert 'ct status' not in text


def test_commit_check_reports_invalid_offload_group(controller, engine, session):
    controller.execute(
        'set firewall ipv4 forward filter rule 10 action accept connection status offload,snat', session,
    )
    result = engine.check(session)
    assert not result['results']['firewall']['success']
    assert 'requires confirmed' in str(result)
