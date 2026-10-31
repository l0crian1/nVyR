"""Named firewall chains share filter rules and participate in atomic cleanup."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import ValidationError
from nvyr.helpers import nftables
from tests.lifecycle import firewall_context
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree, lookup


def render(current, previous=None, *, recovery=False):
    schema = Schema.bundled()
    current = {'firewall': current}
    previous = {'firewall': previous} if previous is not None else {}
    schema.validate_configuration(current)
    effective = ReadOnlyTree(schema.defaults(current))
    context = firewall_context(effective, ReadOnlyTree(previous), 'firewall', ('firewall',),
                            recovery=recovery, previous_effective=ReadOnlyTree(schema.defaults(previous)), schema=schema)
    firewall.verify(effective, context)

    return firewall.generate(effective, context)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_named_schema_reuses_all_filter_options(family, engine, controller, session):
    root = engine.schema.root['children']['firewall']['children'][family]['children']

    named = deepcopy(root['name']['children'])
    input_filter = deepcopy(root['input']['children']['filter']['children'])
    ingress_rule = root['ingress']['children']['filter']['children']['rule']

    # Named chains also serve ingress callers, where VLAN headers are available.
    vlan = named['rule']['children'].pop('vlan')
    assert vlan == ingress_rule['children']['vlan']
    assert 'vlan' not in input_filter['rule']['children']

    # Named chains expose route-based MSS clamping for FORWARD/OUTPUT callers;
    # INPUT exposes only explicit sizes. All remaining filter options are shared.
    named_modify = named['rule']['children'].pop('modify')
    input_modify = input_filter['rule']['children'].pop('modify')
    forward_modify = root['forward']['children']['filter']['children']['rule']['children']['modify']
    assert named_modify == forward_modify
    expected_input = deepcopy(named_modify)
    mss = expected_input['children']['tcp-mss']
    assert set(mss.pop('choices')) == {'clamp-to-pmtu'}
    assert mss['validators']['checks'].pop('list') == {
        'name': 'list', 'args': {'values': 'clamp-to-pmtu'}}
    assert mss['validators']['mode'] == 'OR'
    mss['validators']['mode'] = 'AND'
    assert input_modify == expected_input
    assert named == input_filter

    controller.execute(f'set firewall {family} name CUSTOM rule 10 action accept counter log', session)
    options = dict(controller.completion(f'set firewall {family} name CUSTOM ', session, explicit=True)['candidates'])

    assert {'rule', 'default-action', 'default-log'} <= options.keys()
    assert 'jump-target' in dict(controller.completion(
        f'set firewall {family} name CUSTOM rule 10 ', session, explicit=True)['candidates'])
    assert lookup(engine.schema.defaults(engine.view(session)), ('firewall', family, 'name', 'CUSTOM', 'default-action')) == 'accept'
    assert 'default-action' not in lookup(engine.view(session), ('firewall', family, 'name', 'CUSTOM'))


@pytest.mark.parametrize('name', ['bad name', 'bad;drop', 'x"', 'x\\', 'x'*64, '1first'])
def test_name_and_jump_target_reject_unsafe_identifiers(name):
    schema = Schema.bundled()

    with pytest.raises(ValidationError):
        schema.validate_configuration({'firewall': {'ipv4': {'name': {name: {}}}}})

    with pytest.raises(ValidationError):
        schema.validate_configuration({'firewall': {'ipv4': {'input': {'filter': {
            'rule': {'1': {'action': 'jump', 'jump-target': name}}}}}}})


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('location', ['input', 'output', 'forward', 'name'])
def test_jump_validation_in_each_rule_location(family, location):
    def config(rule):
        section = {'name': {'TARGET': {}}}

        if location == 'name':
            section['name']['SOURCE'] = {'rule': {'10': rule}}
        else:
            section[location] = {'filter': {'rule': {'10': rule}}}

        return {family: section}

    with pytest.raises(ValidationError, match='action jump requires jump-target'):
        render(config({'action': 'jump'}))

    with pytest.raises(ValidationError, match='jump-target requires action jump'):
        render(config({'action': 'accept', 'jump-target': 'TARGET'}))

    missing = config({'action': 'jump', 'jump-target': 'OTHER_FAMILY'})
    other = 'ipv6' if family == 'ipv4' else 'ipv4'
    missing[other] = {'name': {'OTHER_FAMILY': {}}}

    with pytest.raises(ValidationError, match=f'is not a named chain in {family}'):
        render(missing)

    assert f'jump {family}_name_TARGET' in render(config({'action': 'jump', 'jump-target': 'TARGET'}))
    assert 'comment "10|' not in render(config({'disable': True, 'action': 'jump', 'jump-target': 'ABSENT'}))


def test_regular_chains_namespace_logging_and_forward_references():
    config = {family: {'name': {
        'input': {'default-action': 'drop', 'default-log': True, 'rule': {
            '20': {'action': 'jump', 'jump-target': 'z_TARGET', 'log': {}, 'counter': {}},
            '10': {'disable': True}}}, 'z_TARGET': {}},
        'forward': {'filter': {'rule': {'1': {'action': 'jump', 'jump-target': 'input'}}}}}
        for family in ('ipv4', 'ipv6')}
    text = render(config)

    for family in ('ipv4', 'ipv6'):
        body = text.split(f'chain {family}_name_input {{', 1)[1].split('\n    }', 1)[0]

        assert 'hook ' not in body and 'policy ' not in body
        assert f'log prefix "[{family}-name_input-20-J]" counter jump {family}_name_z_TARGET' in body
        assert f'counter log prefix "[{family}-name_input-default-D]" drop' in body
        assert 'comment "10|' not in body
        assert text.rindex(f'add chain inet nvyr_filter {family}_name_z_TARGET') < text.index(f'jump {family}_name_z_TARGET')

    assert 'nvyr_nat' not in text and 'flush ruleset' not in text and 'flush table' not in text


def test_raw_jump_uses_same_named_namespace():
    text = render({'ipv4': {'name': {'EARLY': {}}, 'prerouting': {'raw': {'rule': {
        '10': {'action': 'jump', 'jump-target': 'EARLY'}}}}}})

    assert 'jump ipv4_name_EARLY' in text


@pytest.mark.parametrize('current', [
    {}, {'ipv4': {}}, {'ipv4': {'name': {}}}, {'ipv4': {'name': {'KEEP': {}}}},
])
def test_deleted_names_are_found_even_when_ancestors_disappear(current):
    previous = {'ipv4': {'name': {'REMOVED': {}, 'KEEP': {}}}}
    text = render(current, previous)

    assert 'destroy chain inet nvyr_filter ipv4_name_REMOVED' in text
    assert 'chain ipv4_name_REMOVED {' not in text
    assert text.index('flush chain inet nvyr_filter ipv4_name_REMOVED') < text.index('destroy chain inet nvyr_filter ipv4_name_REMOVED')


def test_remove_entire_firewall_via_engine_uses_deleted_owner(engine, session, monkeypatch):
    applied = []
    monkeypatch.setattr(nftables.manager, 'apply', lambda text, directory, *, accounting=False: applied.append(text))
    engine.mutate(session, 'set', ['firewall', 'ipv4', 'name', 'OLD'])
    assert engine.commit(session)['results']['firewall']['success']
    engine.mutate(session, 'delete', ['firewall'])

    assert engine.commit(session)['results']['firewall']['success']
    assert 'destroy chain inet nvyr_filter ipv4_name_OLD' in applied[-1]
    assert 'chain ipv4_name_OLD {' not in applied[-1]


def test_rename_target_requires_updating_references_before_staging(engine, controller, session):
    controller.execute('set firewall ipv4 name OLD', session)
    controller.execute('set firewall ipv4 forward filter rule 10 action jump jump-target OLD', session)
    engine.commit(session)
    with pytest.raises(ValidationError, match='referenced by'):
        controller.execute('rename firewall ipv4 name OLD to firewall ipv4 name NEW', session)

    assert 'OLD' in lookup(engine.running, ('firewall', 'ipv4', 'name'))

    controller.execute('set firewall ipv4 forward filter rule 10 jump-target NEW', session)
    controller.execute('rename firewall ipv4 name OLD to firewall ipv4 name NEW', session)

    assert engine.commit(session)['results']['firewall']['success']
    assert set(lookup(engine.running, ('firewall', 'ipv4', 'name'))) == {'NEW'}


def test_recovery_discovers_unpublished_named_chains(monkeypatch):
    monkeypatch.setattr(nftables, 'manager', SimpleNamespace(
        rule_limits=lambda: [], named_state=lambda: [], named_chains=lambda: [('ipv6', 'ORPHAN')], flowtables=lambda: [], icmp_groups=lambda: [], singleton_groups=lambda: [], match_groups=lambda: [], maps=lambda: []))
    text = render({}, recovery=True)

    assert 'destroy chain inet nvyr_filter ipv6_name_ORPHAN' in text
    assert 'chain ipv6_name_ORPHAN {' not in text


def test_runtime_inventory_is_limited_to_managed_names(monkeypatch):
    chains = [('inet', 'nvyr_filter', 'ipv4_name_CUSTOM'), ('inet', 'nvyr_filter', 'ipv6_name_CUSTOM'),
              ('inet', 'unrelated', 'ipv4_name_CUSTOM'), ('ip', 'nvyr_filter', 'ipv4_name_CUSTOM'),
              ('inet', 'nvyr_filter', 'ipv4_nat_prerouting'), ('inet', 'nvyr_filter', 'forward')]

    def command(argv):
        assert argv == ['nft', '--json', 'list', 'chains', 'inet']

        return json.dumps({'nftables': [{'metainfo': {}}] + [
            {'chain': {'family': family, 'table': table, 'name': name}} for family, table, name in chains]})

    monkeypatch.setattr(nftables, 'cmd', command)

    assert nftables.Manager().named_chains() == [('ipv4', 'CUSTOM'), ('ipv6', 'CUSTOM')]
