"""Early firewall ownership, schema isolation, and shared rendering contracts."""

from copy import deepcopy
from dataclasses import replace

import pytest

from build_tools.schema_builder import _prepare_firewall_failsafe
from nvyr.config_scripts import firewall, firewall_failsafe
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import nftables
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.op_scripts import firewall as firewall_op
from nvyr.schema import Schema
from tests.lifecycle import firewall_context


def context(configuration, directory, previous=None, *, recovery=False):
    previous = previous or {}
    schema = Schema.bundled()
    result = firewall_context(schema.defaults(configuration), previous, 'firewall_failsafe',
                              firewall_failsafe.ROOT, recovery,
                              previous_effective=schema.defaults(previous), schema=schema)
    return replace(result, state_directory=directory, startup=recovery)


def nodes(node):
    yield node
    for child in node.get('children', {}).values():
        yield from nodes(child)


def test_builder_removes_future_nested_registrar_properties_only_in_failsafe():
    properties = {'dependency': 'x', 'depends': 'x', 'reapply-on-change': ['vrf'],
                  'dependency-format': '{parent}.{value}', 'description': 'Keep me'}
    document = {'children': {'firewall': {'children': {
        'group': deepcopy(properties),
        'fail-safe': {'children': {'future': {'children': {'nested': deepcopy(properties)}}}},
    }}}}
    _prepare_firewall_failsafe(document)
    firewall_node = document['children']['firewall']['children']
    assert firewall_node['group'] == properties
    assert firewall_node['fail-safe']['children']['future']['children']['nested'] == {'description': 'Keep me'}


def test_bundled_schema_is_complete_scoped_and_has_no_registrar():
    schema = Schema.bundled()
    normal = schema.root['children']['firewall']
    early = normal['children']['fail-safe']
    assert early['children'].keys() == normal['children'].keys() - {'fail-safe', 'flowtable'}
    for node in nodes(early):
        assert not {'dependency', 'depends', 'reapply-on-change', 'dependency-format'} & node.keys()
        for suggestion in node.get('suggestors', []):
            if suggestion['name'] == 'config-path':
                assert suggestion['args']['path'].startswith('firewall fail-safe ')
    assert any('depends' in node for node in nodes(normal['children']['ipv4']))
    early_priority = schema.owners['firewall_failsafe'][1]
    for owner in ('vrf', 'ethernet', 'dummy', 'virtual-ethernet', 'bridge', 'loopback', 'firewall'):
        assert early_priority < schema.owners[owner][1]


@pytest.mark.parametrize('suffix', [
    'flowtable FT interface eth0', 'global-options flowtable FT',
    'ipv4 forward filter rule 10 action offload',
    'ipv6 forward filter rule 10 action offload',
    'ipv4 forward filter rule 10 offload-target FT',
])
def test_only_offload_settings_are_removed(controller, session, suffix):
    with pytest.raises(RouterError):
        controller.execute('set firewall fail-safe ' + suffix, session)
    controller.execute('set firewall fail-safe ipv4 input filter rule 10 connection status offload and confirmed', session)


def test_suggestions_and_reference_checks_are_local(controller, engine, session):
    controller.execute('set firewall group address-group ipv4 MAIN address 192.0.2.1', session)
    controller.execute('set firewall fail-safe group address-group ipv4 EARLY address 192.0.2.2', session)
    path = 'set firewall fail-safe ipv4 input filter rule 10 source-address-group '
    choices = dict(controller.completion(path, session, explicit=True)['candidates'])
    assert 'EARLY' in choices and 'MAIN' not in choices
    controller.execute(path + 'EARLY action accept', session)
    assert engine.commit(session)['results']['firewall_failsafe']['success']

    # No registrar blocks deletion, but verify still rejects the dangling reference.
    controller.execute('delete firewall fail-safe group address-group ipv4 EARLY', session)
    result = engine.commit(session)
    assert not result['results']['firewall_failsafe']['success']
    assert 'firewall fail-safe' in result['results']['firewall_failsafe']['error']


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_render_does_not_touch_main_firewall_or_nat(tmp_path, family):
    configuration = {'firewall': {
        'group': {'counter-group': {'MAIN': {}}},
        'fail-safe': {family: {'input': {'filter': {'default-action': 'drop', 'rule': {
            '10': {'action': 'accept', 'inbound-interface': ['absent0']},
        }}}}},
    }, 'nat': {'source': {'rule': {'10': {'translation': {'address': '192.0.2.1'}}}}}}
    current = context(configuration, tmp_path, recovery=True)
    selected = firewall_failsafe.get_config(current)
    firewall_failsafe.verify(selected, current)
    text = firewall_failsafe.generate(selected, current)
    assert 'destroy table inet nvyr_filter_failsafe' in text
    assert 'add table inet nvyr_filter_failsafe' in text
    assert 'add table inet nvyr_filter\n' not in text
    assert 'MAIN' not in text and 'nat_postrouting' not in text
    assert 'iifname { "absent0" }' in text
    assert f'chain {family}_input' in text


def test_inactive_edits_only_validate_and_active_edits_replace(tmp_path, monkeypatch):
    configuration = {'firewall': {'fail-safe': {'ipv4': {'input': {'filter': {'default-action': 'drop'}}}}}}
    current = context(configuration, tmp_path)
    calls = []
    monkeypatch.setattr(nftables.manager, 'apply', lambda text, directory, **kwargs: calls.append((text, kwargs)))
    rendered = firewall_failsafe.generate(firewall_failsafe.get_config(current), current)
    firewall_failsafe.apply(rendered, current)
    assert calls[-1][1]['check_only']

    monkeypatch.setattr(nftables.manager, 'table_exists', lambda name: True)
    firewall_failsafe.apply(rendered, current)
    assert not calls[-1][1]['check_only']
    assert calls[-1][1]['owner'] == 'firewall_failsafe'

    deleted = context({}, tmp_path, configuration)
    text = firewall_failsafe.generate(firewall_failsafe.get_config(deleted), deleted)
    assert text == 'destroy table inet nvyr_filter_failsafe\n'
    firewall_failsafe.apply(text, deleted)
    assert not calls[-1][1]['check_only']


def test_ordinary_failsafe_commit_does_not_rebuild_main(controller, engine, session, monkeypatch):
    calls = []
    monkeypatch.setattr(nftables.manager, 'apply', lambda text, directory, **kwargs: calls.append(kwargs))
    controller.execute('set firewall ipv4 input filter default-action accept', session)
    engine.commit(session)
    calls.clear()
    controller.execute('set firewall fail-safe ipv4 input filter default-action drop', session)
    result = engine.commit(session)
    assert set(result['results']) == {'firewall_failsafe'}
    assert calls == [{'owner': 'firewall_failsafe', 'accounting': False, 'check_only': True}]


def test_rollback_does_not_activate_inactive_failsafe(controller, engine, session, monkeypatch):
    calls = []
    monkeypatch.setattr(nftables.manager, 'apply', lambda text, directory, **kwargs: calls.append(kwargs))
    controller.execute('set firewall fail-safe ipv4 input filter default-action drop', session)
    target = engine.view(session)
    engine._run_recovery(target, {}, {'firewall_failsafe'})
    assert len(calls) == 1
    assert calls[0]['check_only']


def test_recovery_order_and_atomic_handover(controller, engine, session, monkeypatch):
    sequence = []
    controller.execute('set firewall fail-safe ipv4 input filter default-action drop', session)
    controller.execute('set interfaces dummy dum9', session)
    controller.execute('set firewall ipv4 input filter default-action accept', session)
    target = engine.view(session)
    monkeypatch.setattr(nftables.manager, 'apply', lambda text, directory, **kwargs:
                        sequence.append(('nft', kwargs.get('owner', 'firewall'), text)))
    monkeypatch.setattr('nvyr.helpers.interfaces.manager.replace', lambda *args, **kwargs:
                        sequence.append(('interface', 'dummy', '')))
    engine._run_recovery(target, {}, {'firewall_failsafe', 'dummy', 'firewall'}, startup=True)
    assert [entry[1] for entry in sequence] == ['firewall_failsafe', 'dummy', 'firewall']
    assert 'destroy table inet nvyr_filter_failsafe' in sequence[-1][2]
    assert 'add table inet nvyr_filter\n' in sequence[-1][2]


def test_normalizer_uses_the_correct_group_definition():
    configuration = {'firewall': {
        'group': {'map': {'ipv4': {'SAME': {'match': {'source-address': {}}}}}},
        'fail-safe': {'group': {'map': {'ipv4': {'SAME': {'match': {'destination-address': {}}}}}}},
    }}
    document = {'nftables': [{'map': {
        'family': 'inet', 'table': table, 'name': 'ipv4_map_SAME', 'type': 'ipv4_addr', 'map': 'verdict',
        'elem': [['192.0.2.1', {'accept': None}]],
    }} for table in ('nvyr_filter', 'nvyr_filter_failsafe')]}
    tables = normalize(document, configuration=configuration)['tables']['inet']
    assert tables['nvyr_filter']['maps']['ipv4_map_SAME']['match-fields'] == ['source-address']
    assert tables['nvyr_filter_failsafe']['maps']['ipv4_map_SAME']['match-fields'] == ['destination-address']


def test_failsafe_operational_dispatch_and_inactive_output(controller, monkeypatch, capsys):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    controller.execute('show firewall fail-safe detail')
    assert calls == [['firewall.nvyr.op', 'show', '--failsafe', '--detail']]
    monkeypatch.setattr(firewall_op, '_load_table', lambda **kwargs: {})
    firewall_op.show(failsafe=True)
    assert capsys.readouterr().out == 'Fail-safe firewall is not active.\n'
