from types import SimpleNamespace

import pytest

from nvyr.config_scripts import nat, firewall
from nvyr.errors import RouterError
from nvyr.helpers import nftables, validators
from nvyr.helpers.nftables_formatters import nft_nat_dispatch, nft_nat_rule
from nvyr.schema import Schema
from tests.lifecycle import firewall_context
from nvyr.tree import ReadOnlyTree


def generated(config):
    schema = Schema.bundled()
    tree = {'nat': config}
    schema.validate_configuration(tree)
    effective = ReadOnlyTree(schema.defaults(tree))
    nat.verify(effective, None)

    context = firewall_context(effective, ReadOnlyTree({}), 'firewall', ('firewall',),
                            previous_effective=ReadOnlyTree({}), schema=schema)
    return firewall.generate(effective, context)


@pytest.mark.parametrize('direction', ['source', 'destination'])
@pytest.mark.parametrize('address,expected', [
    ('203.0.113.10', '203.0.113.10'), ('203.0.113.0/24', '203.0.113.0/24'),
    ('203.0.113.10-203.0.113.20', '203.0.113.10-203.0.113.20'),
    ('203.0.113.10/32', '203.0.113.10/32'), ('203.0.113.10/31', '203.0.113.10/31'),
])
def test_translation_address_forms(direction, address, expected):
    interface = 'outbound-interface' if direction == 'source' else 'inbound-interface'
    text = generated({direction: {'rule': {'10': {interface: ['eth0'], 'translation': {'address': address}}}}})

    assert ('snat' if direction == 'source' else 'dnat') + ' ip to ' + expected in text
    assert 'table inet nvyr_filter' in text
    assert 'table ip ' not in text


@pytest.mark.parametrize('direction,address,expression', [
    ('source', None, 'snat to :8080-8090'),
    ('destination', None, 'dnat to :8080-8090'),
    ('source', 'masquerade', 'masquerade to :8080-8090'),
    ('source', '203.0.113.10', 'snat ip to 203.0.113.10:8080-8090'),
    ('destination', '203.0.113.10', 'dnat ip to 203.0.113.10:8080-8090'),
    ('source', '203.0.113.0/24', 'snat ip to 203.0.113.0/24 :8080-8090'),
    ('destination', '203.0.113.0/24', 'dnat ip to 203.0.113.0/24 :8080-8090'),
])
def test_ports_flags_and_logging(direction, address, expression):
    translation = {'port': '8080-8090', 'port-mapping': 'fully-random'}

    if address:
        translation.update(address=address, persistent=True)

    interface = 'outbound-interface' if direction == 'source' else 'inbound-interface'
    text = generated({direction: {'rule': {'10': {interface: ['eth0'],
        'protocol': ['tcp', 'udp'], 'translation': translation, 'log': {}}}}})

    assert expression + (' persistent,fully-random' if address else ' fully-random') in text
    assert 'meta l4proto { tcp, udp } log prefix "[ipv4-' in text
    assert 'comment "10|"' in text


def test_shared_matches_dispatch_numeric_order_disable_and_exclude():
    text = generated({'source': {'rule': {
        '100': {'outbound-interface': ['eth0'], 'translation': {'address': 'masquerade'}},
        '20': {'disable': True},
        '10': {'exclude': True, 'log': {}, 'description': 'Internal traffic',
               'source-address': ['192.0.2.0/24', '192.0.2.1'],
               'destination-address': ['198.51.100.1'], 'outbound-interface': ['eth2', 'eth1'],
               'protocol': ['udp', 'tcp'], 'source-port': ['90-100', '95-110'], 'destination-port': ['53']}}}})

    assert 'oifname { "eth1", "eth2" } ip saddr { 192.0.2.0/24, 192.0.2.1 } ip daddr { 198.51.100.1 }' in text
    assert 'th sport { 90-100, 95-110 } th dport { 53 } log prefix "[ipv4-POST-10-E]" return' in text
    assert text.index('comment "10|') < text.index('comment "100|')
    assert 'comment "20|' not in text
    assert 'type nat hook postrouting priority srcnat;' in text
    assert 'meta nfproto vmap { ipv4 : jump ipv4_nat_postrouting }' in text
    assert 'chain nat_prerouting {' not in text and 'ipv6 :' not in text
    assert 'flush ruleset' not in text
    assert [line for line in text.splitlines() if line.startswith('destroy table')] == [
        'destroy table inet nvyr_filter_failsafe']
    assert 'chain nat_postrouting {' not in generated({})
    assert 'chain nat_prerouting {' in generated({'destination': {}})
    assert nft_nat_dispatch({}, 'prerouting') == ''

    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration({'nat': {'forward': {}}})


@pytest.mark.parametrize('suffix', [
    'translation address 203.0.113.1/24', 'translation address 203.0.113.20-203.0.113.10',
    'translation address 2001:db8::1', 'translation address 203.0.113.1-2001:db8::1',
    'translation address 203.0.113.1;drop', 'translation address 1.1.1.1-2.2.2.2-3.3.3.3',
    'translation port 0', 'translation port 65536', 'translation port 90-80',
    'translation port 080', 'translation port 1000-02000',
    'translation port-mapping invalid', 'action accept', 'state established',
    'description ' + 'é' * 61,
])
def test_schema_rejects_invalid_nat_fields(controller, session, suffix):
    with pytest.raises(RouterError):
        controller.execute('set nat source rule 10 ' + suffix, session)


@pytest.mark.parametrize('command', [
    'set nat source rule 10 inbound-interface eth0',
    'set nat destination rule 10 outbound-interface eth0',
    'set nat destination rule 10 translation address masquerade',
    'set nat source rule 0 exclude', 'set nat source rule 1000000 exclude',
    'set nat source rule 0000001 exclude',
])
def test_direction_and_number_validation(controller, session, command):
    with pytest.raises(RouterError):
        controller.execute(command, session)


@pytest.mark.parametrize('rule,message', [
    ({}, 'translation address or port'),
    ({'translation': {}}, 'translation address or port'),
    ({'translation': {'port-mapping': 'default'}}, 'translation address or port'),
    ({'exclude': True, 'translation': {}}, 'exclude cannot'),
    ({'exclude': True, 'translation': {'address': 'masquerade'}}, 'exclude cannot'),
    ({'source-port': ['80'], 'exclude': True}, 'requires an explicit port protocol'),
    ({'protocol': ['icmp'], 'translation': {'port': '80'}}, 'requires an explicit port protocol'),
    ({'protocol': ['tcp', 'icmp'], 'translation': {'port': '80'}}, 'requires an explicit port protocol'),
    ({'translation': {'address': 'masquerade', 'port-mapping': 'random'}}, 'requires an explicit port protocol'),
    ({'protocol': ['tcp'], 'translation': {'port': '80', 'persistent': True}}, 'persistent requires'),
])
def test_lifecycle_verify_identifies_rule(rule, message):
    with pytest.raises(RouterError, match='nat source rule 42:.*' + message):
        generated({'source': {'rule': {'42': rule}}})

    generated({'source': {'rule': {'42': dict(rule, disable=True)}}})


def test_anchor_edit_completion_and_failed_verify_retains_candidate(controller, engine, session, monkeypatch):
    calls = []
    monkeypatch.setattr(nftables, 'manager', SimpleNamespace(apply=lambda *a, **kw: calls.append((a, kw))))
    controller.execute('edit nat source', session)
    controller.execute('set rule 10 source-address 192.0.2.0/24 source-address 198.51.100.0/24 outbound-interface eth0 log', session)
    result = engine.commit(session)

    assert not result['results']['firewall']['success'] and not calls
    assert engine.view(session)['nat']['source']['rule']['10']['log'] == {}

    controller.execute('set rule 10 translation address masquerade', session)
    completions = dict(controller.completion('set rule 10 translation address masquerade ', session, explicit=True)['candidates'])

    assert 'description' in completions and 'exclude' in completions
    assert engine.commit(session)['results']['firewall']['success']
    assert calls[-1][1] == {'accounting': False}
    assert 'masquerade comment' in calls[-1][0][0]

    engine.save(session)

    assert engine.store.read('boot.json')['nat']['source']['rule']['10']['translation']['address'] == 'masquerade'

    controller.execute('delete rule 10 translation address', session)

    assert not engine.commit(session)['results']['firewall']['success']

    controller.execute('delete rule 10', session)

    assert engine.commit(session)['results']['firewall']['success']


@pytest.mark.parametrize('direction', ['source', 'destination'])
@pytest.mark.parametrize('exclude', [False, True])
def test_counter_last_used_completion_rendering_and_disable(controller, engine, session, direction, exclude):
    command = f'set nat {direction} rule 10 '
    candidates = dict(controller.completion(command, session, explicit=True)['candidates'])

    assert {'counter', 'last-used'} <= candidates.keys()

    action = 'exclude' if exclude else 'translation address 203.0.113.10'
    interface = 'outbound-interface' if direction == 'source' else 'inbound-interface'
    controller.execute(command + interface + ' eth0 ' + action + ' counter last-used', session)
    config = engine.view(session)['nat']
    text = generated(config)
    statement = 'return' if exclude else ('snat' if direction == 'source' else 'dnat') + ' ip to 203.0.113.10'

    assert f'counter last {statement} comment "10|"' in text

    controller.execute(command + 'disable', session)

    assert 'comment "10|' not in generated(engine.view(session)['nat'])

    for flag in ('counter', 'last-used'):
        with pytest.raises(RouterError):
            Schema.bundled().validate_configuration({'nat': {direction: {'rule': {
                '10': {'exclude': True, flag: False}}}}})


def test_generic_ip_range_and_owner_specific_artifacts(tmp_path, monkeypatch):
    assert validators.ip_range('2001:db8::1-2001:db8::10', 6)
    assert not validators.ip_range('fe80::1%eth0-fe80::2%eth0', 6)
    assert not validators.ip_range('203.0.113.2-203.0.113.1', 4)

    monkeypatch.setattr(nftables, 'rc_cmd', lambda args, **kwargs: (0, ''))
    manager = nftables.Manager()
    manager.apply('filter', tmp_path)
    manager.apply('translation', tmp_path, owner='nat')

    assert (tmp_path / 'firewall.nft').read_text() == 'filter'
    assert (tmp_path / 'nat.nft').read_text() == 'translation'

    with pytest.raises(ValueError):
        manager.apply('', tmp_path, owner='../escape')


@pytest.mark.parametrize('direction,rule', [
    ('source', {'translation': {'address': '1.1.1.1; drop'}}),
    ('destination', {'translation': {'address': 'masquerade'}}),
    ('source', {'translation': {'address': 'masquerade'}, 'log': False}),
    ('source', {'translation': {'address': 'masquerade'}, 'inbound-interface': ['eth0']}),
    ('destination', {'exclude': True, 'translation': {'port': '80'}}),
])
def test_schema_and_verify_reject_invalid_configuration_before_rendering(direction, rule):
    with pytest.raises(RouterError):
        generated({direction: {'rule': {'10': rule}}})


@pytest.mark.parametrize('direction,address,target,label', [
    ('source', '203.0.113.10', 'snat ip to 203.0.113.10:8080-8090', 'POST-10-S'),
    ('destination', '203.0.113.10', 'dnat ip to 203.0.113.10:8080-8090', 'PRE-10-D'),
    ('source', '203.0.113.0/24', 'snat ip to 203.0.113.0/24 :8080-8090', 'POST-10-S'),
    ('destination', '203.0.113.0/24', 'dnat ip to 203.0.113.0/24 :8080-8090', 'PRE-10-D'),
    ('source', '203.0.113.10-203.0.113.20', 'snat ip to 203.0.113.10-203.0.113.20:8080-8090', 'POST-10-S'),
    ('destination', '203.0.113.10-203.0.113.20', 'dnat ip to 203.0.113.10-203.0.113.20:8080-8090', 'PRE-10-D'),
    ('source', 'masquerade', 'masquerade to :8080-8090', 'POST-10-M'),
    ('source', None, 'snat to :8080-8090', 'POST-10-S'),
    ('destination', None, 'dnat to :8080-8090', 'PRE-10-D'),
])
@pytest.mark.parametrize('mode,suffix', [(None, ''), ('default', ''), ('random', 'random'), ('fully-random', 'fully-random')])
@pytest.mark.parametrize('persistent', [False, True])
def test_translation_keymap_preserves_exact_output_and_input(direction, address, target, label, mode, suffix, persistent):
    if persistent and address is None:
        pytest.skip('Persistent port-only translation is rejected by verify()')

    # Reverse configuration order to ensure map order controls the expression.
    translation = {}

    if mode is not None:
        translation['port-mapping'] = mode

    if persistent:
        translation['persistent'] = True

    translation['port'] = '8080-8090'

    if address is not None:
        translation['address'] = address

    original = dict(translation)
    rule = {'translation': translation, 'last-used': True, 'counter': {}, 'log': {}, 'protocol': ['udp', 'tcp']}
    flags = ','.join(filter(None, ['persistent' if persistent else '', suffix]))
    expected = (f'meta l4proto {{ tcp, udp }} log prefix "[ipv4-{label}]" counter last {target}'
                + (' ' + flags if flags else '') + ' comment "10|"')

    assert nft_nat_rule(direction, '10', ReadOnlyTree(rule)) == expected
    assert translation == original


@pytest.mark.parametrize('direction,hook', [('source', 'POST'), ('destination', 'PRE')])
def test_nat_exclude_and_disable_bypass_translation(direction, hook):
    rule = {'exclude': True, 'log': {}, 'counter': {}, 'last-used': True, 'description': 'Bypass'}

    assert nft_nat_rule(direction, '10', rule) == (
        f'log prefix "[ipv4-{hook}-10-E]" counter last return comment "10|Bypass"')
    assert nft_nat_rule(direction, '10', {'disable': True}) == ''
