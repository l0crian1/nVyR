"""External data errors, provenance, bounded retrieval, direct refresh and rollback."""

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import ValidationError
from nvyr.helpers import firewall_lists as feeds
from nvyr.helpers.nftables_formatters import nft_singleton_group, nft_match_group
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree
from tests.lifecycle import firewall_context


def config(source='/tmp/list', *, kind='address-group', family='ipv4'):
    options = {'source': source}
    definition = {feeds.attachment_node(kind): {'A': options}}
    if kind in ('map', 'match-group'):
        definition['match'] = {'source-address': True, 'destination-address': True,
                               'protocol': True, 'destination-port': True}
        options['column'] = {'source-address': '1', 'destination-address': '2',
                             'destination-port': '3', 'protocol': '4'}
    if kind == 'map':
        definition['result-type'] = 'verdict'
        options['column']['result'] = {'action': '5'}
    definitions = {'G': definition}
    return {'firewall': {'group': {kind: {family: definitions} if family else definitions}}}


def selected(configuration):
    return next(iter(feeds.groups(configuration).items()))


def imported(data, configuration):
    identity, definition = selected(configuration)
    messages = []
    options = definition[feeds.attachment_node(identity[0])]['A']
    record = feeds.parse(data.encode(), identity, definition, options, configuration, messages.append)
    return identity, definition, record, messages


def test_list_bad_rows_are_skipped_without_dns(monkeypatch):
    import socket

    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('address entry resolved DNS'))
    identity, definition, record, messages = imported('192.0.2.1\nexample.com\n192.0.2.1/32\n2001:db8::1\n198.51.100.0/24\n', config())
    assert len(record['entries']) == 2
    assert record['counts'] == {'accepted': 3, 'invalid': 2, 'duplicates': 1}
    assert len(messages) == 2


def test_csv_conflicting_results_remove_every_occurrence_across_sources():
    configuration = config(kind='map')
    identity, definition, first, warnings = imported('192.0.2.1,198.51.100.1,443,tcp,accept\n192.0.2.2,198.51.100.2,53,udp,drop\n', configuration)
    _, _, second, _ = imported('192.0.2.1,198.51.100.1,443,tcp,drop\n192.0.2.2,198.51.100.2,53,udp,drop\n', configuration)
    text, count = feeds.elements(identity, definition, {'A': first, 'B': second, 'C': first}, warnings.append)
    assert count == 1
    assert '192.0.2.1' not in text
    assert 'comment "A, B, C"' in text
    assert 'ambiguous key' in warnings[0]


def test_csv_internal_conflicts_cannot_be_reintroduced():
    configuration = config(kind='map')
    row = '192.0.2.1,198.51.100.1,443,tcp,'
    identity, definition, record, warnings = imported(row+'accept\n'+row+'drop\n'+row+'accept\n', configuration)
    assert not record['entries']
    assert len(record['ambiguous']) == 1
    assert 'ambiguous key' in warnings[0]


def test_single_field_map_excludes_entire_overlap_cluster():
    configuration = config(kind='map')
    definition = selected(configuration)[1]
    definition['match'] = {'source-address': True}
    definition['from-csv']['A']['column'] = {'source-address': '1', 'result': {'action': '2'}}
    identity, definition, first, warnings = imported('192.0.2.0/25,accept\n198.51.100.1,drop\n', configuration)
    _, _, second, _ = imported('192.0.2.64-192.0.2.191,accept\n192.0.2.128/25,drop\n', configuration)
    text, count = feeds.elements(identity, definition, {'A': first, 'B': second}, warnings.append)
    assert count == 1
    assert '198.51.100.1' in text and '192.0.2.' not in text
    assert len(warnings) == 3
    assert all('overlapping single-field map key' in warning for warning in warnings)


def test_hash_skips_parsing_and_failed_retrieval_keeps_cache(monkeypatch, tmp_path):
    manager = feeds.Manager(tmp_path)
    configuration = config()
    monkeypatch.setattr(feeds, 'fetch', lambda source: b'192.0.2.1\n')
    first = manager.collect(configuration, {})
    monkeypatch.setattr(feeds, 'parse', lambda *a: pytest.fail('unchanged file was reparsed'))
    refreshed = manager.collect(configuration, first, refresh=[('address-group', 'ipv4', 'G', 'A')])
    assert first['address-group/ipv4/G']['A']['entries'] == refreshed['address-group/ipv4/G']['A']['entries']
    monkeypatch.setattr(feeds, 'fetch', lambda source: (_ for _ in ()).throw(ValueError('DNS timeout')))
    errors = []
    failed = manager.collect(configuration, first, refresh=[('address-group', 'ipv4', 'G', 'A')], output=errors.append)
    assert failed['address-group/ipv4/G']['A']['entries'] == first['address-group/ipv4/G']['A']['entries']
    assert any('cached' in str(message) for message in errors)


def test_ten_sources_retrieve_concurrently(monkeypatch, tmp_path):
    configuration = config()
    definition = selected(configuration)[1]
    definition['from-list'] = {str(number): {'source': f'https://example.test/{number}'} for number in range(10)}
    barrier = threading.Barrier(10, timeout=3)
    def fetch(source):
        barrier.wait()
        raise ValueError('DNS unavailable')
    monkeypatch.setattr(feeds, 'fetch', fetch)
    cache = feeds.Manager(tmp_path).collect(configuration, {})
    assert len(cache['address-group/ipv4/G']) == 10
    assert all(not record['entries'] for record in cache['address-group/ipv4/G'].values())


@pytest.mark.parametrize('source', ['https://host/a', 'http://host/a', 'ftp://host/a', 'ftps://host:990/a', 'tftp://192.0.2.1/a', '/etc/feeds/a'])
def test_source_validator(source):
    from nvyr.helpers.validators import firewall_list_source
    assert firewall_list_source(source)


@pytest.mark.parametrize('source', ['relative/a', 'sftp://host/a', 'file:///etc/shadow', 'https://host:bad/a'])
def test_invalid_sources(source):
    from nvyr.helpers.validators import firewall_list_source
    assert not firewall_list_source(source)


def test_column_anchoring_and_schedule(controller, engine, session):
    for line in (
        'set firewall group map ipv4 G match source-address destination-address destination-port protocol',
        'set firewall group map ipv4 G result-type verdict',
        'set firewall group map ipv4 G from-csv A source /config/policy.csv',
        'set firewall group map ipv4 G from-csv A column source-address 1 destination-address 2 destination-port 3 protocol 4 result action 5',
        'set firewall group map ipv4 G from-csv A interval 6h',
    ):
        controller.execute(line, session)
    tree = engine.view(session)
    definition = selected(tree)[1]
    assert definition['from-csv']['A']['column']['result']['action'] == '5'
    feeds.verify(tree)
    units = feeds.schedules(feeds.groups(tree))
    assert len(units) == 2
    assert '6h' in next(value for name, value in units.items() if name.endswith('.timer'))


def test_equal_schedules_share_one_batch(engine, tmp_path, monkeypatch):
    configuration = config()
    definition = selected(configuration)[1]
    definition['from-list'] = {
        'A': {'source': '/tmp/a', 'interval': '6h'},
        'B': {'source': '/tmp/b', 'interval': '6h'},
        'C': {'source': '/tmp/c', 'interval': '12h'},
    }
    units = feeds.schedules(feeds.groups(configuration))
    assert len(units) == 4  # One timer/service pair per distinct schedule.
    engine.running = configuration
    fetched = []
    def fetch(source):
        fetched.append(source)
        return b'192.0.2.1\n'
    monkeypatch.setattr(feeds, 'fetch', fetch)
    manager = feeds.Manager(tmp_path)
    manager.publish(manager.collect(configuration, {}))
    fetched.clear()

    manager.update(engine, schedule=feeds.schedule_name({'interval': '6h'}))
    assert set(fetched) == {'/tmp/a', '/tmp/b'}


def test_imports_reject_manual_entries_and_inclusions():
    configuration = config()
    definition = selected(configuration)[1]
    definition['address'] = ['192.0.2.1']
    with pytest.raises(ValidationError, match='cannot coexist'):
        feeds.verify(configuration)
    definition.pop('address')
    configuration['firewall']['group']['address-group']['ipv4']['PARENT'] = {'include-group': ['G']}
    with pytest.raises(ValidationError, match='imported'):
        firewall.verify(configuration, None)


def test_checkpoint_preserves_confirmed_before_refresh(tmp_path):
    manager = feeds.Manager(tmp_path / 'lists')
    state = tmp_path / 'state'
    state.mkdir()
    manager.publish({'old': {}})
    (state/'transaction.json').write_text(json.dumps({'before': {}, 'id': 1}))
    (state/'confirmed.json').write_text(json.dumps({'before': {}, 'owner': 'session', 'deadline': 1}))
    manager.checkpoint(state)
    manager.publish({'new': {}})
    (state/'transaction.json').unlink()
    (state/'confirmed.json').write_text(json.dumps({'before': {}, 'owner': 'session', 'deadline': 2}))
    manager.checkpoint(state)
    manager.publish({'refreshed': {}})
    assert manager.checkpoint(state, recovery=True) == {'old': {}}


def test_new_commit_with_same_owner_and_before_tree_gets_new_pin(tmp_path):
    manager = feeds.Manager(tmp_path / 'lists')
    state = tmp_path / 'state'
    state.mkdir()
    pending = {'before': {}, 'owner': 'session', 'deadline': 1}
    (state/'transaction.json').write_text(json.dumps({'before': {}, 'id': 1}))
    (state/'confirmed.json').write_text(json.dumps(pending))
    manager.publish({'old': {}})
    manager.checkpoint(state)

    manager.publish({'new-runtime-membership': {}})
    (state/'transaction.json').write_text(json.dumps({'before': {}, 'id': 2}))
    manager.checkpoint(state)
    assert manager.checkpoint(state, recovery=True) == {'new-runtime-membership': {}}


def test_invalid_encoding_only_invalidates_its_entry():
    configuration = config()
    identity, definition = selected(configuration)
    warnings = []
    record = feeds.parse(b'192.0.2.1\n\xff\n192.0.2.2\n', identity, definition,
                         definition['from-list']['A'], configuration, warnings.append)
    assert len(record['entries']) == 2
    assert record['counts']['invalid'] == 1


def test_recovery_does_not_download(tmp_path, monkeypatch):
    configuration = config()
    monkeypatch.setattr(feeds, 'fetch', lambda source: b'192.0.2.1\n')
    manager = feeds.Manager(tmp_path)
    before = manager.collect(configuration, {})
    monkeypatch.setattr(feeds, 'fetch', lambda source: pytest.fail('recovery downloaded membership'))
    assert manager.collect(configuration, before, recovery=True) == before


def test_imported_jump_obeys_ingress_hook_restrictions():
    configuration = config(kind='map')
    definition = selected(configuration)[1]
    definition['from-csv']['A']['column']['result']['jump-target'] = '6'
    configuration['firewall']['ipv4'] = {
        'ingress': {'filter': {'rule': {'1': {'map': 'G'}}}},
        'name': {'TRACKED': {'rule': {'1': {'connection': {'state': ['established']}, 'action': 'accept'}}}},
    }
    _, _, record, warnings = imported('192.0.2.1,198.51.100.1,443,tcp,jump,TRACKED\n'
                                     '192.0.2.2,198.51.100.2,443,tcp,drop,\n', configuration)
    assert len(record['entries']) == 1
    assert record['counts']['invalid'] == 1
    assert 'ingress' in warnings[0]


def test_generate_prepare_and_apply_are_separate(tmp_path, monkeypatch):
    manager = feeds.Manager(tmp_path/'lists')
    monkeypatch.setattr(feeds, 'manager', manager)
    monkeypatch.setattr(feeds, 'fetch', lambda source: b'192.0.2.1\n')
    schema = Schema.bundled()
    effective = ReadOnlyTree(schema.defaults(config()))
    before = ReadOnlyTree(schema.defaults({}))
    context = firewall_context(effective, before, 'firewall', ('firewall',), previous_effective=before, schema=schema)
    context = replace(context, state_directory=tmp_path)
    firewall.verify(effective, context)
    plan = firewall.generate(effective, context)
    assert '192.0.2.1 comment "A"' in plan['rules']
    assert not (manager.directory/'cache.json').exists()
    firewall.apply(plan, context)
    assert (manager.directory/'cache.json').exists()


def test_native_declarations_support_later_interval_refresh():
    address = selected(config())[1]
    assert 'auto-merge;' in nft_singleton_group('address-group', 'ipv4', 'G', address)
    match = selected(config(kind='match-group'))[1]
    assert 'flags interval;' in nft_match_group('ipv4', 'G', match)


@pytest.mark.parametrize(('result_type', 'columns', 'first', 'second'), [
    ('verdict', {'action': '5'}, 'accept', 'drop'),
    ('address', {'address': '5'}, '203.0.113.1', '203.0.113.2'),
    ('port', {'port': '5'}, '1000', '2000'),
    ('address-port', {'address': '5', 'port': '6'}, '203.0.113.1,1000', '203.0.113.1,2000'),
])
def test_all_map_results_conflict_by_key(result_type, columns, first, second):
    configuration = config(kind='map')
    definition = selected(configuration)[1]
    definition['result-type'] = result_type
    definition['from-csv']['A']['column']['result'] = columns
    prefix = '192.0.2.1,198.51.100.1,443,tcp,'
    _, _, record, warnings = imported(prefix + first + '\n' + prefix + second + '\n', configuration)
    assert not record['entries']
    assert len(record['ambiguous']) == 1
    assert 'ambiguous' in warnings[0]


def test_malformed_csv_row_does_not_discard_good_rows():
    configuration = config(kind='map')
    _, _, record, warnings = imported('192.0.2.1,198.51.100.1,443,tcp,drop\n"unclosed\n192.0.2.2,198.51.100.2,443,tcp,accept\n', configuration)
    assert len(record['entries']) == 2
    assert record['counts']['invalid'] == 1


def test_changed_mapping_reimports_even_if_file_hash_is_same(monkeypatch, tmp_path):
    configuration = config(kind='map')
    monkeypatch.setattr(feeds, 'fetch', lambda source: b'192.0.2.1,198.51.100.1,443,tcp,drop\n')
    manager = feeds.Manager(tmp_path)
    first = manager.collect(configuration, {})
    columns = selected(configuration)[1]['from-csv']['A']['column']
    columns['source-address'], columns['destination-address'] = '2', '1'
    second = manager.collect(configuration, first)
    assert first['map/ipv4/G']['A']['entries'] != second['map/ipv4/G']['A']['entries']


def test_download_timeouts_and_protocol_allowlist(monkeypatch):
    captured = []
    def run(argv, **kwargs):
        captured.append((argv, kwargs))
        Path(argv[argv.index('--output') + 1]).write_bytes(b'192.0.2.1\n')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(feeds.subprocess, 'run', run)
    assert feeds.fetch('tftp://192.0.2.1/feed') == b'192.0.2.1\n'
    argv, options = captured[0]
    assert argv[argv.index('--connect-timeout') + 1] == '2'
    assert argv[argv.index('--max-time') + 1] == '5'
    assert options['timeout'] == 6
    assert '--insecure' not in argv
    assert argv[argv.index('--proto') + 1] == '=http,https,ftp,ftps,tftp'


def test_manual_refresh_does_not_rebuild_rules_and_failure_keeps_published_cache(engine, tmp_path, monkeypatch):
    manager = feeds.Manager(tmp_path)
    engine.running = config()
    monkeypatch.setattr(feeds, 'fetch', lambda source: b'192.0.2.1\n')
    loaded = []
    monkeypatch.setattr(feeds.nftables.manager, 'apply', lambda text, *a, **k: loaded.append(text))
    manager.update(engine, 'address-group', 'ipv4', 'G')
    assert len(loaded) == 1 and 'chain' not in loaded[0]
    manager.update(engine, 'address-group', 'ipv4', 'G')
    assert len(loaded) == 1
    before = manager.read('cache.json')
    monkeypatch.setattr(feeds, 'fetch', lambda source: b'192.0.2.2\n')
    def reject(*args, **kwargs):
        raise ValidationError('native rejection')
    monkeypatch.setattr(feeds.nftables.manager, 'apply', reject)
    with pytest.raises(ValidationError, match='native rejection'):
        manager.update(engine, 'address-group', 'ipv4', 'G')
    assert manager.read('cache.json') == before
