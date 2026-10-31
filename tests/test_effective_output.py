"""Effective displays include defaults without changing explicit configuration."""

from copy import deepcopy
from importlib.resources import files
import json

import pytest

from nvyr.errors import RouterError
from nvyr.controller import Controller
from nvyr.engine import Engine
from nvyr.schema import Schema
from nvyr.storage import Store
from tests.lifecycle import recorded_registry
from tests.test_login import as_role


@pytest.fixture
def configured(controller, engine, session):
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('set system host-name router', session)
    engine.commit(session)
    engine.save(session)

    return controller, engine, session


def test_effective_running_and_candidate_remain_display_only(configured):
    controller, engine, session = configured
    controller.execute('set interfaces dummy dum1', session)
    controller.execute('set interfaces dummy dum0 mtu 9000', session)
    running, candidate = deepcopy(engine.running), deepcopy(engine.view(session))
    mutations = deepcopy(session.mutations)
    saved = deepcopy(engine.store.read('boot.json', {}))
    revision = engine.commit_id

    for context in (None, session):
        result = json.loads(controller.execute('show running-configuration all', context)['text'])
        assert result == engine.schema.defaults(running)
        assert result['interfaces']['dummy']['dum0']['mtu'] == '1500'
        assert 'dum1' not in result['interfaces']['dummy']
        assert result['system']['configuration']['commit-revisions'] == '20'
        assert 'service' not in result
        assert json.loads(controller.execute('show running-configuration', context)['text']) == running

    for command in ('show all', 'show candidate-configuration all'):
        result = json.loads(controller.execute(command, session)['text'])
        effective = engine.schema.defaults(candidate)
        assert result == (effective if command == 'show all' else {'interfaces': effective['interfaces']})
        assert result['interfaces']['dummy']['dum0']['mtu'] == '9000'
        assert result['interfaces']['dummy']['dum1']['mtu'] == '1500'
        assert 'set interfaces dummy dum1 mtu 1500\n' in controller.execute(command + ' | commands', session)['text']

    assert '1500' not in controller.execute('show candidate-configuration | commands', session)['text']
    assert engine.running == running and engine.view(session) == candidate
    assert session.mutations == mutations and engine.commit_id == revision
    assert engine.store.read('boot.json', {}) == saved


def test_scopes_nested_edits_and_operational_wrapper(configured):
    controller, engine, session = configured
    expected = 'set dummy dum0 mtu 1500\n'
    assert controller.execute('show running-configuration all interfaces | commands')['text'] == expected
    assert controller.execute('show running-configuration all interfaces | commands', session)['text'] == expected

    controller.execute('edit interfaces', session)
    assert controller.execute('show running-configuration all | commands', session)['text'] == expected
    controller.execute('edit dummy dum0', session)

    for command in ('show all', 'show running-configuration all'):
        assert json.loads(controller.execute(command, session)['text']) == {'mtu': '1500'}
        assert controller.execute(command + ' | commands', session)['text'] == 'set mtu 1500\n'
        assert controller.execute(command + ' mtu | commands', session)['text'] == 'set mtu 1500\n'

    assert controller.execute('show candidate-configuration all', session)['text'] == '{}\n'
    assert controller.execute('show candidate-configuration all | commands', session)['text'] == ''

    controller.execute('set description changed', session)
    assert json.loads(controller.execute('show candidate-configuration all', session)['text']) == {
        'description': 'changed', 'mtu': '1500'}
    assert controller.execute('show candidate-configuration all mtu | commands', session)['text'] == 'set mtu 1500\n'

    # run remains an operational command rooted at the configuration root.
    result = controller.execute('run show running-configuration all interfaces | commands', session)
    assert result['text'] == expected


def test_deleted_objects_are_absent_from_effective_candidate(configured):
    controller, engine, session = configured
    controller.execute('delete interfaces dummy dum0', session)
    assert 'dum0' not in controller.execute('show all | commands', session)['text']
    assert 'delete interfaces dummy dum0' in controller.execute('show | commands', session)['text']

    with pytest.raises(RouterError, match='not configured'):
        controller.execute('show all interfaces dummy dum0', session)

    with pytest.raises(RouterError, match='without a setting value'):
        controller.execute('show running-configuration all interfaces dummy dum0 mtu 1500')


def test_multi_and_valueless_defaults_and_pipeline_rendering(tmp_path):
    # Declare test defaults before constructing the schema and its derived indexes.
    root = json.loads(files('nvyr').joinpath('schemas/configuration.json').read_text())
    children = root['children']['interfaces']['children']['dummy']['children']
    children['address']['default'] = {'mode': 'direct', 'value': ['192.0.2.1/24', '2001:db8::1/64']}
    children['disable']['default'] = {'mode': 'direct', 'value': True}
    schema = Schema(root)
    engine = Engine(schema, recorded_registry(schema), Store(tmp_path))
    controller = Controller(engine)
    session = engine.open('alice', '/dev/pts/1')
    controller.execute('set interfaces dummy dum0', session)
    engine.commit(session)

    base = 'show running-configuration all interfaces dummy dum0'

    data = json.loads(controller.execute(base)['text'])
    assert data['address'] == ['192.0.2.1/24', '2001:db8::1/64']
    assert data['disable'] is True
    commands = controller.execute(base + ' | commands')['text']
    assert commands == ('set address 192.0.2.1/24\nset address 2001:db8::1/64\n'
                        'set disable\nset mtu 1500\n')
    assert controller.execute(base + ' | commands | count')['text'] == '4\n'
    assert controller.execute(base + ' | commands | match mtu | no-more')['text'] == 'set mtu 1500\n'
    exported = controller.execute(base + ' | commands | export sample.txt')
    assert exported['text'] == commands and exported['export'] == 'sample.txt'
    masked = controller.execute(base + ' | strip-private | commands')['text']
    assert '192.0.2.1' not in masked and '2001:db8::1' not in masked
    assert engine.running['interfaces']['dummy']['dum0'] == {}


@pytest.mark.parametrize('role', ['read-only', 'net-admin'])
def test_effective_output_keeps_credentials_hidden(configured, role):
    controller, engine, session = configured
    engine.running.setdefault('system', {})['login'] = {'user': {'admin': {
        'role': 'sys-admin', 'authentication': {'encrypted-password': 'secret-hash'}}}}

    with as_role(role):
        assert 'secret-hash' not in controller.execute('show running-configuration all')['text']
        assert 'secret-hash' not in controller.execute('show running-configuration all | commands')['text']


def test_effective_completion_and_abbreviations(configured):
    controller, engine, session = configured
    controller.execute('set interfaces dummy dum0 description changed', session)
    for text, context in [('show ', session), ('show running-configuration ', session),
                          ('show candidate-configuration ', session), ('show running-configuration ', None),
                          ('run show running-configuration ', session)]:
        assert 'all' in dict(controller.completion(text, context, explicit=True)['candidates'])
        assert controller.completion(text + 'al', context, tab=True)['replacement'] == 'all'

    for text, context in [('show all ', session), ('show candidate-configuration all ', session),
                          ('show running-configuration all ', None), ('run show running-configuration all ', session)]:
        assert 'interfaces' in dict(controller.completion(text, context, explicit=True)['candidates'])
        assert '<Enter>' in dict(controller.completion(text, context, explicit=True)['candidates'])
        assert 'all' not in dict(controller.completion(text, context, explicit=True)['candidates'])
        assert 'dum0' in dict(controller.completion(text + 'interfaces dummy ', context, explicit=True)['candidates'])

    assert controller.execute('sho run al int dum dum0 mt | commands')['text'] == 'set mtu 1500\n'
    controller.execute('edit interfaces dummy dum0', session)
    assert controller.execute('sho al mt | commands', session)['text'] == 'set mtu 1500\n'
    assert controller.completion('show all mt', session, tab=True)['replacement'] == 'mtu'


def test_candidate_all_limits_defaults_to_changed_top_level_sections(configured):
    controller, engine, session = configured
    controller.execute('set firewall ipv4 input filter rule 20 action drop', session)
    engine.commit(session)
    controller.execute('set firewall ipv4 forward filter rule 10 action accept', session)
    before, candidate = deepcopy(engine.running), deepcopy(engine.view(session))
    mutations = deepcopy(session.mutations)
    saved = deepcopy(engine.store.read('boot.json', {}))
    revision = engine.commit_id

    command = 'show candidate-configuration all'
    result = json.loads(controller.execute(command, session)['text'])
    assert result == {'firewall': engine.schema.defaults(candidate)['firewall']}
    assert result['firewall']['ipv4']['forward']['filter']['default-action'] == 'accept'
    assert result['firewall']['ipv4']['input']['filter']['rule']['20']['action'] == 'drop'
    lines = controller.execute(command + ' | commands', session)['text'].splitlines()
    assert lines and all(line.startswith('set firewall ') for line in lines)
    assert 'set firewall ipv4 forward filter default-action accept' in lines
    assert controller.execute(command + ' interfaces | commands', session)['text'] == ''
    assert controller.execute(command + ' interfaces', session)['text'] == '{}\n'
    assert controller.execute(command + ' | commands | count', session)['text'] == f'{len(lines)}\n'
    exported = controller.execute(command + ' | commands | export candidate.txt', session)
    assert exported['export'] == 'candidate.txt' and exported['text'].splitlines() == lines

    controller.execute('set interfaces dummy dum1', session)
    assert set(json.loads(controller.execute(command, session)['text'])) == {'firewall', 'interfaces'}
    controller.execute('delete interfaces dummy dum1', session)
    assert session.mutations != mutations  # Net changes, not journal entries, determine sections.
    assert set(json.loads(controller.execute(command, session)['text'])) == {'firewall'}
    assert engine.running == before and engine.view(session) == candidate
    assert engine.store.read('boot.json', {}) == saved and engine.commit_id == revision


@pytest.mark.parametrize('empty', [False, True])
def test_candidate_all_keeps_deleted_sections_and_relative_delete_commands(configured, empty):
    controller, engine, session = configured
    if empty:
        controller.execute('delete interfaces dummy', session)
        engine.commit(session)

    controller.execute('delete interfaces', session)
    command = 'show candidate-configuration all'
    text = controller.execute(command, session)['text']
    assert '-   "interfaces"' in text
    assert 'system' not in text
    assert controller.execute(command + ' | commands', session)['text'] == 'delete interfaces\n'
    assert controller.execute(command + ' interfaces | commands', session)['text'] == 'delete interfaces\n'
    assert controller.execute(command + ' interfaces', session)['text'].startswith('- ')
    if not empty:
        assert '1500' in text
        assert 'dum0' in dict(controller.completion(command + ' interfaces dummy ', session, explicit=True)['candidates'])

    controller.execute('set firewall ipv4 forward filter rule 10 action accept', session)
    commands = controller.execute(command + ' | commands', session)['text']
    assert 'delete interfaces\n' in commands
    assert 'set firewall ipv4 forward filter default-action accept\n' in commands
    assert 'system' not in commands


def test_candidate_all_empty_without_pending_changes(configured):
    controller, engine, session = configured
    command = 'show candidate-configuration all'
    assert controller.execute(command, session)['text'] == '{}\n'
    assert controller.execute(command + ' | commands', session)['text'] == ''
    controller.execute('set interfaces dummy dum0 mtu 1500', session)
    assert 'interfaces' in json.loads(controller.execute(command, session)['text'])
    engine.commit(session)
    assert controller.execute(command, session)['text'] == '{}\n'

