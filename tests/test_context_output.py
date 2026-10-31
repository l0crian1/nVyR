"""Configuration display selection and relative command serialization."""

import json

import pytest

from nvyr.tree import lookup


@pytest.fixture
def configured(controller, engine, session, monkeypatch):
    monkeypatch.setattr('nvyr.helpers.interfaces.exists', lambda name: True)
    controller.execute('set interfaces dummy dum0 address 150.0.0.1/32', session)
    controller.execute('set interfaces ethernet eth0 address dhcp', session)
    controller.execute('set system host-name outside', session)
    engine.commit(session)

    return controller, engine, session


def test_explicit_scope_and_edit_scope_match_and_root_stays_absolute(configured):
    controller, engine, session = configured
    expected = 'set dummy dum0 address 150.0.0.1/32\nset ethernet eth0 address dhcp\n'

    assert controller.execute('show running-configuration interfaces | commands', session)['text'] == expected

    controller.execute('edit interfaces', session)

    assert controller.execute('show running-configuration | commands', session)['text'] == expected
    assert json.loads(controller.execute('show running-configuration', session)['text']) == engine.running['interfaces']
    assert controller.execute('show running-configuration | commands | count', session)['text'] == '2\n'
    assert controller.execute('show running-configuration | commands | match dummy', session)['text'] == expected.splitlines(True)[0]

    exported = controller.execute('show running-configuration | commands | export sample.txt', session)

    assert exported['text'] == expected and exported['export'] == 'sample.txt'

    controller.execute('top', session)
    absolute = ('set interfaces dummy dum0 address 150.0.0.1/32\n'
                'set interfaces ethernet eth0 address dhcp\nset system host-name outside\n')

    assert controller.execute('show running-configuration | commands', session)['text'] == absolute
    assert controller.execute('show running-configuration | commands')['text'] == absolute


def test_show_commands_includes_unchanged_running_configuration(configured):
    controller, engine, session = configured

    for scope in ('', ' interfaces', ' interfaces dummy dum0', ' system host-name'):
        expected = controller.execute(f'show running-configuration{scope} | commands', session)['text']
        assert expected
        assert controller.execute(f'show{scope} | commands', session)['text'] == expected

    assert controller.execute('show candidate-configuration | commands', session)['text'] == ''
    assert controller.execute('compare | commands', session)['text'] == ''


def test_show_commands_keeps_retained_values_and_pending_changes(configured):
    controller, engine, session = configured
    controller.execute('set interfaces dummy dum0 address 192.0.2.1/24', session)
    controller.execute('set system host-name replacement', session)
    controller.execute('delete interfaces ethernet eth0', session)

    expected = (
        'set interfaces dummy dum0 address 150.0.0.1/32\n'
        'set interfaces dummy dum0 address 192.0.2.1/24\n'
        'delete interfaces ethernet eth0\n'
        'set system host-name replacement\n'
    )
    assert controller.execute('show | commands', session)['text'] == expected
    assert controller.execute('show | commands | count', session)['text'] == '4\n'

    controller.execute('edit interfaces dummy dum0', session)
    assert controller.execute('show | commands', session)['text'] == (
        'set address 150.0.0.1/32\nset address 192.0.2.1/24\n'
    )

    controller.execute('delete address 150.0.0.1/32', session)
    assert controller.execute('show address | commands', session)['text'] == (
        'delete address 150.0.0.1/32\nset address 192.0.2.1/24\n'
    )


def test_show_commands_preserves_empty_named_objects(controller, engine, session):
    controller.execute('set firewall group counter-group test', session)
    engine.commit(session)

    assert controller.execute('show firewall | commands', session)['text'] == (
        'set group counter-group test\n'
    )
    assert controller.execute('show firewall group counter-group test | commands', session)['text'] == (
        'set counter-group test\n'
    )

    controller.execute('edit firewall group counter-group test', session)
    assert controller.execute('show | commands', session)['text'] == 'set counter-group test\n'


@pytest.mark.parametrize('view', ['show', 'show candidate-configuration', 'compare'])
def test_nested_edit_context_diffs_replay_relative_to_context(configured, view):
    controller, engine, session = configured
    controller.execute('set system host-name changed-outside', session)
    controller.execute('edit interfaces', session)
    controller.execute('edit dummy dum0', session)
    controller.execute('delete address 150.0.0.1/32', session)
    controller.execute('set address 192.0.2.1/24', session)
    controller.execute('set address 2001:db8::1/64', session)
    controller.execute('set description "Lab router"', session)
    controller.execute('set disable', session)
    expected = ('delete address 150.0.0.1/32\nset address 192.0.2.1/24\n'
                'set address 2001:db8::1/64\nset description \'Lab router\'\nset disable\n')

    assert controller.execute(view + ' | commands', session)['text'] == expected
    assert 'outside' not in controller.execute(view, session)['text']

    replay = engine.open('replay', 'test')
    controller.execute('edit interfaces dummy dum0', replay)

    for line in expected.splitlines():
        controller.execute(line, replay)

    assert lookup(engine.view(replay), session.edit) == lookup(engine.view(session), session.edit)
    assert engine.view(replay)['system']['host-name'] == 'outside'
    assert engine.view(replay)['interfaces']['ethernet'] == engine.running['interfaces']['ethernet']
    assert controller.execute('show running-configuration | commands', session)['text'] == 'set address 150.0.0.1/32\n'

    controller.execute('up', session)

    assert controller.execute('show running-configuration dummy dum0 | commands', session)['text'] == 'set address 150.0.0.1/32\n'


def test_explicit_candidate_scope_and_leaf_selection(configured):
    controller, engine, session = configured
    controller.execute('delete interfaces dummy dum0 address 150.0.0.1/32', session)
    controller.execute('set interfaces dummy dum0 address 192.0.2.1/24', session)
    controller.execute('set system host-name unrelated', session)
    expected = 'delete dummy dum0 address 150.0.0.1/32\nset dummy dum0 address 192.0.2.1/24\n'

    assert controller.execute('show candidate-configuration interfaces | commands', session)['text'] == expected

    controller.execute('edit interfaces dummy dum0', session)

    assert controller.execute('show candidate-configuration address | commands', session)['text'] == (
        'delete address 150.0.0.1/32\nset address 192.0.2.1/24\n')
    assert controller.execute('show running-configuration address | commands', session)['text'] == 'set address 150.0.0.1/32\n'


def test_empty_and_deleted_selected_objects_keep_a_valid_target(configured):
    controller, engine, session = configured
    controller.execute('delete interfaces dummy dum0', session)
    controller.execute('set interfaces dummy dum1', session)

    assert controller.execute('show candidate-configuration interfaces dummy dum0 | commands', session)['text'] == 'delete dummy dum0\n'
    assert controller.execute('show candidate-configuration interfaces dummy dum1 | commands', session)['text'] == 'set dummy dum1\n'

    controller.execute('edit interfaces', session)

    assert controller.execute('show candidate-configuration | commands', session)['text'] == 'delete dummy dum0\nset dummy dum1\n'

    engine.commit(session)
    controller.execute('edit dummy dum1', session)

    assert controller.execute('show running-configuration | commands', session)['text'] == 'set dummy dum1\n'
    assert controller.execute('show candidate-configuration | commands', session)['text'] == ''


def test_deleting_last_child_remains_relative_to_selected_object(configured):
    controller, engine, session = configured
    controller.execute('edit interfaces dummy dum0', session)
    controller.execute('delete address', session)

    assert controller.execute('show candidate-configuration | commands', session)['text'] == 'delete address\n'


@pytest.mark.parametrize('comparison', ['saved', '1'])
def test_saved_and_historical_comparisons_respect_edit_context(configured, comparison):
    controller, engine, session = configured
    engine.save(session)
    controller.execute('set interfaces dummy dum0 description "New description"', session)
    controller.execute('set system host-name unrelated', session)
    engine.commit(session)
    controller.execute('edit interfaces dummy dum0', session)

    assert controller.execute(f'compare {comparison} | commands', session)['text'] == "set description 'New description'\n"
    assert 'unrelated' not in controller.execute(f'compare {comparison}', session)['text']
    assert controller.execute('compare 0 | commands', session)['text'] == ''
