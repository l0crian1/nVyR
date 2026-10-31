"""Duplicate notices refer to individual operations and leave new intents intact."""

import pytest

from nvyr.errors import RouterError
from nvyr.lexer import lex


PREFIX = 'set interfaces dummy dum0 '


@pytest.mark.parametrize('setting', ['description "WAN Interface"', 'address 192.0.2.1/24', 'disable', ''])
@pytest.mark.parametrize('committed', [False, True])
def test_duplicate_scalar_multi_flag_and_container(controller, engine, session, setting, committed):
    line = (PREFIX + setting).strip()

    assert controller.execute(line, session)['text'] == ''

    if committed:
        engine.commit(session)

    before = list(session.mutations)
    message = controller.execute(line, session)['text']

    assert message.startswith('Configuration already exists: set interfaces dummy dum0')
    assert [token.value for token in lex(message.split(': ', 1)[1])] == [token.value for token in lex(line)]
    assert session.mutations == before


def test_anchor_skips_duplicates_including_earlier_operations_in_same_line(controller, engine, session):
    controller.execute(PREFIX + 'description first', session)
    result = controller.execute(PREFIX + 'description first disable disable address 192.0.2.1/24 '
                                'address 192.0.2.1/24 mtu 1400', session)

    assert result['text'].splitlines() == [
        'Configuration already exists: ' + PREFIX + 'description first',
        'Configuration already exists: ' + PREFIX + 'disable',
        'Configuration already exists: ' + PREFIX + 'address 192.0.2.1/24',
    ]
    assert engine.view(session)['interfaces']['dummy']['dum0'] == {
        'description': 'first', 'disable': True, 'address': ['192.0.2.1/24'], 'mtu': '1400'}
    assert len(session.mutations) == 4


def test_relative_abbreviated_command_reports_full_path_and_quotes(controller, session):
    controller.execute(PREFIX + 'description "WAN | interface"', session)
    controller.execute('edit interfaces dummy dum0', session)

    assert controller.execute('se desc "WAN | interface" mtu 1400', session)['text'] == (
        "Configuration already exists: set interfaces dummy dum0 description 'WAN | interface'\n")


def test_invalid_anchor_suffix_remains_atomic(controller, engine, session):
    controller.execute(PREFIX + 'description first', session)
    before = list(session.mutations)

    with pytest.raises(RouterError):
        controller.execute(PREFIX + 'description first disable mtu invalid', session)

    assert session.mutations == before


@pytest.mark.parametrize('deletion', ['interfaces', 'interfaces dummy dum0', 'interfaces dummy dum0 description'])
def test_pending_delete_makes_running_value_new_again(controller, engine, session, deletion):
    controller.execute(PREFIX + 'description first', session)
    engine.commit(session)
    controller.execute('delete ' + deletion, session)

    assert controller.execute(PREFIX + 'description first', session)['text'] == ''
    assert engine.view(session)['interfaces']['dummy']['dum0']['description'] == 'first'


def test_defaults_do_not_count_as_explicit_settings(controller, engine, session):
    controller.execute(PREFIX.strip(), session)

    assert controller.execute(PREFIX + 'mtu 1500', session)['text'] == ''
    assert controller.execute(PREFIX + 'mtu 1500', session)['text'].startswith('Configuration already exists:')
    assert engine.view(session)['interfaces']['dummy']['dum0']['mtu'] == '1500'


def test_multi_subtraction_and_changed_scalar_override_running(controller, engine, session):
    controller.execute(PREFIX + 'address 192.0.2.1/24 description first', session)
    engine.commit(session)
    controller.execute('delete interfaces dummy dum0 address 192.0.2.1/24', session)

    assert controller.execute(PREFIX + 'address 192.0.2.1/24', session)['text'] == ''

    controller.execute(PREFIX + 'description second', session)

    assert controller.execute(PREFIX + 'description first', session)['text'] == ''


def test_load_notices_identify_individual_duplicates_and_continue(controller, engine, session):
    notices = controller.load(session, PREFIX + 'disable\n' + PREFIX + 'disable description new', set_format=True)

    assert len(notices) == 1 and notices[0]['line'] == 2
    assert notices[0]['message'] == 'Configuration already exists: ' + PREFIX + 'disable'
    assert engine.view(session)['interfaces']['dummy']['dum0'] == {'disable': True, 'description': 'new'}


def test_replacement_load_retains_values_that_match_running(controller, engine, session):
    controller.execute(PREFIX + 'description same disable', session)
    engine.commit(session)

    assert not controller.load(session, PREFIX + 'description same', set_format=True, replace=True)
    assert engine.view(session) == {'interfaces': {'dummy': {'dum0': {'description': 'same'}}}}


def test_duplicate_encrypted_password_is_redacted(controller, engine, session):
    from nvyr.helpers.passwords import hash_password

    password = hash_password('test password')
    line = 'set system login user test authentication encrypted-password ' + password
    controller.execute(line, session)
    result = controller.execute(line, session)['text']

    assert 'Configuration already exists:' in result and '<redacted>' in result
    assert password not in result
