"""Configuration session discovery identifies the caller, not just its username."""

import json

import pytest

from nvyr.errors import RouterError, SessionExpiredError
from nvyr.helpers import access
from nvyr.protocol import Client
from tests.test_integration import daemon


@pytest.mark.parametrize('nested', [False, True])
def test_listing_marks_current_session_and_preserves_lock_and_draft(controller, engine, session, nested):
    other = engine.open(session.user, 'another terminal', draft=True)
    if nested:
        controller.execute('edit interfaces dummy dum0', session)

    for caller in (session, other):
        result = json.loads(controller.execute('show config-sessions', caller)['text'])
        rows = {row['session']: row for row in result['sessions']}

        assert result['lock'] == session.id
        assert rows[session.id] == session.identity() | {'draft': False, 'current': caller is session}
        assert rows[other.id] == other.identity() | {'draft': True, 'current': caller is other}

    assert 'config-sessions' in dict(controller.completion('show ', session, explicit=True)['candidates'])
    assert controller.completion('show config-se', session)['replacement'] == 'config-sessions'
    assert dict(controller.completion('show config-sessions ', session, explicit=True)['candidates']) == {
        '<Enter>': 'Execute the current command'}
    assert controller.execute('show config-se', session)['text'] == controller.execute('show config-sessions', session)['text']


def test_session_listing_is_configuration_only_and_takes_no_scope(controller, session):
    assert 'sessions' not in dict(controller.completion('show ', explicit=True)['candidates'])
    assert 'config-sessions' not in dict(controller.completion('show ', explicit=True)['candidates'])

    for line, caller in [('show sessions', None), ('show config-sessions', None),
                         ('show sessions', session), ('run show sessions', session),
                         ('run show config-sessions', session),
                         ('show config-sessions interfaces', session),
                         ('show config-sessions | commands', session),
                         ('show config-sessions | strip-private', session)]:
        with pytest.raises(RouterError):
            controller.execute(line, caller)

    assert controller.execute('show config-sessions | count', session)['text'].strip().isdigit()


def test_expired_session_cannot_list_configuration_sessions(controller, engine, session):
    engine.close(session, expired=True)

    with pytest.raises(SessionExpiredError):
        controller.execute('show config-sessions', session)


@pytest.mark.parametrize('role', ['sys-admin', 'net-admin', 'read-only'])
def test_listing_enforces_configuration_roles(controller, session, role):
    token = access.role.set(role)
    try:
        if role == 'read-only':
            with pytest.raises(RouterError, match='Permission denied'):
                controller.execute('show config-sessions', session)
        else:
            assert json.loads(controller.execute('show config-sessions', session)['text'])['sessions'][0]['current']
    finally:
        access.role.reset(token)


def test_real_connections_identify_their_own_session_with_a_shared_account(daemon):
    first, second = Client(daemon), Client(daemon)
    try:
        identities = [client.request('open') for client in (first, second)]
        for client, identity in zip((first, second), identities):
            result = json.loads(client.request('execute', text='show config-sessions')['text'])
            assert [row['session'] for row in result['sessions'] if row['current']] == [identity['session']]
            assert result['lock'] == identities[0]['session']
    finally:
        first.close()
        second.close()
