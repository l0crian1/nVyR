"""Commit annotations remain durable metadata and history uses retained offsets."""

from copy import deepcopy
import json

import pytest
from tabulate import tabulate

from nvyr.config_session import ConfigurationSession
from nvyr.engine import Engine
from nvyr.errors import ConfirmationRequired, RouterError
from nvyr.helpers.config_feedback import commit_history
from nvyr.protocol import Client
from tests.lifecycle import recorded_registry
from tests.test_integration import daemon
from tests.test_login import as_role


def latest(engine):
    return engine.store.read(f'history/{engine.commit_id:020d}.json')


def test_comment_is_metadata_and_survives_restart(controller, engine, session):
    controller.execute('set system host-name router', session)
    controller.execute('commit comment "WAN | firewall café"', session)
    record = deepcopy(latest(engine))
    assert record['comment'] == 'WAN | firewall café'
    assert record['user'] == session.user and record['reason'] == 'commit'
    assert record['configuration'] == engine.running == {'system': {'host-name': 'router'}}
    engine.save(session)
    assert engine.store.read('boot.json') == engine.running
    assert 'WAN | firewall' not in json.dumps(engine.store.read('state.json'))

    controller.execute('commit comment "No changes"', session)
    assert latest(engine) == record
    restarted = Engine(engine.schema, recorded_registry(engine.schema), engine.store)
    assert latest(restarted) == record


def test_confirm_keeps_comment_and_timeout_has_separate_revision(controller, engine, session):
    engine.clock = lambda: 100
    controller.execute('set interfaces dummy dum0', session)
    line = 'commit-confirm .5 comment "Testing WAN routing"'
    with pytest.raises(ConfirmationRequired) as error:
        controller.execute(line, session)
    assert engine.commit_id == 0 and latest(engine)['comment'] is None
    controller.execute(line, session, confirmation=error.value.details)
    record = deepcopy(latest(engine))
    assert record['comment'] == 'Testing WAN routing' and record['reason'] == 'commit-confirm'
    controller.execute('confirm', session)
    assert latest(engine) == record

    controller.execute('set interfaces dummy dum1', session)
    controller.execute('commit-confirm .5 comment "Temporary interface"', session,
                       confirmation={'confirm_minutes': .5})
    annotated = engine.commit_id
    engine.clock = lambda: 131
    engine.tick()
    assert engine.commit_id == annotated + 1 and latest(engine)['comment'] is None
    assert engine.store.read(f'history/{annotated:020d}.json')['comment'] == 'Temporary interface'


def test_failed_and_partial_commits_attach_comments_only_to_published_revisions(controller, engine, session, monkeypatch):
    def fail(*args):
        raise RouterError('Cannot apply hostname')

    monkeypatch.setattr(engine.modules['system'].implementation, 'apply', fail)
    controller.execute('set system host-name router', session)
    before = deepcopy(latest(engine))
    controller.execute('commit comment "Failed change"', session)
    assert latest(engine) == before

    controller.execute('set interfaces dummy dum0', session)
    controller.execute('commit comment "Partial change"', session)
    assert latest(engine)['comment'] == 'Partial change'
    assert engine.running == {'interfaces': {'dummy': {'dum0': {}}}}
    assert engine.view(session)['system']['host-name'] == 'router'


def test_history_default_table_offsets_retention_and_nested_edit(controller, engine, session, monkeypatch):
    from nvyr.helpers import config_feedback

    controller.execute('set system configuration commit-revisions 2', session)
    controller.execute('commit comment "Retain two"', session)
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('commit', session)
    controller.execute('set interfaces dummy dum1', session)
    controller.execute('commit comment "00123"', session)
    controller.execute('edit interfaces dummy dum1', session)
    records = list(engine.store.history_metadata(engine.commit_id))
    assert [r['id'] for r in records] == [3, 2]
    calls = []

    def render(*args, **kwargs):
        calls.append(kwargs)
        return tabulate(*args, **kwargs)

    monkeypatch.setattr(config_feedback, 'tabulate', render)
    text = controller.execute('show commit-history', session)['text']
    assert text == commit_history(engine.commit_id, records)
    assert all('tablefmt' not in call for call in calls)
    assert text.splitlines()[0].split() == ['Revision', 'Commit', 'Date', 'User', 'Comment']
    assert [line.split()[:2] for line in text.splitlines()[2:]] == [['0', '3'], ['1', '2']]
    assert 'UTC' in text and '00123' in text and 'Retain two' not in text
    assert engine.store.historical(engine.commit_id, 1) == records_config(engine, 2)
    assert controller.execute('show commit-history | match 00123', session)['text'].endswith('00123\n')
    assert controller.execute('show commit-history | no-more', session)['paging'] is False


def records_config(engine, commit_id):
    return engine.store.read(f'history/{commit_id:020d}.json')['configuration']


def test_history_offsets_do_not_renumber_gaps():
    records = [{'id': 9, 'timestamp': 0, 'user': '001', 'comment': 'latest'},
               {'id': 6, 'timestamp': 60, 'user': 'configd', 'comment': None}]
    lines = commit_history(9, records).splitlines()
    assert [line.split()[:2] for line in lines[2:]] == [['0', '9'], ['3', '6']]
    assert '1970-01-01 00:00:00 UTC' in lines[2] and '001' in lines[2]


@pytest.mark.parametrize('line', ['commit comment', 'commit comment ""', 'commit comment unquoted words',
                                'commit-confirm 1 comment', 'commit-confirm 1 "bare comment"',
                                'commit-confirm nope comment "bad time"',
                                'commit-confirm 0 comment "bad time"',
                                'commit comment "bad\tcomment"', 'commit check comment "not a revision"'])
def test_invalid_comment_commands_do_not_commit(controller, engine, session, line):
    controller.execute('set interfaces dummy dum0', session)
    mutations = tuple(session.mutations)
    with pytest.raises(RouterError):
        controller.execute(line, session)
    assert engine.running == {} and engine.commit_id == 0
    assert tuple(session.mutations) == mutations


@pytest.mark.parametrize('comment', ['', 'bad\nline', 'bad\x1btext', 12, [], {}])
def test_programmatic_comment_validation(engine, session, comment):
    with pytest.raises(RouterError, match='Commit comment'):
        engine.commit(session, comment=comment)
    assert engine.commit_id == 0


def test_history_and_comment_completion_and_permissions(controller, engine, session):
    assert controller.completion('commit com', session, tab=True)['replacement'] == 'comment'
    assert controller.completion('commit comment ', session, explicit=True)['hints']
    assert 'comment' in dict(controller.completion('commit-confirm 1 ', session, explicit=True)['candidates'])
    assert '<Enter>' in dict(controller.completion('commit-confirm 1 ', session, explicit=True)['candidates'])
    assert controller.completion('show commit-h', session, tab=True)['replacement'] == 'commit-history'
    assert '<Enter>' in dict(controller.completion('show commit-history ', session, explicit=True)['candidates'])
    with pytest.raises(RouterError):
        controller.execute('show commit-history')
    with pytest.raises(RouterError, match='takes no arguments'):
        controller.execute('show commit-history all', session)

    with as_role('read-only'):
        for command in ('commit comment "Denied"', 'show commit-history'):
            with pytest.raises(RouterError, match='Permission denied'):
                controller.execute(command, session)
    with as_role('net-admin'):
        assert 'Revision' in controller.execute('show commit-history', session)['text']


def test_library_commit_comment_and_history_rpc(daemon):
    with ConfigurationSession(socket_path=daemon) as config:
        config.set('set interfaces dummy dum0')
        config.commit(comment='Automation change')
        config.set('set interfaces dummy dum1')
        config.commit(n=30, comment='Automation confirmation')
        config.confirm()

    client = Client(daemon)
    try:
        client.request('open')
        text = client.request('execute', text='show commit-history')['text']
        assert 'Automation change' in text and 'Automation confirmation' in text
    finally:
        client.close()
