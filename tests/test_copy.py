"""Copy tag instances using candidate state, edit paths and ordinary commit rules."""

from copy import deepcopy
import json
import signal
from types import SimpleNamespace

import pytest

from nvyr.cli import CLI
from nvyr.errors import RouterError
from nvyr.protocol import Client
from nvyr.tree import lookup
from tests.test_integration import daemon
from tests.test_login import as_role, add_user


RULES = 'firewall ipv4 forward filter rule'


def test_copy_rule_uses_candidate_and_stays_pending(controller, engine, session):
    controller.execute(f'set {RULES} 10 action accept protocol tcp destination-port 22', session)
    engine.commit(session)
    before, revision = deepcopy(engine.running), engine.commit_id
    controller.execute(f'set {RULES} 10 description "WAN rule" destination-port 443', session)
    controller.execute(f'set {RULES} 10 source-address 192.0.2.1 mask 255.255.255.255', session)
    controller.execute(f'copy {RULES} 10 to {RULES} 20', session)
    rules = lookup(engine.view(session), tuple(RULES.split()))
    assert rules['20'] == rules['10']
    assert rules['20']['destination-port'] == ['22', '443']
    assert rules['20']['source-address'] == {'192.0.2.1': {'mask': '255.255.255.255'}}
    assert engine.running == before and engine.commit_id == revision

    controller.execute(f'delete {RULES} 20 destination-port 22', session)
    controller.execute(f'set {RULES} 20 action drop', session)
    rules = lookup(engine.view(session), tuple(RULES.split()))
    assert rules['10']['destination-port'] == ['22', '443'] and rules['10']['action'] == 'accept'
    assert rules['20']['destination-port'] == ['443'] and rules['20']['action'] == 'drop'
    engine.commit(session)
    assert lookup(engine.running, tuple(RULES.split())) == rules


def test_copy_edit_context_empty_instances_and_implicit_defaults(controller, engine, session):
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('edit interfaces', session)
    controller.execute('cop dum dum0 to dum dum1', session)
    assert engine.view(session)['interfaces']['dummy'] == {'dum0': {}, 'dum1': {}}
    controller.execute('set dummy dum0 description changed', session)
    assert engine.view(session)['interfaces']['dummy']['dum1'] == {}

    controller.execute('top', session)
    controller.execute(f'set {RULES} 10 action accept', session)
    controller.execute('edit firewall ipv4', session)
    controller.execute('edit forward filter', session)
    controller.execute('copy rule 10 to rule 20', session)
    assert lookup(engine.view(session), tuple((RULES + ' 20').split())) == {'action': 'accept'}


@pytest.mark.parametrize('command', [
    f'copy {RULES} 10 to {RULES} 10',
    f'copy {RULES} 10 to {RULES} 20',
    f'copy {RULES} 999 to {RULES} 30',
    f'copy {RULES} 10 to {RULES} invalid',
    f'copy {RULES} 10 to interfaces dummy dum1',
    f'copy {RULES} 10 to firewall ipv6 forward filter rule 30',
    f'copy {RULES} 10 action to {RULES} 30 action',
    'copy firewall ipv4 to firewall ipv6',
    f'copy {RULES} 10 to 30',
    f'copy {RULES} 10',
    f'copy {RULES} 10 to {RULES} 30 | commands',
])
def test_invalid_copy_leaves_candidate_unchanged(controller, engine, session, command):
    controller.execute(f'set {RULES} 10 action accept', session)
    controller.execute(f'set {RULES} 20', session)
    before, mutations = deepcopy(engine.view(session)), tuple(session.mutations)
    with pytest.raises(RouterError):
        controller.execute(command, session)
    assert engine.view(session) == before and tuple(session.mutations) == mutations


def test_copy_deleted_source_and_destination(controller, engine, session):
    controller.execute('set interfaces dummy dum0 description source', session)
    controller.execute('set interfaces dummy dum1 description previous', session)
    engine.commit(session)
    controller.execute('delete interfaces dummy dum1', session)
    controller.execute('copy interfaces dummy dum0 to interfaces dummy dum1', session)
    assert engine.view(session)['interfaces']['dummy']['dum1'] == {'description': 'source'}
    controller.execute('delete interfaces dummy dum0', session)
    with pytest.raises(RouterError, match='not configured'):
        controller.execute('copy interfaces dummy dum0 to interfaces dummy dum2', session)


def test_copy_preserves_references_and_dependency_checks(controller, engine, session):
    controller.execute('set interfaces dummy dum0', session)
    controller.execute(f'set {RULES} 10 action accept inbound-interface dum0', session)
    controller.execute(f'copy {RULES} 10 to {RULES} 20', session)
    controller.execute('copy interfaces dummy dum0 to interfaces dummy dum1', session)
    controller.execute(f'delete {RULES} 10', session)
    with pytest.raises(RouterError, match='dum0'):
        controller.execute('delete interfaces dummy dum0', session)
    controller.execute('delete interfaces dummy dum1', session)
    assert lookup(engine.view(session), tuple((RULES + ' 20 inbound-interface').split())) == ['dum0']


def test_copy_permissions_and_login_hash_storage(controller, engine, session):
    add_user(controller, session)
    before = deepcopy(engine.view(session))
    with as_role('read-only'):
        with pytest.raises(RouterError, match='Permission denied'):
            controller.execute('copy system login user admin to system login user second', session)
    with as_role('net-admin'):
        with pytest.raises(RouterError, match='Permission denied'):
            controller.execute('copy system login user admin to system login user second', session)
    assert engine.view(session) == before

    controller.execute('copy system login user admin to system login user second', session)
    users = engine.view(session)['system']['login']['user']
    assert users['admin'] == users['second']
    assert 'plaintext-password' not in json.dumps(users)
    assert 'a secret with spaces' not in json.dumps(users)

    with as_role('net-admin'):
        controller.execute('set interfaces dummy dum0', session)
        controller.execute('copy interfaces dummy dum0 to interfaces dummy dum1', session)


def test_copy_completion_and_literal_to_tag(controller, engine, session):
    controller.execute('set firewall ipv4 name to rule 10 action accept', session)
    controller.execute('copy firewall ipv4 name "to" to firewall ipv4 name NEW', session)
    assert set(engine.view(session)['firewall']['ipv4']['name']) == {'to', 'NEW'}
    controller.execute('edit firewall ipv4 name NEW', session)
    assert controller.completion('cop', session, tab=True)['replacement'] == 'copy'
    assert '10' in dict(controller.completion('copy rule ', session, explicit=True)['candidates'])
    assert 'to' in dict(controller.completion('copy rule 10 ', session, explicit=True)['candidates'])
    assert '<Enter>' not in dict(controller.completion('copy rule 10 ', session, explicit=True)['candidates'])
    assert controller.completion('copy rule 10 to ru', session, tab=True)['replacement'] == 'rule'
    assert '<Enter>' in dict(controller.completion('copy rule 10 to rule 20 ', session, explicit=True)['candidates'])


def test_copy_uses_normal_rpc_and_discard(daemon):
    client = Client(daemon)
    try:
        client.request('open')
        for command in ('set interfaces dummy dum0', 'edit interfaces', 'copy dummy dum0 to dummy dum1'):
            client.request('execute', text=command)
        assert client.request('get_config', source='candidate')['configuration']['interfaces']['dummy'] == {'dum0': {}, 'dum1': {}}
        client.request('execute', text='discard')
        assert 'interfaces' not in client.request('get_config', source='candidate')['configuration']
    finally:
        client.close()


def test_copy_insertion_interrupt_finishes_request():
    messages = []
    previous = signal.getsignal(signal.SIGINT)

    def request(*args, **kwargs):
        signal.raise_signal(signal.SIGINT)
        return {}

    cli = CLI(SimpleNamespace(request=request), emit=messages.append)
    cli.mode = 'normal'
    cli.submit('copy rule 10 to rule 20')
    assert any('Command insertion interrupted' in message for message in messages)
    assert signal.getsignal(signal.SIGINT) is previous


def test_copy_only_reads_source_and_destination_branches(controller, engine, session, monkeypatch):
    controller.execute('set interfaces dummy dum0 description original', session)

    def no_full_view(*args):
        pytest.fail('Copy should not materialize the entire candidate')

    with monkeypatch.context() as patch:
        patch.setattr(engine, 'view', no_full_view)
        controller.execute('copy interfaces dummy dum0 to interfaces dummy dum1', session)

    assert engine.view(session)['interfaces']['dummy']['dum1'] == {'description': 'original'}
