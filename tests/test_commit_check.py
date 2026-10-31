"""Check-only commits reuse verification without changing intent or host state."""

from copy import deepcopy
import threading

import pytest

from nvyr.errors import BusyError, LockError, RouterError, SessionExpiredError
from nvyr.helpers import access
from nvyr.tree import lookup
from tests.test_integration import daemon
from nvyr.protocol import Client


def persisted(engine):
    return {str(path.relative_to(engine.store.directory)): path.read_bytes()
            for path in engine.store.directory.rglob('*') if path.is_file()}


def test_check_only_gets_and_verifies_changed_owners_with_defaults(controller, engine, session, monkeypatch):
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('set firewall ipv4 input filter rule 10 action accept', session)
    controller.execute('edit interfaces', session)
    before, files = deepcopy(engine.view(session)), persisted(engine)
    identities = (engine.commit_id, session.commit_id, engine.lock_owner, session.edit)
    calls = []

    for owner, module in engine.modules.items():
        module.calls.clear()

        def verify(configuration, context, owner=owner):
            assert context.check_only and not context.recovery
            assert lookup(context.effective, ('interfaces', 'dummy', 'dum0', 'mtu')) == '1500'
            assert 'mtu' not in engine.view(session)['interfaces']['dummy']['dum0']
            calls.append(owner)

        monkeypatch.setattr(module, 'verify', verify)

    result = controller.execute('commit check', session)

    assert result['text'] == 'Configuration check passed.\n'
    assert calls == ['dummy', 'firewall']
    assert engine.running == {} and engine.view(session) == before
    assert persisted(engine) == files
    assert identities == (engine.commit_id, session.commit_id, engine.lock_owner, session.edit)
    assert not engine.busy and not engine.unhealthy and engine.pending is None
    for owner, module in engine.modules.items():
        assert [stage for _, stage, _ in module.calls] == (['get_config'] if owner in calls else [])


def test_verification_errors_are_reported_across_owners_without_applying(controller, engine, session):
    controller.execute('set firewall ipv4 input filter rule 10 description invalid', session)
    controller.execute('set protocols static route 192.0.2.0/24', session)
    before, files = deepcopy(engine.view(session)), persisted(engine)

    result = controller.execute('commit check', session)['text']

    assert 'action is required' in result and 'at least one enabled next-hop' in result
    assert 'Configuration check failed' in result
    assert engine.view(session) == before and engine.running == {}
    assert persisted(engine) == files and not engine.unhealthy


def test_check_reports_unexpected_failures_without_poisoning_engine(controller, engine, session, monkeypatch, caplog):
    controller.execute('set system host-name router', session)

    def fail(configuration, context):
        raise RuntimeError('diagnostic detail')

    monkeypatch.setattr(engine.modules['system'], 'verify', fail)
    output = controller.execute('commit check', session)['text']

    assert 'Unable to verify' in output and 'diagnostic detail' not in output
    assert 'diagnostic detail' in caplog.text
    assert not engine.busy and not engine.unhealthy and session.mutations


def test_deleted_owners_are_checked_and_net_zero_changes_are_skipped(controller, engine, session, monkeypatch):
    controller.execute('set system host-name router', session)
    controller.execute('set service ssh', session)
    engine.commit(session)
    controller.execute('delete service ssh', session)
    controller.execute('set system host-name other', session)
    controller.execute('set system host-name router', session)
    calls = []

    def verify(configuration, context):
        assert configuration['current'] is None and context.check_only
        assert configuration['previous'] is not None
        assert ('service', 'ssh') in context.get_deleted()
        calls.append(context.owner)

    monkeypatch.setattr(engine.modules['ssh'], 'verify', verify)
    monkeypatch.setattr(engine.modules['system'], 'verify', lambda *args: pytest.fail('unchanged owner checked'))

    assert engine.check(session)['results'] == {'ssh': {'success': True}}
    assert calls == ['ssh'] and 'ssh' in engine.running['service']


def test_check_retains_physical_interface_existence_validation(controller, engine, session, monkeypatch):
    from nvyr.helpers import interfaces

    controller.execute('set interfaces ethernet eth999 disable', session)
    monkeypatch.setattr(interfaces, 'require_named', lambda name: None)
    monkeypatch.setattr(interfaces, 'exists', lambda name: False)

    assert 'interface does not exist' in controller.execute('commit check', session)['text']


def test_empty_candidate_noops_and_check_does_not_take_lock(controller, engine, session):
    assert controller.execute('commit check', session)['text'] == 'No configuration changes to check.\n'
    for draft in (False, True):
        other = engine.open('bob', 'pts/2', draft=draft)
        controller.execute('set system host-name router', other)
        assert 'check passed' in controller.execute('commit check', other)['text']
        assert engine.lock_owner == session.id


def test_check_does_not_acknowledge_stale_candidate(controller, engine, session):
    other = engine.open('bob', 'pts/2')
    controller.execute('set system host-name first', session)
    engine.commit(session)
    controller.execute('set system host-name second', other)
    observed = other.commit_id

    assert 'check passed' in controller.execute('commit check', other)['text']
    assert other.commit_id == observed < engine.commit_id


def test_check_rejects_expired_busy_and_pending_sessions(controller, engine, session):
    engine.busy = True
    with pytest.raises(BusyError):
        engine.check(session)
    engine.busy = False

    controller.execute('set system host-name router', session)
    engine.commit(session, minutes=5, confirmed_minutes=5)
    pending = deepcopy(engine.pending)
    with pytest.raises(LockError, match='rollback'):
        engine.check(session)
    assert engine.pending == pending

    engine.close(session, expired=True)
    with pytest.raises(SessionExpiredError):
        engine.check(session)


def test_check_uses_configuration_and_account_permissions(controller, engine, session):
    controller.execute('set system host-name router', session)
    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError, match='Permission denied'):
            engine.check(session)
    finally:
        access.role.reset(token)

    controller.execute('set system login user admin role sys-admin', session)
    token = access.role.set('net-admin')
    try:
        with pytest.raises(RouterError, match='manage login accounts'):
            engine.check(session)
    finally:
        access.role.reset(token)


def test_check_excludes_concurrent_mutation_and_apply(controller, engine, session, monkeypatch):
    controller.execute('set system host-name router', session)
    entered, release = threading.Event(), threading.Event()
    outcomes = []

    def verify(configuration, context):
        entered.set()
        assert release.wait(5)

    monkeypatch.setattr(engine.modules['system'], 'verify', verify)
    worker = threading.Thread(target=lambda: outcomes.append(engine.check(session)))
    worker.start()
    try:
        assert entered.wait(5)
        with pytest.raises(BusyError):
            controller.execute('set system host-name another', session)
        with pytest.raises(BusyError):
            engine.commit(session)
    finally:
        release.set()
        worker.join(5)

    assert outcomes[0]['results']['system']['success'] and not engine.busy


def test_host_address_checks_are_deferred_but_regular_commit_still_checks(controller, engine, session, monkeypatch):
    from nvyr.helpers import interfaces

    controller.execute('set service ssh listen-address 192.0.2.1', session)
    controller.execute('set protocols static route 198.51.100.0/24 next-hop 192.0.2.2', session)

    def forbidden(*args, **kwargs):
        pytest.fail('check-only queried unapplied host addresses')

    monkeypatch.setattr(interfaces, 'local_addresses', forbidden)
    text = controller.execute('commit check', session)['text']
    assert 'check passed' in text and 'SSH: skipped' in text and 'Static routing: skipped' in text

    monkeypatch.setattr(interfaces, 'local_addresses', lambda **kwargs: set())
    result = engine.commit(session)
    assert not result['results']['ssh']['success']
    assert 'not assigned' in result['results']['ssh']['error']
    assert result['results']['static']['success']


def test_check_only_is_false_during_normal_commit_and_recovery(controller, engine, session, monkeypatch):
    contexts = []
    monkeypatch.setattr(engine.modules['system'], 'verify', lambda configuration, context: contexts.append(context))
    controller.execute('set system host-name router', session)
    engine.commit(session)
    engine._run_recovery(engine.running, engine.running, {'system'})

    assert [context.check_only for context in contexts] == [False, False]
    assert [context.recovery for context in contexts] == [False, True]


def test_check_rpc_completion_and_failure_leave_candidate_intact(daemon):
    client = Client(daemon)
    try:
        client.request('open')
        completion = client.request('complete', text='commit ', explicit=True)
        assert {'check', '<Enter>'} <= dict(completion['candidates']).keys()
        client.request('execute', text='set firewall ipv4 input filter rule 10 description invalid')
        before = client.request('get_config', source='candidate')

        output = client.request('execute', text='commit ch')['text']
        assert 'action is required' in output and 'check failed' in output
        assert client.request('get_config', source='candidate') == before
        assert client.request('get_config', source='running')['configuration'] == {}

        client.request('execute', text='set firewall ipv4 input filter rule 10 action accept')
        assert 'check passed' in client.request('execute', text='commit check')['text']
        assert 'firewall: done' in client.request('execute', text='commit')['text']
    finally:
        client.close()
