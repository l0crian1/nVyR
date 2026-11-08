"""Shared firewall/NAT failure boundaries preserve recovery and error identity."""

import threading

import pytest

from nvyr.errors import RecoveryError, RouterError, ValidationError, recovery_required
from nvyr.helpers import nftables, task_schedule
from tests.lifecycle import RuntimeEngine


@pytest.mark.parametrize('error', [OSError('disk full'), RouterError('service failed')])
def test_publication_failure_keeps_its_cause(error):
    with pytest.raises(RecoveryError, match='already applied') as failure:
        with recovery_required('already applied'):
            raise error

    assert failure.value.__cause__ is error
    assert str(error) in str(failure.value)


@pytest.mark.parametrize('error', [RecoveryError('uncertain outcome'), KeyError('programming defect')])
def test_publication_boundary_preserves_recovery_and_unexpected_errors(error):
    with pytest.raises(type(error)) as failure:
        with recovery_required('publication failed'):
            raise error

    assert failure.value is error


@pytest.mark.parametrize('error', [RecoveryError('uncertain outcome'), ValidationError('rejected'), KeyError('defect')])
def test_runtime_recovery_is_recorded_before_unlock(error):
    states_at_unlock = []
    lock = threading.RLock()

    class ObservedLock:
        def __enter__(self):
            lock.acquire()

        def __exit__(self, *args):
            states_at_unlock.append(engine.unhealthy)
            lock.release()

    engine = RuntimeEngine(mutex=ObservedLock(), unhealthy=False)
    with pytest.raises(type(error)) as failure:
        with engine.runtime_apply():
            raise error

    assert failure.value is error
    assert states_at_unlock == [isinstance(error, RecoveryError)]
    assert lock.acquire(blocking=False)
    lock.release()


@pytest.mark.parametrize('root', ['nat', 'nat66'])
@pytest.mark.parametrize('failed_stage', ['native', 'schedule'])
def test_nat_commit_distinguishes_rejection_from_post_apply_failure(
        root, failed_stage, engine, controller, session, monkeypatch):
    controller.execute(f'set {root} source rule 10 outbound-interface eth0 translation address masquerade', session)
    loaded = []

    def native_apply(text, *args, **kwargs):
        if failed_stage == 'native':
            raise ValidationError('native rejection')
        loaded.append(text)

    def schedule_apply(*args, **kwargs):
        raise RouterError('schedule installation failed')

    monkeypatch.setattr(nftables.manager, 'apply', native_apply)
    monkeypatch.setattr(task_schedule, 'reconcile', schedule_apply)

    if failed_stage == 'native':
        result = engine.commit(session)
        assert not result['results']['firewall']['success']
        assert not engine.unhealthy
        assert not engine.store.path('transaction.json').exists()
        assert not loaded
    else:
        with pytest.raises(RecoveryError, match='list schedules could not be installed'):
            engine.commit(session)
        assert engine.unhealthy
        assert engine.store.path('transaction.json').exists()
        assert len(loaded) == 1
        assert 'masquerade' in loaded[0]

    assert root not in engine.running
