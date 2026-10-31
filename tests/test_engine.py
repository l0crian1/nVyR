import json
import threading
import pytest
from nvyr.engine import Engine
from nvyr.errors import BusyError, ConfirmationRequired, LockError, RouterError, ValidationError
from nvyr.lexer import lex
from tests.lifecycle import recorded_registry
from nvyr.tree import lookup, MISSING


def set_(engine, session, path):
    engine.mutate(session, "set", lex(path))


def test_independent_candidates_rebase_as_intents(engine, session):
    second = engine.open("bob", "pts/2")
    set_(engine, second, "interfaces dummy dum1 description second")
    set_(engine, session, "interfaces dummy dum0 description first")
    engine.commit(session)

    assert len(second.mutations) == 1
    assert set(engine.view(second)["interfaces"]["dummy"]) == {"dum0", "dum1"}

    engine.request_lock(second, session.id)

    with pytest.raises(ConfirmationRequired):
        engine.commit(second)

    result = engine.commit(second, expected_id=engine.commit_id)

    assert result["commit_id"] == 2
    assert second.commit_id == 2


@pytest.mark.parametrize("stage", ["get_config", "verify", "generate", "apply"])
def test_partial_commit_retains_entire_failed_unit_and_continues(engine, session, stage, monkeypatch):
    original = getattr(engine.modules['firewall'], stage)

    def fail(*args):
        if not args[-1].recovery:
            raise ValidationError(f'Injected {stage} failure')

        return original(*args)

    monkeypatch.setattr(engine.modules['firewall'], stage, fail)
    set_(engine, session, "interfaces dummy dum0 description works")
    set_(engine, session, "firewall ipv4 forward filter rule 10 action accept")
    set_(engine, session, "firewall description pending")
    set_(engine, session, "system host-name router")
    result = engine.commit(session)

    assert result["commit_id"] == 1
    assert result["results"]["system"]["success"]
    assert not result["results"]["firewall"]["success"]
    assert result['results']['firewall']['error'] == f'Injected {stage} failure'
    assert {m.owner for m in session.mutations} == {"firewall"}
    assert len(session.mutations) == 2
    assert "firewall" not in engine.running
    assert session.commit_id == 1
    assert engine.commit(session)["commit_id"] == 1
    assert len(list((engine.store.directory / "history").glob("*.json"))) == 2
    assert len([call for call in engine.modules["dummy"].calls if call[1:] == ("apply", False)]) == 1


def test_delete_ancestor_preserves_owner_awareness(engine, session):
    set_(engine, session, "interfaces dummy dum0 description works")
    engine.commit(session)
    engine.mutate(session, "delete", ["interfaces"])

    assert engine.configuration_status(session)["changed"] == ["dummy"]
    assert "interfaces" not in engine.view(session)

    engine.commit(session)

    assert engine.running == {}


def test_duplicate_sets_do_not_pin_values_against_other_users_changes(engine, session):
    set_(engine, session, "system host-name first")
    engine.commit(session)
    second = engine.open("bob", "pts/2")

    assert engine.mutate(second, 'set', ['system', 'host-name', 'first']) == [
        'Configuration already exists: set system host-name first\n']
    assert not second.mutations

    set_(engine, session, "system host-name changed")
    engine.commit(session)

    assert engine.view(second)["system"]["host-name"] == "changed"


def test_draft_lock_takeover_and_disconnect(engine, session):
    draft = engine.open("reviewer", "pts/3", True)
    set_(engine, draft, "system host-name proposal")

    for action in (engine.commit, engine.save, engine.request_lock):
        with pytest.raises(LockError):
            action(draft)

    second = engine.open("bob", "pts/2")

    with pytest.raises(ConfirmationRequired) as error:
        engine.request_lock(second)

    assert error.value.details["vty"] == "".join(["/dev/", "pts/1"])

    engine.request_lock(second, session.id)

    assert draft.mutations

    engine.close(second)
    engine.request_lock(session)

    assert engine.lock_owner == session.id


def test_commit_blocks_lock_transfer_and_mutations(engine, session):
    entered, release = threading.Event(), threading.Event()
    original = engine.modules["system"].apply

    def slow(generated, context):
        entered.set()

        assert release.wait(5)

        original(generated, context)

    engine.modules["system"].apply = slow
    set_(engine, session, "system host-name test")
    worker = threading.Thread(target=engine.commit, args=(session,))
    worker.start()

    assert entered.wait(5)

    second = engine.open("bob", "pts/2")

    with pytest.raises(BusyError):
        engine.request_lock(second, session.id)

    with pytest.raises(BusyError):
        engine.discard(session)

    release.set()
    worker.join(5)

    assert not worker.is_alive()


def test_confirm_expiry_pins_lock_after_disconnect(engine, session):
    now = [100.0]
    engine.clock = lambda: now[0]
    set_(engine, session, "system host-name changed")
    engine.commit(session, minutes=1, confirmed_minutes=1)
    engine.close(session)
    second = engine.open("bob", "pts/2")

    with pytest.raises(LockError):
        engine.request_lock(second)

    now[0] = 161
    engine.tick()

    assert engine.running == {}
    assert engine.commit_id == 2
    assert engine.pending is None

    engine.request_lock(second)


def test_confirm_cancels_timer_and_save_excludes_defaults(engine, session):
    set_(engine, session, "firewall description explicit")
    engine.commit(session, minutes=1, confirmed_minutes=1)

    with pytest.raises(LockError):
        engine.save(session)

    engine.confirm(session)
    engine.save(session)

    assert engine.store.read("boot.json") == {"firewall": {"description": "explicit"}}


def test_confirm_after_reconnect_preserves_candidate_and_releases_dead_lock(engine, session, caplog):
    now = [100.0]
    engine.clock = lambda: now[0]
    set_(engine, session, 'system host-name confirmed')
    engine.commit(session, minutes=1, confirmed_minutes=1)
    engine.close(session)
    reconnected = engine.open(session.user, 'pts/2')
    set_(engine, reconnected, 'system host-name candidate')
    assert engine.pending['deadline'] == 160

    with pytest.raises(LockError):
        engine.request_lock(reconnected)
    with caplog.at_level('INFO', logger='nvyr.engine'):
        engine.confirm(reconnected)

    assert engine.pending is None
    assert engine.store.read('confirmed.json') is None
    assert engine.lock_owner is None
    assert engine.running['system']['host-name'] == 'confirmed'
    assert engine.view(reconnected)['system']['host-name'] == 'candidate'
    assert engine.commit_id == reconnected.commit_id == 1
    assert 'Commit 1 confirmed by alice on pts/2' in caplog.text
    now[0] = 161
    engine.tick()
    assert engine.running['system']['host-name'] == 'confirmed'
    engine.request_lock(reconnected)
    assert engine.lock_owner == reconnected.id


def test_another_authorized_user_can_confirm_without_taking_live_lock(engine, session):
    from nvyr.helpers import access

    set_(engine, session, 'system host-name confirmed')
    engine.commit(session, minutes=1, confirmed_minutes=1)
    other = engine.open('bob', 'pts/2')
    token = access.role.set('net-admin')
    try:
        engine.confirm(other)
    finally:
        access.role.reset(token)

    assert engine.pending is None
    assert engine.lock_owner == session.id
    with pytest.raises(LockError):
        engine.commit(other)


def test_confirmation_still_requires_configure_permission_and_normal_session(engine, session):
    from nvyr.helpers import access

    set_(engine, session, 'system host-name confirmed')
    engine.commit(session, minutes=1, confirmed_minutes=1)
    draft = engine.open('alice', 'pts/2', draft=True)
    with pytest.raises(LockError, match='Draft sessions cannot confirm'):
        engine.confirm(draft)

    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError, match='Permission denied'):
            engine.confirm(session)
    finally:
        access.role.reset(token)
    assert engine.pending is not None


def test_reconnected_confirmation_at_deadline_cannot_cancel_rollback(engine, session):
    now = [100.0]
    engine.clock = lambda: now[0]
    set_(engine, session, 'system host-name unconfirmed')
    engine.commit(session, minutes=1, confirmed_minutes=1)
    engine.close(session)
    other = engine.open('alice', 'pts/2')
    now[0] = 160

    with pytest.raises(LockError, match='timer has expired'):
        engine.confirm(other)
    assert engine.store.read('confirmed.json') is not None
    engine.tick()
    assert engine.pending is None
    assert engine.running == {}


def test_confirmation_cannot_interrupt_in_progress_rollback(engine, session, monkeypatch):
    now = [100.0]
    engine.clock = lambda: now[0]
    set_(engine, session, 'system host-name unconfirmed')
    engine.commit(session, minutes=1, confirmed_minutes=1)
    other = engine.open('bob', 'pts/2')
    started = threading.Event()
    release = threading.Event()
    restore = engine._restore

    def blocked_restore(*args, **kwargs):
        started.set()
        assert release.wait(5)
        return restore(*args, **kwargs)

    monkeypatch.setattr(engine, '_restore', blocked_restore)
    now[0] = 160
    worker = threading.Thread(target=engine.tick)
    worker.start()
    try:
        assert started.wait(5)
        with pytest.raises(BusyError, match='rollback is in progress'):
            engine.confirm(other)
        assert engine.pending is not None
    finally:
        release.set()
        worker.join(5)

    assert not worker.is_alive()
    assert engine.pending is None
    assert engine.running == {}


def test_save_only_considers_current_candidate(engine, session):
    draft = engine.open("bob", "pts/2", True)
    set_(engine, draft, "system host-name pending")
    engine.save(session)
    set_(engine, session, "system host-name mine")

    with pytest.raises(RouterError):
        engine.save(session)

    engine.discard(session)

    assert draft.mutations


def test_rollback_only_stages_actual_differences(engine, session):
    set_(engine, session, "system host-name first")
    set_(engine, session, "interfaces dummy dum0")
    engine.commit(session)
    set_(engine, session, "system host-name second")
    engine.commit(session)
    engine.rollback(session, 1)

    assert engine.running["system"]["host-name"] == "second"
    assert {m.owner for m in session.mutations} == {"system"}
    assert engine.view(session)["system"]["host-name"] == "first"


def test_rename_and_edit_paths(engine, session):
    set_(engine, session, "interfaces dummy dum1 description LAN")
    engine.mutate(session, "edit", ["interfaces"])
    engine.rename(session, ["dummy", "dum1"], ["dummy", "dum55"])

    assert set(engine.view(session)["interfaces"]["dummy"]) == {"dum55"}

    engine.mutate(session, "edit", ["dummy", "dum55"])

    assert session.edit == ("interfaces", "dummy", "dum55")

    with pytest.raises(RouterError):
        engine.mutate(session, "edit", ["description"])

    engine.up(session)

    assert session.edit == ("interfaces",)

    engine.up(session)

    assert session.edit == ()


def test_up_visits_tag_instances_and_skips_bare_tag_container(engine, session):
    node = engine.schema.root["children"]["interfaces"]["children"]["dummy"]
    node["children"]["settings"] = {"kind": "node", "children": {}}
    engine.mutate(session, "edit", ["interfaces", "dummy", "dum0", "settings"])
    engine.up(session)

    assert session.edit == ("interfaces", "dummy", "dum0")

    engine.up(session)

    assert session.edit == ("interfaces",)


def test_restart_rolls_back_unconfirmed_and_keeps_explicit_history(engine, session):
    set_(engine, session, "system host-name stable")
    engine.commit(session)
    set_(engine, session, "system host-name risky")
    engine.commit(session, minutes=5, confirmed_minutes=5)
    restarted = Engine(engine.schema, recorded_registry(engine.schema), engine.store)

    assert restarted.running["system"]["host-name"] == "stable"
    assert restarted.pending is None
    assert restarted.commit_id == 3


def test_interrupted_apply_journal_recovers_precommit_state(engine, session):
    set_(engine, session, "system host-name stable")
    engine.commit(session)
    engine.store.write("transaction.json", {"before": {}, "id": 0, "owners": ["system"]})
    restarted = Engine(engine.schema, recorded_registry(engine.schema), engine.store)

    assert restarted.running == {}
    assert not (engine.store.directory / "transaction.json").exists()


def test_new_machine_boot_uses_saved_configuration(engine, session):
    set_(engine, session, "system host-name saved")
    engine.commit(session)
    engine.save(session)
    set_(engine, session, "system host-name unsaved")
    engine.commit(session)
    restarted = Engine(engine.schema, recorded_registry(engine.schema), engine.store, boot_id="new-boot")

    assert restarted.running["system"]["host-name"] == "saved"


def test_failed_publication_is_fail_closed_and_recoverable(engine, session, monkeypatch):
    set_(engine, session, "system host-name proposed")
    original = engine.store.write

    def fail(name, value):
        if name == "state.json":
            raise OSError("disk full")

        return original(name, value)

    monkeypatch.setattr(engine.store, "write", fail)

    with pytest.raises(OSError):
        engine.commit(session)

    assert engine.unhealthy
    assert engine.store.read("transaction.json") is not None

    with pytest.raises(BusyError):
        engine.save(session)

    monkeypatch.setattr(engine.store, "write", original)
    restarted = Engine(engine.schema, recorded_registry(engine.schema), engine.store)

    assert restarted.running == {}
