import asyncio
import json
import subprocess
import sys
from datetime import datetime, timezone

import pytest

from nvyr.helpers.process import cmd, run, CommandError
from nvyr.errors import ConfirmationRequired, LockError, RouterError
from nvyr.history import navigation_histories
from nvyr.lexer import lex
from nvyr.schema import Schema
from nvyr.helpers.suggestors import Context, commit_history
from nvyr.helpers import validators


def test_candidate_is_changes_only_tree_and_not_mutation_metadata(controller, engine, session):
    controller.execute("set system host-name stable", session)
    engine.commit(session)
    controller.execute("set interfaces dummy dum0 disable", session)
    result = controller.execute("show candidate-configuration", session)

    assert json.loads(result["text"]) == {"interfaces": {"dummy": {"dum0": {"disable": True}}}}
    assert controller.execute("show candidate-configuration | commands", session)["text"] == "set interfaces dummy dum0 disable\n"
    assert session.mutations and session.mutations[0].owner == "dummy"


def test_candidate_deletions_replacements_lists_and_rename(controller, engine, session):
    controller.execute("set interfaces dummy dum0 address 192.0.2.1/24", session)
    controller.execute("set interfaces dummy dum0 address 192.0.2.2/24", session)
    controller.execute("set system host-name old", session)
    engine.commit(session)
    controller.execute("delete interfaces dummy dum0 address 192.0.2.1/24", session)
    controller.execute("set system host-name new", session)
    candidate = controller.execute("show candidate-configuration", session)["text"]

    assert '-           "192.0.2.1/24"' in candidate
    assert '-     "host-name": "old"' in candidate and '+     "host-name": "new"' in candidate

    controller.execute("rename interfaces dummy dum0 to interfaces dummy dum1", session)
    candidate = controller.execute("show candidate-configuration", session)["text"]

    assert '-       "dum0"' in candidate and '+       "dum1"' in candidate
    assert '"192.0.2.2/24"' in candidate and 'null' not in candidate

    controller.execute("delete system", session)

    assert '-   "system"' in controller.execute("show candidate-configuration", session)["text"]

    controller.execute("discard", session)

    assert json.loads(controller.execute("show candidate-configuration", session)["text"]) == {}


def test_edit_tag_instance_completion_relative_values_and_up(controller, engine, session):
    controller.execute("set interfaces dummy dum0 description LAN", session)
    help_ = controller.completion("edit interfaces dummy dum0", session, explicit=True)

    assert "<Enter>" in dict(help_["candidates"])
    assert "<Enter>" not in dict(controller.completion("edit interfaces dummy", session, explicit=True)["candidates"])

    controller.execute("edit interfaces dummy dum0", session)

    assert controller.completion("set des", session)["replacement"] == "description"
    assert controller.completion("set description L", session)["replacement"] == "LAN"

    controller.execute('set description "Test Interface"', session)
    controller.execute("set address 192.0.2.1/24", session)

    assert engine.view(session)["interfaces"]["dummy"]["dum0"]["description"] == "Test Interface"

    with pytest.raises(RouterError, match="edit location"):
        controller.execute("edit description", session)

    controller.execute("up", session)

    assert session.edit == ("interfaces",)

    with pytest.raises(RouterError):
        controller.execute("edit dummy", session)

    controller.execute("top", session)

    assert session.edit == ()


def test_history_suggestions_are_retained_offsets_in_all_completion_modes(controller, engine, session):
    for index in range(1, 8):
        controller.execute(f"set system host-name r{index}", session)
        engine.commit(session)

    engine.store.prune(4)
    engine.store.delete("history/00000000000000000005.json")  # A real retention gap.
    calls = []
    suggest = controller.control.suggestors["commit-history"]
    controller.control.suggestors["commit-history"] = lambda: calls.append(1) or suggest()
    controller.completion("compare ", session)
    controller.completion("compare s", session, tab=True)
    controller.completion("compare s", session, space=True)

    assert len(calls) == 3

    result = controller.completion("compare ", session, tab=True)

    assert result["display"] and len(calls) == 4
    assert set(dict(result["candidates"])) == {"saved", "0", "1", "3", "<Enter>"}

    timestamp = engine.store.read("history/00000000000000000004.json")["timestamp"]

    assert dict(result["candidates"])["3"] == datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    assert set(dict(controller.completion("compare 3", session, explicit=True)["candidates"])) == {"3", "<Enter>"}
    assert len(calls) == 5


@pytest.mark.parametrize("command", ["compare", "compare saved", "compare 0"])
def test_empty_comparison_is_explicit_but_commands_stays_empty(controller, session, command):
    assert controller.execute(command, session)["text"].startswith("No differences between ")
    assert controller.execute(command + " | commands", session)["text"] == ""


def test_commit_confirm_requires_interval_specific_confirmation_without_side_effects(controller, engine, session):
    controller.execute("set system host-name proposed", session)

    with pytest.raises(ConfirmationRequired) as required:
        controller.execute("commit-confirm 10", session)

    assert required.value.details == {"confirm_minutes": 10}
    assert engine.running == {} and engine.commit_id == 0 and engine.pending is None
    assert not engine.store.read("transaction.json")

    with pytest.raises(ConfirmationRequired):
        controller.execute("commit-confirm 20", session, confirmation=required.value.details)

    controller.execute("commit-confirm 10", session, confirmation=required.value.details)

    assert engine.pending and session.commit_id == engine.commit_id == 1
    assert "cancelled" in controller.execute("confirm", session)["text"]
    assert engine.pending is None


def test_rollback_updates_only_originating_session_and_emits_once(engine, controller, session):
    now = [0]
    engine.clock = lambda: now[0]
    other = engine.open("bob", "/dev/pts/2")
    controller.execute("set system host-name temporary", session)
    engine.commit(session, minutes=1, confirmed_minutes=1)
    controller.execute("set interfaces dummy dum0", session)  # Pending during the lease.

    assert engine.status(session)["events"] == []

    now[0] = 61
    engine.tick()
    engine.tick()
    status = engine.status(session)

    assert session.commit_id == engine.commit_id == 2 and other.commit_id == 0
    assert status["events"] == [{"id": 1, "type": "confirmed-rollback", "owner": session.id, "commit_id": 2,
                                  "message": "Commit-confirm timer expired. Configuration has been rolled back."}]
    assert engine.status(session, after=1)["events"] == []
    assert engine.lock_owner == session.id and engine.pending is None
    assert engine.store.read("state.json")["id"] == 2
    assert engine.store.historical(2, 0) == {}

    engine.commit(session)  # No stale warning against this session's own rollback.
    engine.request_lock(other, session.id)

    with pytest.raises(ConfirmationRequired):
        engine.commit(other)


def test_failed_rollback_does_not_notify_or_sync_until_success(engine, session, controller):
    now = [0]
    engine.clock = lambda: now[0]
    controller.execute("set system host-name temporary", session)
    engine.commit(session, minutes=1, confirmed_minutes=1)
    apply = engine.modules["system"].apply

    def fail(*args):
        raise RuntimeError("unavailable")

    engine.modules["system"].apply = fail
    now[0] = 61

    with pytest.raises(RouterError):
        engine.tick()

    assert engine.pending and session.commit_id == 1 and not engine.events

    other = engine.open("bob", "pts/2")

    with pytest.raises(LockError):
        engine.request_lock(other, session.id)

    engine.modules["system"].apply = apply
    engine.tick()

    assert session.commit_id == 2 and len(engine.events) == 1


def test_confirm_cancels_notification(engine, session, controller):
    now = [0]
    engine.clock = lambda: now[0]
    controller.execute("set system host-name permanent", session)
    engine.commit(session, minutes=1, confirmed_minutes=1)
    engine.confirm(session)
    now[0] = 61
    engine.tick()

    assert not engine.events and engine.commit_id == session.commit_id == 1


@pytest.mark.parametrize("name,valid,invalid", [
    ("ipv4-address", "192.0.2.1", "192.0.2.500"),
    ("ipv4-prefix", "192.0.2.1/24", "192.0.2.1"),
    ("ipv6-prefix", "2001:db8::1/64", "2001:db8::1/129"),
    ("port", "65535", "65536"),
])
def test_central_validator_examples(name, valid, invalid):
    assert validators.REGISTRY[name](valid)
    assert not validators.REGISTRY[name](invalid)


def test_add_validator_without_parser_changes():
    @validators.register("test-even-number", "even number")
    def even(value):
        return value.isdecimal() and int(value) % 2 == 0

    try:
        schema = Schema({"kind": "node", "children": {"value": {"kind": "leaf_node", "validators": {'checks': {'test-even-number': {'name': 'test-even-number'}}}}}})

        assert schema.resolve(["value", "4"]).value == "4"

        with pytest.raises(RouterError, match="even number"):
            schema.resolve(["value", "3"])
    finally:
        validators.REGISTRY.pop("test-even-number")
        validators.LABELS.pop("test-even-number")


def test_persistent_navigation_histories_never_auto_record_buffers(tmp_path):
    histories = navigation_histories(tmp_path, persistent=True)
    histories["operational"].append_string("whole buffer must not be recorded")
    histories["operational"].record("show version")
    histories["configuration"].record("set system host-name router")
    reloaded = navigation_histories(tmp_path, persistent=True)

    async def values(history):
        return [item async for item in history.load()]

    assert asyncio.run(values(reloaded["operational"])) == ["show version"]
    assert asyncio.run(values(reloaded["configuration"])) == ["set system host-name router"]
    assert (tmp_path / "operational").stat().st_mode & 0o777 == 0o600


def test_command_helper_captures_streams_without_shell_and_handles_errors():
    value = "literal ; echo never-executed | $(false)"
    result = cmd([sys.executable, "-c", "import sys; print(sys.argv[1]); print('warning', file=sys.stderr)", value])

    assert result == value + "\nwarning\n"

    with pytest.raises(CommandError, match="command not found"):
        run(["/definitely/not/an/installed/command"])

    assert run([sys.executable, "-c", "import sys; print('bad route',file=sys.stderr);sys.exit(3)"]) == 3
    assert run([sys.executable, "-c", "raise SystemExit(2)"]) == 2

    with pytest.raises(CommandError, match="did not finish"):
        run([sys.executable, "-c", "import time;time.sleep(5)"], timeout=.02)


@pytest.fixture
def installed_static_wrapper(tmp_path):
    from build_tools.op_scripts import install_scripts
    from nvyr.op_scripts import static
    import shutil

    source = tmp_path / 'op_scripts'
    source.mkdir()
    shutil.copyfile(static.__file__, source / 'static.py')
    install_scripts(source, tmp_path)
    (tmp_path / 'python3').symlink_to(sys.executable)


def test_configured_os_commands_share_run_parser(controller, session, monkeypatch, tmp_path, installed_static_wrapper):
    executable = tmp_path / 'vtysh'
    executable.write_text('#!' + sys.executable + '\nimport sys\n'
                          'assert sys.argv[1:] == ["-c", "show ip route"]\n'
                          'print("route output")\n')
    executable.chmod(0o755)
    monkeypatch.setenv('PATH', str(tmp_path))

    assert controller.execute("show ip route")["text"] == "route output\n"
    assert controller.execute("run sho ip rou", session)["text"] == "route output\n"
    assert controller.execute("show ip route | match output")["text"] == "route output\n"


def test_configured_vtysh_command_reaches_os_without_installing_frr(controller, session, monkeypatch, tmp_path, installed_static_wrapper):
    monkeypatch.setenv("PATH", str(tmp_path))

    with pytest.raises(CommandError, match="'vtysh': command not found"):
        controller.execute("show ip route")

    with pytest.raises(CommandError, match="'vtysh': command not found"):
        controller.execute("run show ip route", session)


def test_cli_reports_connection_failure_without_traceback(tmp_path):
    result = subprocess.run([sys.executable, "-m", "nvyr.cli", "--socket", str(tmp_path / "not-running.sock")],
                            text=True, capture_output=True)

    assert result.returncode == 1 and "Cannot connect to the router" in result.stderr
    assert "Traceback" not in result.stderr


def test_operator_errors_include_location_and_corrective_guidance(controller, session):
    with pytest.raises(RouterError) as invalid:
        controller.execute("set interfaces dummy dum0 address 192.168.1.500/24", session)

    assert "192.168.1.500/24" in str(invalid.value) and "IPv4" in str(invalid.value)
    assert "interfaces dummy dum0 address" in str(invalid.value) and invalid.value.start == 34

    with pytest.raises(RouterError, match="Expected a value after 'default-action'"):
        controller.execute("set firewall ipv4 forward filter default-action", session)

    with pytest.raises(RouterError, match="Use \\?"):
        controller.execute("set nonsense", session)
