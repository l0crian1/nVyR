import pytest
from nvyr.engine import Session
from nvyr.lexer import lex
from nvyr.render import diff_commands
from nvyr.tree import MISSING, Mutation, lookup, overlay, projected_value


@pytest.mark.parametrize("mutations", [
    [Mutation("delete", ("a",))],
    [Mutation("set", ("a",), {"b": "new"})],
    [Mutation("set", ("a", "b"), "new")],
    [Mutation("delete", ("a", "b"))],
    [Mutation("add", ("a", "items"), "y"), Mutation("subtract", ("a", "items"), "x")],
    [Mutation("delete", ("a",)), Mutation("ensure", ("a", "tag"))],
])
def test_projected_lookup_matches_full_overlay(mutations):
    running = {"a": {"b": "old", "items": ["x"]}, "untouched": {"huge": {}}}
    intended = overlay(running, mutations)

    for path in [(), ("a",), ("a", "b"), ("a", "items"), ("a", "tag"), ("untouched",)]:
        assert projected_value(running, mutations, path) == lookup(intended, path)


@pytest.mark.parametrize("before,after", [
    ({"interfaces": {"dummy": {"dum0": {"description": "old"}}}}, {"interfaces": {"dummy": {"dum0": {}}}}),
    ({"interfaces": {"dummy": {"dum0": {}}}}, {"interfaces": {"dummy": {"dum0": {"description": "new"}}}}),
    ({"interfaces": {"dummy": {"dum0": {"address": ["1.1.1.1/24", "::1/128"]}}}}, {"interfaces": {"dummy": {"dum0": {"address": ["::1/128"]}}}}),
    ({"interfaces": {"dummy": {"dum0": {"disable": True}}}}, {}),
])
def test_diff_commands_reconstruct_target(engine, before, after):
    engine.running = before
    session = engine.open("test", "test")

    for line in diff_commands(engine.schema, before, after):
        tokens = lex(line)
        engine.mutate(session, tokens[0].value, tokens[1:])

    assert engine.view(session) == after


def test_quoted_value_tab_and_inline_do_not_create_extra_tokens(controller, session):
    controller.execute('set interfaces dummy dum0 description "Main LAN"', session)
    result = controller.completion("set interfaces dummy dum0 description M", session)

    assert result["extension"] == ""
    assert result["replacement"] == "'Main LAN'"

    result = controller.completion('set interfaces dummy dum0 description "Ma', session)

    assert result["extension"] == 'in LAN"'


def test_failed_rollback_retains_lease_and_retries(engine, session):
    now = [0]
    engine.clock = lambda: now[0]
    engine.mutate(session, "set", lex("system host-name temporary"))
    engine.commit(session, minutes=1, confirmed_minutes=1)
    original = engine.modules["system"].apply

    def fail(generated, context):
        raise RuntimeError("recovery unavailable")

    engine.modules["system"].apply = fail
    now[0] = 61

    with pytest.raises(Exception, match="Recovery failed"):
        engine.tick()

    assert engine.pending and engine.store.read("confirmed.json")

    engine.modules["system"].apply = original
    engine.tick()

    assert engine.running == {} and engine.pending is None


def test_history_is_immutable_across_restart(engine, session):
    from nvyr.engine import Engine
    from tests.lifecycle import recorded_registry

    engine.mutate(session, "set", lex("system host-name stable"))
    engine.commit(session)
    record = engine.store.read("history/00000000000000000001.json")
    Engine(engine.schema, recorded_registry(engine.schema), engine.store)

    assert engine.store.read("history/00000000000000000001.json") == record


def test_candidate_completion_does_not_construct_full_view(controller, engine, session, monkeypatch):
    controller.execute("set interfaces dummy dum0", session)

    def no_full_view(*args):
        raise AssertionError("completion must project branches")

    monkeypatch.setattr(engine, "view", no_full_view)

    assert controller.completion("set interfaces dummy du", session)["replacement"] == "dum0"


def test_completion_display_cap_does_not_choose_from_truncated_matches(controller, engine, session):
    engine.running = {"interfaces": {"dummy": {f"dum{i}": {} for i in range(1000)}}}
    result = controller.completion("set interfaces dummy du", session)

    assert len(result["candidates"]) == 256
    assert result["total"] == 1000 and not result["unique"]
    assert result["extension"] == "m"


def test_rename_tag_named_to(controller, engine, session):
    engine.schema.root["children"]["interfaces"]["children"]["dummy"]["validators"] = {}
    controller.execute("set interfaces dummy to description LAN", session)
    controller.execute("rename interfaces dummy to to interfaces dummy new", session)

    assert set(engine.view(session)["interfaces"]["dummy"]) == {"new"}


def test_confirm_record_failure_does_not_start_live_apply(engine, session, monkeypatch):
    engine.mutate(session, "set", lex("system host-name proposed"))
    original = engine.store.write

    def fail(name, value):
        if name == "confirmed.json":
            raise OSError("disk full")

        return original(name, value)

    monkeypatch.setattr(engine.store, "write", fail)

    with pytest.raises(OSError):
        engine.commit(session, minutes=1, confirmed_minutes=1)

    assert engine.pending is None and not engine.busy
    assert engine.store.read("transaction.json") is None
    assert engine.running == {} and session.mutations
    assert not [call for call in engine.modules["system"].calls if not call[2]]


def test_root_always_default_is_effective_only():
    from nvyr.schema import Schema

    schema = Schema({"kind": "node", "children": {"flag": {"kind": "leaf_node", "valueless": True, "default": {"mode": "always"}}}})
    explicit = {}

    assert schema.defaults(explicit) == {"flag": True}
    assert explicit == {}


def test_many_mutations_run_each_owner_once(engine, session):
    for index in range(100):
        engine.mutate(session, "set", lex(f"interfaces dummy dum{index} description LAN"))

    engine.commit(session)
    applies = [call for call in engine.modules["dummy"].calls if call[1:] == ("apply", False)]

    assert len(applies) == 1 and engine.commit_id == 1
