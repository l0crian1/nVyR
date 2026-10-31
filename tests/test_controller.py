import pytest
from nvyr.errors import RouterError
from nvyr.lexer import lex
from nvyr.schema import Schema


def test_completion_prefix_not_exact_match_short_circuit(controller):
    controller.operational = Schema({"kind": "node", "children": {"show": {"kind": "node", "children": {name: {"kind": "node", "command": name} for name in ["dhcp", "dhcpv6", "dns", "route", "route6"]}}}})
    result = controller.completion("show dh")

    assert result["extension"] == "cp"
    assert not result["unique"]

    result = controller.completion("show dhcp", explicit=True)

    assert {v for v, _ in result["candidates"]} == {"dhcp", "dhcpv6", "<Enter>"}

    result = controller.completion("show dhc", explicit=True)

    assert {v for v, _ in result["candidates"]} == {"dhcp", "dhcpv6"}
    assert controller.completion("show route")["extension"] == ""


def test_configured_values_and_pending_deletions(controller, engine, session):
    for tag in ["dum0", "dum1"]:
        controller.execute(f"set interfaces dummy {tag} description LAN", session)

    engine.commit(session)

    assert controller.completion("set interfaces dummy du", session)["extension"] == "m"

    controller.execute("delete interfaces dummy dum1", session)
    result = controller.completion("set interfaces dummy du", session)

    assert result["replacement"] == "dum0"
    assert controller.completion("set interfaces dummy dum0 description L", session)["replacement"] == "LAN"

    controller.execute("set interfaces dummy dum0 description WAN", session)

    assert controller.completion("set interfaces dummy dum0 description L", session)["candidates"] == []


def test_dynamic_suggestors_in_all_completion_modes(controller, engine, session):
    calls = []
    engine.schema.suggestors["interfaces"] = lambda prefix="": calls.append(prefix) or ["dum9"]
    controller.completion("set interfaces dummy du", session)
    controller.completion("set interfaces dummy du", session, space=True)

    assert calls == ["dum", "dum"]

    result = controller.completion("set interfaces dummy du", session, explicit=True)

    assert calls == ["dum", "dum", "dum"]
    assert "dum9" in [v for v, _ in result["candidates"]]

    controller.execute("set interfaces dummy dum7", session)


def test_common_resolver_for_space_and_execution(controller, session):
    assert controller.completion("set inter", session, space=True)["replacement"] == "interfaces"

    controller.execute("se inter dum dum0 desc LAN", session)

    assert controller.engine.view(session)["interfaces"]["dummy"]["dum0"]["description"] == "LAN"


def test_pipeline_commands_match_export_and_sink_validation(controller, session):
    controller.execute("set system host-name router", session)
    result = controller.execute("compare | commands | match host-name | export /tmp/proposal", session)

    assert result["text"] == "set system host-name router\n"
    assert result["export"] == "/tmp/proposal"

    with pytest.raises(RouterError):
        controller.execute("compare | export /tmp/x | match x", session)

    with pytest.raises(RouterError):
        controller.execute("commit | count", session)

    assert controller.engine.commit_id == 0
    assert controller.completion("compare | co", session)["extension"] == ""
    assert controller.completion("compare | comm", session)["replacement"] == "commands"


def test_native_merge_replace_and_invalid_load_is_atomic(controller, engine, session):
    controller.execute("set interfaces dummy dum0", session)
    controller.load(session, '{"system":{"host-name":"router"}}')

    assert "interfaces" in engine.view(session)

    with pytest.raises(RouterError):
        controller.load(session, '{"system":{"bogus":"router"}}')

    assert "interfaces" in engine.view(session)

    controller.load(session, '{"system":{"host-name":"only"}}', replace=True)

    assert engine.view(session) == {"system": {"host-name": "only"}}


def test_load_set_partial_line_errors_and_absolute_paths(controller, engine, session):
    controller.execute("edit firewall", session)
    errors = controller.load(session, "set interfaces dummy dum0\nset misspelled value\nset system host-name good\n", set_format=True)

    assert len(errors) == 1
    assert errors[0]["line"] == 2
    assert engine.view(session)["system"]["host-name"] == "good"

    controller.load(session, "set system host-name replacement", set_format=True, replace=True)

    assert engine.view(session) == {"system": {"host-name": "replacement"}}


def test_saved_compare_direction_and_rollback_commands(controller, engine, session):
    controller.execute("set system host-name saved", session)
    engine.commit(session)
    engine.save(session)
    controller.execute("set system host-name current", session)
    engine.commit(session)

    assert "set system host-name current" in controller.execute("compare saved | commands", session)["text"]
    assert "set system host-name current" in controller.execute("compare 1 | commands", session)["text"]

    engine.rollback(session, 1)

    assert "set system host-name saved" in controller.execute("compare | commands", session)["text"]


def test_operational_and_run_share_parser(controller, session):
    assert controller.execute("show version")["text"] == controller.execute("run sho ver", session)["text"]

    with pytest.raises(RouterError):
        controller.execute("show")

    with pytest.raises(RouterError):
        controller.execute("run configure", session)


def test_registered_operational_handler_uses_same_argument_parser(controller, session):
    from nvyr.pipeline import Output

    controller.operational.root["children"]["echo"] = {"kind": "leaf_node", "command": "echo"}
    controller.operational = Schema(controller.operational.root)
    controller.register_operation("echo", lambda cursor: Output(str(cursor.value)))

    assert controller.execute('echo "a|b"')["text"] == "a|b"
    assert controller.execute('run echo "a|b"', session)["text"] == "a|b"


def test_load_and_rename_help(controller, session):
    # This grammar fixture intentionally allows a tag named like the separator.
    controller.engine.schema.root["children"]["interfaces"]["children"]["dummy"]["validators"] = {}

    assert controller.completion("load rep", session)["replacement"] == "replace"
    assert "<Enter>" in dict(controller.completion("load set /tmp/file", session, explicit=True)["candidates"])

    controller.execute("set interfaces dummy to", session)

    assert "to" in dict(controller.completion("rename interfaces dummy to ", session, explicit=True)["candidates"])
    assert "<Enter>" in dict(controller.completion("rename interfaces dummy to to interfaces dummy new", session, explicit=True)["candidates"])
