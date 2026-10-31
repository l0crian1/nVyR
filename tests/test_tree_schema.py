import json
import pytest
from nvyr.errors import RouterError, ValidationError
from nvyr.lexer import lex, split_pipeline
from nvyr.render import set_commands
from nvyr.schema import Schema
from nvyr.tree import MISSING, Mutation, ReadOnlyTree, apply, lookup, overlay, put, remove


def test_copy_on_write_and_shared_branches():
    original = {"a": {"b": 1}, "untouched": {"c": 2}}
    changed = put(original, ("a", "b"), 3)

    assert original["a"]["b"] == 1
    assert changed["untouched"] is original["untouched"]
    assert lookup(changed, ("missing",)) is MISSING
    assert remove(changed, ("a", "b")) == {"a": {}, "untouched": {"c": 2}}

    with pytest.raises(TypeError):
        ReadOnlyTree(original)["a"]["b"] = 9


def test_mutation_collection_semantics():
    tree = overlay({}, [Mutation("add", ("a",), "x"), Mutation("add", ("a",), "x"), Mutation("add", ("a",), "y")])

    assert tree == {"a": ["x", "y"]}
    assert apply(tree, Mutation("subtract", ("a",), "x")) == {"a": ["y"]}
    assert apply({"a": {"x": 1}}, Mutation("ensure", ("a",))) == {"a": {"x": 1}}


@pytest.mark.parametrize("line", ["set system host-name", "set interfaces dummy dum0 description Main LAN"])
def test_incomplete_and_unquoted_paths_rejected(line, engine):
    with pytest.raises(RouterError):
        engine.schema.configuration_path(lex(line)[1:])


def test_quotes_valueless_and_spans(engine):
    cursor = engine.schema.configuration_path(lex('interfaces dummy dum0 description "Main LAN"'))

    assert cursor.value == "Main LAN"
    assert engine.schema.configuration_path(lex("interfaces dummy dum0 disable")).value is True

    with pytest.raises(ValidationError) as error:
        engine.schema.configuration_path(lex("interfaces dummy dum0 address nope"))

    assert error.value.start == 30
    assert len(split_pipeline('show version | match "a|b"')) == 2


def test_defaults_never_modify_explicit_or_invent_tags(engine):
    explicit = {"firewall": {"description": "present"}}
    effective = engine.schema.defaults(explicit)

    # Always-mode firewall defaults are effective, without entering explicit state.
    assert explicit == {"firewall": {"description": "present"}}
    assert effective['firewall']['description'] == 'present'
    assert effective['firewall']['global-options']['syn-cookies'] == 'enable'
    assert "ipv4" not in explicit["firewall"]
    assert "interfaces" not in effective

    configured = {"firewall": {"ipv4": {"forward": {"filter": {"default-action": "drop"}}}}}

    assert engine.schema.defaults(configured)["firewall"]["ipv4"]["forward"]["filter"] == {"default-action": "drop"}

    configured['firewall']['ipv4']['forward']['filter'] = {}

    assert engine.schema.defaults(configured)['firewall']['ipv4']['forward']['filter'] == {'default-action': 'accept'}
    assert engine.schema.defaults({}) == {}


@pytest.mark.parametrize("mode,value,accepted", [("OR", "a", True), ("AND", "a", False), ("AND", "ab", True), ("OR", "c", False)])
def test_validator_combinations(mode, value, accepted):
    schema = Schema({"kind": "node", "children": {"value": {"kind": "leaf_node", "validators": {"mode": mode, 'checks': {'a': {'name': 'a'}, 'b': {'name': 'b'}}}}}}, validators={"a": lambda v: "a" in v, "b": lambda v: "b" in v})

    if accepted:
        schema.resolve(["value", value])
    else:
        with pytest.raises(ValidationError):
            schema.resolve(["value", value])


@pytest.mark.parametrize("configuration", [{"unknown": {}}, {"interfaces": {"dummy": {"d0": {"disable": False}}}}, {"system": {"host-name": 3}}, {"interfaces": {"dummy": {"d0": {"address": []}}}}])
def test_invalid_native_configuration(configuration, engine):
    with pytest.raises(RouterError):
        engine.schema.validate_configuration(configuration)


def test_command_serialization_roundtrip(engine, session):
    configuration = {"interfaces": {"dummy": {"dum0": {"description": "Bob's \"main\" | LAN", "disable": True, "address": ["1.1.1.1/24", "::1/128"]}, "dum1": {}}}}
    engine.schema.validate_configuration(configuration)

    for line in set_commands(engine.schema, configuration):
        engine.mutate(session, "set", lex(line)[1:])

    assert engine.view(session) == configuration
