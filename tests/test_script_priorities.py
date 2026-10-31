"""Build-time script inventory and its read-only operational display."""

import json

import pytest
import yaml

from build_tools.schema_builder import SchemaBuildError, build_schemas, script_inventory
from nvyr import opmode
from nvyr.helpers.script_schema import ScriptIndex
from nvyr.op_scripts import system
from nvyr.schema import Schema


def test_build_inventory_uses_expanded_declarations_only(tmp_path):
    source = tmp_path / 'source'
    includes = source / 'includes'
    includes.mkdir(parents=True)
    shared = {'static': {'kind': 'node', 'script': {'name': 'static', 'priority': 20},
                         'children': {'route': {'kind': 'tag_node', 'children': {
                             'distance': {'kind': 'leaf_node'}}}}}}
    (includes / 'static.yaml.i').write_text(yaml.safe_dump(shared))
    protocols = {'kind': 'node', 'children': {'include_schema': [{'file': 'static.yaml.i'}]}}
    configuration = {'kind': 'node', 'children': {
        'protocols': protocols,
        'vrf': {'kind': 'node', 'children': {
            'name': {'kind': 'tag_node', 'script': {'name': 'vrf', 'priority': 5},
                     'children': {'protocols': protocols}}}},
        'firewall': {'kind': 'node', 'script': {'name': 'firewall', 'priority': 20}},
    }}
    (source / 'configuration.yaml').write_text(yaml.safe_dump(configuration))
    output = tmp_path / 'output'

    build_schemas(source, output)
    artifact = output / 'script-priorities.json'
    assert json.loads(artifact.read_text()) == [
        {'script': 'vrf', 'priority': 5, 'paths': ['vrf name <name>']},
        {'script': 'firewall', 'priority': 20, 'paths': ['firewall']},
        {'script': 'static', 'priority': 20,
         'paths': ['protocols static', 'vrf name <name> protocols static']},
    ]

    build_schemas(source, output, check=True)
    artifact.write_text('[]\n')
    with pytest.raises(SchemaBuildError, match='stale: script-priorities.json'):
        build_schemas(source, output, check=True)


def test_bundled_inventory_matches_runtime_registration():
    expected = script_inventory(ScriptIndex(Schema.bundled().root))
    assert json.loads(system.script_priority(raw=True)) == expected
    assert expected


def test_table_keeps_multiple_paths_in_one_script_row(monkeypatch, tmp_path):
    directory = tmp_path / 'schemas'
    directory.mkdir()
    records = [{'script': 'static', 'priority': 20,
                'paths': ['protocols static', 'vrf name <name> protocols static']}]
    (directory / 'script-priorities.json').write_text(json.dumps(records))
    monkeypatch.setattr(system, 'files', lambda package: tmp_path)

    output = system.script_priority()
    assert 'Script' in output and 'Priority' in output and 'Paths' in output
    assert output.count('protocols static') == 2
    assert output.count('20') == 1
    assert json.loads(system.script_priority(raw=True)) == records


def test_empty_inventory(monkeypatch, tmp_path):
    directory = tmp_path / 'schemas'
    directory.mkdir()
    (directory / 'script-priorities.json').write_text('[]')
    monkeypatch.setattr(system, 'files', lambda package: tmp_path)
    assert system.script_priority() == 'No configuration scripts registered.\n'


def test_missing_inventory_is_a_readable_error(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(system, 'files', lambda package: tmp_path)
    with pytest.raises(SystemExit) as result:
        opmode.run(['script_priority'], namespace=vars(system))

    assert result.value.code == 1
    output = capsys.readouterr()
    assert 'Cannot read configuration script inventory:' in output.err
    assert 'Traceback' not in output.err
