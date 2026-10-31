"""Suggestor authoring mappings preserve runtime callbacks and include edits."""

import json

import pytest

from build_tools.schema_builder import ROOT, SchemaBuildError, SchemaBuilder, build_schemas
from nvyr.schema import Schema


def compile_source(tmp_path, content):
    source = tmp_path / 'source'
    source.mkdir(exist_ok=True)
    (source / 'configuration.yaml').write_text(content, encoding='utf-8')
    output = tmp_path / 'runtime'
    build_schemas(source, output)

    return json.loads((output / 'configuration.json').read_text())


def test_named_suggestors_preserve_order_arguments_and_completion(tmp_path, monkeypatch):
    result = compile_source(tmp_path, """kind: leaf_node
suggestors:
  interfaces: {prefix: eth}
  commit-history: {}
""")

    assert result['suggestors'] == [
        {'name': 'interfaces', 'args': {'prefix': 'eth'}}, {'name': 'commit-history'},
    ]

    monkeypatch.setattr('nvyr.helpers.suggestors.cmd',
                        lambda command: json.dumps([{'ifname': name} for name in ('lo', 'eth0', 'dum0')]))
    schema = Schema({'kind': 'node', 'children': {'interface': result}})

    assert dict(schema.candidates(schema.resolve(['interface']), '', {})) == {
        'eth0': '',
    }


def test_recursive_include_edits_happen_before_suggestor_normalization(tmp_path):
    includes = tmp_path / 'source/includes'
    includes.mkdir(parents=True)
    (includes / 'base.yaml.i').write_text("""interface:
  kind: leaf_node
  suggestors:
    interfaces: {prefix: eth}
    commit-history: {}
""")
    (includes / 'dummy.yaml.i').write_text("""include_schema:
  - file: base.yaml.i
    replace:
      /suggestors/interfaces/prefix: dum
    remove:
      - /suggestors/commit-history
""")
    result = compile_source(tmp_path, """kind: node
children:
  include_schema:
    - file: dummy.yaml.i
      add:
        /suggestors/commit-history: {}
    - file: base.yaml.i
      as: original
""")

    assert result['children']['interface']['suggestors'] == [
        {'name': 'interfaces', 'args': {'prefix': 'dum'}}, {'name': 'commit-history'},
    ]
    assert result['children']['original']['suggestors'][0]['args'] == {'prefix': 'eth'}

    Schema(result)


@pytest.mark.parametrize('source', [
    'suggestors: [interfaces]', 'suggestors: null',
    'suggestors: {interfaces: null}', 'suggestors: {interfaces: []}',
    'suggestors: {"": {}}', 'suggestors:\n  interfaces: {}\n  interfaces: {}',
])
def test_invalid_suggestor_source_reports_filename(tmp_path, source):
    with pytest.raises(SchemaBuildError, match='configuration.yaml'):
        compile_source(tmp_path, 'kind: leaf_node\n' + source)


@pytest.mark.parametrize('reference', [
    'unknown: {}', 'interfaces: {typo: eth}',
    'interfaces: {name: interfaces, args: {prefix: eth}}',
])
def test_runtime_still_checks_callback_names_and_arguments(tmp_path, reference):
    result = compile_source(tmp_path, 'kind: leaf_node\nsuggestors: {' + reference + '}')

    with pytest.raises(ValueError):
        Schema(result)


def test_empty_suggestors_and_multiline_arguments(tmp_path):
    result = compile_source(tmp_path, """kind: node
suggestors: {}
children:
  interface:
    kind: leaf_node
    suggestors:
      interfaces:
        prefix: dum
""")

    assert result['suggestors'] == []
    assert result['children']['interface']['suggestors'] == [
        {'name': 'interfaces', 'args': {'prefix': 'dum'}},
    ]


def test_bundled_sources_follow_validator_mode_convention():
    def check(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == 'validators' or key.endswith('/validators'):
                    count = len(child.keys() - {'mode'})

                    assert ('mode' in child) == (count > 1), child

                check(child)
        elif isinstance(value, list):
            for child in value:
                check(child)

    builder = SchemaBuilder(ROOT / 'schemas/includes')

    # Check both reusable fragments and their fully composed consumers.
    for path in (ROOT / 'schemas').rglob('*'):
        if path.name.endswith(('.yaml', '.yaml.i')):
            check(builder.resolve_file(path))
