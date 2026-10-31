"""Human-facing validator YAML lowers to the established runtime representation."""

import json

import pytest

from build_tools.schema_builder import build_schemas, SchemaBuildError
from nvyr.helpers.validators import REGISTRY, ipv4_address, ipv6_address, inet_address, byte_length
from nvyr.schema import Schema


def compile_source(tmp_path, validators):
    source, output = tmp_path / 'source', tmp_path / 'output'
    source.mkdir(exist_ok=True)
    (source / 'configuration.yaml').write_text('kind: leaf_node\n' + validators, encoding='utf-8')
    build_schemas(source, output)

    return json.loads((output / 'configuration.json').read_text())


def test_direct_names_arguments_defaults_and_types(tmp_path):
    result = compile_source(tmp_path, """validators:
  mode: AND
  integer-range: {minimum: 1, maximum: 999999}
  length: {maximum: 6}
  regex: {pattern: '\\d+'}
""")

    assert result['validators'] == {'mode': 'AND', 'checks': {
        'integer-range': {'name': 'integer-range', 'args': {'minimum': 1, 'maximum': 999999}},
        'length': {'name': 'length', 'args': {'maximum': 6}},
        'regex': {'name': 'regex', 'args': {'pattern': r'\d+'}},
    }}

    schema = Schema(result)
    schema.validate(result, '42')


def test_or_flags_and_suggestors_are_independent(tmp_path):
    result = compile_source(tmp_path, """validators:
  mode: OR
  port: {allow_range: true}
  list: {values: 'dhcp on off'}
suggestors:
  interfaces: {prefix: eth}
""")

    assert result['validators']['checks']['port']['args']['allow_range'] is True
    assert result['suggestors'] == [{'name': 'interfaces', 'args': {'prefix': 'eth'}}]

    schema = Schema(result)

    for value in ('80-90', 'dhcp', 'on', 'off'):
        schema.validate(result, value)


@pytest.mark.parametrize('source', [
    'validators: []', 'validators: null', 'validators: {mode: XOR}',
    'validators: {regex: null}', 'validators: {regex: []}',
    'validators: {checks: {regex: {name: regex}}}',
    'validators: {names: [text]}', 'validators: {"": {}}',
    'validators:\n  ipv4-address: {}\n  ipv4-address: {}',
])
def test_invalid_source_forms_fail_with_filename(tmp_path, source):
    with pytest.raises(SchemaBuildError, match='configuration.yaml'):
        compile_source(tmp_path, source)


@pytest.mark.parametrize('source', [
    'validators: {number: {integer-range: {minimum: 1, maximum: 99}}}',
    'validators: {ipv4: {ip-address: {version: 4}}}',
    'validators: {regex: {name: regex, args: {pattern: "x"}}}',
])
def test_aliases_and_callback_wrappers_are_not_validator_definitions(tmp_path, source):
    with pytest.raises(ValueError):
        Schema(compile_source(tmp_path, source))


def test_no_argument_and_multiline_argument_definitions(tmp_path):
    result = compile_source(tmp_path, """validators:
  mode: AND
  text: {}
  byte-length:
    minimum: 1
    maximum: 4
""")

    assert result['validators']['checks']['text'] == {'name': 'text'}

    schema = Schema(result)
    schema.validate(result, 'éé')

    with pytest.raises(ValueError):
        # Prepared callback arguments retain their existing schema-load checks.
        Schema(compile_source(tmp_path, 'validators: {byte-length: {maximum: -1}}'))


@pytest.mark.parametrize('definition,name,argument', [
    ('regex: {pattren: "x"}', 'regex', 'pattren'),
    ('integer-range: {minimum: 1, maximum: 10, allow_ranges: true}', 'integer-range', 'allow_ranges'),
    ('inet-address: {version: 4}', 'inet-address', 'version'),
    ('text: {value: x}', 'text', 'value'),
    ('regex: {}', 'regex', 'pattern'),
])
def test_validator_argument_errors_identify_path_before_writing(tmp_path, definition, name, argument):
    source, output = tmp_path / 'source', tmp_path / 'output'
    source.mkdir()
    output.mkdir()
    generated = output / 'configuration.json'
    generated.write_text('existing output')
    (source / 'configuration.yaml').write_text(
        'kind: node\nchildren:\n  example:\n    kind: leaf_node\n    validators:\n      ' + definition + '\n')

    with pytest.raises(SchemaBuildError) as failure:
        build_schemas(source, output)

    message = str(failure.value)

    assert 'configuration.yaml' in message and 'example/validators' in message
    assert name in message and argument in message
    assert generated.read_text() == 'existing output'


def test_argument_checks_use_final_included_definition(tmp_path):
    source, output = tmp_path / 'source', tmp_path / 'output'
    (source / 'includes').mkdir(parents=True)
    (source / 'includes/value.yaml.i').write_text(
        'value:\n  kind: leaf_node\n  validators:\n    regex: {pattern: "x"}\n')
    definition = '''kind: node
children:
  section:
    kind: node
    children:
      include_schema:
      - file: value.yaml.i
        add:
          /validators/regex/typo: true
'''
    schema = source / 'configuration.yaml'
    schema.write_text(definition)

    with pytest.raises(SchemaBuildError, match="section/value/validators:.*regex.*typo"):
        build_schemas(source, output)

    assert not output.exists()

    schema.write_text(definition.replace('        add:\n          /validators/regex/typo: true',
                                         '        replace:\n          /validators/regex/pattern: "y"'))
    build_schemas(source, output)
    node = json.loads((output / 'configuration.json').read_text())['children']['section']['children']['value']
    Schema(node).validate(node, 'y')


@pytest.mark.parametrize('value,family', [
    ('192.0.2.1', 4), ('0.0.0.0', 4), ('255.255.255.255', 4),
    ('2001:db8::1', 6), ('::', 6), ('::1', 6), ('::ffff:192.0.2.1', 6),
    ('', None), ('host.example', None), ('192.0.2.1/24', None), ('2001:db8::1/64', None),
    ('fe80::1%eth0', None), ('fe80::1%2', None), ('192.168.001.1', None),
    ('256.0.0.1', None), ('2001:db8:::1', None), ('[::1]', None),
    (' 192.0.2.1', None), ('::1 ', None), ('::1\n', None),
])
def test_address_families_without_schema_arguments(value, family):
    assert ipv4_address(value) is (family == 4)
    assert ipv6_address(value) is (family == 6)
    assert inet_address(value) is (family in (4, 6))


def test_byte_length_is_a_distinct_generic_validator():
    assert byte_length('éé', minimum=4, maximum=4)
    assert not byte_length('ééé', maximum=4)
    assert not byte_length('', minimum=1, maximum=4)
    assert 'ip-address' not in REGISTRY
    assert {'ipv4-address', 'ipv6-address', 'inet-address'} <= REGISTRY.keys()


def test_bundled_nodes_select_the_intended_address_validators():
    root = Schema.bundled().root['children']
    checks = lambda node: node['validators']['checks']

    assert set(checks(root['service']['children']['ssh']['children']['listen-address'])) == {'inet-address'}
    assert set(checks(root['system']['children']['name-server'])) == {'inet-address', 'regex'}

    static = root['protocols']['children']['static']['children']

    assert set(checks(static['route']['children']['next-hop'])) == {'inet-address'}
    assert set(checks(static['route6']['children']['next-hop'])) == {'ipv6-address'}
