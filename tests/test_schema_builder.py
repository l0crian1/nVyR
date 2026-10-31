import json
import shutil
import subprocess
import sys

import pytest
import yaml

from build_tools.schema_builder import ROOT, SchemaBuildError, SchemaBuilder, build_schemas
from nvyr.errors import ValidationError
from nvyr.schema import Schema


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False, allow_unicode=True), encoding='utf-8')

    return path


def entry(file, **operations):
    return {'file': file, **operations}


def include(file, **operations):
    return {'include_schema': [entry(file, **operations)]}


def test_multiple_named_files_merge_in_place_with_independent_edits(tmp_path):
    write(tmp_path / 'address.yaml.i', {'address': {
        'description': 'Address', 'multi': True, 'hints': {'prefix': 'IP prefix'}}})
    write(tmp_path / 'disable.yaml.i', {'disable': {
        'description': 'Disable', 'valueless': True}})
    source = write(tmp_path / 'source.yaml', {'children': {
        'before': {},
        'include_schema': [
            entry('address.yaml.i', remove=['/hints'],
                  replace={'/description': 'Static address'}, add={'/extra': 4}),
            entry('disable.yaml.i', replace={'/description': 'Administratively disable'},
                  add={'/extra': 6}),
        ],
        'after': {},
    }})
    children = SchemaBuilder(tmp_path).resolve_file(source)['children']

    assert list(children) == ['before', 'address', 'disable', 'after']
    assert children['address'] == {'description': 'Static address', 'multi': True, 'extra': 4}
    assert children['disable'] == {'description': 'Administratively disable', 'valueless': True, 'extra': 6}


def test_edits_cannot_target_another_include_or_the_outer_node_name(tmp_path):
    write(tmp_path / 'first.yaml.i', {'first': {'description': 'First'}})
    write(tmp_path / 'second.yaml.i', {'second': {'description': 'Second'}})

    for pointer in ['/first/description', '/second/description']:
        source = write(tmp_path / 'source.yaml', {'include_schema': [
            entry('first.yaml.i'), entry('second.yaml.i', replace={pointer: 'Wrong scope'})]})

        with pytest.raises(SchemaBuildError, match='does not exist') as error:
            SchemaBuilder(tmp_path).resolve_file(source)

        assert "include_schema[1] ('second.yaml.i')" in str(error.value)
        assert pointer in str(error.value)


def test_duplicate_names_from_files_and_aliases_fail(tmp_path):
    write(tmp_path / 'first.yaml.i', {'same': {'description': 'First'}})
    write(tmp_path / 'second.yaml.i', {'same': {'description': 'Second'}})
    write(tmp_path / 'third.yaml.i', {'different': {'description': 'Third'}})

    for second in [entry('second.yaml.i'), entry('first.yaml.i'),
                   entry('third.yaml.i', **{'as': 'same'})]:
        source = write(tmp_path / 'source.yaml', {'include_schema': [entry('first.yaml.i'), second]})

        with pytest.raises(SchemaBuildError, match='same.*conflicts'):
            SchemaBuilder(tmp_path).resolve_file(source)


@pytest.mark.parametrize('fragment,message', [
    ({}, 'exactly one named node'),
    ({'one': {}, 'two': {}}, 'exactly one named node'),
    ({'': {}}, 'nonempty name'),
    ({'one': None}, 'mapping contents'),
    ({'one': []}, 'mapping contents'),
    ({'one': 'text'}, 'mapping contents'),
])
def test_includes_require_a_single_named_mapping(tmp_path, fragment, message):
    write(tmp_path / 'fragment.yaml.i', fragment)
    source = write(tmp_path / 'source.yaml', include('fragment.yaml.i'))

    with pytest.raises(SchemaBuildError, match=message) as error:
        SchemaBuilder(tmp_path).resolve_file(source)

    assert 'fragment.yaml.i' in str(error.value)


@pytest.mark.parametrize('alias', ['', 0, True, [], {}, 'include_schema'])
def test_invalid_alias_is_rejected(tmp_path, alias):
    write(tmp_path / 'fragment.yaml.i', {'node': {}})
    source = write(tmp_path / 'source.yaml', include('fragment.yaml.i', **{'as': alias}))

    with pytest.raises(SchemaBuildError, match='as must be'):
        SchemaBuilder(tmp_path).resolve_file(source)


def test_contents_only_include_for_node_valued_edits_and_recursive_derivation(tmp_path):
    write(tmp_path / 'address.yaml.i', {'address': {'description': 'Address', 'multi': True}})
    write(tmp_path / 'dhcp.yaml.i', include('address.yaml.i',
        add={'/choices': {'dhcp': 'DHCP'}}))
    write(tmp_path / 'base.yaml.i', {'interface': {'children': include('address.yaml.i')}})
    source = write(tmp_path / 'source.yaml', include('base.yaml.i', replace={
        '/children/address': include('dhcp.yaml.i', **{'as': None})}))

    assert SchemaBuilder(tmp_path).resolve_file(source) == {'interface': {'children': {
        'address': {'description': 'Address', 'multi': True, 'choices': {'dhcp': 'DHCP'}}}}}

    # Contents imports have the same collision protection as named imports.
    write(source, {**include('address.yaml.i', **{'as': None}), 'description': 'Collision'})

    with pytest.raises(SchemaBuildError, match='description.*conflicts'):
        SchemaBuilder(tmp_path).resolve_file(source)


def test_empty_include_list_is_a_noop(tmp_path):
    source = write(tmp_path / 'source.yaml', {'include_schema': [], 'children': {}})

    assert SchemaBuilder(tmp_path).resolve_file(source) == {'children': {}}


def test_nested_fragments_edits_and_independent_consumers(tmp_path):
    fragments = tmp_path / 'includes'
    write(fragments / 'validators/network.yaml.i', {'validators': {'network': {}}})
    write(fragments / 'protocols/route.yaml.i', {'route': {
        **include('validators/network.yaml.i'),
        'kind': 'tag_node', 'description': 'Route', 'hints': {'prefix': 'Network'},
        'children': {'next-hop': {'kind': 'tag_node', 'hints': {'address': 'Address'}}},
    }})
    source = write(tmp_path / 'configuration.yaml', {'children': {
        'include_schema': [entry('protocols/route.yaml.i',
                         remove=['/children/next-hop/hints'],
                         replace={'/hints': {'x.x.x.x/x': 'IPv4 network'}},
                         add={'/validators/network/version': 4,
                              '/children/next-hop/description': 'IPv4 next hop'}),
        entry('protocols/route.yaml.i', **{'as': 'route6'},
                          add={'/validators/network/version': 6}),
        entry('protocols/route.yaml.i', **{'as': 'unmodified'})],
    }})
    result = SchemaBuilder(fragments).resolve_file(source)['children']

    assert result['route']['validators']['network'] == {'version': 4}
    assert result['route6']['validators']['network'] == {'version': 6}
    assert result['unmodified']['validators'] == {'network': {}}
    assert result['route']['hints'] == {'x.x.x.x/x': 'IPv4 network'}
    assert result['route']['children']['next-hop'] == {'kind': 'tag_node', 'description': 'IPv4 next hop'}
    assert result['route6']['children']['next-hop']['hints'] == {'address': 'Address'}
    assert 'include_schema' not in json.dumps(result)


def test_complete_static_route_includes_preserve_family_validation(tmp_path):
    source = ROOT / 'schemas'
    definition = yaml.safe_load((source / 'includes/protocols/static.yaml.i').read_text())
    entries = definition['static']['children']['include_schema']

    assert entries == [entry('protocols/route.yaml.i'), entry('protocols/route6.yaml.i')]

    for name in ('route', 'route6'):
        fragment = yaml.safe_load((source / f'includes/protocols/{name}.yaml.i').read_text())

        assert set(fragment) == {name}

    output = tmp_path / 'runtime'
    build_schemas(source, output)
    schema = Schema(json.loads((output / 'configuration.json').read_text()))

    for family, version, prefix, hop in [
        ('route', 4, '192.0.2.0/24', '192.0.2.1'),
        ('route6', 6, '2001:db8::/64', '2001:db8::1'),
    ]:
        node = schema.resolve(['protocols', 'static', family]).node

        for child, name in [(node, 'network'), (node['children']['next-hop'], 'inet-address' if version == 4 else 'ipv6-address')]:
            checks = child['validators']['checks']

            assert checks[name].get('args', {}) == ({'version': version} if name == 'network' else {})

        schema.resolve(['protocols', 'static', family, prefix, 'next-hop', hop])
        other_family = 'route6' if family == 'route' else 'route'

        with pytest.raises(ValidationError):
            schema.resolve(['protocols', 'static', other_family, prefix])


def test_validator_arguments_can_be_replaced_and_validators_removed_without_affecting_others(tmp_path):
    write(tmp_path / 'base.yaml.i', {'validators': {
        'text': {}, 'network': {'version': 4},
    }})
    source = write(tmp_path / 'source.yaml', include('base.yaml.i',
        replace={'/network/version': 6}, remove=['/text']))

    assert SchemaBuilder(tmp_path).resolve_file(source) == {'validators': {'network': {'version': 6}}}


def test_pointer_escaping_array_edits_and_include_in_edit_value(tmp_path):
    write(tmp_path / 'base.yaml.i', {'base': {'hints': {'a/b~c': 'old'}, 'callbacks': ['first', 'second']}})
    write(tmp_path / 'child.yaml.i', {'child': {'kind': 'leaf_node', 'description': 'Added child'}})
    source = write(tmp_path / 'source.yaml', include('base.yaml.i',
        remove=['/callbacks/0'], replace={'/hints/a~1b~0c': 'new', '/callbacks/0': 'updated'},
        add={'/callbacks/-': 'last', '/children': include('child.yaml.i')}))
    result = SchemaBuilder(tmp_path).resolve_file(source)['base']

    assert result == {'hints': {'a/b~c': 'new'}, 'callbacks': ['updated', 'last'],
                      'children': {'child': {'kind': 'leaf_node', 'description': 'Added child'}}}


@pytest.mark.parametrize('operations,message', [
    ({'add': {'/description': 'new'}}, 'already exists'),
    ({'replace': {'/missing': 'new'}}, 'does not exist'),
    ({'remove': ['/missing']}, 'does not exist'),
    ({'add': {'/missing/child': 1}}, 'does not exist'),
    ({'replace': {'/description/child': 1}}, 'does not exist'),
    ({'replace': {'description': 'new'}}, 'JSON Pointer'),
    ({'replace': {'': {}}}, 'JSON Pointer'),
    ({'replace': {'/bad~2key': 1}}, 'escape'),
    ({'remove': '/description'}, 'list of JSON Pointers'),
    ({'remove': [1]}, 'list of JSON Pointers'),
    ({'add': []}, 'map JSON Pointers'),
    ({'replace': []}, 'map JSON Pointers'),
    ({'replace': {'/list/01': 1}}, 'does not exist'),
    ({'remove': ['/list/2']}, 'does not exist'),
    ({'remove': ['/list/-1']}, 'does not exist'),
    ({'add': {'/list/0': 1}}, 'append to a list'),
    ({'typo': {}}, 'supports only'),
])
def test_invalid_modifications_fail_with_source_context(tmp_path, operations, message):
    write(tmp_path / 'base.yaml.i', {'base': {'description': 'old', 'list': [0]}})
    source = write(tmp_path / 'source.yaml', include('base.yaml.i', **operations))

    with pytest.raises(SchemaBuildError, match=message) as error:
        SchemaBuilder(tmp_path).resolve_file(source)

    assert 'source.yaml' in str(error.value)


@pytest.mark.parametrize('local_first', [True, False])
def test_local_collisions_are_rejected_regardless_of_order(tmp_path, local_first):
    write(tmp_path / 'base.yaml.i', {'base': {'description': 'old'}})
    local, imported = {'base': {'description': 'new'}}, include('base.yaml.i')
    source = write(tmp_path / 'source.yaml', local | imported if local_first else imported | local)

    with pytest.raises(SchemaBuildError, match='base.*conflicts'):
        SchemaBuilder(tmp_path).resolve_file(source)


@pytest.mark.parametrize('spec', [None, 'base.yaml.i', {}, {'file': 'base.yaml.i'},
                                 [None], ['base.yaml.i'], [{}], [{'replace': {}}]])
def test_invalid_include_definition(tmp_path, spec):
    source = write(tmp_path / 'source.yaml', {'include_schema': spec})

    with pytest.raises(SchemaBuildError, match='include_schema.*(list|requires file)'):
        SchemaBuilder(tmp_path).resolve_file(source)


@pytest.mark.parametrize('name', ['../outside.yaml.i', '/outside.yaml.i', 'C:/outside.yaml.i',
                                  'folder\\base.yaml.i', 'base.json', '', None])
def test_include_paths_are_rooted_and_fragments_have_distinct_extension(tmp_path, name):
    source = write(tmp_path / 'source.yaml', include(name))

    with pytest.raises(SchemaBuildError, match='[Ii]nclude file'):
        SchemaBuilder(tmp_path).resolve_file(source)


def test_symlinks_cannot_escape_include_root(tmp_path):
    outside = write(tmp_path / 'outside.yaml.i', {})
    fragments = tmp_path / 'includes'
    fragments.mkdir()
    (fragments / 'linked.yaml.i').symlink_to(outside)
    source = write(tmp_path / 'source.yaml', include('linked.yaml.i'))

    with pytest.raises(SchemaBuildError, match='escapes'):
        SchemaBuilder(fragments).resolve_file(source)


def test_missing_include_and_cycles_show_chain(tmp_path):
    source = write(tmp_path / 'source.yaml', include('a.yaml.i'))
    builder = SchemaBuilder(tmp_path)

    with pytest.raises(SchemaBuildError, match='a.yaml.i'):
        builder.resolve_file(source)

    write(tmp_path / 'a.yaml.i', include('sub/b.yaml.i'))
    write(tmp_path / 'sub/b.yaml.i', include('a.yaml.i'))

    with pytest.raises(SchemaBuildError, match='Include cycle') as error:
        builder.resolve_file(source)

    assert all(name in str(error.value) for name in ['source.yaml', 'a.yaml.i', 'b.yaml.i'])


@pytest.mark.parametrize('text,message', [
    ('x: 1\nx: 2', 'Duplicate YAML key'),
    ('x: {nested: 1, nested: 2}', 'Duplicate YAML key'),
    ('true: value', 'keys must be strings'),
    ('10: value', 'keys must be strings'),
    ('? [a, b]\n: value', 'keys must be strings'),
    ('x: !!float .nan', 'Non-finite'),
    ('x: !!float .inf', 'Non-finite'),
    ('x: 1e999', 'Non-finite'),
    ('x: !!timestamp 2026-10-11', 'Unsupported YAML value type'),
    ('x: !!binary YQ==', 'Unsupported YAML value type'),
    ('x: !!set {a: null}', 'Unsupported YAML value type'),
    ('x: !!python/object:builtins.object {}', 'could not determine a constructor'),
    ('x: &cycle [*cycle]', 'Recursive YAML aliases'),
    ('x: &cycle {child: *cycle}', 'Recursive YAML aliases'),
    ('x: [', 'expected'),
    ('{}\n---\n{}', 'expected a single document'),
    ('[]', 'YAML mapping'),
    ('', 'YAML mapping'),
])
def test_invalid_yaml_is_rejected_with_source_context(tmp_path, text, message):
    source = tmp_path / 'source.yaml'
    source.write_text(text)

    with pytest.raises(SchemaBuildError, match=message) as error:
        SchemaBuilder(tmp_path).resolve_file(source)

    assert 'source.yaml' in str(error.value)


def test_yaml_scalars_preserve_json_types_and_literal_strings(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    (source / 'tree.yaml').write_text(r'''# YAML comments and block syntax are supported.
enabled: true
disabled: false
nothing: null
zero: 0
integer: -42
decimal: 1.25
exponent: 1e3
negative-exponent: -2E-2
numeric-string: '1500'
boolean-string: 'true'
null-string: 'null'
ambiguous: [on, off, yes, no, True, FALSE, 0123, 0x10, 12:34:56, 2026-10-11, .nan, ~]
pattern: '^eth\d+$'
text: |-
  Two lines:
  # retained in the description
choices:
  '10': Numeric choice
  'false': Boolean-looking choice
''', encoding='utf-8')
    output = tmp_path / 'output'
    build_schemas(source, output)
    actual = json.loads((output / 'tree.json').read_text())
    expected = {
        'enabled': True, 'disabled': False, 'nothing': None, 'zero': 0,
        'integer': -42, 'decimal': 1.25, 'exponent': 1000.0, 'negative-exponent': -0.02,
        'numeric-string': '1500', 'boolean-string': 'true', 'null-string': 'null',
        'ambiguous': ['on', 'off', 'yes', 'no', 'True', 'FALSE', '0123', '0x10',
                      '12:34:56', '2026-10-11', '.nan', '~'],
        'pattern': r'^eth\d+$', 'text': 'Two lines:\n# retained in the description',
        'choices': {'10': 'Numeric choice', 'false': 'Boolean-looking choice'},
    }

    # JSON comparison distinguishes bool/int and int/float as well as their values.
    assert json.dumps(actual, sort_keys=True) == json.dumps(expected, sort_keys=True)

    # The build loader must not change PyYAML behavior for other consumers.
    assert yaml.safe_load('flag: yes') == {'flag': True}


def test_nonrecursive_yaml_aliases_expand_to_independent_values(tmp_path):
    source = tmp_path / 'source.yaml'
    source.write_text('first: &shared {description: Original}\nsecond: *shared')
    result = SchemaBuilder(tmp_path).resolve_file(source)
    result['first']['description'] = 'Changed'

    assert result['second']['description'] == 'Original'


def test_build_validates_all_inputs_before_writing_and_rejects_directives_added_by_path(tmp_path):
    source, output = tmp_path / 'source', tmp_path / 'output'
    write(source / 'a.yaml', {'description': 'original'})
    build_schemas(source, output)
    write(source / 'a.yaml', {'description': 'changed'})
    write(source / 'includes/base.yaml.i', {'base': {}})
    write(source / 'z.yaml', include('base.yaml.i', add={'/include_schema': {'file': 'base.yaml.i'}}))

    with pytest.raises(SchemaBuildError, match='unresolved include_schema'):
        build_schemas(source, output)

    assert json.loads((output / 'a.json').read_text()) == {'description': 'original'}
    assert not (output / 'z.json').exists()


def test_build_is_repeatable_and_check_detects_stale_outputs(tmp_path):
    source, output = tmp_path / 'source', tmp_path / 'output'
    write(source / 'tree.yaml', {'description': 'Unicode: \u2013'})
    build_schemas(source, output)
    path = output / 'tree.json'
    initial = path.stat().st_mtime_ns, path.read_bytes()
    build_schemas(source, output)
    build_schemas(source, output, check=True)

    assert (path.stat().st_mtime_ns, path.read_bytes()) == initial

    path.write_text('{}')

    with pytest.raises(SchemaBuildError, match='stale: tree.json'):
        build_schemas(source, output, check=True)

    assert path.read_text() == '{}'

    path.unlink()

    with pytest.raises(SchemaBuildError, match='missing or stale'):
        build_schemas(source, output, check=True)

    with pytest.raises(SchemaBuildError, match='must differ'):
        build_schemas(source, source)

    with pytest.raises(SchemaBuildError, match='No schema sources'):
        build_schemas(tmp_path / 'missing', output)


def test_all_project_schemas_match_snapshots_and_load_with_existing_runtime(tmp_path):
    build_schemas(output=tmp_path)
    build_schemas(check=True)

    for path in sorted((ROOT / 'schemas').glob('*.yaml')):
        generated = json.loads((tmp_path / path.with_suffix('.json').name).read_text())

        assert 'include_schema' not in json.dumps(generated)
        bundled = ROOT / 'src' / 'nvyr' / 'schemas' / path.with_suffix('.json').name
        assert generated == json.loads(bundled.read_text())

        # Runtime derives exclusion branches; generated files contain only negatable metadata.
        assert Schema(generated).root == Schema.bundled(path.stem).root


def test_default_descriptions_follow_final_include_values_and_do_not_change_sources(tmp_path):
    source, output = tmp_path / 'source', tmp_path / 'output'
    fragment = write(source / 'includes/value.yaml.i', {'value': {'kind': 'leaf_node',
        'description': 'Shared value', 'default': {'mode': 'direct', 'value': 'original'}}})
    original = fragment.read_bytes()
    tree = {'kind': 'node', 'children': {
        'include_schema': [
            entry('value.yaml.i', replace={'/description': 'Overridden value', '/default/value': 'accept'}),
            entry('value.yaml.i', **{'as': 'removed'}, remove=['/default'])],
        'flag': {'kind': 'leaf_node', 'description': 'Flag', 'valueless': True, 'default': {'mode': 'always'}},
        'multi': {'kind': 'leaf_node', 'description': 'Addresses', 'multi': True,
                  'default': {'mode': 'direct', 'value': ['one', 'two']}},
        'nested': {'kind': 'node', 'children': {'zero': {'kind': 'leaf_node',
                   'description': 'Zero', 'default': {'value': 0}}}},
    }}
    config = write(source / 'configuration.yaml', tree)
    write(source / 'operational.yaml', tree)
    original_config = config.read_bytes()
    build_schemas(source, output)
    first = (output / 'configuration.json').read_bytes()
    children = json.loads(first)['children']

    assert children['value']['description'] == 'Overridden value (default: accept)'
    assert children['removed']['description'] == 'Shared value'
    assert children['flag']['description'] == 'Flag (default: true)'
    assert children['multi']['description'] == 'Addresses (default: ["one", "two"])'
    assert children['nested']['children']['zero']['description'] == 'Zero (default: 0)'
    assert json.loads((output / 'operational.json').read_text())['children']['value']['description'] == 'Overridden value'

    build_schemas(source, output)

    assert (output / 'configuration.json').read_bytes() == first
    assert fragment.read_bytes() == original and config.read_bytes() == original_config


def test_cli_works_outside_repository_and_failure_is_actionable(tmp_path):
    # Build before installation: ignore PYTHONPATH and user-site packages from the test runner.
    command = [sys.executable, '-I', str(ROOT / 'build_tools/schema_builder.py'), '--output', str(tmp_path / 'out')]
    result = subprocess.run(command, cwd=tmp_path, capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'out/configuration.json').exists()

    (tmp_path / 'out/configuration.json').write_text('{}')
    result = subprocess.run([*command, '--check'], cwd=tmp_path, capture_output=True, text=True)

    assert result.returncode == 1
    assert 'Schema build failed:' in result.stderr and 'configuration.json' in result.stderr
    assert 'Traceback' not in result.stderr
