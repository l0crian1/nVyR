"""Operational authoring, placeholder binding and installed executable contracts."""

import json
import os
from pathlib import Path
import shutil
import subprocess

import pytest

from build_tools.schema_builder import build_schemas, SchemaBuilder, SchemaBuildError
from build_tools.op_scripts import install_scripts
from nvyr.helpers.process import operational_argv
from nvyr.lexer import lex, quote
from nvyr.schema import Schema


def compile_source(tmp_path, text, **options):
    source = tmp_path / 'schemas'
    source.mkdir(exist_ok=True)
    (source / 'operational.yaml').write_text(text)
    build_schemas(source, tmp_path / 'runtime', **options)
    result = json.loads((tmp_path / 'runtime/operational.json').read_text())
    Schema(result)

    return result


def test_optional_value_omits_only_its_option_and_preserves_empty_strings(tmp_path):
    node = compile_source(tmp_path, """kind: leaf_node
optional_value: true
command: ['interfaces.nvyr.op', 'show', '--detail', '--intf_name', '@3', '--statistics']
timeout: 10
stream: true
""")
    command = node['command']

    assert command['timeout'] == 10 and command['stream'] is True
    assert 'timeout' not in node and 'stream' not in node
    assert operational_argv(command, lex('show interfaces'), 'show interfaces', omitted_positions=(3,)) == [
        'interfaces.nvyr.op', 'show', '--detail', '--statistics']

    for value in ('eth0', '', 'WAN Interface', '@line', '$(echo unsafe)'):
        line = 'show interfaces ' + quote(value)

        assert operational_argv(command, lex(line), line) == [
            'interfaces.nvyr.op', 'show', '--detail', '--intf_name', value, '--statistics']


def test_optional_positional_value_and_multiple_occurrences(tmp_path):
    node = compile_source(tmp_path, """kind: leaf_node
optional_value: true
command: ['echo', '@2', '--copy', '@2', '@1', '@line']
""")

    assert operational_argv(node['command'], lex('show'), 'show', omitted_positions=(2,)) == ['echo', 'show', 'show']
    assert operational_argv(node['command'], lex('show x'), 'show x') == [
        'echo', 'x', '--copy', 'x', 'show', 'show x']


@pytest.mark.parametrize('line,intf,vif', [
    ('show interfaces ethernet eth0 vif 200', 'eth0', '200'),
    ('sh int ethernet "WAN Interface" vif "200; echo nope"', 'WAN Interface', '200; echo nope'),
])
def test_multiple_original_positions_and_whole_line(tmp_path, line, intf, vif):
    scripts = tmp_path / 'op_scripts'
    scripts.mkdir()
    (scripts / 'probe.py').write_text('from nvyr import opmode\n@opmode.command\n'
                                    'def show(intf_name=None, vif=None, cmd=None): pass\n')
    node = compile_source(tmp_path, """kind: node
command: ['probe.nvyr.op', 'show', '--intf_name', '@4', '--vif', '@6', '--cmd', '@line']
""", op_scripts=scripts)

    assert operational_argv(node['command'], lex(line), line) == [
        'probe.nvyr.op', 'show', '--intf_name', intf, '--vif', vif, '--cmd', line]


def test_exclusions_survive_schema_generation_and_optional_argument_omission(tmp_path):
    node = compile_source(tmp_path, """kind: leaf_node
optional_value: true
command: ['echo', '--selector', '@3', '@line-1', '@line']
""")
    line = 'show interfaces'

    assert operational_argv(node['command'], lex(line), line, omitted_positions=(3,)) == [
        'echo', ' interfaces', line]

    line = 'show interfaces ""'

    assert operational_argv(node['command'], lex(line), line) == ['echo', '--selector', '', ' interfaces ""', line]


def test_exclusion_ranges_do_not_renumber_other_placeholders():
    line = 'show interfaces ethernet eth0 vif 200'
    command = {'argv': ['echo', '@line-1-4', '@line-2-5', '@line-6-6', '@6', '@line']}

    assert operational_argv(command, lex(line), line) == [
        'echo', ' vif 200', 'show  200', 'show interfaces ethernet eth0 vif ', '200', line]


@pytest.mark.parametrize('definition', [
    "command: ['echo', 12]", "command: ['echo', true]", "command: ['echo', null]",
    "command: ['echo', {}]", "command: ['echo', ['nested']]",
    "command: [echo]", "command: ['echo', unquoted]", "command: []",
    "command: echo", "command: {argv: ['echo']}", "command: ['@1']",
    "command: ['echo']\nscript: interfaces", "command: ['echo']\nargv: ['echo']",
    "command: ['echo']\nvalue_argv: ['echo']", "timeout: 10",
])
def test_invalid_authoring_rejected_by_builder(tmp_path, definition):
    with pytest.raises(SchemaBuildError, match='operational.yaml'):
        compile_source(tmp_path, 'kind: node\n' + definition)


def test_quoted_numeric_and_boolean_arguments_stay_strings(tmp_path):
    node = compile_source(tmp_path, '''kind: node
command: ['echo', '12', "true", 'null', '']
''')

    assert node['command']['argv'] == ['echo', '12', 'true', 'null', '']


def test_interface_includes_supply_commands_at_each_use_and_use_default_timeouts(tmp_path):
    root = Path(__file__).resolve().parents[1]
    includes = root / 'schemas/includes'
    builder = SchemaBuilder(includes)
    shared = builder.resolve_file(includes / 'operational/interface_options.yaml.i')['children']

    assert set(shared) == {'detail', 'statistics', 'offload', 'queues', 'hardware-statistics', 'transceiver'}
    assert all(set(node) == {'kind', 'description', 'valueless'} for node in shared.values())

    build_schemas(root / 'schemas', tmp_path)
    runtime = json.loads((tmp_path / 'operational.json').read_text())
    interface = runtime['children']['show']['children']['interfaces']
    ethernet = interface['children']['ethernet']

    for node, position, type_options in [(interface, '@3', []), (ethernet, '@4', ['--intf_type', 'ethernet'])]:
        assert 'anchor' not in node

        for name, original in shared.items():
            child = node['children'][name]

            assert {key: child[key] for key in original} == original
            if name in {'detail', 'statistics'}:
                expected = ['interfaces.nvyr.op', 'show', *type_options, '--intf_name', position, '--' + name]
            else:
                expected = ['interfaces.nvyr.op', 'hardware', name, *type_options, '--intf_name', position]
            assert child['command']['argv'] == expected

    def check_defaults(node):
        assert 'timeout' not in node

        if isinstance(node.get('command'), dict):
            assert 'timeout' not in node['command']

        for child in node.get('children', {}).values():
            check_defaults(child)

    # This contract belongs to interface commands; trace analysis has its own timeout.
    check_defaults(interface)


def test_include_commands_are_checked_and_lowered_after_edits(tmp_path):
    includes = tmp_path / 'schemas/includes'
    includes.mkdir(parents=True)
    fragment = includes / 'example.yaml.i'
    fragment.write_text("example:\n  kind: node\n  command: ['echo', 'first']\n")
    text = '''kind: node
children:
  include_schema:
  - file: example.yaml.i
    add:
      /command/-: 'second'
'''

    assert compile_source(tmp_path, text)['children']['example']['command']['argv'] == ['echo', 'first', 'second']

    with pytest.raises(SchemaBuildError, match='quoted strings'):
        compile_source(tmp_path, text.replace("'second'", 'second'))

    fragment.write_text('example:\n  kind: node\n  command: [echo]\n')

    with pytest.raises(SchemaBuildError, match='example.yaml.i'):
        compile_source(tmp_path, text)


@pytest.mark.parametrize('name', ['configure', 'configure-draft', 'running', 'version', 'license', 'exit', 'shell'])
def test_builtin_handlers_keep_runtime_dispatch(tmp_path, name):
    node = compile_source(tmp_path, f"kind: node\ncommand: ['{name}']\n")

    assert node['command'] == name


def test_installer_discovers_scripts_sets_modes_and_uses_path_without_shell(tmp_path):
    stage = tmp_path / 'stage'
    source, bindir = stage / 'usr/lib/nvyr/op_scripts', stage / 'usr/bin'
    source.mkdir(parents=True)
    script = source / 'example.py'
    script.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n')
    script.chmod(0o644)
    (source / '__init__.py').write_text('')
    (source / '_helper.py').write_text('')
    install_scripts(source, bindir)
    install_scripts(source, bindir)
    link = bindir / 'example.nvyr.op'

    assert link.is_symlink() and not os.path.isabs(os.readlink(link))
    assert script.stat().st_mode & 0o777 == 0o755
    assert list(bindir.iterdir()) == [link]

    # Relative symlinks must remain valid after the package staging root moves.
    installed = tmp_path / 'installed'
    shutil.move(stage, installed)
    environment = dict(os.environ, PATH=str(installed / 'usr/bin') + os.pathsep + os.environ['PATH'])
    value = '$(touch should-not-exist); "quoted value"'
    result = subprocess.run(['example.nvyr.op', value], env=environment, text=True, capture_output=True, check=True)

    assert json.loads(result.stdout) == [value]


def test_installer_rejects_missing_shebang_and_existing_executable(tmp_path):
    source = tmp_path / 'scripts'
    source.mkdir()
    script = source / 'example.py'
    script.write_text('print("hello")\n')

    with pytest.raises(ValueError, match='shebang|require'):
        install_scripts(source, tmp_path / 'bin')

    script.write_text('#!/usr/bin/env python3\nprint("hello")\n')
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    (bindir / 'example.nvyr.op').write_text('owned by something else')

    with pytest.raises(ValueError, match='Refusing'):
        install_scripts(source, bindir)


def test_packaging_installs_operational_links_and_real_script_is_executable():
    root = Path(__file__).resolve().parents[1]
    packaging = (root / 'scripts/build-deb.sh').read_text()

    assert 'build_tools/op_scripts.py' in packaging

    script = root / 'src/nvyr/op_scripts/interfaces.py'

    assert script.read_bytes().startswith(b'#!/usr/bin/env python3\n')
