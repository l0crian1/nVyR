"""Check script/function/argument mappings without importing operational code."""

import json

import pytest

from build_tools.schema_builder import SchemaBuildError, build_schemas


@pytest.fixture
def mapping_build(tmp_path):
    source = tmp_path / 'schemas'
    scripts = tmp_path / 'op_scripts'
    output = tmp_path / 'output'
    source.mkdir()
    scripts.mkdir()
    (scripts / 'probe.py').write_text('''#!/usr/bin/env python3
from nvyr import opmode
import unavailable_router_dependency
raise AssertionError('Build must not execute script code')

@opmode.command
def show(name: str, *, interface: list[str] | None = None, count: list[int] | None = None, detail=False):
    raise AssertionError('Build must not call command functions')

def helper():
    pass

@opmode.command
def _private():
    pass
''')

    def build(arguments):
        (source / 'operational.yaml').write_text('kind: node\nchildren:\n  probe:\n'
            '    kind: leaf_node\n    command: ' + json.dumps(arguments) + '\n')
        build_schemas(source, output, op_scripts=scripts)
        return json.loads((output / 'operational.json').read_text())

    return build, scripts, output


def test_mapping_uses_shared_argument_registration_without_imports(mapping_build):
    build, _, _ = mapping_build
    arguments = ['probe.nvyr.op', 'show', '@2', '--interface', 'eth0', '--interface', '@3',
                 '--count', '@4', '--count', '5', '--detail']
    assert build(arguments)['children']['probe']['command']['argv'] == arguments

    for placeholder in ('@line', '@line-1', '@line-1-2'):
        assert build(['probe.nvyr.op', 'show', placeholder])


@pytest.mark.parametrize('arguments, error', [
    (['missing.nvyr.op', 'show'], 'does not exist'),
    (['probe.nvyr.op'], 'fixed'),
    (['probe.nvyr.op', '@1'], 'fixed'),
    (['probe.nvyr.op', 'missing'], 'public'),
    (['probe.nvyr.op', 'helper'], 'public'),
    (['probe.nvyr.op', '_private'], 'public'),
    (['probe.nvyr.op', 'show'], 'required'),
    (['probe.nvyr.op', 'show', '@1', '--inteface', '@2'], 'inteface'),
    (['probe.nvyr.op', 'show', '@1', '--interface'], 'expected one argument'),
    (['probe.nvyr.op', 'show', '@1', '--count', 'wrong'], 'invalid'),
    (['probe.nvyr.op', 'show', '@1', '--count', '@@wrong'], 'invalid'),
    (['probe.nvyr.op', 'show', '@1', '--count', '@value'], 'placeholder'),
    (['probe.nvyr.op', 'show', '@1', '--detail', 'true'], 'unrecognized'),
])
def test_invalid_mappings_identify_tree_path_and_do_not_replace_output(mapping_build, arguments, error):
    build, _, output = mapping_build
    build(['probe.nvyr.op', 'show', 'original'])
    before = (output / 'operational.json').read_bytes()

    with pytest.raises(SchemaBuildError, match=error) as failure:
        build(arguments)

    assert 'operational.yaml: probe:' in str(failure.value)
    assert arguments[0] in str(failure.value)
    assert (output / 'operational.json').read_bytes() == before


def test_signature_changes_checked_on_every_build_and_external_commands_untouched(mapping_build):
    build, scripts, _ = mapping_build
    build(['probe.nvyr.op', 'show', 'target', '--detail'])
    path = scripts / 'probe.py'
    path.write_text(path.read_text().replace('detail=False', 'statistics=False'))

    with pytest.raises(SchemaBuildError, match='detail'):
        build(['probe.nvyr.op', 'show', 'target', '--detail'])

    assert build(['vtysh', '-c', '@line'])['children']['probe']['command']['argv'] == ['vtysh', '-c', '@line']


def test_signature_expressions_are_not_executed(mapping_build):
    build, scripts, _ = mapping_build
    path = scripts / 'probe.py'
    path.write_text("from nvyr import opmode\n@opmode.command\ndef show(value=str()): pass\n")

    with pytest.raises(SchemaBuildError):
        build(['probe.nvyr.op', 'show'])


def test_help_mapping_follows_argparse_without_build_output(mapping_build, capsys):
    build, _, _ = mapping_build
    assert build(['probe.nvyr.op', 'show', '--help'])
    captured = capsys.readouterr()
    assert captured.out == captured.err == ''
