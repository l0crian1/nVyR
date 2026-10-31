"""Signature dispatch, shell-free placeholder binding and operational integration."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from nvyr import opmode
from nvyr.errors import RouterError
from nvyr.helpers import access
from nvyr.schema import Schema


def script(source):
    namespace = {'__name__': 'example_op_script'}
    exec('from nvyr import opmode\n' + source, namespace)

    return namespace


def test_repeated_typed_options_defaults_and_invocation_isolation(capsys):
    namespace = script('''
@opmode.command
def show(interface: list[str] | None = None, count: list[int] = [7], delay: list[float] | None = None):
    result = repr((interface, count, delay))
    count.append(99)
    return result
''')
    opmode.run(['show', '--interface', 'eth0', '--interface', 'WAN Interface',
                '--count', '1', '--count', '2', '--delay', '.5'], namespace=namespace)
    assert capsys.readouterr().out == "(['eth0', 'WAN Interface'], [1, 2], [0.5])\n"

    for _ in range(2):
        opmode.run(['show'], namespace=namespace)
        assert capsys.readouterr().out == '(None, [7], None)\n'

    with pytest.raises(SystemExit) as error:
        opmode.run(['show', '--count', 'invalid'], namespace=namespace)
    assert error.value.code == 2
    assert 'invalid' in capsys.readouterr().err


def test_required_and_optional_positional_lists_and_required_named_list(capsys):
    namespace = script('''
@opmode.command
def show(names: list[str], *, counts: list[int]):
    return repr((names, counts))

@opmode.command
def defaults(numbers: list[int] = [3], /):
    return repr(numbers)
''')
    opmode.run(['show', 'eth0', 'eth1', '--counts', '1', '--counts', '2'], namespace=namespace)
    assert capsys.readouterr().out == "(['eth0', 'eth1'], [1, 2])\n"

    for values, expected in [([], '[3]\n'), (['5', '6'], '[5, 6]\n')]:
        opmode.run(['defaults', *values], namespace=namespace)
        assert capsys.readouterr().out == expected

    for values in (['show'], ['show', 'eth0'], ['show', '--counts', '1']):
        with pytest.raises(SystemExit) as error:
            opmode.run(values, namespace=namespace)
        assert error.value.code == 2


@pytest.mark.parametrize('annotation, default', [('list[bool]', 'None'), ('list[list[str]]', 'None'),
                                               ('list[int]', "['wrong']"), ('list[str]', "'wrong'")])
def test_invalid_list_signatures(annotation, default, capsys):
    namespace = script(f'@opmode.command\ndef show(value: {annotation} = {default}): pass')

    with pytest.raises(SystemExit) as error:
        opmode.run(['show'], namespace=namespace)

    assert error.value.code == 2
    assert 'Invalid operational script' in capsys.readouterr().err


def test_command_arguments_reuses_schema_for_normal_multi_and_valueless_nodes():
    schema = Schema({'kind': 'node', 'children': {'probe': {
        'kind': 'tag_node', 'anchor': True, 'command': {'argv': ['probe', '@line']},
        'children': {
            'interface': {'kind': 'leaf_node', 'multi': True},
            'numeric': {'kind': 'leaf_node', 'valueless': True},
            'transport': {'kind': 'node', 'children': {'port': {'kind': 'leaf_node'}}},
        }}}})
    mapping = {'interface': '--interface', 'numeric': ['--format', 'numeric'], ('transport', 'port'): '--port'}

    path, argv = opmode.command_arguments(
        'ru pro "some target" int "WAN Interface" num transport port 123 int eth1', mapping, schema=schema)

    assert path == ('probe', 'some target')
    assert argv == ['--interface', 'WAN Interface', '--format', 'numeric', '--port', '123', '--interface', 'eth1']
    assert opmode.command_arguments('probe target', mapping, schema=schema) == (('probe', 'target'), [])

    with pytest.raises(RouterError, match='mapping'):
        opmode.command_arguments('probe target numeric', {}, schema=schema)
    with pytest.raises(RouterError):
        opmode.command_arguments('probe target transport', mapping, schema=schema)
    with pytest.raises(ValueError, match='mapping'):
        opmode.command_arguments('probe target numeric', {'numeric': ('-n',)}, schema=schema)


def test_command_argument_functions_receive_validated_values_and_flags():
    schema = Schema({'kind': 'node', 'children': {'probe': {
        'kind': 'tag_node', 'anchor': True, 'command': {'argv': ['probe', '@line']},
        'children': {
            'dscp': {'kind': 'leaf_node', 'multi': True, 'validators': {'checks': {
                'integer-range': {'name': 'integer-range', 'args': {'minimum': 0, 'maximum': 63}}}}},
            'numeric': {'kind': 'leaf_node', 'valueless': True},
        }}}})
    seen = []

    def numeric(value):
        seen.append(value)
        return []

    mapping = {'dscp': lambda value: ['-t', str(int(value) * 4)], 'numeric': numeric}
    path, argv = opmode.command_arguments('probe target dscp 1 numeric dscp 46', mapping, schema=schema)

    assert path == ('probe', 'target')
    assert argv == ['-t', '4', '-t', '184']
    assert seen == [True]

    with pytest.raises(RouterError):
        opmode.command_arguments('probe target dscp 64 numeric', mapping, schema=schema)
    assert seen == [True]

    for invalid in ('-t', None, [1], ['bad\x00arg']):
        with pytest.raises(ValueError, match='function must return a list of strings'):
            opmode.command_arguments('probe target numeric', {'numeric': lambda value: invalid}, schema=schema)


def test_signature_defaults_flags_aliases_and_explicit_registration(capsys):
    namespace = script('''
@opmode.command
def show(intf_name=None, detail=False, statistics=False, enabled=True):
    return repr((intf_name, detail, statistics, enabled))

def helper():
    raise AssertionError('must not be exposed')

@opmode.command
def _private():
    raise AssertionError('must not be exposed')
''')

    # Even another script's explicitly marked command must not leak through imports.
    from nvyr.op_scripts.interfaces import show

    namespace['imported'] = show
    opmode.run(['show'], namespace=namespace)

    assert capsys.readouterr().out == '(None, False, False, True)\n'

    opmode.run(['show', '--intf_name', 'eth1', '--detail', '--statistics', '--no-enabled'], namespace=namespace)

    assert capsys.readouterr().out == "('eth1', True, True, False)\n"

    opmode.run(['show', '--intf-name', 'eth2', '--no-detail'], namespace=namespace)

    assert capsys.readouterr().out == "('eth2', False, False, True)\n"

    for name in ('helper', '_private', 'imported', 'missing'):
        with pytest.raises(SystemExit) as error:
            opmode.run([name], namespace=namespace)

        assert error.value.code == 2
        assert 'invalid choice' in capsys.readouterr().err


def test_required_keyword_only_positional_only_and_optional_annotations(capsys):
    namespace = script('''
@opmode.command
def show(name, /, count: int = 1, delay: float | None = None, *, family: int):
    return repr((name, count, delay, family))
''')
    opmode.run(['show', 'eth0', '--count', '4', '--delay', '.5', '--family', '6'], namespace=namespace)

    assert capsys.readouterr().out == "('eth0', 4, 0.5, 6)\n"

    for argv in (['show'], ['show', 'eth0'], ['show', 'eth0', '--family', 'six'],
                 ['show', 'eth0', '--fam', '6'], ['show', 'eth0', '--family', '6', '--surprise']):
        with pytest.raises(SystemExit) as error:
            opmode.run(argv, namespace=namespace)

        assert error.value.code == 2
        assert 'error:' in capsys.readouterr().err


def test_main_namespace_required_normal_parameter_and_no_reserved_parameter_names(capsys, monkeypatch):
    namespace = script('''
@opmode.command
def show(_function, mode='brief'):
    return _function + ':' + mode
''')

    import types

    monkeypatch.setitem(sys.modules, '__main__', types.SimpleNamespace(**namespace))
    monkeypatch.setattr(sys, 'argv', ['interfaces.py', 'show', 'eth0', '--mode', 'detail'])
    opmode.run()

    assert capsys.readouterr().out == 'eth0:detail\n'


@pytest.mark.parametrize('source', [
    '@opmode.command\ndef show(*args): pass',
    '@opmode.command\ndef show(**kwargs): pass',
    '@opmode.command\ndef show(value: list): pass',
    '@opmode.command\ndef show(detail: bool): pass',
    '@opmode.command\ndef show(help=False): pass',
    '@opmode.command\nasync def show(): pass',
    '@opmode.command\ndef show(): yield 1',
    'def helper(): pass',
])
def test_unsupported_signatures_fail_before_function_execution(source, capsys):
    with pytest.raises(SystemExit) as error:
        opmode.run(['show'], namespace=script(source))

    assert error.value.code == 2
    assert 'Invalid operational script:' in capsys.readouterr().err


def test_help_and_operational_errors_are_readable(capsys):
    namespace = script('''
from nvyr.errors import RouterError
@opmode.command
def show(detail=False):
    """Show interface state."""
    raise RouterError('Interface is unavailable')
''')

    with pytest.raises(SystemExit) as error:
        opmode.run(['show', '--help'], namespace=namespace)

    assert error.value.code == 0

    help_text = capsys.readouterr().out

    assert 'Show interface state.' in help_text and '--no-detail' in help_text

    with pytest.raises(SystemExit) as error:
        opmode.run(['show'], namespace=namespace)

    assert error.value.code == 1
    assert capsys.readouterr().err == 'Interface is unavailable\n'


def test_printing_function_does_not_print_none(capsys):
    opmode.run(['show'], namespace=script('@opmode.command\ndef show(): print("hello")'))

    assert capsys.readouterr().out == 'hello\n'


def echo_schema(argv):
    return Schema({'kind': 'node', 'children': {'show': {'kind': 'node', 'children': {
        'echo': {'kind': 'leaf_node', 'command': {'argv': argv, 'timeout': 7}}}}}})


def test_original_tokens_quotes_line_pipeline_and_run_are_not_reconstructed(controller, session, monkeypatch):
    calls = []

    def capture(argv, **kwargs):
        calls.append((argv, kwargs))
        return 'hello\n'

    monkeypatch.setattr('nvyr.controller.cmd', capture)
    controller.operational = echo_schema(['echo', '@1', '@2', '@3', '@line', '@3', '@@literal'])
    line = '  sh ec "WAN Interface|literal"  | count'

    assert controller.execute(line)['text'] == '1\n'
    assert calls[-1] == (['echo', 'sh', 'ec', 'WAN Interface|literal', '  sh ec "WAN Interface|literal"', 'WAN Interface|literal', '@literal'],
                        {'timeout': 7, 'env': dict(os.environ, NVYR_SESSION_TTY='')})

    line = 'run sh ec "quoted value"'
    controller.execute(line, session)

    assert calls[-1][0] == ['echo', 'sh', 'ec', 'quoted value', line, 'quoted value', '@literal']


@pytest.mark.parametrize('placeholder', ['@value', '@0', '@-1', '@01', '@missing', '@', '@99', '@' + '9' * 5000])
def test_bad_or_missing_placeholders_fail_without_a_subprocess(controller, monkeypatch, placeholder):
    controller.operational = echo_schema(['echo', placeholder])

    def must_not_run(*args, **kwargs):
        pytest.fail('Invalid placeholders reached subprocess execution')

    monkeypatch.setattr('nvyr.controller.cmd', must_not_run)

    with pytest.raises(RouterError):
        controller.execute('show echo value')


def test_output_pipeline_tokens_do_not_satisfy_missing_command_arguments(controller, monkeypatch):
    controller.operational = echo_schema(['echo', '@4'])

    with pytest.raises(RouterError, match='token 4'):
        controller.execute('show echo value | count')


@pytest.mark.parametrize('configuration_mode', [False, True])
@pytest.mark.parametrize('stream', [False, True])
def test_line_exclusions_share_original_positions_and_dispatch(controller, session, monkeypatch, configuration_mode, stream):
    from nvyr.lexer import lex

    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'hello\n')
    controller.operational = echo_schema(['echo', '@line-1', '@line-1-2', '@line-3', '@line-2-3', '@line', '@3', '@@line-1'])
    controller.operational.root['children']['show']['children']['echo']['command']['stream'] = stream
    prefix = 'run ' if configuration_mode else ''
    suffix = '' if stream else ' | count'
    value = '"WAN Interface|literal"'
    line = prefix + '  sh ec ' + value + suffix
    result = controller.execute(line, session if configuration_mode else None)
    argv = result['argv'] if stream else calls[-1]

    assert argv == ['echo', prefix + '   ec ' + value,
                    prefix + '   ' + value,
                    prefix + '  sh ec ',
                    prefix + '  sh ', prefix + '  sh ec ' + value, 'WAN Interface|literal', '@line-1']
    assert lex(argv[2])[-1].value == 'WAN Interface|literal'


@pytest.mark.parametrize('placeholder', [
    '@line-', '@line-0', '@line-01', '@line--1', '@line-1-0', '@line-3-2',
    '@line-1-2-3', '@line-4', '@line-1-4', '@line-' + '9' * 5000,
])
@pytest.mark.parametrize('stream', [False, True])
def test_bad_line_exclusions_fail_before_captured_or_streaming_execution(controller, monkeypatch, placeholder, stream):
    controller.operational = echo_schema(['echo', placeholder])
    controller.operational.root['children']['show']['children']['echo']['command']['stream'] = stream
    monkeypatch.setattr('nvyr.controller.cmd', lambda *args, **kwargs: pytest.fail('Invalid exclusion executed'))

    with pytest.raises(RouterError):
        controller.execute('show echo value')


def test_excluded_line_reaches_script_as_one_argument_without_shell_expansion(controller, tmp_path):
    from nvyr.lexer import quote

    marker = tmp_path / 'must-not-exist'
    value = f'$(touch {marker}); "quoted" \\ @line-1'
    controller.operational = echo_schema([sys.executable, '-c', 'import json,sys; print(json.dumps(sys.argv[1:]))',
                                         '@line-1-2', '@line-1-3'])
    line = 'show echo ' + quote(value)

    assert json.loads(controller.execute(line)['text']) == [' ' + quote(value), '']
    assert not marker.exists()


def test_real_argv_round_trip_has_no_shell_expansion(controller, tmp_path):
    marker = tmp_path/'must-not-exist'
    value = f'$(touch {marker}); "quoted" \\ @line'
    controller.operational = echo_schema([sys.executable, '-c', 'import json,sys; print(json.dumps(sys.argv[1:]))', '@3', '@line'])

    from nvyr.lexer import quote

    line = 'show echo ' + quote(value)

    assert json.loads(controller.execute(line)['text']) == [value, line]
    assert not marker.exists()
    assert json.loads(controller.execute('show echo ""')['text']) == ['', 'show echo ""']


@pytest.mark.parametrize('command', [
    {'argv': ['@1']}, {'argv': ['']},
    {'argv': ['show'], 'script': 'interfaces'},
    {'argv': ['show'], 'script': '../interfaces'},
    {'argv': ['show'], 'script': 'interfaces.py'},
    {'argv': ['show'], 'script': 1},
    {'argv': ['show'], 'value_argv': ['show', '--selector', '@value']},
    {'argv': ['show'], 'value_argv': []},
    {'argv': ['show'], 'value_argv': ['@value']},
])
def test_bad_command_templates_are_rejected_when_schema_loads(command):
    with pytest.raises(ValueError):
        Schema({'kind': 'leaf_node', 'optional_value': True, 'command': command})


@pytest.fixture
def fake_op_script(tmp_path, monkeypatch):
    from build_tools.op_scripts import install_scripts

    source = tmp_path / 'op_scripts'
    source.mkdir()
    (source / 'interfaces.py').write_text('''#!/usr/bin/env python3
from nvyr import opmode
@opmode.command
def show(intf_name=None, intf_type=None, detail=False, statistics=False):
    return ' '.join(part for part in (intf_type, intf_name or 'all',
                                     'detail' if detail else '',
                                     'statistics' if statistics else '') if part)
if __name__ == '__main__':
    opmode.run()
''')
    install_scripts(source, tmp_path / 'bin')
    monkeypatch.setenv('PATH', str(tmp_path / 'bin') + os.pathsep + os.environ['PATH'])


def test_script_dispatch_works_for_all_modes_and_operator(controller, session, monkeypatch, fake_op_script):
    expected = {'show interfaces': 'all\n',
                'show interfaces eth0': 'eth0\n',
                'show interfaces dummy': 'dummy\n'}

    for command, output in expected.items():
        assert controller.execute(command)['text'] == output
        assert controller.execute('run ' + command, session)['text'] == output

    token = access.role.set('read-only')

    try:
        assert controller.execute('show interfaces eth0')['text'] == expected['show interfaces eth0']
    finally:
        access.role.reset(token)

    controller.operational.suggestors['interfaces'] = lambda: ['eth0', 'eth1']
    completion = controller.completion('show interfaces ', explicit=True)

    assert {'ethernet', 'eth0', 'eth1', '<Enter>'} <= set(dict(completion['candidates']))
    assert controller.completion('show interfaces ethe')['replacement'] == 'ethernet'
    assert controller.completion('run show interfaces eth0', session, explicit=True)['candidates'][-1][0] == '<Enter>'
    assert controller.execute('show interfaces | count')['text'] == '1\n'


@pytest.mark.parametrize('intf_type', [None, 'ethernet'])
@pytest.mark.parametrize('name', [None, 'eth0'])
@pytest.mark.parametrize('flags', ['', 'detail', 'statistics'])
def test_optional_interface_tags_dispatch_positions_and_included_commands(
        controller, session, fake_op_script, intf_type, name, flags):
    from nvyr.helpers.process import operational_argv
    from nvyr.lexer import lex

    line = ' '.join(part for part in ('show interfaces', intf_type, name, flags) if part)
    cursor = controller.operational.operational(lex(line))
    placeholder = '@4' if intf_type else '@3'

    assert placeholder in cursor.node['command']['argv']
    assert '@value' not in cursor.node['command']['argv']

    expected = ['interfaces.nvyr.op', 'show']

    if intf_type:
        expected.extend(['--intf_type', intf_type])

    if name:
        expected.extend(['--intf_name', name])

    expected.extend('--' + flag for flag in flags.split())

    assert operational_argv(cursor.node['command'], lex(line), line,
                            omitted_positions=cursor.omitted_positions) == expected

    output = ' '.join(part for part in (intf_type, name or 'all',
                                      'detail' if 'detail' in flags else '',
                                      'statistics' if 'statistics' in flags else '') if part) + '\n'

    assert controller.execute(line)['text'] == output
    assert controller.execute('run ' + line, session)['text'] == output


@pytest.mark.parametrize('line', [
    'show interfaces ', 'show interfaces eth0 ',
    'show interfaces ethernet ', 'show interfaces ethernet eth0 ',
])
def test_interface_tag_completion_and_help(controller, session, line):
    controller.operational.suggestors['interfaces'] = lambda prefix='': [
        name for name in ['eth0', 'eth1', 'dum0'] if name.startswith(prefix)]

    for wrapper, mode in [('', None), ('run ', session)]:
        text = wrapper + line

        for options in ({'explicit': True}, {'tab': True}, {}):
            completion = controller.completion(text, mode, **options)
            names = dict(completion['candidates'])

            assert {'detail', 'statistics'} <= names.keys()

            if options.get('explicit'):
                assert '<Enter>' in names

        assert controller.completion(text + 'det', mode)['extension'] == 'ail'
        assert controller.completion(text + 'det', mode, tab=True)['replacement'] == 'detail'
        assert controller.completion(text + 'stat', mode, space=True)['replacement'] == 'statistics'

    if line == 'show interfaces ':
        assert {'ethernet', 'eth0', 'eth1', 'dum0'} <= names.keys()
    elif line == 'show interfaces ethernet ':
        assert {'eth0', 'eth1'} <= names.keys() and 'dum0' not in names
    else:
        assert 'ethernet' not in names and 'eth1' not in names


@pytest.mark.parametrize('line', [
    'show interfaces ethernet dum0',
    'show interfaces ethernet eth0 detail detail',
    'show interfaces detail eth0',
    'show interfaces eth0 ethernet eth1',
    'show interfaces detail ethernet eth0',
    'show interfaces detail statistics',
    'show interfaces statistics detail',
    'show interfaces eth0 detail statistics',
    'show interfaces ethernet eth0 statistics detail',
])
def test_invalid_interface_arguments_do_not_execute(controller, monkeypatch, line):
    monkeypatch.setattr('nvyr.controller.cmd', lambda *a, **k: pytest.fail('Invalid command executed'))

    with pytest.raises(RouterError):
        controller.execute(line)

    assert '<Enter>' not in dict(controller.completion(line, explicit=True)['candidates'])


def test_ethernet_child_precedence_abbreviation_and_invalid_name_navigation(controller, fake_op_script):
    assert controller.execute('sho int eth eth0 det')['text'] == 'ethernet eth0 detail\n'
    assert controller.execute('sho int stat')['text'] == 'all statistics\n'

    for text in ('show interfaces ethernet dum0', 'show interfaces ethernet dum0 '):
        completion = controller.completion(text, explicit=True)

        assert {'detail', 'statistics'} <= dict(completion['candidates']).keys()
        assert '<Enter>' not in dict(completion['candidates'])

    assert controller.completion('show interfaces ethernet', explicit=True)['hints'] == [('ethN', 'Ethernet interface name')]


def test_optional_tag_streaming_uses_the_same_positions(controller, session):
    node = controller.operational.root['children']['show']['children']['interfaces']
    node['children']['detail']['command']['stream'] = True

    for wrapper, mode in [('', None), ('run ', session)]:
        for suffix, arguments in [('detail', ['--detail']),
                                  ('eth0 detail', ['--intf_name', 'eth0', '--detail'])]:
            result = controller.execute(wrapper + 'show interfaces ' + suffix, mode)

            assert result['event'] == 'command'
            assert result['argv'] == ['interfaces.nvyr.op', 'show', *arguments]


def test_existing_argv_commands_still_use_the_same_helper(controller, monkeypatch):
    seen = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: seen.append(argv) or 'up\n')

    assert controller.execute('show uptime')['text'] == 'up\n'
    assert seen == [['uptime']]


def test_user_script_still_runs_as_module_and_as_python_file():
    path = Path(__file__).resolve().parents[1]/'src/nvyr/op_scripts/interfaces.py'

    for prefix in ([sys.executable, '-m', 'nvyr.op_scripts.interfaces'], [sys.executable, str(path)]):
        result = subprocess.run([*prefix, 'show', '--help'], capture_output=True, text=True, check=True)

        assert '--intf-name' in result.stdout
