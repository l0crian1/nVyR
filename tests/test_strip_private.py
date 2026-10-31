"""Structured privacy masking, schema annotations and script-owned formatting."""

from copy import deepcopy
import json
import os
from pathlib import Path
import sys

import pytest

from nvyr import opmode
from nvyr.errors import ParseError
from nvyr.helpers.strip_private import (
    ConfigurationMasker, strip_ip, strip_ipv4, strip_ipv6, strip_mac,
    strip_password, strip_value,
)
from nvyr.pipeline import Output, Pipelines
from nvyr.schema import Schema


@pytest.mark.parametrize('function,value,masked', [
    (strip_ipv4, '1.1.1.1/32', '<ipv4>'),
    (strip_ipv4, '192.0.2.1-192.0.2.25', '<ipv4>'),
    (strip_ipv6, '2001:db8::1/64', '<ipv6>'),
    (strip_ip, 'fe80::1%eth0', '<ipv6>'),
    (strip_ip, 'dhcp', 'dhcp'),
    (strip_ip, 'eth0', 'eth0'),
    (strip_ipv4, '::1', '::1'),
    (strip_ipv6, '127.0.0.1', '127.0.0.1'),
    (strip_mac, '00:11:22:33:44:55', '<mac>'),
    (strip_password, '$y$secret-hash', '<password>'),
    (strip_value, 'Customer location', '<private>'),
])
def test_reusable_masks(function, value, masked):
    assert function(value, False) is value
    assert function(value, True) == masked


def test_masked_tags_remain_distinct_and_diffs_keep_changes():
    schema = Schema({'kind': 'node', 'children': {'route': {
        'kind': 'tag_node', 'strip_kind': 'ipv4', 'children': {
            'password': {'kind': 'leaf_node', 'strip_kind': 'password'}}}}})
    before = {'route': {'192.0.2.0/24': {'password': 'one'}, '198.51.100.0/24': {'password': 'two'}}}
    after = deepcopy(before)
    after['route']['192.0.2.0/24']['password'] = 'three'
    original = deepcopy((before, after))
    masker = ConfigurationMasker(schema)
    old, new = masker.tree(before), masker.tree(after)

    assert len(old['route']) == len(new['route']) == 2

    scope = masker.path(('route', '192.0.2.0/24'))

    assert scope[1] in old['route'] and scope[1] in new['route']

    pipelines = Pipelines(schema)
    output = pipelines.commands(Output(before=old, after=new, scope=scope), None).text

    assert output.startswith("set password '<password-")
    assert (before, after) == original

    full = pipelines.commands(Output(after=new), None).text

    assert full.count('set route ') == 2
    assert '192.0.2' not in full and '198.51.100' not in full


def test_bundled_annotations_cover_credentials_routes_nat_and_dns():
    schema = Schema.bundled()
    tree = {
        'system': {'login': {'user': {'admin': {'authentication': {'encrypted-password': '$y$private'}}}},
                   'name-server': ['1.1.1.1', '2606:4700:4700::1111', 'eth0']},
        'protocols': {'static': {'route': {'192.0.2.0/24': {'next-hop': {'192.0.2.1': {}}}},
                                 'route6': {'2001:db8::/64': {'next-hop': {'2001:db8::1': {}}}}}},
        'nat': {'source': {'rule': {'10': {'translation': {'address': '192.0.2.1-192.0.2.50'}}}}},
    }
    original = deepcopy(tree)
    masker = ConfigurationMasker(schema)
    masked = masker.tree(tree)
    text = json.dumps(masked)

    assert all(value not in text for value in ['admin', '$y$private', '1.1.1.1', '2606:', '192.0.2', '2001:db8'])
    assert masked['system']['name-server'][-1] == 'eth0'
    assert tree == original


@pytest.fixture
def configured_private(controller, engine, session, monkeypatch):
    monkeypatch.setattr('nvyr.helpers.interfaces.exists', lambda name: True)

    for command in [
        'set interfaces dummy dum0 address 192.0.2.10/24',
        'set interfaces dummy dum0 address 2001:db8::10/64',
        'set interfaces dummy dum0 mac 02:11:22:33:44:55',
        'set interfaces dummy dum0 description "Customer location"',
        'set system host-name customer-router',
    ]:
        controller.execute(command, session)

    engine.commit(session)
    engine.save(session)
    controller.execute('delete interfaces dummy dum0 address 192.0.2.10/24', session)
    controller.execute('set interfaces dummy dum0 address 198.51.100.10/24', session)
    controller.execute('set interfaces dummy dum0 description "New customer location"', session)

    return controller, engine, session


PRIVATE = ['192.0.2.10', '198.51.100.10', '2001:db8::10', '02:11:22:33:44:55',
           'Customer location', 'New customer location', 'customer-router']


@pytest.mark.parametrize('view', ['show', 'show running-configuration', 'show candidate-configuration',
                                 'compare', 'compare saved', 'compare 1'])
@pytest.mark.parametrize('suffix', [' | strip-private', ' | strip-private | commands', ' | commands | strip-private'])
def test_configuration_views(configured_private, view, suffix):
    controller, engine, session = configured_private
    original = deepcopy((engine.running, engine.view(session), engine.store.read('boot.json', {})))
    output = controller.execute(view + suffix, session)['text']

    assert all(value not in output for value in PRIVATE)

    if view not in {'compare saved'}:
        assert '<' in output

    assert (engine.running, engine.view(session), engine.store.read('boot.json', {})) == original
    assert '192.0.2.10' in controller.execute('show running-configuration', session)['text']


def test_scoped_commands_operational_running_and_other_modifiers(configured_private):
    controller, engine, session = configured_private
    controller.execute('edit interfaces dummy dum0', session)

    for view in ['show running-configuration', 'show candidate-configuration', 'compare']:
        text = controller.execute(view + ' | commands | strip-private', session)['text']

        assert 'interfaces dummy' not in text
        assert '<ipv4-' in text and all(value not in text for value in PRIVATE)

    text = controller.execute('show running-configuration address | strip-private | commands', session)['text']

    assert text.count('set address ') == 2

    exported = controller.execute('show running-configuration | commands | strip-private | match address | export masked.txt', session)

    assert exported['export'] == 'masked.txt' and exported['text'] == text
    assert controller.execute('show running-configuration | strip-private | commands | count', session)['text'] == '4\n'

    operational = controller.execute('show running-configuration | strip-private')['text']

    assert '<mac-' in operational and all(value not in operational for value in PRIVATE)
    assert 'strip-private' in dict(controller.completion('show | ', session)['candidates'])

    with pytest.raises(ParseError):
        controller.execute('set system host-name example | strip-private', session)


@pytest.mark.parametrize('line,expected', [
    ('show interfaces', ['show']),
    ('show interfaces eth0 detail', ['show', '--intf_name', 'eth0', '--detail']),
    ('show interfaces ethernet statistics', ['show', '--intf_type', 'ethernet', '--statistics']),
])
def test_script_flag_dispatch_preserves_optional_positions(controller, session, monkeypatch, line, expected):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs:
                        calls.append(argv) or 'script output 192.0.2.1\n')

    for prefix, context in [('', None), ('run ', session)]:
        result = controller.execute(prefix + line + ' | strip-private', context)

        assert calls[-1] == ['interfaces.nvyr.op', expected[0], '--strip-private', *expected[1:]]

        # The framework must not guess at or rewrite the script's output.
        assert result['text'] == 'script output 192.0.2.1\n'

        controller.execute(prefix + line, context)

        assert '--strip-private' not in calls[-1]


def test_line_placeholder_and_streaming(controller):
    controller.operational = Schema({'kind': 'node', 'children': {'report': {
        'kind': 'node', 'command': {'argv': ['example.nvyr.op', 'show', '@line'], 'stream': True}}}})
    line = 'report | strip-private'

    with pytest.raises(ParseError, match='not supported on streaming commands'):
        controller.execute(line)


def test_installed_script_receives_boolean_and_original_line(controller, tmp_path, monkeypatch):
    from build_tools.op_scripts import install_scripts

    source = tmp_path / 'scripts'
    source.mkdir()
    (source / 'example.py').write_text('''#!/usr/bin/env python3
import json
from nvyr import opmode
from nvyr.helpers.strip_private import strip_ip
@opmode.command
def show(line: str, strip_private: bool = False):
    return json.dumps([strip_private, strip_ip('192.0.2.1', strip_private), line])
opmode.run()
''')
    executable = tmp_path / 'bin'
    install_scripts(source, executable)
    monkeypatch.setenv('PATH', str(executable) + os.pathsep + str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH'])
    monkeypatch.setenv('PYTHONPATH', str(Path('src').resolve()))
    controller.operational = Schema({'kind': 'node', 'children': {'report': {
        'kind': 'leaf_node', 'command': {'argv': ['example.nvyr.op', 'show', '@line']}}}})
    line = 'report "value with spaces"'

    assert json.loads(controller.execute(line)['text']) == [False, '192.0.2.1', line]

    assert json.loads(controller.execute(line + ' | strip-private')['text']) == [True, '<ipv4>', line]


def test_direct_executable_cannot_silently_ignore_masking(controller, monkeypatch):
    controller.operational = Schema({'kind': 'node', 'children': {'show': {
        'kind': 'node', 'command': {'argv': ['ip', 'address', 'show']}}}})
    monkeypatch.setattr('nvyr.controller.cmd', lambda *a, **kw: pytest.fail('must not execute'))

    with pytest.raises(ParseError, match='supports masking'):
        controller.execute('show | strip-private')


@pytest.mark.parametrize('kind', ['typo', [], None, True])
def test_invalid_strip_kind_rejected(kind):
    with pytest.raises(ValueError, match='strip_kind'):
        Schema({'kind': 'leaf_node', 'strip_kind': kind})


@pytest.mark.parametrize('raw,detail,statistics', [(False, False, False), (False, True, False),
                                                 (False, False, True), (True, False, False)])
def test_interface_script_masks_before_formatting_without_changing_input(monkeypatch, capsys, raw, detail, statistics):
    from nvyr.op_scripts import interfaces

    kernel = [{'ifname': 'eth0', 'address': '02:11:22:33:44:55', 'broadcast': 'ff:ff:ff:ff:ff:ff',
               'flags': ['UP'], 'operstate': 'UP', 'ifalias': 'Customer location',
               'stats64': {'rx': {}, 'tx': {}}, 'addr_info': [
                   {'local': '192.0.2.10', 'broadcast': '192.0.2.255', 'prefixlen': 24, 'scope': 'global'},
                   {'local': '2001:db8::10', 'prefixlen': 64, 'scope': 'global'}]}]
    original = deepcopy(kernel)
    monkeypatch.setattr(interfaces, 'cmd', lambda argv: json.dumps(kernel))
    words = ['show', '--strip-private']

    for name, enabled in [('raw', raw), ('detail', detail), ('statistics', statistics)]:
        if enabled:
            words.append('--' + name)

    opmode.run(words, namespace=vars(interfaces))
    output = capsys.readouterr().out

    assert all(value not in output for value in PRIVATE)
    assert '192.0.2.255' not in output and 'ff:ff:ff:ff:ff:ff' not in output

    if not statistics:
        assert '<mac>' in output and '<ipv4>' in output and '<ipv6>' in output

    assert kernel == original

    opmode.run(['show', '--raw'], namespace=vars(interfaces))

    assert '192.0.2.10' in capsys.readouterr().out
