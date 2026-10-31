"""Cross-cutting operational coverage using the real command tree and entry points."""

import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from build_tools.op_scripts import install_scripts
from nvyr.errors import RouterError
from nvyr.helpers import access


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = sorted(path.stem for path in (ROOT / 'src/nvyr/op_scripts').glob('*.py')
                 if not path.name.startswith('_'))


@pytest.fixture(scope='module')
def installed_scripts(tmp_path_factory):
    """Exercise the real package installer and actual script imports, without running actions."""
    stage = tmp_path_factory.mktemp('operational-install')
    source = stage / 'lib/op_scripts'
    shutil.copytree(ROOT / 'src/nvyr/op_scripts', source, ignore=shutil.ignore_patterns('__pycache__'))
    install_scripts(source, stage / 'bin')
    installed = stage.with_name(stage.name + '-relocated')
    stage.rename(installed)
    return installed / 'bin'


@pytest.mark.parametrize('script', SCRIPTS)
def test_every_real_installed_entry_point_starts(installed_scripts, script):
    """Catch missing imports, broken relative links, mode/shebang errors and signature failures."""
    environment = dict(os.environ, PATH=str(installed_scripts) + os.pathsep + os.environ['PATH'])
    result = subprocess.run([script + '.nvyr.op', '--help'], env=environment,
                            capture_output=True, text=True, timeout=15)

    assert result.returncode == 0, result.stdout + result.stderr
    assert 'usage:' in result.stdout
    assert not result.stderr


def command_nodes(node, path=()):
    if 'command' in node:
        yield path, node
    for name, child in node.get('children', {}).items():
        yield from command_nodes(child, (*path, name))


@pytest.mark.parametrize('role', ['read-only', 'net-admin', 'sys-admin', 'dev-admin'])
def test_all_command_permissions_follow_operational_contract(controller, role):
    """Adding a command below an administrative verb must not silently expose it to operators."""
    readable = {'show', 'ping', 'traceroute', 'lookup', 'exit'}
    administrative = {'release', 'renew', 'update', 'restart', 'generate', 'clear', 'reboot',
                      'poweroff', 'install', 'add', 'rename', 'delete', 'configure', 'connect'}
    token = access.role.set(role)
    try:
        for path, node in command_nodes(controller.operational.root):
            # Capturing and reading packet traces both expose privileged packet data.
            if path == ('disable', 'system', 'developer-access'):
                expected = 'dev-admin'
            elif path[:3] in {('monitor', 'firewall', 'trace'), ('show', 'firewall', 'trace')}:
                expected = 'net-admin'
            elif path[0] in readable or path[:2] == ('set', 'terminal'):
                expected = 'read-only'
            elif path[0] in administrative or path[:2] == ('set', 'system'):
                expected = 'net-admin'
            else:
                assert path[0] in ('shell', 'shellcmd'), f'Define the access expectation for {path}'
                expected = 'dev-admin'

            assert controller.operational.minimum_access(node) == expected, path
            cursor = SimpleNamespace(node=node, required_access=())
            if access.allows(expected):
                controller.check_operational_access(cursor)
            else:
                with pytest.raises(RouterError, match=f'requires {expected}'):
                    controller.check_operational_access(cursor)
    finally:
        access.role.reset(token)


@pytest.mark.parametrize('line, argv, streaming', [
    ('clear firewall counter TOTAL', ['firewall.nvyr.op', 'clear_counter', 'TOTAL'], False),
    ('clear firewall quota TOTAL', ['firewall.nvyr.op', 'clear_quota', 'TOTAL'], False),
    ('clear firewall group address-group ipv4 LEARNED learned',
     ['firewall.nvyr.op', 'clear_group', 'clear firewall group address-group ipv4 LEARNED learned'], False),
    ('clear firewall group address-group ipv6 LEARNED member 2001:db8::1',
     ['firewall.nvyr.op', 'clear_group', 'clear firewall group address-group ipv6 LEARNED member 2001:db8::1'], False),
    ('update firewall geoip', ['geoip.nvyr.op', 'update'], True),
    ('restart container DNS', ['containers.nvyr.op', 'restart', 'DNS'], True),
    ('update container image container DNS', ['containers.nvyr.op', 'update_container', 'DNS'], True),
    ('release dhcp interface eth1', ['dhcp.nvyr.op', 'release', 'eth1'], False),
    ('renew dhcp interface eth1', ['dhcp.nvyr.op', 'renew', 'eth1'], False),
])
def test_state_changes_dispatch_and_reauthorize(controller, session, monkeypatch, line, argv, streaming):
    """Check both CLI modes and the terminal boundary without touching runtime state."""
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda arguments, **kwargs: calls.append(arguments) or 'done')
    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError, match='net-admin'):
            controller.execute(line)
        with pytest.raises(RouterError, match='net-admin'):
            controller.authorize_terminal(line, None)
        assert not calls
    finally:
        access.role.reset(token)

    for role in ('net-admin', 'sys-admin'):
        token = access.role.set(role)
        try:
            for command, mode in ((line, None), ('run ' + line, session)):
                result = controller.execute(command, mode)
                if streaming:
                    assert result['event'] == 'command' and result['argv'] == argv
                    controller.authorize_terminal(command, mode)
                else:
                    assert result['text'] == 'done'
                    # @line deliberately preserves the run prefix for the script's shared parser.
                    expected = [command if value == line else value for value in argv]
                    assert calls[-1] == expected
        finally:
            access.role.reset(token)
