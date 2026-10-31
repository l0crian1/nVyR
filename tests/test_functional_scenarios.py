"""Guard live-scenario imports and keep observation tests free of setup commits."""

from tests.container_harness import verify_container

import ast
import builtins
from pathlib import Path
import symtable

import pytest

from tests.test_static_smoketest import local_session


ROOT = Path(__file__).resolve().parents[1]


def test_functional_helpers_are_defined():
    """Catch missing imported assertions even when a live feature is not exercised in CI."""
    missing = []
    for path in (ROOT / 'functionaltests').rglob('*.py'):
        module = symtable.symtable(path.read_text(), str(path), 'exec')
        known = {symbol.get_name() for symbol in module.get_symbols()
                 if symbol.is_assigned() or symbol.is_imported()}
        known |= set(dir(builtins)) | {'__file__', '__name__'}
        pending = [module]
        while pending:
            scope = pending.pop()
            for symbol in scope.get_symbols():
                if symbol.is_referenced() and symbol.is_global() and symbol.get_name() not in known:
                    missing.append(f'{path.name}:{scope.get_name()}: {symbol.get_name()}')
            pending.extend(scope.get_children())
    assert not missing, '\n'.join(missing)


@pytest.mark.parametrize('filename', ['containers.conf', 'pods.conf'])
def test_container_batch_commands_parse(local_session, filename):
    """Exercise the actual CLI parser against every batch command, with short valid inputs."""
    text = (ROOT / 'functionaltests/configs' / filename).read_text()
    for token, value in {'@IMAGE@': 'alpine', '@ENV@': 'test.env', '@VOLUME@': 'volume', '@HOSTFILE@': '/run/test-file',
                         '@TCP_PORT@': '18200', '@UDP_PORT@': '18201'}.items():
        text = text.replace(token, value)
    for command in text.splitlines():
        if command and not command.startswith('#'):
            local_session.set(command)
    candidate = local_session.get_config(source='candidate')
    names = candidate['container']['name']
    assert len(names) == (26 if filename == 'containers.conf' else 6)


def test_containers_and_pods_can_coexist(local_session):
    """Combined workloads must pass real cross-network and attachment verification."""
    for filename in ('containers.conf', 'pods.conf'):
        text = (ROOT / 'functionaltests/configs' / filename).read_text()
        for token, value in {'@IMAGE@': 'alpine', '@ENV@': 'test.env', '@VOLUME@': 'volume', '@HOSTFILE@': '/run/test-file',
                             '@TCP_PORT@': '18200', '@UDP_PORT@': '18201'}.items():
            text = text.replace(token, value)
        for command in text.splitlines():
            if command and not command.startswith('#'):
                local_session.set(command)

    candidate = local_session.get_config(source='candidate')
    configuration = candidate['container']
    verify_container(configuration, vrfs=candidate.get('vrf', {}).get('name', {}))
    assert len(configuration['name']) == 32
    assert len(configuration['pod']) == 4


def test_interface_batch_commands_verify(local_session):
    """All compatible addresses, bridges and routing domains must commit together."""
    text = (ROOT / 'functionaltests/configs/interfaces.conf').read_text()
    for command in text.splitlines():
        if command and not command.startswith('#'):
            local_session.set(command)
    local_session.commit()
    running = local_session.get_config()
    assert set(running['vrf']['name']) == {'NVYRIFSMOKE', 'NVYRIFSMOKE2'}
    assert len(running['interfaces']['bridge']) == 14


def test_bgp_observations_do_not_reconfigure():
    """Route/neighbor display checks must use the already installed module baseline."""
    path = ROOT / 'functionaltests/network/test_bgp_operations.py'
    for function in ast.parse(path.read_text()).body:
        if isinstance(function, ast.FunctionDef) and function.name.startswith('test_'):
            for node in ast.walk(function):
                if isinstance(node, ast.Call):
                    assert ast.unparse(node.func) not in {'config.set', 'config.delete', 'config.commit'}


def test_container_observations_do_not_reconfigure():
    """Only deliberate lifecycle mutations should commit during individual container cases."""
    mutations = {'test_disable_and_reenable', 'test_unrelated_commit_preserves_workload',
                 'test_network_edit_recreates_attached_workload', 'test_persistent_volume_survives_recreation',
                 'test_resource_overrides_and_removal'}
    path = ROOT / 'functionaltests/workloads/test_container.py'
    for function in ast.parse(path.read_text()).body:
        if (isinstance(function, ast.FunctionDef) and function.name.startswith('test_')
                and function.name not in mutations):
            for node in ast.walk(function):
                if isinstance(node, ast.Call):
                    assert ast.unparse(node.func) not in {'config.set', 'config.delete', 'config.commit'}
