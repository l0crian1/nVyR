"""Harness regression checks only: never connect to a host or change its routes."""

import ast
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
from types import SimpleNamespace

import pytest

from smoketests.support import SmokeSession, configuration_case, prepared_test, preserved_configuration, wait_for

pytest_plugins = ['pytester']


def test_all_live_fixture_dependencies_resolve_without_mutations():
    """Imported case fixtures must also expose their module-scoped dependencies."""
    repository = Path(__file__).resolve().parents[1]
    environment = os.environ | {'PYTHONPATH': str(repository / 'src')}
    result = subprocess.run(
        [sys.executable, '-m', 'pytest', '--setup-plan', '-q', 'smoketests', 'functionaltests'],
        cwd=repository, env=environment, text=True, capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'Original configuration snapshot' not in result.stdout


@pytest.mark.parametrize('filename, selection, elsewhere, selected_names, status', [
    ('test_static.py', [], False, None, 0),
    ('test_static.py', ['-k', 'disable_and_reenable'], False, {'test_disable_and_reenable'}, 0),
    ('test_static.py', ['-k', 'ipv4_blackhole'], True, {'test_ipv4_blackhole'}, 0),
    ('test_static.py', ['-k', 'does_not_exist'], False, set(), 5),
    ('functionaltests/network/test_firewall.py', ['-k', 'shared_quota'], True, {'test_shared_quota_counter_reset_and_display'}, 0),
    ('test_firewall_connection.py', [], True, None, 0),
    ('test_firewall_timeouts.py', [], True, None, 0),
    ('test_firewall_helpers.py', [], True, None, 0),
    ('test_firewall_groups.py', [], True, None, 0),
    ('test_firewall_ports.py', [], True, None, 0),
    ('functionaltests/network/test_firewall_allowances.py', [], True, None, 0),
    ('functionaltests/test_system_operations.py', [], True, None, 0),
    ('test_firewall_geoip.py', [], True, None, 0),
    ('test_firewall_validation.py', [], True, None, 0),
    ('test_firewall_zones.py', [], True, None, 0),
    ('test_container.py', [], True, None, 0),
    ('test_container_pods.py', [], True, None, 0),
    ('test_container_validation.py', [], True, None, 0),
    ('functionaltests/workloads/test_container.py', [], True, None, 0),
    ('functionaltests/workloads/test_container_pods.py', [], True, None, 0),
    ('test_firewall_global_flowtable.py', [], True, None, 0),
    ('functionaltests/network/test_firewall_flowtable_packets.py', [], True, None, 0),
    ('test_bgp_default.py', [], True, None, 0),
    ('test_bgp_neighbors.py', [], True, None, 0),
    ('functionaltests/network/test_bgp_operations.py', [], True, None, 0),
    ('functionaltests/network/test_policy_operations.py', [], True, None, 0),
    ('functionaltests/network/test_bgp_operational_peers.py', [], True, None, 0),
    ('functionaltests/test_frr_scripting.py', [], True, None, 0),
    ('test_firewall_interfaces.py', [], True, None, 0),
    ('test_ethernet.py', [], True, None, 0),
    ('test_dummy.py', [], True, None, 0),
    ('test_virtual_ethernet.py', [], True, None, 0),
    ('functionaltests/test_interface_operations.py', [], True, None, 0),
    ('test_vrf.py', [], True, None, 0),
    ('test_dhcp_server.py', [], True, None, 0),
    ('test_ntp.py', [], True, None, 0),
    ('test_policy.py', [], True, None, 0),
    ('test_bgp.py', [], True, None, 0),
    ('functionaltests/network/test_bgp_policy.py', [], True, None, 0),
    ('functionaltests/network/test_routed_network.py', [], True, None, 0),
])
def test_direct_script_collection(tmp_path, filename, selection, elsewhere, selected_names, status):
    """Direct entry points collect every feature test and honor explicit selections."""
    repository = Path(__file__).resolve().parents[1]
    for name in ('smoketests', 'functionaltests'):
        shutil.copytree(repository / name, tmp_path / name,
                        ignore=shutil.ignore_patterns('__pycache__', '.pytest_cache'))
    location = Path(filename)
    suite = tmp_path / (location.parent if location.parent != Path('.') else 'smoketests')
    filename = location.name
    script = str(suite / filename) if elsewhere else filename
    # Only nvyr is on PYTHONPATH. Pytest must discover the copied suite itself.
    environment = os.environ | {'PYTHONPATH': str(repository / 'src')}

    result = subprocess.run([sys.executable, script, '--collect-only', '-q', *selection],
                            cwd=tmp_path if elsewhere else suite, env=environment,
                            text=True, capture_output=True, timeout=30)

    assert result.returncode == status, result.stdout + result.stderr
    collected = [line.strip().rsplit('/', 1)[-1] for line in result.stdout.splitlines()
                 if line.strip().rsplit('/', 1)[-1].startswith(filename + '::')]
    if selected_names is None:
        # The suite uses explicit feature functions; additions must collect automatically.
        source = ast.parse((suite / filename).read_text())
        selected_names = {node.name for node in source.body
                          if isinstance(node, ast.FunctionDef) and node.name.startswith('test_')}
        assert selected_names

    expected = {f'{filename}::{name}' for name in selected_names}
    assert set(collected) == expected, result.stdout + result.stderr
    assert len(collected) == len(expected)
    assert 'Original configuration snapshot' not in result.stdout


class FakeSession:
    def __init__(self):
        self.running = {'system': {'host-name': 'original'}, 'service': {'ssh': {}}}
        self.candidate = deepcopy(self.running)
        self.calls = []

    def request_lock(self, force=False):
        assert force is True
        self.calls.append('lock')

    def get_config(self):
        return deepcopy(self.running)

    def discard(self):
        self.calls.append('discard')
        self.candidate = deepcopy(self.running)

    def load(self, configuration, *, replace):
        assert replace is True
        self.calls.append('replace')
        self.candidate = deepcopy(configuration)

    def commit(self):
        self.calls.append('commit')
        self.running = deepcopy(self.candidate)


def test_case_reset_skips_commit_for_rejected_edits():
    config = FakeSession()
    baseline = config.get_config()
    request = SimpleNamespace(session=SimpleNamespace(shouldstop=False))
    with configuration_case(config, request, baseline):
        config.candidate = {'invalid': True}

    assert config.get_config() == config.candidate == baseline
    assert config.calls == ['discard']


def test_case_reset_restores_after_failure_and_stops_if_restore_fails(monkeypatch):
    config = FakeSession()
    baseline = config.get_config()
    request = SimpleNamespace(session=SimpleNamespace(shouldstop=False))
    with pytest.raises(AssertionError, match='failed case'):
        with configuration_case(config, request, baseline):
            config.running = {'changed': True}
            raise AssertionError('failed case')
    assert config.get_config() == baseline
    assert config.calls == ['discard', 'replace', 'commit']

    def broken_commit():
        raise RuntimeError('restore failed')

    monkeypatch.setattr(config, 'commit', broken_commit)
    with pytest.raises(RuntimeError, match='restore failed'):
        with configuration_case(config, request, baseline):
            config.running = {'changed': True}
    assert 'reset failed' in request.session.shouldstop


@pytest.mark.parametrize('failure', [None, AssertionError, KeyboardInterrupt])
def test_restores_original_and_discards_candidate_on_every_exit(tmp_path, failure):
    config = FakeSession()
    original = config.get_config()
    messages = []

    def run():
        with preserved_configuration(config, directory=tmp_path, report=messages.append):
            snapshot, = tmp_path.iterdir()
            assert json.loads(snapshot.read_text()) == original
            if os.name == 'posix':
                assert snapshot.stat().st_mode & 0o777 == 0o600

            config.running = {'protocols': {'static': {'route': {}}}}
            config.candidate = {'system': {'host-name': 'leftover'}}
            if failure:
                raise failure('test failed')

    if failure:
        with pytest.raises(failure, match='test failed'):
            run()
    else:
        run()

    assert config.running == config.candidate == original
    assert config.calls == ['lock', 'discard', 'replace', 'commit']
    assert not list(tmp_path.iterdir())
    assert 'restored' in messages[-1]


@pytest.mark.parametrize('failure', ['commit', 'comparison'])
def test_restore_failure_retains_snapshot_and_reports_it(tmp_path, monkeypatch, failure):
    config = FakeSession()
    original = config.get_config()
    messages = []

    def broken_commit():
        if failure == 'commit':
            raise RuntimeError('restore failed')

    monkeypatch.setattr(config, 'commit', broken_commit)
    with pytest.raises(RuntimeError):
        with preserved_configuration(config, directory=tmp_path, report=messages.append):
            config.running = {}

    snapshot, = tmp_path.iterdir()
    assert json.loads(snapshot.read_text()) == original
    assert 'RESTORATION FAILED' in messages[-1] and str(snapshot) in messages[-1]


def test_lock_failure_does_not_snapshot_or_restore(tmp_path, monkeypatch):
    config = FakeSession()

    def locked(force=False):
        assert force is True
        raise RuntimeError('commit-confirm timer is active')

    monkeypatch.setattr(config, 'request_lock', locked)
    with pytest.raises(RuntimeError, match='commit-confirm timer is active'):
        with preserved_configuration(config, directory=tmp_path):
            pytest.fail('Must not run without the lock')

    assert not config.calls and not list(tmp_path.iterdir())


def test_setup_and_cleanup_run_for_each_function_even_after_failure():
    events = []
    for index in range(3):
        try:
            with prepared_test(None, lambda session: events.append('setup'),
                               lambda session: events.append('cleanup'), stop=pytest.fail):
                events.append(index)
                if index == 1:
                    raise AssertionError('failed test')
        except AssertionError:
            pass

    assert events == ['setup', 0, 'cleanup', 'setup', 1, 'cleanup', 'setup', 2, 'cleanup']


def test_setup_failure_still_runs_cleanup():
    events = []

    def standup(session):
        events.append('setup')
        raise RuntimeError('partial setup failed')

    with pytest.raises(RuntimeError, match='partial setup failed'):
        with prepared_test(None, standup, lambda session: events.append('cleanup'), stop=pytest.fail):
            pytest.fail('Test must not run after failed setup')

    assert events == ['setup', 'cleanup']


def test_local_cleanup_failure_stops_run_and_global_restore_still_runs(tmp_path):
    config = FakeSession()
    original = config.get_config()
    stopped = []

    def cleanup(session):
        raise RuntimeError('local cleanup failed')

    with pytest.raises(RuntimeError, match='local cleanup failed'):
        with preserved_configuration(config, directory=tmp_path):
            with prepared_test(config, lambda session: None, cleanup, stop=stopped.append):
                config.running = {}

    assert config.running == original
    assert len(stopped) == 1 and 'stopping tests' in stopped[0]


def test_ctrl_c_is_delivered_after_rpc_response_is_consumed():
    events = []

    class Client:
        def request(self, operation, **arguments):
            signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
            events.append('reply consumed')
            return {}

    session = object.__new__(SmokeSession)
    session._client = Client()
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        with pytest.raises(KeyboardInterrupt):
            session.get_config()

        assert events == ['reply consumed']
        assert signal.getsignal(signal.SIGINT) == signal.default_int_handler
    finally:
        signal.signal(signal.SIGINT, previous)


def test_ctrl_c_during_cleanup_waits_until_restore_finishes(tmp_path, monkeypatch):
    config = FakeSession()
    original = config.get_config()
    commit = config.commit

    def interrupted_commit():
        signal.getsignal(signal.SIGINT)(signal.SIGINT, None)
        commit()

    monkeypatch.setattr(config, 'commit', interrupted_commit)
    previous = signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        with pytest.raises(KeyboardInterrupt):
            with preserved_configuration(config, directory=tmp_path):
                config.running = {}

        assert config.running == original and not list(tmp_path.iterdir())
    finally:
        signal.signal(signal.SIGINT, previous)


def test_wait_for_reports_last_observation_and_accepts_eventual_success(monkeypatch):
    values = iter(['pending', 'ready'])
    monkeypatch.setattr('smoketests.support.time.sleep', lambda interval: None)
    assert wait_for(lambda: next(values), lambda value: value == 'ready', description='ready') == 'ready'

    with pytest.raises(AssertionError, match='Last observation:\nstill pending'):
        wait_for(lambda: 'still pending', lambda value: False, description='ready', timeout=0)


@pytest.mark.parametrize('mode', ['all', 'selected', 'failure', 'setup_failure', 'cleanup_failure'])
def test_pytest_lifecycle_and_selection(pytester, monkeypatch, mode):
    """Exercise the real global fixture and pytest finalization, with a fake API."""
    repository = Path(__file__).resolve().parents[1]
    monkeypatch.setenv('PYTHONPATH', os.pathsep.join([str(repository), str(repository / 'src')]))
    monkeypatch.setenv('SMOKE_HARNESS_CASE', mode)
    fixture = (repository / 'smoketests/conftest.py').read_text()
    pytester.makeini((repository / 'smoketests/pytest.ini').read_text())
    pytester.makeconftest(fixture + '''
import json
import os
import sys
from pathlib import Path
import tempfile
from tests.test_smoketest_harness import FakeSession

# Only this isolated pytest subprocess uses fake host identity and API objects.
sys.platform = 'linux'
os.geteuid = lambda: 0
tempfile.tempdir = str(Path.cwd())

class RecordingSession(FakeSession):
    def __init__(self, *, timeout):
        super().__init__()
        assert timeout == 28800

    def exit(self):
        Path('closed.json').write_text(json.dumps({'running': self.running, 'calls': self.calls}))

live.SmokeSession = RecordingSession
''')
    pytester.makepyfile(test_example='''
import os
from pathlib import Path
import pytest
from smoketests.support import prepared_test

mode = os.environ['SMOKE_HARNESS_CASE']

def record(event):
    with Path('events.txt').open('a') as output:
        output.write(event + '\\n')

def standup(config):
    record('setup')
    config.running = {}
    if mode == 'setup_failure':
        raise RuntimeError('setup failed')

def cleanup(config):
    record('cleanup')
    if mode == 'cleanup_failure':
        raise RuntimeError('cleanup failed')

@pytest.fixture(autouse=True)
def environment(config, request):
    def stop(message):
        request.session.shouldstop = message
    with prepared_test(config, standup, cleanup, stop=stop):
        yield

def test_first():
    record('first')
    if mode == 'failure':
        assert False, 'deliberate failure'

def test_second():
    record('second')
''')
    arguments = ['-q', '-s']
    if mode == 'selected':
        arguments.extend(['-k', 'second'])

    result = pytester.runpytest_subprocess(*arguments)
    lines = [line.strip() for line in result.stdout.str().splitlines()]
    assert lines.count('########## test_example.py ##########') == 1
    snapshot_line = next(index for index, line in enumerate(lines) if line.startswith('Original configuration snapshot:'))
    restored_line = next(index for index, line in enumerate(lines) if line.startswith('Original running configuration restored.'))
    results = [index for index, line in enumerate(lines) if line.startswith(('test_first ', 'test_second '))]
    assert results and snapshot_line < min(results)
    assert all(' | ' in lines[index] for index in results)
    # Teardown errors are reported after global restoration has been attempted.
    assert max(index for index in results if '(teardown)' not in lines[index]) < restored_line
    assert not any('test_example.py::' in lines[index] for index in results)
    if mode == 'all':
        result.assert_outcomes(passed=2)
    elif mode == 'selected':
        result.assert_outcomes(passed=1, deselected=1)
    elif mode == 'failure':
        result.assert_outcomes(passed=1, failed=1)
    elif mode == 'setup_failure':
        result.assert_outcomes(errors=2)
    else:
        result.assert_outcomes(passed=1, errors=1)

    output = result.stdout.str()
    if mode in ('all', 'selected'):
        assert 'Live-test failures' not in output
    else:
        summary = output.split('Live-test failures', 1)[1]
        assert output.index('Original running configuration restored.') < output.index('Live-test failures')
        phase = {'failure': 'Test', 'setup_failure': 'Setup', 'cleanup_failure': 'Cleanup'}[mode]
        reason = {'failure': 'deliberate failure', 'setup_failure': 'setup failed', 'cleanup_failure': 'cleanup failed'}[mode]
        assert 'test_example.py' in summary and 'test_first' in summary
        assert phase in summary and reason in summary

    events = (pytester.path / 'events.txt').read_text().splitlines()
    expected = {
        'selected': ['setup', 'second', 'cleanup'],
        'setup_failure': ['setup', 'cleanup', 'setup', 'cleanup'],
        'cleanup_failure': ['setup', 'first', 'cleanup'],
    }
    assert events == expected.get(mode, ['setup', 'first', 'cleanup', 'setup', 'second', 'cleanup'])
    closed = json.loads((pytester.path / 'closed.json').read_text())
    assert closed['running'] == FakeSession().running
    assert closed['calls'] == ['lock', 'discard', 'replace', 'commit']
    assert not list(pytester.path.glob('nvyr-smoketest-*.json'))


def test_reporter_groups_scripts_and_preserves_outcomes(pytester, monkeypatch):
    repository = Path(__file__).resolve().parents[1]
    monkeypatch.setenv('PYTHONPATH', os.pathsep.join([str(repository), str(repository / 'src')]))
    pytester.makeini((repository / 'smoketests/pytest.ini').read_text())
    pytester.makeconftest('from smoketests.conftest import pytest_configure')
    pytester.makepyfile(test_alpha='''
import pytest

@pytest.mark.parametrize('value', [1, 2, '2001:db8::1'])
def test_value(value):
    assert value

@pytest.mark.skip(reason='not available')
def test_skip():
    pass

@pytest.mark.xfail(reason='known failure')
def test_expected_failure():
    assert False

@pytest.mark.xfail(reason='unexpected success')
def test_unexpected_success():
    pass
''', test_beta='''
def test_failure():
    assert False, 'failure details must remain visible'
''')

    result = pytester.runpytest_subprocess('-v', '-s', '-ra')
    result.assert_outcomes(passed=3, skipped=1, xfailed=1, xpassed=1, failed=1)
    output = result.stdout.str()
    progress = output.split(' FAILURES ')[0]
    lines = [line.strip() for line in progress.splitlines()]
    result_lines = [line for line in lines if line.startswith('test_') and ' | ' in line]
    assert len(result_lines) == 7
    assert {line.index('|') for line in result_lines} == {91}
    lines = [' | '.join(column.strip() for column in line.split('|')) for line in lines]

    for expected in ('########## test_alpha.py ##########', '########## test_beta.py ##########',
                     'test_value[1] | PASSED', 'test_value[2] | PASSED', 'test_value[2001:db8::1] | PASSED',
                     'test_skip | SKIPPED (setup)',
                     'test_expected_failure | XFAIL', 'test_unexpected_success | XPASS', 'test_failure | FAIL'):
        assert lines.count(expected) == 1

    assert progress.index('test_value[2]') < progress.index('########## test_beta.py ##########')
    assert 'test_alpha.py::' not in progress and 'test_beta.py::' not in progress
    assert 'failure details must remain visible' in output


def test_failure_table_includes_multiple_scripts_and_parameterized_tests(pytester, monkeypatch):
    repository = Path(__file__).resolve().parents[1]
    monkeypatch.setenv('PYTHONPATH', os.pathsep.join([str(repository), str(repository / 'src')]))
    pytester.makeini((repository / 'smoketests/pytest.ini').read_text())
    pytester.makeconftest('from smoketests.conftest import pytest_configure')
    pytester.makepyfile(test_alpha='''
import pytest

@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_route(family):
    raise RuntimeError('route missing: ' + family)
''', test_beta='''
import pytest

@pytest.fixture
def environment():
    yield
    raise RuntimeError('cleanup failed')

def test_rule(environment):
    assert False, 'rule missing'

@pytest.mark.xfail(strict=True, reason='must fail')
def test_strict_xpass():
    pass
''')

    result = pytester.runpytest_subprocess('-v', '-s')
    result.assert_outcomes(failed=4, errors=1)
    output = result.stdout.str()
    summary = output.split('Live-test failures', 1)[1]
    rows = [line.split() for line in summary.splitlines() if line.startswith('test_')]

    assert [row[:3] for row in rows] == [
        ['test_alpha.py', 'test_route[ipv4]', 'Test'],
        ['test_alpha.py', 'test_route[ipv6]', 'Test'],
        ['test_beta.py', 'test_rule', 'Test'],
        ['test_beta.py', 'test_rule', 'Cleanup'],
        ['test_beta.py', 'test_strict_xpass', 'Test'],
    ]
    for reason in ('route missing: ipv4', 'route missing: ipv6', 'rule missing', 'cleanup failed', '[XPASS(strict)] must fail'):
        assert reason in summary

    assert 'AssertionError: rule missing' in output.split('Live-test failures', 1)[0]
