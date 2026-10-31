"""Verify boot-test sequencing without rebooting or touching the host network."""

import base64
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest

from acceptance import agent, baseline, runner
from nvyr.config_session import CommitError
from nvyr.storage import atomic_json, saved_document


OPTIONS = {'ethernet': 'eth1', 'image': 'alpine'}


@pytest.fixture
def fake_agent(tmp_path, monkeypatch):
    """Model distinct saved/running data and the local ConfigurationSession contract."""
    saved = tmp_path / 'saved'
    original_bytes = b'{"system": {}, "_nvyr": {"factory": false}}\n'
    saved.write_bytes(original_bytes)
    state = {'running': {'interfaces': {}}, 'saved_count': 0, 'commits': 0, 'boot': 'before'}
    directory = tmp_path / 'runs' / str(uuid.uuid4())

    class Config:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def request_lock(self):
            pass

        def get_config(self):
            return deepcopy(state['running'])

        def commit(self, **kwargs):
            state['commits'] += 1
            if state.get('fail_commit'):
                raise CommitError({'results': {'interfaces': {'success': False, 'error': 'apply failed'}}})

        def save(self):
            state['saved_count'] += 1
            atomic_json(saved, saved_document(state['running']))

        def load(self, value, *, replace):
            assert replace
            state['running'] = deepcopy(value)

    def configure(config, options):
        state['running']['firewall'] = {'example': {}}

    monkeypatch.setattr(agent, 'SAVED', saved)
    monkeypatch.setattr(agent, 'ConfigurationSession', lambda **kwargs: Config())
    monkeypatch.setattr(agent, 'check_idle', lambda: None)
    monkeypatch.setattr(agent, 'identity', lambda: {'boot_id': state['boot']})
    monkeypatch.setattr(agent, 'command', lambda args: '\n'.join(['active'] * len(agent.SERVICES)))
    monkeypatch.setattr(agent.baseline, 'preflight', lambda value, options: None)
    monkeypatch.setattr(agent.baseline, 'configure', configure)
    monkeypatch.setattr(agent.baseline, 'prepare_assets', lambda options: None)
    monkeypatch.setattr(agent.snapshots, 'capture', lambda: {'firewall': {}, 'routing': [], 'vrf_conntrack': {}})
    monkeypatch.setattr(agent, 'observations', lambda options: [{'check': 'native', 'status': 'PASSED'}])
    return SimpleNamespace(directory=directory, state=state, saved=saved, original_bytes=original_bytes)


def test_agent_roundtrip_preserves_unsaved_configuration(fake_agent):
    """Restoration must never turn original unsaved changes into saved configuration."""
    lab = fake_agent
    agent.prepare(lab.directory, OPTIONS)
    backup = agent.read_record(lab.directory, 'original.json')
    assert base64.b64decode(backup['saved_bytes']) == lab.original_bytes
    assert backup['running'] == {'interfaces': {}}
    assert lab.state['saved_count'] == 1
    options = agent.read_record(lab.directory, 'options.json')
    assert options == {**OPTIONS, 'assets': 'boot-' + lab.directory.name}
    assert (lab.directory / 'before-native.json').is_file()

    lab.state['boot'] = 'after'
    result = agent.verify(lab.directory)
    assert all(check['status'] == 'PASSED' for check in result['checks'])
    agent.restore(lab.directory)

    assert lab.state['running'] == {'interfaces': {}}
    assert lab.saved.read_bytes() == lab.original_bytes
    assert lab.state['saved_count'] == 1


def test_agent_partial_commit_does_not_save(fake_agent):
    """A partial application retains the backup and must never proceed to save."""
    lab = fake_agent
    lab.state['fail_commit'] = True
    with pytest.raises(CommitError, match='apply failed'):
        agent.prepare(lab.directory, OPTIONS)

    assert (lab.directory / 'original.json').is_file()
    assert not (lab.directory / 'prepared.json').exists()
    assert lab.saved.read_bytes() == lab.original_bytes
    assert lab.state['saved_count'] == 0


def test_agent_failed_preboot_assertion_does_not_save(fake_agent, monkeypatch):
    """A committed configuration must pass native checks before it can become boot config."""
    monkeypatch.setattr(agent, 'observations', lambda options: [{'check': 'kernel_route', 'status': 'FAIL'}])
    with pytest.raises(AssertionError, match='kernel_route'):
        agent.prepare(fake_agent.directory, OPTIONS)

    assert fake_agent.state['saved_count'] == 0
    assert (fake_agent.directory / 'before.json').exists()


def test_agent_reports_all_postboot_failures(fake_agent, monkeypatch):
    """Keep both native failures and configuration drift instead of stopping at the first."""
    agent.prepare(fake_agent.directory, OPTIONS)
    fake_agent.state['boot'] = 'after'
    fake_agent.state['running']['extra'] = {}
    monkeypatch.setattr(agent, 'observations', lambda options: [{'check': 'vrf', 'status': 'FAIL'}])

    with pytest.raises(AssertionError, match='running_configuration, vrf'):
        agent.verify(fake_agent.directory)
    result = agent.read_record(fake_agent.directory, 'after.json')
    assert [check['status'] for check in result['checks']] == ['FAIL', 'PASSED', 'FAIL', 'PASSED', 'PASSED', 'PASSED']
    assert not (fake_agent.directory / 'restored.json').exists()


def test_native_policy_drift_fails_even_when_configuration_matches(fake_agent, monkeypatch):
    """A missing installed rule cannot hide behind an unchanged configuration dictionary."""
    agent.prepare(fake_agent.directory, OPTIONS)
    fake_agent.state['boot'] = 'after'
    monkeypatch.setattr(agent.snapshots, 'capture', lambda: {'firewall': {'missing': 'rule'}, 'routing': [], 'vrf_conntrack': {}})

    with pytest.raises(AssertionError, match='firewall_native_configuration'):
        agent.verify(fake_agent.directory)
    assert (fake_agent.directory / 'after-native.json').is_file()
    assert not (fake_agent.directory / 'restored.json').exists()


def test_agent_reboot_requires_unchanged_prepared_config(fake_agent, monkeypatch):
    """Changes made after preflight must not be saved/rebooted on someone else's behalf."""
    agent.prepare(fake_agent.directory, OPTIONS)
    fake_agent.state['running']['extra'] = {}
    commands = []
    monkeypatch.setattr(agent, 'command', lambda argv: commands.append(argv))
    with pytest.raises(RuntimeError, match='changed after preparation'):
        agent.reboot(fake_agent.directory)
    assert commands == []


def test_agent_reboot_is_scheduled_only_once(fake_agent, monkeypatch):
    """An uncertain SSH response must not lead to an accidental second reboot."""
    agent.prepare(fake_agent.directory, OPTIONS)
    commands = []
    monkeypatch.setattr(agent, 'command', lambda argv: commands.append(argv))
    assert agent.reboot(fake_agent.directory)['scheduled']
    assert commands[0][-2:] == ['/usr/bin/systemctl', 'reboot']
    with pytest.raises(RuntimeError, match='already requested'):
        agent.reboot(fake_agent.directory)
    assert len(commands) == 1


def test_agent_refuses_to_verify_without_reboot(fake_agent):
    """A healthy original process is not evidence of boot recovery."""
    agent.prepare(fake_agent.directory, OPTIONS)
    assert agent.ready(fake_agent.directory)['ready'] is False
    with pytest.raises(RuntimeError, match='not rebooted'):
        agent.verify(fake_agent.directory)


def test_readiness_requires_every_service(fake_agent, monkeypatch):
    """systemctl's success for any active unit must not hide one failed dependency."""
    agent.prepare(fake_agent.directory, OPTIONS)
    fake_agent.state['boot'] = 'after'
    monkeypatch.setattr(agent, 'command', lambda argv: 'active\nfailed\nactive\nactive')

    with pytest.raises(RuntimeError, match='not all recovered'):
        agent.ready(fake_agent.directory)


def test_restore_saved_file_that_was_absent(fake_agent):
    """Restoring a lab without a saved file must not leave the test baseline persisted."""
    fake_agent.saved.unlink()
    agent.prepare(fake_agent.directory, OPTIONS)
    assert fake_agent.saved.exists()
    agent.restore(fake_agent.directory)
    assert not fake_agent.saved.exists()


def test_observations_keep_independent_failures(monkeypatch):
    """Each feature gets a named result even when another check fails."""
    def failed(options):
        raise AssertionError('route missing')

    def passed(options):
        pass

    def skipped(options):
        raise agent.CheckSkipped('eth1 has no carrier')

    monkeypatch.setattr(baseline, 'CHECKS', (failed, skipped, passed))
    result = agent.observations(OPTIONS)
    assert [item['status'] for item in result] == ['FAIL', 'SKIPPED', 'PASSED']
    assert result[0]['reason'] == 'route missing'
    assert result[1]['reason'] == 'eth1 has no carrier'
    with pytest.raises(AssertionError, match='Failed checks: failed$'):
        agent.require_passed(result)
    agent.require_passed(result[1:])


def test_carrier_skip_is_recorded_without_blocking_reboot_or_restore(fake_agent, monkeypatch, capsys):
    """Explicit skips survive both phases and remain visible to the controller."""
    checks = [{'check': 'check_ethernet_ipv6', 'status': 'SKIPPED', 'reason': 'eth1 has no carrier'}]
    monkeypatch.setattr(agent, 'observations', lambda options: checks)

    prepared = agent.prepare(fake_agent.directory, OPTIONS)
    assert fake_agent.state['saved_count'] == 1
    assert agent.read_record(fake_agent.directory, 'before.json') == checks
    assert agent.reboot(fake_agent.directory)['scheduled']

    fake_agent.state['boot'] = 'after'
    verified = agent.verify(fake_agent.directory)
    assert checks[0] in agent.read_record(fake_agent.directory, 'after.json')['checks']
    runner.show_checks(prepared)
    runner.show_checks(verified)
    output = capsys.readouterr().out
    assert output.count('SKIPPED') == 2
    assert output.count('eth1 has no carrier') == 2

    agent.restore(fake_agent.directory)
    assert fake_agent.saved.read_bytes() == fake_agent.original_bytes


class FakeRouter:
    """Record remote phases and simulate a failed postboot check."""
    def __init__(self, failure=None):
        self.calls = []
        self.failure = failure
        self.options = None

    def call(self, action, run_id, **kwargs):
        self.calls.append(action)
        if action == self.failure:
            raise runner.RemoteError('simulated failure')
        if action == 'diagnostics':
            return {'records': {'original.json': {'running': {}}}}
        if action == 'prepare':
            self.options = kwargs['options']
            return {'boot_id': 'before', 'checks': []}
        if action == 'ready':
            return {'boot_id': 'after', 'ready': True}
        return {}


def test_runner_success_restores_only_after_verification(tmp_path):
    """A passing run has one reboot and restoration follows the postboot checks."""
    router = FakeRouter()
    result = runner.run(router, str(uuid.uuid4()), tmp_path, options=OPTIONS)
    assert result['status'] == 'PASSED'
    assert router.options == OPTIONS
    assert router.calls == ['prepare', 'diagnostics', 'reboot', 'ready', 'verify', 'diagnostics', 'restore']


def test_runner_failed_verification_leaves_state(tmp_path):
    """Keep failure evidence instead of restoring away the defect."""
    router = FakeRouter(failure='verify')
    result = runner.run(router, str(uuid.uuid4()), tmp_path, options=OPTIONS)
    assert result['status'] == 'FAIL'
    assert result['phase'] == 'verify'
    assert 'restore' not in router.calls
    assert (tmp_path / 'failure-diagnostics.json').exists()


def test_runner_requires_external_backup_before_reboot(tmp_path):
    """Don't risk losing the only original snapshot inside an unreachable router."""
    router = FakeRouter(failure='diagnostics')
    result = runner.run(router, str(uuid.uuid4()), tmp_path, options=OPTIONS)
    assert result['status'] == 'FAIL'
    assert 'reboot' not in router.calls


def test_wait_does_not_accept_old_boot(monkeypatch):
    """Even an incorrectly ready response must include a changed boot ID."""
    clock = [0]
    monkeypatch.setattr(runner.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(runner.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    router = SimpleNamespace(call=lambda *args, **kwargs: {'ready': True, 'boot_id': 'before'})

    with pytest.raises(runner.RemoteError, match='deadline exceeded'):
        runner.await_reboot(router, 'test', 'before', timeout=3, interval=1)


def test_ssh_arguments_are_data():
    """The remote command stays fixed; run arguments travel in the JSON input."""
    recorded = {}

    def execute(command, **kwargs):
        recorded.update(command=command, **kwargs)
        return SimpleNamespace(returncode=0, stdout='{"ok": true, "result": {}}', stderr='')

    router = runner.Router('admin@router')
    router.password_transport = SimpleNamespace(execute=execute)
    router.call('verify', 'an-id')
    assert recorded['command'] == 'cd /usr/lib/nvyr && exec python3 -m acceptance.agent'
    assert not recorded['root']
    assert json.loads(recorded['payload']) == {'action': 'verify', 'run_id': 'an-id'}
    with pytest.raises(ValueError):
        runner.Router('-oProxyCommand=bad')


def test_run_id_cannot_escape_backup_directory():
    """Remote phase selectors cannot turn into arbitrary backup paths."""
    with pytest.raises(ValueError):
        agent.run_directory('../../saved')


def test_agent_packaged_separately_from_smoketests():
    """Installed images carry the agent, but the ordinary pytest suite does not collect it."""
    script = Path('scripts/build-deb.sh').read_text()
    assert '"$stage/usr/lib/nvyr/acceptance/$relative"' in script
    assert "-name '*.set'" in script
    assert 'recursive-include acceptance *.py *.md *.set' in Path('MANIFEST.in').read_text()
    assert not list(Path('acceptance').glob('test_*.py'))


def test_runner_rejects_missing_spare_port_before_connecting(monkeypatch, capsys):
    """A comprehensive run must not silently omit physical interface coverage."""
    monkeypatch.setattr('sys.argv', ['acceptance.runner', 'run', 'nvyr-lab', '--disposable'])
    with pytest.raises(SystemExit) as error:
        runner.main()
    assert error.value.code == 2
    assert '--ethernet-interface is required' in capsys.readouterr().err


def test_restoration_failure_is_not_reported_as_success(tmp_path):
    """A passed reboot test with failed restoration still requires attention."""
    router = FakeRouter(failure='restore')
    result = runner.run(router, str(uuid.uuid4()), tmp_path, options=OPTIONS)
    assert result['status'] == 'FAIL'
    assert result['phase'] == 'restore'


def test_reconnect_tolerates_transport_downtime(monkeypatch):
    """SSH disconnects are expected during reboot and don't themselves fail the run."""
    calls = []

    def call(*args, **kwargs):
        calls.append(args)
        if len(calls) == 1:
            raise runner.RemoteError('Connection refused')
        return {'ready': True, 'boot_id': 'after'}

    monkeypatch.setattr(runner.time, 'sleep', lambda seconds: None)
    status = runner.await_reboot(SimpleNamespace(call=call), 'test', 'before', timeout=10)
    assert status['boot_id'] == 'after'
    assert len(calls) == 2


def test_diagnostics_collects_failed_container_units(tmp_path, monkeypatch):
    """Keep the real startup error even after rollback has removed the container."""
    commands = []

    def execute(argv):
        commands.append(argv)
        return 'container startup failure'

    monkeypatch.setattr(agent, 'command', execute)
    result = agent.diagnostics(tmp_path)
    assert result['commands']['container_journal'] == 'container startup failure'
    assert ['journalctl', '-b', '--no-pager', '-n', '200', '-u', 'nvyr-container-*'] in commands
