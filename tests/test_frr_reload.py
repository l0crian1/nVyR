"""Shared reload orchestration and static configuration ownership."""

import json
from pathlib import Path

import pytest

from nvyr.config_scripts import protocols_static as static
from nvyr.errors import RecoveryError, RouterError
from nvyr.helpers import frr_reload
from nvyr.helpers.frr_reload import Manager, MgmtdCandidate
from nvyr.helpers.frr_static import adapter


class Backend(Manager):
    def __init__(self, directory):
        super().__init__(directory=directory, candidates=())
        self.running = 'hostname test\nroute-map KEEP permit 10\n set metric 10\n!\nend\n'
        self.loads = []
        self.failures = 0
        self.silent_failure = False
        self.crash = False

    def snapshot(self):
        return self.running

    def check_daemons(self, daemons):
        pass

    def reload(self, target):
        self.loads.append(target)
        if self.silent_failure:
            return
        self.running = target
        if self.crash:
            raise SystemExit('interrupted configd')
        if self.failures:
            self.failures -= 1
            raise RouterError('failed after changing FRR')


def test_snapshot_replacement_preserves_other_protocols_and_vrfs():
    before = ('hostname test\nip route 192.0.2.0/24 blackhole\n'
              'vrf BLUE\n ip route 192.0.2.0/24 reject\n vni 100\nexit-vrf\n'
              'router bgp 65001\n address-family ipv4 unicast\n'
              '  network 203.0.113.0/24\n exit-address-family\nexit\nend\n')
    target = adapter.replace(before, {'BLUE': []})
    assert 'ip route 192.0.2.0/24 blackhole' in target
    assert 'reject' not in target
    assert 'vrf BLUE\n vni 100\nexit-vrf' in target
    assert '  network 203.0.113.0/24' in target
    assert adapter.select(target, ['BLUE', 'default']) == {
        'BLUE': [], 'default': ['ip route 192.0.2.0/24 blackhole']}


def test_reload_staging_never_requests_persistence(tmp_path):
    calls = []

    def run(argv):
        calls.append(argv)
        directory = Path(argv[argv.index('--confdir') + 1])
        assert Path(argv[-1]) == directory / 'frr.conf'
        assert directory.is_relative_to(tmp_path)
        assert Path(argv[-1]).read_text() == 'hostname test\nend\n'
        assert '--overwrite' not in argv
        return ''

    manager = Manager(runner=run, directory=tmp_path)
    manager.reload('hostname test\nend\n')
    assert len(calls) == 1 and '--reload' in calls[0]
    assert calls[0][0] == '/usr/lib/frr/frr-reload.py'
    assert not list(tmp_path.iterdir())


def test_noop_and_route_deletion_preserve_other_configuration(tmp_path):
    manager = Backend(tmp_path / 'stage')
    state = tmp_path / 'state'
    desired = {'default': ['ip route 192.0.2.0/24 blackhole'],
               'BLUE': ['ipv6 route 2001:db8::/64 reject']}
    manager.apply('static', desired, state, adapter=adapter)
    manager.apply('static', desired, state, adapter=adapter)
    assert len(manager.loads) == 1

    manager.apply('static', {'default': []}, state, adapter=adapter)
    assert adapter.select(manager.running, desired) == {'default': [], 'BLUE': []}
    assert 'route-map KEEP permit 10\n set metric 10' in manager.running
    assert 'vrf BLUE\nexit-vrf' in manager.running


def test_partial_reload_failure_restores_previous_routes(tmp_path):
    manager = Backend(tmp_path / 'stage')
    state = tmp_path / 'state'
    before = {'default': ['ip route 192.0.2.0/24 blackhole']}
    manager.apply('static', before, state, adapter=adapter)
    manager.failures = 1
    with pytest.raises(RouterError, match='previous configuration restored'):
        manager.apply('static', {'default': ['ip route 198.51.100.0/24 reject']}, state, adapter=adapter)
    assert adapter.select(manager.running, before) == before
    assert 'pending' not in json.loads((state / 'frr-reload/static.json').read_text())


def test_silent_failure_is_not_reported_as_success(tmp_path):
    manager = Backend(tmp_path / 'stage')
    manager.silent_failure = True
    with pytest.raises(RouterError, match='does not match'):
        manager.apply('static', {'default': ['ip route 192.0.2.0/24 blackhole']}, tmp_path, adapter=adapter)


def test_failed_restoration_retains_journal_and_blocks_publication(tmp_path):
    manager = Backend(tmp_path / 'stage')
    manager.failures = 2
    with pytest.raises(RecoveryError, match='restoration could not be confirmed'):
        manager.apply('static', {'BLUE': ['ip route 192.0.2.0/24 reject']}, tmp_path, adapter=adapter)
    assert json.loads((tmp_path / 'frr-reload/static.json').read_text())['pending']


def test_process_interruption_recovers_new_scope_missing_from_before_image(tmp_path):
    manager = Backend(tmp_path / 'stage')
    manager.crash = True
    with pytest.raises(SystemExit):
        manager.apply('static', {'BLUE': ['ip route 192.0.2.0/24 blackhole']}, tmp_path, adapter=adapter)
    recovered = Backend(tmp_path / 'stage')
    recovered.running = manager.running
    recovered.apply('static', {'default': []}, tmp_path, adapter=adapter, recovery=True)
    assert adapter.select(recovered.running, ['BLUE', 'default']) == {'BLUE': [], 'default': []}


def test_recovery_failure_does_not_restore_interrupted_configuration(tmp_path):
    manager = Backend(tmp_path / 'stage')
    manager.running += 'ip route 192.0.2.0/24 blackhole\n'
    manager.failures = 1
    with pytest.raises(RecoveryError, match='recovery failed'):
        manager.apply('static', {'default': []}, tmp_path, adapter=adapter, recovery=True)
    assert len(manager.loads) == 1


def test_foreign_candidate_is_rejected_without_discarding_it(tmp_path):
    class ForeignCandidate:
        def check(self, runner):
            raise RouterError('foreign candidate')

        def abort(self, runner):
            pytest.fail('Foreign changes must not be discarded')

    manager = Backend(tmp_path / 'stage')
    manager.candidates = (ForeignCandidate(),)
    with pytest.raises(RouterError, match='foreign candidate'):
        manager.apply('static', {'default': []}, tmp_path, adapter=adapter)
    assert not manager.loads
    assert not (tmp_path / 'frr-reload/static.json').exists()


def test_mgmtd_discard_takes_native_lock_and_confirms_clean_candidate():
    commands = []

    def run(argv):
        commands.append(argv)
        return '{}' if 'json' in argv[-1] else ''

    MgmtdCandidate().abort(run)
    assert commands[0] == ['vtysh', '-c', 'configure terminal file-lock', '-c', 'mgmt commit abort']
    assert len(commands) == 3


def test_recovery_discards_owned_staging_even_when_running_already_matches(tmp_path):
    class Candidate:
        def __init__(self):
            self.aborted = False

        def check(self, runner):
            assert self.aborted

        def abort(self, runner):
            self.aborted = True

    from nvyr.storage import atomic_json

    atomic_json(tmp_path / 'frr-reload/static.json', {'scopes': ['default'], 'pending': {'target': {}}})
    manager = Backend(tmp_path / 'stage')
    candidate = Candidate()
    manager.candidates = (candidate,)
    manager.apply('static', {'default': []}, tmp_path, adapter=adapter, recovery=True)
    assert candidate.aborted and not manager.loads


def test_engine_restart_after_interrupted_static_apply(tmp_path, monkeypatch):
    from nvyr.controller import Controller
    from nvyr.engine import Engine
    from nvyr.schema import Schema
    from nvyr.storage import Store
    from tests.lifecycle import recorded_registry

    manager = Backend(tmp_path / 'stage')
    monkeypatch.setattr(frr_reload, 'manager', manager)
    schema = Schema.bundled()
    store = Store(tmp_path / 'state')
    engine = Engine(schema, recorded_registry(schema), store)
    session = engine.open('test', 'test')
    Controller(engine).execute('set protocols static route 192.0.2.0/24 blackhole', session)
    manager.failures = 2
    with pytest.raises(RecoveryError):
        engine.commit(session)
    assert engine.unhealthy and store.read('transaction.json')
    engine = Engine(schema, recorded_registry(schema), store)
    assert engine.running == {} and store.read('transaction.json') is None
    assert adapter.select(manager.running, ['default']) == {'default': []}


def test_engine_restart_after_unconfirmed_policy_restoration(tmp_path, monkeypatch):
    from nvyr.controller import Controller
    from nvyr.engine import Engine
    from nvyr.helpers.frr_policy import adapter as policy_adapter
    from nvyr.schema import Schema
    from nvyr.storage import Store
    from tests.lifecycle import recorded_registry

    manager = Backend(tmp_path / 'stage')
    monkeypatch.setattr(frr_reload, 'manager', manager)
    schema = Schema.bundled()
    store = Store(tmp_path / 'state')
    engine = Engine(schema, recorded_registry(schema), store)
    session = engine.open('test', 'test')
    Controller(engine).execute('set policy route-map TEST rule 10 action permit set local-preference 200', session)

    manager.failures = 2
    with pytest.raises(RecoveryError):
        engine.commit(session)
    assert engine.unhealthy and store.read('transaction.json')

    engine = Engine(schema, recorded_registry(schema), store)
    assert engine.running == {} and store.read('transaction.json') is None
    assert policy_adapter.select(manager.running, ['route-map TEST']) == {'route-map TEST': []}
    assert 'route-map KEEP permit 10' in manager.running


@pytest.mark.parametrize('path', ['vrf name BLUE protocols static route',
                                 'vrf name BLUE protocols static', 'vrf name BLUE'])
def test_cli_vrf_deletion_withdraws_routes_without_deleting_native_instance(
        tmp_path, monkeypatch, controller, engine, session, path):
    manager = Backend(tmp_path / 'stage')
    monkeypatch.setattr(frr_reload, 'manager', manager)
    controller.execute('set vrf name BLUE table 100', session)
    controller.execute('set vrf name BLUE protocols static route 192.0.2.0/24 blackhole', session)
    assert all(item['success'] for item in engine.commit(session)['results'].values())
    controller.execute('delete ' + path, session)
    assert all(item['success'] for item in engine.commit(session)['results'].values())
    assert adapter.select(manager.running, ['BLUE']) == {'BLUE': []}
    assert 'vrf BLUE\nexit-vrf' in manager.running
