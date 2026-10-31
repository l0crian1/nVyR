import ipaddress

import pytest

from nvyr.config_scripts import service_ssh
from nvyr.errors import RecoveryError, RouterError
from nvyr.helpers import ssh


def test_host_key_path_is_absolute_for_relative_state_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert ssh.host_key('state') == tmp_path / 'state' / 'ssh' / 'host_ed25519_key'


def test_ssh_lifecycle_empty_subtree_scoped_address_and_removal(controller, engine, session, monkeypatch):
    loaded = []
    monkeypatch.setattr(ssh.manager, 'apply', lambda plan, directory, **kwargs: loaded.append(plan))
    monkeypatch.setattr(service_ssh.interfaces, 'local_addresses',
                        lambda vrf: {ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('2001:db8::1')})
    controller.execute('set service ssh', session)

    assert engine.commit(session)['results']['ssh']['success']
    assert 'ListenAddress 0.0.0.0\nListenAddress ::' in loaded[-1].desired
    assert loaded[-1].previous is None
    assert engine.running['service']['ssh'] == {}

    for index, address in enumerate(('192.0.2.1', '2001:db8::1'), 1):
        controller.execute('set service ssh listen-address ' + address, session)

        assert engine.commit(session)['results']['ssh']['success']
        assert f'ListenAddress {address}\n' in loaded[-1].desired
        assert loaded[-1].desired.count('ListenAddress') == index

    engine.save(session)

    assert engine.store.read('boot.json')['service']['ssh']['listen-address'] == ['192.0.2.1', '2001:db8::1']

    controller.execute('set service ssh listen-address 192.0.2.1', session)

    assert engine.view(session)['service']['ssh']['listen-address'] == ['192.0.2.1', '2001:db8::1']

    controller.execute('delete service ssh listen-address 192.0.2.1', session)
    engine.commit(session)

    assert loaded[-1].desired.count('ListenAddress') == 1
    assert 'ListenAddress 2001:db8::1' in loaded[-1].desired

    controller.execute('delete service ssh listen-address', session)
    engine.commit(session)

    assert 'ListenAddress 0.0.0.0' in loaded[-1].desired

    engine.save(session)

    assert engine.store.read('boot.json')['service']['ssh'] == {}

    controller.execute('delete service ssh', session)
    engine.commit(session)

    assert loaded[-1].desired is None and 'ListenAddress' in loaded[-1].previous
    assert 'ssh' not in engine.running['service']


def test_ssh_requires_local_address_and_runs_after_interfaces(controller, engine, session, monkeypatch):
    monkeypatch.setattr(service_ssh.interfaces, 'local_addresses', lambda vrf: {ipaddress.ip_address('192.0.2.1')})
    controller.execute('set service ssh listen-address 192.0.2.1', session)
    controller.execute('set service ssh listen-address 192.0.2.99', session)
    result = engine.commit(session)['results']['ssh']

    assert not result['success'] and 'not assigned' in result['error']
    assert session.mutations

    for owner, (path, priority) in engine.schema.owners.items():
        if path[0] in {'firewall', 'interfaces'}:
            assert priority < engine.schema.owners['ssh'][1]


@pytest.mark.parametrize('address', ['example.com', '192.0.2.1/24', '::1/128', 'fe80::1%eth0', 'not-an-ip'])
def test_ssh_listen_address_uses_generic_ip_validators(controller, session, address):
    with pytest.raises(RouterError):
        controller.execute('set service ssh listen-address ' + address, session)


class Service:
    def __init__(self, directory):
        self.directory = directory
        self.active = set()
        self.calls = []
        self.failures = 0

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)

        if argv[:2] == ['systemctl', 'is-active']:
            result = 0 if argv[-1] in self.active else 3
            return result

        if argv[:2] == ['systemctl', 'restart']:
            if self.failures:
                self.failures -= 1
                return 1

            self.active.add(argv[-1])

        if argv[:2] == ['systemctl', 'stop']:
            self.active.discard(argv[-1])

        return 0


@pytest.fixture
def manager(tmp_path, monkeypatch):
    run = Service(tmp_path)
    manager = ssh.Manager(tmp_path, run=run)
    monkeypatch.setattr(manager, '_key', lambda state: None)
    monkeypatch.setattr(manager, '_check_listeners', lambda unit, path: None)

    return manager, run


def test_loader_checks_before_start_skips_unchanged_and_stops_on_delete(manager, tmp_path):
    backend, run = manager
    backend.apply(ssh.Plan('default', 'new', None), tmp_path)
    commands = run.calls

    assert next(i for i, argv in enumerate(commands) if argv[0] == '/usr/sbin/sshd') < next(
        i for i, argv in enumerate(commands) if argv[:2] == ['systemctl', 'restart'])
    assert (tmp_path / 'default.conf').read_text() == 'new'

    run.calls.clear()
    backend.apply(ssh.Plan('default', 'new', 'new'), tmp_path)

    assert not any(argv[:2] == ['systemctl', 'restart'] for argv in run.calls)

    backend.apply(ssh.Plan('default', None, 'new'), tmp_path)

    assert not run.active and not (tmp_path / 'default.conf').exists()


def test_failed_listener_change_restores_previous_configuration(manager, tmp_path):
    backend, run = manager
    backend.apply(ssh.Plan('default', 'old', None), tmp_path)
    run.failures = 1

    with pytest.raises(RouterError, match='previous service configuration restored'):
        backend.apply(ssh.Plan('default', 'new', 'old'), tmp_path)

    assert (tmp_path / 'default.conf').read_text() == 'old'
    assert 'nvyr-ssh@default.service' in run.active


def test_failed_initial_enable_restores_disabled_state(manager, tmp_path):
    backend, run = manager
    run.failures = 1

    with pytest.raises(RouterError, match='previous service configuration restored'):
        backend.apply(ssh.Plan('default', 'new', None), tmp_path)

    assert not run.active and not (tmp_path / 'default.conf').exists()


def test_failed_compensation_requires_journal_recovery(manager, tmp_path):
    backend, run = manager
    run.failures = 2

    with pytest.raises(RecoveryError, match='restoring the previous service also failed'):
        backend.apply(ssh.Plan('default', 'new', 'old'), tmp_path)


def test_unmanaged_ssh_and_unsafe_instance_are_rejected(manager, tmp_path):
    backend, run = manager
    run.active.add('ssh.service')

    with pytest.raises(RouterError, match='outside nVyR management'):
        backend.apply(ssh.Plan('default', 'new', None), tmp_path)

    assert not (tmp_path / 'default.conf').exists()

    with pytest.raises(RouterError, match='Invalid SSH instance'):
        backend.apply(ssh.Plan('../escape', 'new', None), tmp_path)


def test_listener_check_requires_every_configured_address_owned_by_sshd(tmp_path, monkeypatch):
    def run(argv, **kwargs):
        if argv[0] == '/usr/sbin/sshd':
            text = 'listenaddress 127.0.0.1:22\nlistenaddress [::1]:22\n'
        elif argv[0] == 'systemctl':
            text = '123\n'
        elif '-4' in argv:
            text = 'LISTEN 0 128 127.0.0.1:22 0.0.0.0:* users:(("sshd",pid=123,fd=3))\n'
        else:
            text = f'LISTEN 0 128 [::1]:22 [::]:* users:(("sshd",pid={owner[0]},fd=4))\n'

        return text

    owner = [456]
    monkeypatch.setattr(ssh, 'cmd', run)
    backend = ssh.Manager(tmp_path)

    with pytest.raises(RouterError, match='did not bind all configured addresses: ::1'):
        backend._check_listeners('nvyr-ssh@default.service', tmp_path / 'default.conf')

    owner[0] = 123
    backend._check_listeners('nvyr-ssh@default.service', tmp_path / 'default.conf')


def test_generation_uses_gathered_current_previous_and_logging(tmp_path):
    from types import SimpleNamespace
    from nvyr.tree import ReadOnlyTree

    gathered = service_ssh.get_config(SimpleNamespace(
        effective=ReadOnlyTree({'service': {'ssh': {'listen-address': ['192.0.2.2']}},
                               'system': {'logging': {'service': {'ssh': {'level': 'debug'}}}}}),
        previous_effective=ReadOnlyTree({'service': {'ssh': {'listen-address': ['192.0.2.1']}}}),
    ))
    later = SimpleNamespace(check_only=True, report=lambda text: None, state_directory=tmp_path)
    service_ssh.verify(gathered, later)
    plan = service_ssh.generate(gathered, later)

    assert 'ListenAddress 192.0.2.2' in plan.desired
    assert 'LogLevel DEBUG3' in plan.desired
    assert 'ListenAddress 192.0.2.1' in plan.previous
    assert 'LogLevel INFO' in plan.previous
