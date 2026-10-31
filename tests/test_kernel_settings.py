"""Kernel-setting lifecycle tests use a private procfs tree, never host tunables."""

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from build_tools.kernel_settings import generated_files
from nvyr.config_scripts import firewall
from nvyr.errors import RecoveryError, RouterError, ValidationError
from nvyr.helpers import kernel_settings, nftables
from nvyr.helpers.kernel_settings_map import SETTINGS, boot_configuration, native_value
from nvyr.schema import Schema
from nvyr.tree import lookup


@pytest.fixture
def manager(tmp_path):
    return kernel_settings.Manager(tmp_path / 'proc', profile=tmp_path / 'run/90-nvyr-firewall.conf',
                                   baseline=tmp_path / 'run/auto.json')


def seed(manager, name, value, **parameters):
    """Create a simulated kernel-provided setting and return its file."""
    path = manager.path(name, **parameters)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + '\n')
    return path


def seed_interface(manager, name, *, interface='eth0.100', value='0', gate='0'):
    """Model per-link storage and its separate all/default kernel controls."""
    seed(manager, name, value, interface='default')
    if '/conf/' in str(manager.path(name, interface='default')):
        seed(manager, name, gate, interface='all')
    return seed(manager, name, value, interface=interface)


def test_generated_defaults_and_schema_are_current():
    for path, expected in generated_files().items():
        assert path.read_text(encoding='utf-8') == expected


def test_boot_baseline_retains_routing_without_detailed_firewall_tuning():
    """Early boot enables routing without duplicating the entire CLI settings map."""
    text = boot_configuration()
    assert 'net/ipv4/ip_forward = 1\n' in text
    assert 'net/ipv6/conf/all/forwarding = 1\n' in text
    assert 'net/ipv4/conf/*/rp_filter = 0\n' in text
    assert 'net/ipv4/conf/*/send_redirects = 0\n' in text
    assert 'net/ipv4/conf/*/accept_source_route = 0\n' in text
    assert 'net/ipv4/icmp_echo_ignore_all = 0\n' in text
    assert 'net/ipv4/tcp_syncookies = 1\n' in text

    assert 'net/netfilter/' not in text
    assert '/arp_' not in text
    assert '/neigh/' not in text
    assert 'log_martians' not in text
    assert 'ratelimit' not in text


def test_startup_without_firewall_applies_detailed_defaults(engine, monkeypatch):
    """Startup still invokes the firewall helper when no firewall branch exists."""
    applied = []

    @contextmanager
    def transaction(values):
        applied.append(values)
        yield

    monkeypatch.setattr(kernel_settings, 'manager', SimpleNamespace(transaction=transaction))
    engine._run_recovery({}, {}, set(engine.schema.owners), startup=True)

    assert applied == [kernel_settings.firewall_values({})]
    assert applied[0]['connection-tracking timeout tcp established'] == '5d'
    assert applied[0]['flowtable-timeout tcp'] == '30s'


def test_defaults_are_valid_and_schema_accepts_every_setting():
    """Catch drift between backend validation, schema grammar and default units."""
    schema = Schema.bundled()
    for name, spec in SETTINGS.items():
        assert kernel_settings.validate_value(spec, spec['default']), name
        if spec['owner'] != 'firewall':
            continue
        branch = {}
        cursor = branch
        parts = name.split()
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[parts[-1]] = True if spec['kind'] == 'presence' else spec['default']
        schema.validate_configuration({'firewall': {'global-options': branch}})


def test_schema_defaults_cover_all_global_settings_without_explicit_parents():
    """A firewall branch activates every global default without creating a fail-safe."""
    schema = Schema.bundled()
    assert 'firewall' not in schema.defaults({})
    tree = schema.defaults({'firewall': {}})
    for name, spec in SETTINGS.items():
        if spec['owner'] == 'firewall' and spec['kind'] != 'presence':
            path = ('firewall', 'global-options', *name.split())
            assert lookup(tree, path) == spec['default'], name

    assert 'fail-safe' not in tree['firewall']
    assert 'connection-accounting' not in tree['firewall']['global-options']


def test_effective_firewall_commands_show_all_kernel_defaults(controller, engine, session):
    """The user's all view shows implicit defaults without persisting them as intent."""
    controller.execute('set firewall global-options state-policy established action accept', session)
    engine.commit(session)

    commands = controller.execute('show running-configuration all firewall | commands', session)['text']
    for name, spec in SETTINGS.items():
        if spec['owner'] == 'firewall' and spec['kind'] != 'presence':
            assert f'set global-options {name} {spec["default"]}\n' in commands, name

    explicit = controller.execute('show running-configuration firewall | commands', session)['text']
    assert explicit == 'set global-options state-policy established action accept\n'


def test_explicit_global_override_and_delete_restore_effective_default(controller, engine, session):
    """Removing the last child of a nested global node restores its always defaults."""
    controller.execute('set firewall global-options state-policy established action accept', session)
    controller.execute('set firewall global-options ipv4 echo-request disable', session)
    engine.commit(session)
    assert kernel_settings.firewall_values(engine.schema.defaults(engine.running))['ipv4 echo-request'] == 'disable'

    controller.execute('delete firewall global-options ipv4', session)
    engine.commit(session)
    effective = engine.schema.defaults(engine.running)
    assert lookup(effective, ('firewall', 'global-options', 'ipv4', 'echo-request')) == 'enable'
    assert kernel_settings.firewall_values(effective)['ipv4 echo-request'] == 'enable'


def test_failsafe_has_no_second_kernel_settings_owner():
    schema = Schema.bundled()
    with pytest.raises(ValidationError):
        schema.validate_configuration({'firewall': {'fail-safe': {
            'global-options': {'ipv4': {'echo-request': 'disable'}}}}})


def test_inverted_boolean_and_delete_reset(manager):
    path = seed(manager, 'ipv4 echo-request', '0')
    with manager.transaction({'ipv4 echo-request': 'disable'}):
        assert path.read_text().strip() == '1'
    values = kernel_settings.firewall_values({})
    with manager.transaction({'ipv4 echo-request': values['ipv4 echo-request']}):
        assert path.read_text().strip() == '0'


def test_duration_conversions_and_zero_intervals():
    values = kernel_settings.firewall_values({'firewall': {'global-options': {
        'ipv4': {'icmp-rate-limit': {'interval': '0ms'}, 'arp': {'cache-timeout': '2m'}},
        'connection-tracking': {'timeout': {'tcp': {'established': '2d'}}},
    }}})
    assert native_value(SETTINGS['ipv4 icmp-rate-limit interval'], values['ipv4 icmp-rate-limit interval']) == '0'
    assert native_value(SETTINGS['ipv4 arp cache-timeout'], values['ipv4 arp cache-timeout']) == '120000'
    assert native_value(SETTINGS['connection-tracking timeout tcp established'],
                        values['connection-tracking timeout tcp established']) == '172800'


@pytest.mark.parametrize('name,value', [
    ('ipv4 echo-request', 'yes'), ('ipv4 arp ignore', '4'),
    ('ipv4 arp cache-timeout', '0s'), ('ipv4 arp cache-timeout', '999999999999d'),
    ('ipv6 icmp-rate-limit interval', '1.5s'), ('ipv6 icmp-rate-limit interval', '1s10ms'),
    ('connection-tracking timeout tcp established', '1ms'),
    ('connection-tracking maximum-entries', '0'), ('connection-tracking maximum-entries', 'AUTO'),
    ('connection-tracking timestamp', 'yes'),
])
def test_invalid_values_fail_before_writes(manager, name, value):
    with pytest.raises(ValidationError):
        with manager.transaction({name: value}):
            pytest.fail('Invalid value reached the apply body')
    assert not manager.profile.exists()


def test_dotted_interfaces_and_explicit_override_precedence(manager):
    name = 'ipv4 arp proxy'
    path = seed_interface(manager, name)
    with manager.transaction({name: 'enable'}, overrides={'eth0.100': {name: 'disable'}}):
        assert path.read_text().strip() == '0'
        assert manager.path(name, interface='default').read_text().strip() == '1'
        assert manager.path(name, interface='all').read_text().strip() == '0'
        assert 'net/ipv4/conf/eth0.100/proxy_arp = 0' in manager.profile.read_text()
    with manager.transaction({name: 'enable'}):
        assert path.read_text().strip() == '1'


def test_source_route_gate_permits_future_interface_overrides(manager):
    name = 'ipv4 source-route'
    path = seed_interface(manager, name)
    with manager.transaction({name: 'disable'}, overrides={'eth0.100': {name: 'enable'}}):
        assert path.read_text().strip() == '1'
        assert manager.path(name, interface='default').read_text().strip() == '0'
        assert manager.path(name, interface='all').read_text().strip() == '1'


def test_ipv6_source_route_minimum_gate_permits_interface_override(manager):
    """Linux takes the minimum of all and the interface's routing-header setting."""
    name = 'ipv6 source-route'
    path = seed_interface(manager, name)
    with manager.transaction({name: 'disable'}, overrides={'eth0.100': {name: 'routing-header-2'}}):
        assert path.read_text().strip() == '0'
        assert manager.path(name, interface='default').read_text().strip() == '-1'
        assert manager.path(name, interface='all').read_text().strip() == '0'


@pytest.mark.parametrize('interface', ['../netfilter', 'eth0/x', '.', '..', 'eth0\\foo', 'a'*16])
def test_path_components_reject_traversal(manager, interface):
    with pytest.raises(ValidationError, match='path component'):
        manager.path('ipv4 arp proxy', interface=interface)


def test_unchanged_values_do_not_write(manager, monkeypatch):
    seed(manager, 'ipv4 echo-request', '0')
    calls = []
    monkeypatch.setattr(manager, '_write', lambda *args: calls.append(args))
    with manager.transaction({'ipv4 echo-request': 'enable'}):
        pass
    assert calls == []


def test_missing_target_does_not_partially_apply(manager):
    path = seed(manager, 'ipv4 echo-request', '0')
    with pytest.raises(RouterError, match='kernel settings'):
        with manager.transaction({'ipv4 echo-request': 'disable', 'syn-cookies': 'disable'}):
            pytest.fail('Missing sysctl reached the apply body')
    assert path.read_text().strip() == '0'
    assert not manager.profile.exists()


def test_owner_failure_restores_values_and_runtime_file(manager):
    path = seed(manager, 'ipv4 echo-request', '0')
    manager.profile.parent.mkdir(parents=True)
    manager.profile.write_text('# Previous profile\n')
    with pytest.raises(RouterError, match='nft failed'):
        with manager.transaction({'ipv4 echo-request': 'disable'}):
            assert path.read_text().strip() == '1'
            raise RouterError('nft failed')
    assert path.read_text().strip() == '0'
    assert manager.profile.read_text() == '# Previous profile\n'


def test_partial_procfs_failure_restores_prior_writes(manager, monkeypatch):
    first = seed(manager, 'ipv4 echo-request', '0')
    second = seed(manager, 'syn-cookies', '1')
    original = manager._write

    def fail(path, value):
        if path == second:
            raise PermissionError('injected write rejection')
        original(path, value)

    monkeypatch.setattr(manager, '_write', fail)
    with pytest.raises(RouterError, match='write rejection'):
        with manager.transaction({'ipv4 echo-request': 'disable', 'syn-cookies': 'disable'}):
            pytest.fail('Write failure reached body')
    assert first.read_text().strip() == '0'
    assert second.read_text().strip() == '1'
    assert not manager.profile.exists()


def test_failed_restoration_is_a_recovery_error(manager, monkeypatch):
    seed(manager, 'ipv4 echo-request', '0')
    original = manager._write

    def fail_restore(path, value):
        if value == '0':
            raise PermissionError('restore rejected')
        original(path, value)

    monkeypatch.setattr(manager, '_write', fail_restore)
    with pytest.raises(RecoveryError, match='restore rejected'):
        with manager.transaction({'ipv4 echo-request': 'disable'}):
            raise RouterError('owner failed')


def test_interface_created_during_failure_regains_old_global(manager):
    name = 'ipv4 arp proxy'
    seed_interface(manager, name)
    with pytest.raises(RouterError):
        with manager.transaction({name: 'enable'}):
            new = seed(manager, name, '1', interface='veth1')
            raise RouterError('owner failed')
    assert new.read_text().strip() == '0'


def test_auto_capacity_survives_manager_restart_and_restores_boot_value(manager):
    for name, value in [('hash-size', '65536'), ('maximum-entries', '262144'), ('maximum-expectations', '256')]:
        seed(manager, 'connection-tracking ' + name, value)
    manager.initialize()
    with manager.transaction({'connection-tracking maximum-entries': '524288'}):
        pass
    restarted = kernel_settings.Manager(manager.root, profile=manager.profile, baseline=manager.baseline)
    with restarted.transaction({'connection-tracking maximum-entries': 'auto'}):
        assert restarted.path('connection-tracking maximum-entries').read_text().strip() == '262144'


def test_firewall_apply_keeps_kernel_transaction_open_through_nft(monkeypatch, tmp_path):
    events = []

    @contextmanager
    def transaction(values):
        events.append('kernel')
        try:
            yield
        except RouterError:
            events.append('restore')
            raise

    def apply(*args, **kwargs):
        events.append('nft')
        raise RouterError('nft rejected')

    monkeypatch.setattr(kernel_settings, 'manager', SimpleNamespace(transaction=transaction))
    monkeypatch.setattr(nftables.manager, 'apply', apply)
    context = SimpleNamespace(effective={}, state_directory=tmp_path)
    with pytest.raises(RouterError, match='nft rejected'):
        firewall.apply('candidate', context)
    assert events == ['kernel', 'nft', 'restore']
