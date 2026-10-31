"""NTP schema, compensation, service startup and operational formatting."""

import ipaddress
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import system_ntp
from nvyr.engine import Engine
from nvyr.errors import RecoveryError, RouterError, ValidationError
from nvyr.helpers import ntp
from nvyr.op_scripts import ntp as operational
from nvyr.lexer import lex
from nvyr.schema import Schema
from tests.lifecycle import recorded_registry


def test_sources_anchor_and_listener_singletons(controller, engine, session, monkeypatch):
    """Sources retain independent options; replacing a listener cannot create two bindings."""
    plans = []
    monkeypatch.setattr(ntp.manager, 'apply', lambda plan, **kwargs: plans.append(plan))
    monkeypatch.setattr(system_ntp.interfaces, 'local_addresses', lambda **kwargs: {
        ipaddress.ip_address('192.0.2.2'), ipaddress.ip_address('2001:db8::1')})

    controller.execute('set system ntp server ntp.example.net prefer nts', session)
    controller.execute('set system ntp pool pool.example.net nts', session)
    controller.execute('set system ntp listen-address ipv4 192.0.2.1 ipv6 2001:db8::1', session)
    controller.execute('set system ntp listen-address ipv4 192.0.2.2', session)
    controller.execute('set system ntp allow-client 192.0.2.0/24', session)
    controller.execute('set system ntp allow-client 2001:db8::/64', session)

    assert engine.commit(session)['results']['ntp']['success']
    rendered = plans[-1].desired
    assert 'server ntp.example.net iburst prefer nts' in rendered
    assert 'pool pool.example.net iburst nts' in rendered
    assert rendered.count('bindaddress ') == 2
    assert 'bindaddress 192.0.2.2' in rendered
    assert 'bindaddress 192.0.2.1' not in rendered
    assert 'allow 192.0.2.0/24' in rendered
    assert 'allow 2001:db8::/64' in rendered

    controller.execute('delete system ntp', session)
    assert engine.commit(session)['results']['ntp']['success']
    assert plans[-1].desired is None
    assert plans[-1].previous == rendered


def test_schema_rejects_wrong_listener_family(controller, session):
    """The leaf schemas enforce family without custom count checks."""
    with pytest.raises(RouterError):
        controller.execute('set system ntp listen-address ipv4 2001:db8::1', session)
    with pytest.raises(RouterError):
        controller.execute('set system ntp listen-address ipv6 192.0.2.1', session)


def test_saved_ntp_reapplied_on_boot(controller, engine, session, monkeypatch):
    """Cold startup restores saved sources, dropping unsaved runtime changes."""
    plans = []
    monkeypatch.setattr(ntp.manager, 'apply', lambda plan, **kwargs: plans.append(plan))
    controller.execute('set system ntp server ntp.example.net nts', session)
    assert engine.commit(session)['results']['ntp']['success']
    engine.save(session)
    controller.execute('set system ntp server 192.0.2.123', session)
    assert engine.commit(session)['results']['ntp']['success']

    recovered = Engine(engine.schema, recorded_registry(engine.schema), engine.store, boot_id='next-boot')
    assert 'server ntp.example.net iburst nts' in plans[-1].desired
    assert '192.0.2.123' not in plans[-1].desired
    assert recovered.running['system']['ntp']['server'] == {'ntp.example.net': {'nts': True}}


def test_interface_changes_reverify_ntp(controller, engine, session, monkeypatch):
    """Declarative watching catches a listener that leaves its routing domain."""
    local = {ipaddress.ip_address('192.0.2.1')}
    monkeypatch.setattr(system_ntp.interfaces, 'local_addresses', lambda **kwargs: local)

    def apply_interfaces(owner, links, **kwargs):
        local.clear()
        for link in links.values():
            local.update(ipaddress.ip_interface(address).ip for address in link['addresses'])

    monkeypatch.setattr(system_ntp.interfaces.manager, 'replace', apply_interfaces)
    controller.execute('set interfaces dummy dum97 address 192.0.2.1/24', session)
    controller.execute('set system ntp listen-address ipv4 192.0.2.1', session)
    assert engine.commit(session)['results']['ntp']['success']

    controller.execute('delete interfaces dummy dum97 address', session)
    result = engine.commit(session)['results']['ntp']
    assert not result['success']
    assert ipaddress.ip_address('192.0.2.1') in local


def test_source_and_client_values_cannot_inject_directives(controller, session):
    """Values are strict addresses/DNS names, never arbitrary Chrony fragments."""
    with pytest.raises(RouterError):
        controller.execute('set system ntp server "example.net iburst"', session)
    with pytest.raises(RouterError):
        controller.execute('set system ntp allow-client example.net', session)


def test_client_only_defaults():
    """No implicit upstream, client authorization or remote management socket is added."""
    rendered = system_ntp.render_service({})
    assert 'allow ' not in rendered
    assert 'server ' not in rendered
    assert 'pool ' not in rendered
    assert 'cmdport 0' in rendered
    assert 'driftfile /config/ntp/drift' in rendered
    assert 'ntsdumpdir /config/ntp' in rendered


def test_generation_uses_gathered_sections_and_preserves_source_directives():
    from copy import deepcopy
    from nvyr.tree import ReadOnlyTree

    current = {'server': {'time.example.net': {'prefer': True, 'nts': True}, '192.0.2.123': {}},
               'pool': {'pool.example.net': {'nts': True}}, 'vrf': 'BLUE',
               'listen-address': {'ipv4': '0.0.0.0', 'ipv6': '::'},
               'allow-client': ['192.0.2.0/24', '2001:db8::/64']}
    configuration = system_ntp.get_config(SimpleNamespace(
        effective=ReadOnlyTree({'system': {'ntp': current}, 'vrf': {'name': {'BLUE': {}}}}),
        previous_effective=ReadOnlyTree({'system': {'ntp': {}}}),
    ))
    before = deepcopy(configuration)
    later = SimpleNamespace(check_only=True, report=lambda text: None)

    system_ntp.verify(configuration, later)
    plan = system_ntp.generate(configuration, later)

    assert plan.desired.splitlines() == [
        'pidfile /run/nvyr-chrony/chronyd.pid', 'bindcmdaddress /run/nvyr-chrony/chronyd.sock',
        'cmdport 0', 'driftfile /config/ntp/drift', 'ntsdumpdir /config/ntp', 'makestep 1.0 3', 'rtcsync',
        'server time.example.net iburst prefer nts', 'server 192.0.2.123 iburst',
        'pool pool.example.net iburst nts', 'bindaddress 0.0.0.0', 'bindaddress ::',
        'allow 192.0.2.0/24', 'allow 2001:db8::/64', 'binddevice BLUE', 'bindacqdevice BLUE',
    ]
    assert plan.previous == system_ntp.render_service({})
    assert configuration == before


def test_vrf_dependency_blocks_deletion(controller, engine, session):
    """The dependency registrar protects the selected routing domain."""
    controller.execute('set vrf name BLUE table 101', session)
    controller.execute('set system ntp vrf BLUE', session)
    with pytest.raises(RouterError, match='referenc'):
        controller.execute('delete vrf name BLUE', session)


def test_missing_vrf_rejected():
    """An unresolved registrar reference is rejected by the consuming script."""
    context = SimpleNamespace(effective={}, check_only=True)
    with pytest.raises(ValidationError, match='VRF is not configured'):
        system_ntp.verify({'current': {'vrf': 'MISSING'}, 'vrfs': {}}, context)


def test_listener_checked_in_selected_vrf(monkeypatch):
    """An address from another routing domain cannot be used as this listener."""
    seen = []
    def addresses(*, vrf):
        seen.append(vrf)
        return set()

    monkeypatch.setattr(system_ntp.interfaces, 'local_addresses', addresses)
    context = SimpleNamespace(effective={'vrf': {'name': {'BLUE': {}}}}, check_only=False)
    with pytest.raises(ValidationError, match='not assigned in VRF BLUE'):
        system_ntp.verify({'current': {'vrf': 'BLUE', 'listen-address': {'ipv4': '192.0.2.1'}},
                           'vrfs': {'BLUE': {}}}, context)
    assert seen == ['BLUE']


def test_commit_check_does_not_require_applied_addresses(monkeypatch):
    """Dry-run verification must work before interfaces have been created."""
    monkeypatch.setattr(system_ntp.interfaces, 'local_addresses', lambda **kwargs: pytest.fail('host lookup'))
    messages = []
    context = SimpleNamespace(effective={}, check_only=True, report=messages.append)
    system_ntp.verify({'current': {'listen-address': {'ipv4': '192.0.2.1'}}, 'vrfs': {}}, context)
    assert messages and 'skipped' in messages[0]
    system_ntp.verify({'current': None, 'vrfs': {}}, context)
    system_ntp.verify({'current': {}, 'vrfs': {}}, context)


def test_vrf_launcher_covers_dns_and_restarts():
    """The process routing domain also applies to asynchronous DNS and NTS-KE."""
    configuration = system_ntp.render_service({'vrf': 'BLUE'})
    assert 'binddevice BLUE' in configuration
    assert 'bindacqdevice BLUE' in configuration
    command = ntp.launch_command(configuration, restarted=True)
    assert command[:5] == ['/usr/sbin/ip', 'vrf', 'exec', 'BLUE', '/usr/sbin/chronyd']
    assert command[-1] == '-R'
    assert '-R' not in ntp.launch_command('', restarted=False)


def test_start_marker_survives_reconfiguration(tmp_path, monkeypatch):
    """Only the first successful daemon launch in a boot permits initial stepping."""
    path = tmp_path / 'chrony.conf'
    path.write_text('cmdport 0\n')
    calls = []
    monkeypatch.setattr(ntp, 'CONFIGURATION', path)
    monkeypatch.setattr(ntp.subprocess, 'run', lambda argv, **kwargs: calls.append(argv))
    ntp.main()
    ntp.main()
    assert '-R' not in calls[0]
    assert '-R' in calls[1]


class Service:
    """Model systemctl return codes and native syntax/readiness failures."""
    def __init__(self):
        self.calls = []
        self.active = set()
        self.failures = 0
        self.invalid = False

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:2] == ['systemctl', 'is-active']:
            return 0 if argv[-1] in self.active else 3
        if argv[:2] == ['systemctl', 'restart']:
            if self.failures:
                self.failures -= 1
                return 1
            self.active.add(argv[-1])
        if argv[:2] == ['systemctl', 'stop']:
            self.active.discard(argv[-1])
        return 0

    def cmd(self, argv, **kwargs):
        self.calls.append(argv)
        if self.invalid and argv[0] == '/usr/sbin/chronyd':
            raise RouterError('Invalid configuration')
        return 'Not synchronised'


def test_manager_validates_before_apply_and_skips_unchanged(tmp_path):
    """An unreachable source must not make successful daemon startup fail."""
    service = Service()
    manager = ntp.Manager(tmp_path, run=service.run, cmd=service.cmd)
    manager.apply(ntp.Plan('new', None))
    parse_index = next(i for i, argv in enumerate(service.calls) if argv[0] == '/usr/sbin/chronyd')
    restart_index = service.calls.index(['systemctl', 'restart', ntp.UNIT])
    assert parse_index < restart_index

    manager.apply(ntp.Plan('new', 'new'))
    assert service.calls.count(['systemctl', 'restart', ntp.UNIT]) == 1
    manager.apply(ntp.Plan(None, 'new'))
    assert not (tmp_path / 'chrony.conf').exists()
    assert ntp.UNIT not in service.active


def test_native_parse_failure_leaves_service_untouched(tmp_path):
    """Rejected native syntax never stops or replaces the working instance."""
    service = Service()
    service.invalid = True
    (tmp_path / 'chrony.conf').write_text('previous')
    manager = ntp.Manager(tmp_path, run=service.run, cmd=service.cmd)
    with pytest.raises(RouterError, match='Invalid configuration'):
        manager.apply(ntp.Plan('bad', 'previous'))
    assert (tmp_path / 'chrony.conf').read_text() == 'previous'
    assert ['systemctl', 'restart', ntp.UNIT] not in service.calls


def test_start_failure_restores_previous_configuration(tmp_path):
    """A failed desired service is compensated using the previous effective tree."""
    service = Service()
    service.failures = 1
    manager = ntp.Manager(tmp_path, run=service.run, cmd=service.cmd)
    with pytest.raises(RouterError, match='previous configuration restored'):
        manager.apply(ntp.Plan('bad', 'previous'))
    assert (tmp_path / 'chrony.conf').read_text() == 'previous'
    assert ntp.UNIT in service.active


def test_failed_compensation_requires_recovery(tmp_path):
    """Do not claim recovery if the prior service cannot be restored either."""
    service = Service()
    service.failures = 2
    manager = ntp.Manager(tmp_path, run=service.run, cmd=service.cmd)
    with pytest.raises(RecoveryError, match='restoring the previous configuration failed'):
        manager.apply(ntp.Plan('bad', 'previous'))


def test_another_clock_daemon_rejected(tmp_path):
    """Never start a second process that would compete to discipline the clock."""
    service = Service()
    service.active.add('chrony.service')
    manager = ntp.Manager(tmp_path, run=service.run, cmd=service.cmd)
    with pytest.raises(RouterError, match='outside nVyR'):
        manager.apply(ntp.Plan('new', None))
    assert ['systemctl', 'restart', ntp.UNIT] not in service.calls


def test_tracking_and_sources_output(monkeypatch):
    """Keep unsynchronized state and unresolved sources visible in text and raw output."""
    monkeypatch.setattr(operational, 'report', lambda command, **kwargs: [[
        '00000000', '', '0', '0', '0', '0', '0', '0', '0', '0', '1', '1', '0', 'Not synchronised']])
    assert 'Not synchronised' in operational.tracking()
    assert json.loads(operational.tracking(raw=True))['Reference time (UTC)'] == 'Never'

    monkeypatch.setattr(operational, 'report', lambda command, **kwargs: [[
        '^', '?', 'ntp.example.invalid', '0', '6', '0', '4294967295', '0', '0', '0']])
    data = json.loads(operational.sources(raw=True))
    assert data[0]['Source'] == 'ntp.example.invalid'
    assert data[0]['Last received (s)'] is None
    assert 'Unavailable' in operational.sources()


def test_empty_sources(monkeypatch):
    """An enabled server with no upstreams has a useful empty source report."""
    monkeypatch.setattr(operational, 'report', lambda command, **kwargs: [])
    assert operational.sources() == 'No NTP sources configured.\n'
    assert json.loads(operational.sources(raw=True)) == []


@pytest.mark.parametrize('no_resolve', [False, True])
def test_source_names_or_addresses_reach_chrony(monkeypatch, tmp_path, no_resolve):
    """Numeric mode identifies both IPv4 and IPv6 pool members without changing columns."""
    socket = tmp_path / 'chronyd.sock'
    socket.touch()
    monkeypatch.setattr(operational, 'SOCKET', str(socket))
    calls = []
    addresses = ['192.0.2.123', '2001:db8::123']
    names = addresses if no_resolve else ['pool.example.net', 'pool.example.net']

    def command(argv, **kwargs):
        calls.append(argv)
        return '\n'.join(f'^,*,{name},2,6,17,14,0.001,0.001,0.01' for name in names)

    monkeypatch.setattr(operational, 'cmd', command)
    data = json.loads(operational.sources(raw=True, no_resolve=no_resolve))
    assert [row['Source'] for row in data] == names
    text = operational.sources(no_resolve=no_resolve)
    assert all(name in text for name in names)
    assert 'Poll (s)' in text
    assert all(argv == ['chronyc', '-h', str(socket), '-c',
                        '-n' if no_resolve else '-N', 'sources', '-a'] for argv in calls)


def test_no_resolve_command_and_completion(controller):
    """The numeric source view is executable and discoverable through normal CLI help."""
    schema = Schema.bundled('operational')
    node = schema.resolve(lex('show ntp sources no-resolve')).node
    assert node['command']['argv'] == ['ntp.nvyr.op', 'sources', '--no_resolve']
    completion = controller.completion('show ntp sources ', explicit=True)
    assert 'no-resolve' in dict(completion['candidates'])


def test_packaging_contains_service_and_persistent_state():
    """The ISO/deb include Chrony and writable configd/runtime paths on first boot."""
    root = Path(__file__).resolve().parents[1]
    assert 'chrony (>= 4.6)' in (root / 'packaging/debian/control').read_text()
    assert 'chrony\n' in (root / 'images/router.list.chroot').read_text()
    assert '/run/nvyr-ntp' in (root / 'packaging/nvyr-configd.service').read_text()
    assert 'd /config/ntp 0750 _chrony _chrony' in (root / 'packaging/nvyr-network.conf').read_text()
    assert 'nvyr-ntp.service' in (root / 'scripts/build-deb.sh').read_text()
