import json
from types import SimpleNamespace

import pytest

from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import kea, reapply
from nvyr.config_scripts import service_dhcp
from nvyr.helpers.kea_formatters import subnet_id
from tests.dhcp_config import generated_server, verify_servers
from nvyr.helpers.script_schema import ScriptIndex
from nvyr.schema import Schema


def devices():
    return {'eth1': {'vrf': 'default', 'up': True,
                     'addresses': ['192.0.2.1', '192.0.2.2', 'fe80::1', '2001:db8::1']},
            'eth2': {'vrf': 'BLUE', 'up': True,
                     'addresses': ['192.0.2.1', 'fe80::2', '2001:db8::1']}}


def server4():
    return {'listen-interface': ['eth1'], 'lease-time': '1d', 'shared-network': {
        'OFFICE': {'subnet': {'192.0.2.0/24': {'range': ['192.0.2.20-192.0.2.30', '192.0.2.50-192.0.2.60']}}}}}


def context(check_only=True):
    return SimpleNamespace(check_only=check_only, report=lambda message: None)


def test_default_vrf_schema_and_inherited_defaults(controller, engine, session, monkeypatch):
    monkeypatch.setattr(kea, 'inventory', devices)
    plans = []
    monkeypatch.setattr(kea.manager, 'apply', lambda plan, *args, **kwargs: plans.append(plan))
    controller.execute('set service dhcp-server listen-interface eth1', session)
    controller.execute('set service dhcp-server shared-network OFFICE subnet 192.0.2.0/24 range 192.0.2.20-192.0.2.30', session)
    controller.execute('set service dhcp-server shared-network OFFICE subnet 192.0.2.0/24 range 192.0.2.50-192.0.2.60', session)

    result = engine.commit(session)

    assert result['results']['dhcp-server']['success']
    native = json.loads(next(iter(plans[-1].desired.values())))['Dhcp4']
    assert native['valid-lifetime'] == 86400
    assert len(native['shared-networks'][0]['subnet4'][0]['pools']) == 2
    assert 'lease-time' not in engine.running['service']['dhcp-server']

    controller.execute('delete service dhcp-server', session)
    assert engine.commit(session)['results']['dhcp-server']['success']
    assert plans[-1].desired == {}


def test_vrf_dhcpv6_registration(controller, engine, session, monkeypatch):
    monkeypatch.setattr(kea, 'inventory', devices)
    plans = []
    monkeypatch.setattr(kea.manager, 'apply', lambda plan, *args, **kwargs: plans.append(plan))
    controller.execute('set vrf name BLUE table 40101', session)
    controller.execute('set vrf name BLUE service dhcpv6-server listen-address 2001:db8::1', session)
    controller.execute('set vrf name BLUE service dhcpv6-server shared-network OFFICE subnet 2001:db8::/64 range 2001:db8::20-2001:db8::30', session)

    assert engine.commit(session)['results']['dhcpv6-server']['success']
    native = json.loads(plans[-1].desired[kea.instance_name(6, 'BLUE')])['Dhcp6']
    assert native['interfaces-config']['interfaces'] == ['eth2/2001:db8::1']
    assert native['preferred-lifetime'] == 43200
    assert native['valid-lifetime'] == 86400


def test_logging_reapply_changes_severity_without_unnecessary_rebind(controller, engine, session, monkeypatch):
    """Rotation changes leave DHCP sockets alone; a severity change updates Kea."""
    monkeypatch.setattr(kea, 'inventory', devices)
    plans = []
    monkeypatch.setattr(kea.manager, 'apply', lambda plan, *args, **kwargs: plans.append(plan))
    controller.execute('set service dhcp-server listen-interface eth1', session)
    controller.execute('set service dhcp-server shared-network OFFICE subnet 192.0.2.0/24 range 192.0.2.20-192.0.2.30', session)
    assert engine.commit(session)['results']['dhcp-server']['success']
    initial = plans[-1].desired

    controller.execute('set system logging rotation size 64m', session)
    assert engine.commit(session)['results']['dhcp-server']['success']
    assert plans[-1].desired == initial
    assert not plans[-1].rebind

    controller.execute('set system logging service dhcp-server level debug', session)
    assert engine.commit(session)['results']['dhcp-server']['success']
    native = json.loads(next(iter(plans[-1].desired.values())))['Dhcp4']
    assert native['loggers'][0]['severity'] == 'DEBUG'
    assert not plans[-1].rebind


def test_listener_address_resolves_only_in_selected_vrf():
    assert service_dhcp.verify_listeners({'listen-address': ['192.0.2.1']}, 4, 'BLUE', devices()) == ['eth2/192.0.2.1']


def test_whole_interface_uses_one_broadcast_socket():
    assert service_dhcp.verify_listeners({'listen-interface': ['eth1']}, 4, 'default', devices()) == ['eth1/192.0.2.1']


def test_shared_interface_is_selection_and_receive_path():
    config = {'listen-address': ['192.0.2.2'], 'shared-network': {'OFFICE': {'interface': 'eth1'}}}
    assert service_dhcp.verify_listeners(config, 4, 'default', devices()) == ['eth1/192.0.2.2']


@pytest.mark.parametrize('config,family,vrf,message', [
    ({'listen-interface': ['eth1'], 'listen-address': ['192.0.2.1']}, 4, 'default', 'overlaps'),
    ({'listen-interface': ['eth2']}, 4, 'default', 'does not exist'),
    ({'listen-address': ['192.0.2.99']}, 4, 'default', 'exactly one'),
    ({'listen-address': ['192.0.2.1', '192.0.2.2']}, 4, 'default', 'only one'),
    ({}, 4, 'default', 'configure listen'),
])
def test_listener_validation(config, family, vrf, message):
    with pytest.raises(ValidationError, match=message):
        service_dhcp.verify_listeners(config, family, vrf, devices())


@pytest.mark.parametrize('ranges,message', [
    (['192.0.2.10-192.0.2.20', '192.0.2.20-192.0.2.30'], 'overlap'),
    (['192.0.3.10-192.0.3.20'], 'outside'),
    (['192.0.2.0-192.0.2.10'], 'network or broadcast'),
    ([], 'range or reservation'),
])
def test_subnet_rejections(ranges, message):
    config = server4()
    config['shared-network']['OFFICE']['subnet']['192.0.2.0/24']['range'] = ranges
    with pytest.raises(ValidationError, match=message):
        verify_servers({'default': config}, context(), 4)


def test_duplicate_and_outside_reservations():
    config = server4()
    subnet = config['shared-network']['OFFICE']['subnet']['192.0.2.0/24']
    subnet['reservation'] = {'printer': {'mac-address': '02:00:00:00:00:01', 'address': '192.0.3.1'}}
    with pytest.raises(ValidationError, match='outside'):
        verify_servers({'default': config}, context(), 4)
    subnet['reservation']['printer']['address'] = '192.0.2.10'
    subnet['reservation']['duplicate'] = dict(subnet['reservation']['printer'])
    with pytest.raises(ValidationError, match='duplicate'):
        verify_servers({'default': config}, context(), 4)


def test_lifetime_overrides_are_verified():
    with pytest.raises(ValidationError, match='preferred-lifetime'):
        verify_servers({'default': {'listen-interface': ['eth1'], 'preferred-lifetime': '2d',
                                     'valid-lifetime': '1d'}}, context(), 6)


def test_disabled_instance_needs_no_live_interfaces(monkeypatch):
    monkeypatch.setattr(kea, 'inventory', lambda: pytest.fail('unexpected host lookup'))
    verify_servers({'BLUE': {'disable': {}}}, context(False), 4)


def test_formatter_preserves_inheritance_and_stable_ids():
    config = server4()
    config['option'] = {'name-server': ['192.0.2.1', '192.0.2.2']}
    config['shared-network']['OFFICE']['lease-time'] = '12h'
    native = generated_server(config, 4, devices())['Dhcp4']
    assert native['valid-lifetime'] == 86400
    assert native['shared-networks'][0]['valid-lifetime'] == 43200
    subnet = native['shared-networks'][0]['subnet4'][0]
    assert 'valid-lifetime' not in subnet
    assert subnet['id'] == subnet_id('192.0.2.0/24')
    assert native['option-data'][0]['data'] == '192.0.2.1, 192.0.2.2'


def test_interface_changes_reapply_configured_dhcp():
    from nvyr.helpers.dependencies import Dependencies
    schema = Schema.bundled()
    before = {'service': {'dhcp-server': {}}, 'interfaces': {'dummy': {'dum0': {'address': ['192.0.2.1/24']}}}}
    after = {'service': {'dhcp-server': {}}, 'interfaces': {'dummy': {'dum0': {'address': ['192.0.2.2/24']}}}}
    plan = reapply.plan(Dependencies(schema), before, after)
    assert plan.requires['dhcp-server'] == {'dummy'}
    assert plan.order({'dummy'}, schema).index('dummy') < plan.order({'dummy'}, schema).index('dhcp-server')
    assert 'dhcpv6-server' not in plan.paths


def test_script_watch_rejects_unknown_paths():
    root = {'kind': 'node', 'script': {'name': 'test', 'priority': 1, 'watch': ['typo']}}
    with pytest.raises(ValueError, match='Unknown script watch'):
        ScriptIndex(root)


def test_address_only_watch_reapplies_and_compensates_provider(controller, engine, session, monkeypatch):
    """A derived listener still joins its interface provider's commit boundary."""
    monkeypatch.setattr(kea, 'inventory', devices)
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('set service dhcp-server listen-address 192.0.2.2', session)
    controller.execute('set service dhcp-server shared-network LAN subnet 192.0.2.0/24 range 192.0.2.10-192.0.2.20', session)
    assert engine.commit(session)['results']['dhcp-server']['success']

    plans = []

    def apply(plan, state_directory, *, recovery=False, report=None):
        plans.append((plan, recovery))
        if not recovery:
            raise RouterError('intentional listener failure')

    monkeypatch.setattr(kea.manager, 'apply', apply)
    controller.execute('set interfaces dummy dum0 description changed', session)
    controller.execute('set system host-name independent', session)
    result = engine.commit(session)

    assert result['results']['system']['success']
    assert not result['results']['dummy']['success']
    assert not result['results']['dhcp-server']['success']
    assert 'description' not in engine.running['interfaces']['dummy']['dum0']
    assert plans[0][0].rebind
    assert any(recovery for _, recovery in plans)


def test_default_and_named_vrf_duplicate_ipv4_listener_rejected(monkeypatch):
    monkeypatch.setattr(kea, 'inventory', devices)
    blue = server4()
    blue['listen-interface'] = ['eth2']
    with pytest.raises(ValidationError, match='overlaps the default VRF'):
        verify_servers({'default': server4(), 'BLUE': blue}, context(False), 4)


def test_manager_compensates_all_instances_after_reconfigure_failure(tmp_path):
    calls = []
    manager = kea.Manager(tmp_path, execute=lambda command, **kwargs: 1 if 'is-active' in command else 0)
    old = json.dumps({'Dhcp4': {'interfaces-config': {'interfaces': []}, 'user-context': {'version': 'old'}}})
    for instance in ('4-a', '4-b'):
        (tmp_path / f'{instance}.json').write_text(old)
    text = json.dumps({'Dhcp4': {'interfaces-config': {'interfaces': []}, 'lease-database': {'name': str(tmp_path / 'leases.csv')}}})

    def install(instance, value):
        calls.append((instance, value))
        if instance == '4-b' and value == text:
            raise RouterError('bind failed')
    manager._install = install

    with pytest.raises(RouterError, match='previous instances restored'):
        manager.apply(kea.Plan(4, {'4-a': text, '4-b': text}), tmp_path)
    assert calls[-4:] == [('4-b', None), ('4-a', None), ('4-a', old), ('4-b', old)]


def test_watch_forces_socket_reconfiguration_with_identical_json(tmp_path):
    """An interface recreated with the same name/address still needs new sockets."""
    text = json.dumps({'Dhcp4': {'interfaces-config': {'interfaces': []}, 'lease-database': {'name': str(tmp_path / 'leases.csv')}}})
    (tmp_path / '4-a.json').write_text(text)
    calls = []

    def execute(command, **kwargs):
        if 'is-active' in command:
            return 0 if command[-1].startswith('nvyr-kea@') else 3
        return 0

    manager = kea.Manager(tmp_path, execute=execute)
    manager._install = lambda instance, value: calls.append((instance, value))
    manager.apply(kea.Plan(4, {'4-a': text}), tmp_path)
    assert calls == []

    manager.apply(kea.Plan(4, {'4-a': text}, rebind=True), tmp_path)
    assert calls == [('4-a', text)]


def test_ipv6_shared_interface_is_derived_from_listening_prefix():
    configuration = {'shared-network': {'LAN': {'subnet': {'2001:db8::/64': {}}}}}
    assert service_dhcp.verify_shared_interfaces(configuration, 6, ['eth1'], devices()) == {'LAN': 'eth1'}


def test_ipv6_shared_interface_requires_an_unambiguous_match():
    configuration = {'shared-network': {'LAN': {'subnet': {'2001:db8::/64': {}}}}}
    with pytest.raises(ValidationError, match='configure its interface explicitly'):
        service_dhcp.verify_shared_interfaces(configuration, 6, ['eth1', 'eth2'], devices())

    configuration['shared-network']['LAN']['interface'] = 'eth1'
    assert service_dhcp.verify_shared_interfaces(configuration, 6, ['eth1', 'eth2'], devices()) == {'LAN': 'eth1'}


def test_ipv6_readiness_waits_for_dad(monkeypatch):
    """New interfaces may exist before their link-local address can bind a socket."""
    pending = {'eth1': {'addresses': ['fe80::1'], 'tentative': ['fe80::1']}}
    ready = {'eth1': {'addresses': ['fe80::1'], 'tentative': []}}
    observations = iter((pending, ready))
    monkeypatch.setattr(kea, 'inventory', lambda: next(observations))
    monkeypatch.setattr(kea.time, 'sleep', lambda seconds: None)
    kea.wait_listeners(6, ['eth1'])


def test_ipv6_readiness_reports_duplicate_address(monkeypatch):
    monkeypatch.setattr(kea, 'inventory', lambda: {
        'eth1': {'addresses': ['fe80::1'], 'dadfailed': ['fe80::1']}})
    with pytest.raises(RouterError, match='duplicate-address detection failed'):
        kea.wait_listeners(6, ['eth1'])


def test_ipv6_readiness_has_a_bounded_deadline(monkeypatch):
    monkeypatch.setattr(kea, 'inventory', lambda: {
        'eth1': {'addresses': ['fe80::1'], 'tentative': ['fe80::1']}})
    with pytest.raises(RouterError, match='did not become ready: eth1'):
        kea.wait_listeners(6, ['eth1'], timeout=0)


def test_control_readiness_requires_successfully_bound_service_sockets():
    assert kea.sockets_ready({'arguments': {'sockets': {'status': 'ready'}}})
    assert not kea.sockets_ready({'arguments': {'sockets': {'status': 'retrying'}}})
    with pytest.raises(RouterError, match='service sockets are failed'):
        kea.sockets_ready({'arguments': {'sockets': {'status': 'failed', 'errors': ['bind failed']}}})


def test_offline_ipv6_listener_defers_link_local_readiness(monkeypatch):
    """An enabled but unplugged port need not have generated a link-local address."""
    offline = {'eth1': {'vrf': 'default', 'up': True, 'running': False, 'addresses': ['2001:db8::1']}}
    monkeypatch.setattr(kea, 'inventory', lambda: offline)

    assert service_dhcp.verify_listeners({'listen-interface': ['eth1']}, 6, 'default', offline) == ['eth1']
    kea.wait_listeners(6, ['eth1'], timeout=0)

    offline['eth1']['up'] = False
    with pytest.raises(ValidationError, match='administratively disabled'):
        service_dhcp.verify_listeners({'listen-interface': ['eth1']}, 6, 'default', offline)


def test_carrier_wait_does_not_hide_other_socket_errors(monkeypatch):
    """Only selected, administratively enabled, offline interfaces may wait."""
    offline = {'eth1': {'up': True, 'running': False}}
    monkeypatch.setattr(kea, 'inventory', lambda: offline)
    sockets = {'status': 'retrying', 'errors': ['the interface eth1 is not running']}
    status = {'arguments': {'sockets': sockets}}

    assert kea.waiting_for_carrier(status, ['eth1/192.0.2.1']) == ['eth1']
    assert kea.waiting_for_carrier(status, ['eth2']) == []
    sockets['errors'].append('Address already in use')
    assert kea.waiting_for_carrier(status, ['eth1']) == []

    sockets['errors'].pop()
    offline['eth1']['running'] = True
    assert kea.waiting_for_carrier(status, ['eth1']) == []


def test_manager_accepts_and_reports_waiting_for_carrier(tmp_path, monkeypatch):
    """Commit accepts pending service with an explicit message rather than timing out."""
    monkeypatch.setattr(kea, 'inventory', lambda: {'eth1': {'up': True, 'running': False}})
    instance = kea.instance_name(4, 'default')
    text = json.dumps({'Dhcp4': {'interfaces-config': {'interfaces': ['eth1/192.0.2.1']},
                               'lease-database': {'name': str(tmp_path / 'leases.csv')}}})

    def request(path, command, arguments=None):
        assert command == 'status-get'
        return {'arguments': {'sockets': {'status': 'retrying',
                                         'errors': ['the interface eth1 is not running']}}}

    # Observe reconciliation without touching the test runner's /etc/hosts.
    reconciled = []
    manager = kea.Manager(tmp_path, execute=lambda command, **kwargs: 3 if 'is-active' in command else 0,
                          request=request, update_hosts=reconciled.append)
    messages = []
    manager.apply(kea.Plan(4, {instance: text}), tmp_path, report=messages.append)

    assert messages == ['DHCPv4 (default): waiting for carrier on eth1.']
    assert (tmp_path / f'{instance}.json').read_text() == text
    assert reconciled == [tmp_path / f'{instance}.json']


@pytest.mark.parametrize('address', ['::', 'ff02::1', 'fe80::1', '192.0.2.1'])
@pytest.mark.parametrize('root', ['service dhcpv6-server', 'vrf name BLUE service dhcpv6-server'])
def test_ipv6_listener_restriction_at_entry(controller, session, address, root):
    with pytest.raises(RouterError, match='non-link-local unicast IPv6'):
        controller.execute(f'set {root} listen-address {address}', session)
    assert not session.mutations


@pytest.mark.parametrize('service,vrf,settings', [
    ('dhcpv6-server', 'default', {'listen-address': ['fe80::1']}),
    ('dhcpv6-server', 'BLUE', {'listen-address': ['ff02::1']}),
    ('dhcpv6-server', 'default', {'update-hostfile': {}}),
    ('dhcp-server', 'BLUE', {'update-hostfile': {}}),
])
def test_loaded_service_scalar_and_scope_validation(service, vrf, settings):
    configuration = {'service': {service: settings}}
    if vrf != 'default':
        configuration = {'vrf': {'name': {vrf: configuration}}}
    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration(configuration)


@pytest.mark.parametrize('family,owner', [(4, 'dhcp-server'), (6, 'dhcpv6-server')])
def test_lifecycle_uses_one_gathered_inventory(monkeypatch, tmp_path, family, owner):
    from copy import deepcopy
    from nvyr.tree import ReadOnlyTree

    server = server4() if family == 4 else {
        'listen-interface': ['eth1'], 'preferred-lifetime': '12h', 'valid-lifetime': '1d',
        'shared-network': {'LAN': {'subnet': {'2001:db8::/64': {'range': ['2001:db8::10-2001:db8::20']}}}},
    }
    calls = []

    def inventory():
        calls.append(True)
        return devices()

    monkeypatch.setattr(kea, 'inventory', inventory)
    gathered = service_dhcp.get_config(SimpleNamespace(
        owner=owner, effective=ReadOnlyTree({'service': {owner: server}}),
        scripts={owner: {'vrf': ['default']}}, check_only=False, reapply_paths=(),
    ))
    before = deepcopy(gathered)
    later = SimpleNamespace(check_only=False, report=lambda text: None, state_directory=tmp_path)
    service_dhcp.verify(gathered, later)

    def unexpected(*args, **kwargs):
        pytest.fail('generation must not query the host or repeat configuration verification')

    monkeypatch.setattr(kea, 'inventory', unexpected)
    monkeypatch.setattr(service_dhcp, 'verify_listeners', unexpected)
    monkeypatch.setattr(service_dhcp, 'verify_shared_interfaces', unexpected)
    plan = service_dhcp.generate(gathered, later)

    assert len(plan.desired) == 1
    assert calls == [True]
    assert gathered == before


def test_check_only_does_not_query_listener_inventory(monkeypatch):
    monkeypatch.setattr(kea, 'inventory', lambda: pytest.fail('unexpected live inventory'))
    verify_servers({'default': server4()}, context(True), 4)
