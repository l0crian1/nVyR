"""DHCP views preserve journal semantics, runtime truth and CLI scoping."""

import csv
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from nvyr.errors import OperationalError
from nvyr.helpers import access, dhcp as client, kea_leases, suggestors
from nvyr.op_scripts import dhcp, dhcp_server


def journal(path, rows, family=4):
    fields = ['address', 'hwaddr', 'client_id', 'valid_lifetime', 'expire', 'subnet_id',
              'fqdn_fwd', 'fqdn_rev', 'hostname', 'state']
    if family == 6:
        fields += ['duid', 'iaid', 'lease_type']
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({'valid_lifetime': 3600, 'expire': 4600, 'subnet_id': 7,
                             'state': 0, **row})


def test_lease_journal_replays_updates_tombstones_and_cleanup(tmp_path):
    """Current records override both LFC generations, even when a record deletes a lease."""
    path = tmp_path / 'leases.csv'
    journal(tmp_path / 'leases.csv.2', [{'address': '192.0.2.10'}, {'address': '192.0.2.11'}])
    journal(tmp_path / 'leases.csv.1', [{'address': '192.0.2.10', 'hostname': 'new-name'}])
    journal(path, [{'address': '192.0.2.11', 'valid_lifetime': 0},
                   {'address': '192.0.2.12', 'expire': 999},
                   {'address': '192.0.2.13', 'state': 2},
                   {'address': '192.0.2.14', 'state': 1}])

    records = kea_leases.current_leases(path, 4, now=1000)
    assert [record['address'] for record in records] == ['192.0.2.10', '192.0.2.14']
    assert records[0]['hostname'] == 'new-name'
    assert records[1]['status'] == 'Declined'

    # Completed LFC supersedes .1 and .2, even before those files have been unlinked.
    journal(tmp_path / 'leases.csv.completed', [{'address': '192.0.2.20'}])
    records = kea_leases.current_leases(path, 4, now=1000)
    assert [record['address'] for record in records] == ['192.0.2.14', '192.0.2.20']


def test_ipv6_lease_identifiers_and_infinite_lifetime(tmp_path):
    """DUID/IAID remain usable and infinite leases are not expired by their timestamp."""
    path = tmp_path / 'leases.csv'
    journal(path, [{'address': '2001:db8::10', 'duid': '00:03:00:01:aa:bb:cc:dd:ee:ff',
                    'iaid': 9, 'lease_type': 0, 'expire': 0, 'valid_lifetime': 4294967295}], 6)
    record, = kea_leases.current_leases(path, 6, now=1000)
    assert record['iaid'] == 9
    assert record['duid'].startswith('00:03:')
    assert record['infinite'] and record['expires_in'] is None


def test_journal_missing_partial_and_corrupt_are_errors(tmp_path):
    """Unavailable or truncated lease data must not display zero utilization."""
    path = tmp_path / 'leases.csv'
    with pytest.raises(OperationalError, match='unavailable'):
        kea_leases.current_leases(path, 4)
    path.write_text('address,valid_lifetime')
    with pytest.raises(OperationalError, match='retry'):
        kea_leases.current_leases(path, 4)
    path.write_text('address,valid_lifetime\nwrong,NaN\n')
    with pytest.raises(OperationalError, match='Invalid Kea'):
        kea_leases.current_leases(path, 4)


def test_journal_rotation_retries_instead_of_double_counting(tmp_path, monkeypatch):
    """A rotation detected after the read invalidates the complete first snapshot."""
    path = tmp_path / 'leases.csv'
    journal(path, [{'address': '192.0.2.10'}])
    real = kea_leases.fingerprint
    calls = []

    def changed_once(paths):
        calls.append(True)
        result = real(paths)
        return [None] * 4 if len(calls) == 1 else result

    monkeypatch.setattr(kea_leases, 'fingerprint', changed_once)
    assert len(kea_leases.current_leases(path, 4, 1000)) == 1
    assert len(calls) == 4


@pytest.fixture
def server(tmp_path, monkeypatch):
    path = tmp_path / 'leases.csv'
    journal(path, [{'address': '192.0.2.10', 'hostname': 'laptop', 'hwaddr': 'aa:bb:cc:dd:ee:ff'},
                   {'address': '192.0.2.11', 'state': 1}, {'address': '192.0.2.50'}])
    native = {'lease-database': {'name': str(path)}, 'interfaces-config': {'interfaces': ['eth1/192.0.2.1']},
              'shared-networks': [{'name': 'LAN', 'interface': 'eth1', 'subnet4': [
                  {'id': 7, 'subnet': '192.0.2.0/24', 'pools': [{'pool': '192.0.2.10-192.0.2.20'}]}]}]}
    configuration = {'service': {'dhcp-server': {'shared-network': {'LAN': {}}}},
                     'vrf': {'name': {'BLUE': {'service': {'dhcp-server': {'shared-network': {'OFFICE': {}}}}}}}}
    calls = []

    def control(path, command, **kwargs):
        calls.append((path, command))
        if command == 'config-get':
            return {'arguments': {'Dhcp4': native}}
        return {'arguments': {'sockets': {'status': 'ready'}}}

    monkeypatch.setattr(dhcp_server.services, 'running_configuration', lambda: configuration)
    monkeypatch.setattr(dhcp_server.kea, 'control', control)
    monkeypatch.setattr(dhcp_server.kea, 'inventory', lambda: {})
    monkeypatch.setattr(dhcp_server.time, 'time', lambda: 1000)
    return SimpleNamespace(native=native, configuration=configuration, calls=calls)


def test_pool_usage_counts_declines_without_counting_out_of_range_reservations(server):
    record, = json.loads(dhcp_server.show(4, 'pools', vrf='default', raw=True))['records']
    assert record['assigned'] == 1
    assert record['declined'] == 1
    assert record['total'] == 11
    assert record['used_percent'] == pytest.approx(200 / 11)
    output = dhcp_server.show(4, 'pools', vrf='default')
    assert 'Pool' in output and 'Shared network' not in output
    assert 'LAN' in output and '18.2%' in output


def test_lease_scope_and_unknown_selections(server):
    records = json.loads(dhcp_server.show(4, 'leases', vrf='default', shared_network='LAN', raw=True))['records']
    assert len(records) == 3
    assert all(record['pool'] == 'LAN' and record['vrf'] == 'default' for record in records)
    assert all('64656661756c74.sock' in str(path) for path, _ in server.calls)
    with pytest.raises(OperationalError, match='No configured'):
        dhcp_server.show(4, 'leases', vrf='MISSING')
    with pytest.raises(OperationalError, match='No configured'):
        dhcp_server.show(4, 'leases', shared_network='MISSING')


def test_disabled_and_unreachable_servers_are_visible(server, monkeypatch):
    server.configuration['service']['dhcp-server']['disable'] = True
    output = dhcp_server.show(4, 'leases', vrf='default')
    assert 'Disabled servers omitted: default' in output
    assert not server.calls
    del server.configuration['service']['dhcp-server']['disable']

    def unavailable(*args, **kwargs):
        raise ConnectionRefusedError('server stopped')

    monkeypatch.setattr(dhcp_server.kea, 'control', unavailable)
    with pytest.raises(OperationalError, match='DHCPv4 server default: server stopped'):
        dhcp_server.show(4, 'leases', vrf='default')


def test_listener_readiness_and_pool_filter(server, monkeypatch):
    records = json.loads(dhcp_server.show(4, 'listeners', vrf='default', shared_network='LAN', raw=True))['records']
    assert records == [{'vrf': 'default', 'interface': 'eth1', 'address': '192.0.2.1',
                        'socket_type': 'raw', 'state': 'Listening', 'detail': ''}]
    original = dhcp_server.kea.control

    def waiting(path, command, **kwargs):
        if command == 'status-get':
            return {'arguments': {'sockets': {'status': 'retrying', 'errors': ['the interface eth1 is not running']}}}
        return original(path, command, **kwargs)

    monkeypatch.setattr(dhcp_server.kea, 'control', waiting)
    monkeypatch.setattr(dhcp_server.kea, 'inventory', lambda: {'eth1': {'up': True, 'running': False}})
    record, = json.loads(dhcp_server.show(4, 'listeners', vrf='default', raw=True))['records']
    assert record['state'] == 'Waiting for carrier'


def test_ipv6_unicast_listener_also_shows_link_local_socket(server, monkeypatch):
    server.native['interfaces-config']['interfaces'] = ['eth1/2001:db8::1']
    monkeypatch.setattr(dhcp_server.kea, 'inventory', lambda: {
        'eth1': {'addresses': ['2001:db8::1', 'fe80::1']}})
    rows = dhcp_server.listener_rows('BLUE', 'control.sock', server.native, None, 6)
    assert [row['address'] for row in rows] == ['2001:db8::1', 'fe80::1']
    assert all(row['socket_type'] == 'udp' for row in rows)


def test_listener_reports_applied_socket_type(server):
    server.native['interfaces-config']['dhcp-socket-type'] = 'udp'
    record, = json.loads(dhcp_server.show(4, 'listeners', vrf='default', raw=True))['records']
    assert record['socket_type'] == 'udp'
    output = dhcp_server.show(4, 'listeners', vrf='default')
    assert 'Socket type' in output and 'udp' in output


def test_client_retains_received_information_without_changing_route_policy():
    environment = {'NVYR_DHCP_TOKEN': 'test', 'NVYR_DHCP_INDEX': '2', 'ip': '192.0.2.10',
                   'subnet': '255.255.255.0', 'lease': '3600', 'router': '192.0.2.1',
                   'serverid': '192.0.2.2', 'dns': '9.9.9.9 1.1.1.1', 'domain': 'home.example'}
    lease = client.lease_event('bound', environment, now=1000)
    assert lease['server'] == '192.0.2.2'
    assert lease['duration'] == 3600 and lease['expires'] == 4600
    assert lease['domain'] == 'home.example'
    assert lease['routes'][0]['gateway'] == '192.0.2.1'


@pytest.fixture
def client_runtime(tmp_path, monkeypatch):
    runtime = client.DHCP(tmp_path, run=lambda argv: None)
    runtime.start('eth1', 2, 'aa:bb:cc:dd:ee:ff')
    token = runtime._read('clients', 'eth1')['token']
    environment = {'NVYR_DHCP_TOKEN': token, 'NVYR_DHCP_INDEX': '2', 'ip': '192.0.2.10',
                   'subnet': '255.255.255.0', 'lease': '3600', 'router': '192.0.2.1',
                   'serverid': '192.0.2.2', 'dns': '9.9.9.9'}
    lease = client.lease_event('bound', environment, now=1000)
    runtime._path('leases', 'eth1').parent.mkdir()
    runtime._path('leases', 'eth1').write_text(json.dumps(lease))
    spec = {'dhcp4': True, 'disabled': False, 'attributes': {'vrf': 'BLUE'},
            'dhcp-options': {'no-default-route': True, 'default-route-distance': 210}}
    status = {'owners': {'ethernet': {'eth1': spec}}, 'pending': {}, 'dns': {'sources': []}}
    monkeypatch.setattr(dhcp.manager, 'request', lambda operation: status)
    monkeypatch.setattr(dhcp.dhcp, 'DHCP', lambda: runtime)
    monkeypatch.setattr(dhcp.time, 'monotonic', lambda: 1000)
    monkeypatch.setattr(dhcp.kea, 'inventory', lambda: {'eth1': {'vrf': 'BLUE'}})
    monkeypatch.setattr(dhcp.services, 'unit_properties', lambda units: {units[0]: {'ActiveState': 'active'}})
    links = [{'ifname': 'eth1', 'ifindex': 2, 'addr_info': [{'local': '192.0.2.10', 'prefixlen': 24}]}]
    monkeypatch.setattr(dhcp, 'cmd', lambda argv: json.dumps([] if 'route' in argv else links))
    return SimpleNamespace(runtime=runtime, status=status, spec=spec, links=links)


def test_client_received_vs_installed_and_detail(client_runtime):
    record, = json.loads(dhcp.show(raw=True))
    assert record['state'] == 'Bound'
    assert record['vrf'] == 'BLUE'
    assert record['address_installed']
    assert record['default_route'] == 'Suppressed by no-default-route'
    assert record['gateway'] == '192.0.2.1' and not record['dns_selected']
    output = dhcp.show(interface='eth1', detail=True)
    assert 'Received name servers' in output and ' | ' in output
    assert 'Suppressed by no-default-route' in output
    assert '3600' not in output and '01:00:00' in output


def test_stale_generation_expiry_and_disabled_client_are_not_bound(client_runtime):
    client_runtime.links[0]['ifindex'] = 3
    assert dhcp.client_records()[0]['state'] == 'Seeking'
    client_runtime.links[0]['ifindex'] = 2
    path = client_runtime.runtime._path('leases', 'eth1')
    lease = json.loads(path.read_text())
    lease['expires'] = 900
    path.write_text(json.dumps(lease))
    assert dhcp.client_records()[0]['state'] == 'Seeking'
    client_runtime.spec['disabled'] = True
    assert dhcp.client_records()[0]['state'] == 'Disabled'
    with pytest.raises(OperationalError, match='not configured'):
        dhcp.show(interface='eth2')


def test_client_observation_failure_is_an_operational_error(monkeypatch):
    def removed_during_read(interface):
        raise FileNotFoundError('client lease changed')

    monkeypatch.setattr(dhcp, 'client_records', removed_during_read)
    with pytest.raises(OperationalError, match='client lease changed.*Retry'):
        dhcp.show()


@pytest.mark.parametrize(('line', 'argv'), [
    ('show dhcp-server leases', ['dhcp_server.nvyr.op', 'show', '4', 'leases']),
    ('show dhcp-server shared-network LAN pools', ['dhcp_server.nvyr.op', 'show', '4', 'pools', '--shared-network', 'LAN']),
    ('show dhcp-server vrf BLUE listeners', ['dhcp_server.nvyr.op', 'show', '4', 'listeners', '--vrf', 'BLUE']),
    ('show dhcpv6-server vrf BLUE shared-network LAN leases',
     ['dhcp_server.nvyr.op', 'show', '6', 'leases', '--vrf', 'BLUE', '--shared-network', 'LAN']),
    ('show dhcp-client', ['dhcp.nvyr.op', 'show']),
    ('show dhcp-client interface eth1 detail', ['dhcp.nvyr.op', 'show', '--interface', 'eth1', '--detail']),
])
def test_dhcp_views_are_read_only_operator_commands(controller, session, monkeypatch, line, argv):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda arguments, **kwargs: calls.append(arguments) or 'output')
    role = access.role.set('read-only')
    try:
        controller.execute(line)
    finally:
        access.role.reset(role)
    controller.execute('run ' + line, session)
    assert calls == [argv, argv]


@pytest.mark.parametrize('scope', ['empty', 'default', 'vrf'])
@pytest.mark.parametrize('service', ['dhcp-server', 'dhcpv6-server'])
def test_pool_completion_with_missing_configuration_sections(controller, scope, service):
    pools = {service: {'shared-network': {'LAN': {}}}}
    configurations = {
        'empty': {},
        'default': {'service': pools},
        'vrf': {'vrf': {'name': {'BLUE': {'service': pools}}}},
    }
    controller.engine.running = configurations[scope]

    candidates = dict(controller.completion(f'show {service} shared-network ', explicit=True)['candidates'])

    assert ('LAN' in candidates) == (scope != 'empty')


def test_pool_suggestions_include_routing_instances():
    configuration = {'service': {'dhcp-server': {'shared-network': {'LAN': {}}}},
                     'vrf': {'name': {'BLUE': {'service': {'dhcp-server': {'shared-network': {'OFFICE': {}}}}}}}}
    values = suggestors.dhcp_pools(SimpleNamespace(configuration=configuration), 4)
    assert [item.value for item in values] == ['LAN', 'OFFICE']


@pytest.fixture
def isolated_servers(tmp_path, monkeypatch):
    """Reuse pool names and subnet IDs across both families and VRFs, with separate journals."""
    configuration = {'service': {}, 'vrf': {'name': {'BLUE': {'service': {}}}}}
    native = {}
    calls = []
    for family, service in ((4, 'dhcp-server'), (6, 'dhcpv6-server')):
        for vrf, scope, number in (('default', configuration, 1),
                                   ('BLUE', configuration['vrf']['name']['BLUE'], 2)):
            scope['service'][service] = {'shared-network': {'LAN': {}}}
            address = f'192.0.{number}.10' if family == 4 else f'2001:db8:{number}::10'
            prefix = f'192.0.{number}.0/24' if family == 4 else f'2001:db8:{number}::/64'
            filename = tmp_path / f'{family}-{vrf}.csv'
            lease = {'address': address, 'hostname': f'{family}-{vrf}'}
            if family == 6:
                lease.update(duid='00:03:00:01:aa:bb:cc:dd:ee:ff', iaid=1, lease_type=0)
            journal(filename, [lease], family)
            socket = dhcp_server.kea.RUNTIME / (dhcp_server.kea.instance_name(family, vrf) + '.sock')
            native[socket] = {f'Dhcp{family}': {
                'lease-database': {'name': str(filename)},
                'shared-networks': [{'name': 'LAN', f'subnet{family}': [
                    {'id': 7, 'subnet': prefix, 'pools': [{'pool': address + '-' + address}]}]}]}}

    def control(path, command, **kwargs):
        calls.append(path)
        assert command == 'config-get'
        return {'arguments': native[path]}

    monkeypatch.setattr(dhcp_server.services, 'running_configuration', lambda: configuration)
    monkeypatch.setattr(dhcp_server.kea, 'control', control)
    monkeypatch.setattr(dhcp_server.time, 'time', lambda: 1000)
    return configuration, calls


@pytest.mark.parametrize('family,vrf,address', [
    (4, 'default', '192.0.1.10'), (4, 'BLUE', '192.0.2.10'),
    (6, 'default', '2001:db8:1::10'), (6, 'BLUE', '2001:db8:2::10'),
])
def test_same_pool_name_and_subnet_id_do_not_cross_scopes(isolated_servers, family, vrf, address):
    """Only the requested daemon and journal may supply a scoped result."""
    configuration, calls = isolated_servers
    records = json.loads(dhcp_server.show(family, 'leases', vrf=vrf, shared_network='LAN', raw=True))['records']
    assert [(item['vrf'], item['address']) for item in records] == [(vrf, address)]
    assert calls == [dhcp_server.kea.RUNTIME / (dhcp_server.kea.instance_name(family, vrf) + '.sock')]


@pytest.mark.parametrize('family,addresses', [
    (4, {'192.0.1.10', '192.0.2.10'}), (6, {'2001:db8:1::10', '2001:db8:2::10'}),
])
def test_unscoped_leases_keep_vrf_identity_without_crossing_family(isolated_servers, family, addresses):
    """An all-VRF query reads both matching daemons while retaining record ownership."""
    records = json.loads(dhcp_server.show(family, 'leases', shared_network='LAN', raw=True))['records']
    assert {item['address'] for item in records} == addresses
    assert {item['vrf'] for item in records} == {'default', 'BLUE'}


def test_failed_other_vrf_does_not_break_scoped_query(isolated_servers, monkeypatch):
    """A scoped view must not contact another instance, but an all-instance failure stays visible."""
    original = dhcp_server.kea.control
    broken = dhcp_server.kea.RUNTIME / (dhcp_server.kea.instance_name(4, 'default') + '.sock')

    def control(path, *args, **kwargs):
        if path == broken:
            raise ConnectionRefusedError('default server unavailable')
        return original(path, *args, **kwargs)

    monkeypatch.setattr(dhcp_server.kea, 'control', control)
    assert '192.0.2.10' in dhcp_server.show(4, 'leases', vrf='BLUE')
    with pytest.raises(OperationalError, match='DHCPv4 server default: default server unavailable'):
        dhcp_server.show(4, 'leases')


@pytest.mark.parametrize('family', [4, 6])
def test_empty_servers_and_empty_journals_are_distinct(server, monkeypatch, family):
    """No configured service and a running service with no leases are legitimate empty views."""
    monkeypatch.setattr(dhcp_server.services, 'running_configuration', lambda: {})
    assert json.loads(dhcp_server.show(family, 'leases', raw=True)) == {'records': [], 'disabled_servers': []}
    with pytest.raises(OperationalError, match='No configured'):
        dhcp_server.show(family, 'leases', vrf='BLUE')

    service = 'dhcp-server' if family == 4 else 'dhcpv6-server'
    monkeypatch.setattr(dhcp_server.services, 'running_configuration', lambda: {'service': {service: {}}})
    monkeypatch.setattr(dhcp_server.kea, 'control', lambda *args, **kwargs: {
        'arguments': {f'Dhcp{family}': server.native}})
    journal(Path(server.native['lease-database']['name']), [], family)
    assert json.loads(dhcp_server.show(family, 'leases', raw=True))['records'] == []
    assert 'No ' in dhcp_server.show(family, 'leases')
