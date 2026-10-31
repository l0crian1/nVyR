"""Lease publication, shared hosts ownership, and configuration compensation."""

import csv
import json
from pathlib import Path
import threading
from types import SimpleNamespace

import pytest

from nvyr.errors import OperationalError, RouterError
from nvyr.helpers import dhcp_hosts, hosts, kea, system, template
from nvyr.helpers.kea_formatters import subnet_id
from tests.dhcp_config import generated_server


def write_leases(path, rows):
    """Represent the append-only memfile journal, including superseded records."""
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=('address', 'valid_lifetime', 'expire',
                                                    'subnet_id', 'state', 'hostname'))
        writer.writeheader()
        for row in rows:
            writer.writerow({'address': '192.0.2.10', 'valid_lifetime': 3600, 'expire': 5000,
                             'subnet_id': subnet_id('192.0.2.0/24'), 'state': 0,
                             'hostname': 'printer', **row})


@pytest.fixture
def files(tmp_path):
    """Use real files and the production parser, never the machine's hosts file."""
    lease_file = tmp_path / 'leases.csv'
    host_file = tmp_path / 'hosts'
    configuration_file = tmp_path / 'server.json'
    host_file.write_text('127.0.0.1 localhost\n127.0.1.1 nvyr\n# static\n192.0.2.1 gateway\n')
    configuration = generated_server({
        'update-hostfile': {}, 'option': {'domain-name': 'home.example'},
        'shared-network': {'LAN': {'subnet': {'192.0.2.0/24': {}}}},
    }, 4, {})
    configuration['Dhcp4']['lease-database']['name'] = str(lease_file)
    configuration_file.write_text(json.dumps(configuration))
    write_leases(lease_file, [])
    return SimpleNamespace(leases=lease_file, hosts=host_file, config=configuration_file,
                           native=configuration)


def test_publish_domain_alias_and_preserve_static(files):
    """A lease contributes an FQDN and alias while static text stays intact."""
    original = files.hosts.read_text()
    write_leases(files.leases, [{}])
    dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
    assert files.hosts.read_text() == original + hosts.DHCP_BEGIN + (
        '192.0.2.10\tprinter.home.example printer\n') + hosts.DHCP_END

    previous = files.hosts.stat().st_mtime_ns
    dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
    assert files.hosts.stat().st_mtime_ns == previous


def test_renew_release_decline_expiration_and_restart(files):
    """Latest rows win; restart reconciliation rebuilds only still-active names."""
    write_leases(files.leases, [
        {}, {'hostname': 'renamed'},
        {'address': '192.0.2.11', 'hostname': 'released'},
        {'address': '192.0.2.11', 'hostname': 'released', 'valid_lifetime': 0},
        {'address': '192.0.2.12', 'hostname': 'declined', 'state': 1},
        {'address': '192.0.2.13', 'hostname': 'expired', 'expire': 999},
        {'address': '192.0.2.14', 'hostname': 'removed', 'subnet_id': 123},
        {'address': '192.0.2.15', 'hostname': 'reclaimed', 'state': 2},
    ])
    dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
    _, managed = hosts.split_dhcp(files.hosts.read_text())
    assert managed == '192.0.2.10\trenamed.home.example renamed\n'

    dhcp_hosts.reconcile(files.config, files.hosts, now=5000)
    assert hosts.DHCP_BEGIN not in files.hosts.read_text()


def test_domain_inheritance_and_reported_fqdn(files):
    """Subnet overrides shared scope, shared overrides server; FQDNs remain qualified."""
    server = files.native['Dhcp4']
    network = server['shared-networks'][0]
    network['option-data'] = [{'name': 'domain-name', 'data': 'office.example'}]
    write_leases(files.leases, [{}])
    assert dhcp_hosts.records(files.native, now=1000)[0][1] == ['printer.office.example', 'printer']

    network['subnet4'][0]['option-data'] = [{'name': 'domain-name', 'data': 'floor.example'}]
    assert dhcp_hosts.records(files.native, now=1000)[0][1] == ['printer.floor.example', 'printer']

    write_leases(files.leases, [{'hostname': 'Printer.Client.Example.'}])
    assert dhcp_hosts.records(files.native, now=1000)[0][1] == ['printer.client.example', 'printer']


def test_invalid_names_and_reserved_aliases(files):
    """Client-supplied hosts syntax is ignored and cannot shadow static aliases."""
    write_leases(files.leases, [
        {'hostname': 'localhost'},
        {'address': '192.0.2.11', 'hostname': 'nvyr'},
        {'address': '192.0.2.12', 'hostname': 'bad\n127.0.0.1 injected'},
        {'address': '192.0.2.13', 'hostname': 'bad#comment'},
        {'address': '192.0.2.14', 'hostname': 'gateway.home.example'},
    ])
    dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
    _, managed = hosts.split_dhcp(files.hosts.read_text())
    assert hosts.entries(managed) == [
        ('192.0.2.10', ['localhost.home.example']),
        ('192.0.2.11', ['nvyr.home.example']),
        ('192.0.2.14', ['gateway.home.example']),
    ]


def test_hostname_change_preserves_dhcp_and_removes_name_collision(files):
    """Renaming the router cannot leave a DHCP alias that overrides its new name."""
    write_leases(files.leases, [{}])
    dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
    updated = system.hostname_hosts(files.hosts.read_text(), 'printer.home.example')
    assert '127.0.1.1\tprinter.home.example printer\n' in updated
    assert hosts.DHCP_BEGIN not in updated
    assert '# static\n192.0.2.1 gateway\n' in updated


def test_disable_and_deleted_configuration_remove_only_managed_entries(files):
    """Turning the feature off cleans up immediately, without requiring a lease event."""
    original = files.hosts.read_text()
    write_leases(files.leases, [{}])
    dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
    enabled = files.config.read_text()
    files.native['Dhcp4']['hooks-libraries'] = []
    files.config.write_text(json.dumps(files.native))
    dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
    assert files.hosts.read_text() == original

    files.config.write_text(enabled)
    dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
    files.config.unlink()
    dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
    assert files.hosts.read_text() == original


def test_failed_journal_read_preserves_previous_hosts(files):
    """A partial write or missing DB must not masquerade as an empty lease list."""
    write_leases(files.leases, [{}])
    dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
    previous = files.hosts.read_text()
    files.leases.write_text('incomplete')
    with pytest.raises(OperationalError):
        dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
    assert files.hosts.read_text() == previous

    files.leases.unlink()
    with pytest.raises(OperationalError):
        dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
    assert files.hosts.read_text() == previous


def test_lfc_completed_journal_does_not_resurrect_released_name(files):
    """A compacted database and the newer append journal are reconciled together."""
    write_leases(Path(str(files.leases) + '.completed'), [{}])
    write_leases(files.leases, [{'valid_lifetime': 0}])
    assert dhcp_hosts.records(files.native, now=1000) == []


def test_lock_survives_atomic_hosts_replacement(files):
    """A concurrent update waits and reads the newly written static entries."""
    write_leases(files.leases, [{}])
    started = threading.Event()
    completed = threading.Event()
    errors = []

    def update():
        started.set()
        try:
            dhcp_hosts.reconcile(files.config, files.hosts, now=1000)
        except Exception as error:
            errors.append(error)
        finally:
            completed.set()

    with hosts.locked(files.hosts):
        worker = threading.Thread(target=update)
        worker.start()
        assert started.wait(2)
        assert not completed.wait(0.05)
        template.write(files.hosts, '127.0.1.1 printer\n')

    worker.join(timeout=3)
    assert completed.is_set() and not errors
    assert files.hosts.read_text().startswith('127.0.1.1 printer\n')
    assert '192.0.2.10\tprinter.home.example\n' in files.hosts.read_text()


def test_hook_queues_update_without_client_environment_arguments(monkeypatch):
    """Only the known event selects work; hostname payloads never become shell commands."""
    calls = []
    monkeypatch.setattr(dhcp_hosts.sys, 'argv', ['hook', 'leases4_committed'])
    monkeypatch.setenv('LEASE4_HOSTNAME', '$(untrusted)')
    monkeypatch.setattr(dhcp_hosts.subprocess, 'run', lambda command, **kwargs: calls.append((command, kwargs)))
    dhcp_hosts.hook_main()
    assert calls == [(['/usr/bin/systemctl', '--no-block', 'start', dhcp_hosts.SERVICE],
                      {'check': True, 'timeout': 10})]


def test_global_only_schema_and_native_hook(controller, engine, session, monkeypatch):
    """Global DHCPv4 can load/unload the hook; VRF and IPv6 paths reject it."""
    from tests.test_kea import devices

    monkeypatch.setattr(kea, 'inventory', devices)
    plans = []
    monkeypatch.setattr(kea.manager, 'apply', lambda plan, *args, **kwargs: plans.append(plan))
    controller.execute('set service dhcp-server listen-interface eth1', session)
    controller.execute('set service dhcp-server shared-network LAN subnet 192.0.2.0/24 range 192.0.2.10-192.0.2.20', session)
    controller.execute('set service dhcp-server update-hostfile', session)
    engine.commit(session)
    assert dhcp_hosts.enabled(json.loads(plans[-1].desired[kea.instance_name(4, 'default')]))

    controller.execute('delete service dhcp-server update-hostfile', session)
    engine.commit(session)
    native = json.loads(plans[-1].desired[kea.instance_name(4, 'default')])
    assert native['Dhcp4']['hooks-libraries'] == []

    with pytest.raises(RouterError):
        controller.execute('set vrf name BLUE service dhcp-server update-hostfile', session)
    with pytest.raises(RouterError):
        controller.execute('set service dhcpv6-server update-hostfile', session)


def test_hostfile_failure_restores_previous_kea_configuration(tmp_path, monkeypatch):
    """Host publication participates in the existing DHCP apply compensation."""
    instance = kea.instance_name(4, 'default')
    path = tmp_path / f'{instance}.json'
    old = generated_server({}, 4, {}, state_directory=tmp_path)
    new = generated_server({'update-hostfile': {}}, 4, {}, state_directory=tmp_path)
    path.write_text(json.dumps(old))
    calls = []

    def update(configuration_path):
        current = json.loads(configuration_path.read_text())
        calls.append(current)
        if dhcp_hosts.enabled(current):
            raise RouterError('hosts write failed')

    def install(name, text):
        if text is None:
            path.unlink(missing_ok=True)
        else:
            path.write_text(text)

    def execute(arguments, **kwargs):
        return 1 if 'is-active' in arguments else 0

    manager = kea.Manager(tmp_path, execute=execute, update_hosts=update)
    monkeypatch.setattr(manager, '_install', install)
    monkeypatch.setattr(kea, 'wait_listeners', lambda *args: None)
    with pytest.raises(RouterError, match='previous instances restored'):
        manager.apply(kea.Plan(4, {instance: json.dumps(new)}), tmp_path)

    assert json.loads(path.read_text()) == old
    assert calls == [new, old]
