"""Publish default-VRF DHCPv4 lease names without a persistent helper daemon."""

import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys

from nvyr.errors import RouterError
from nvyr.helpers import hosts, kea_leases

CONFIGURATION = Path('/run/nvyr-kea/4-64656661756c74.json')
HOOK_LIBRARY = '/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_run_script.so'
HOOK_SCRIPT = '/usr/share/kea/scripts/nvyr-dhcp-hosts'
SERVICE = 'nvyr-dhcp-hosts.service'
EVENTS = frozenset(('leases4_committed', 'lease4_renew', 'lease4_expire',
                    'lease4_recover', 'lease4_release', 'lease4_decline'))


def enabled(configuration):
    """The generated hook selection is the runtime switch for host publication."""
    for hook in configuration.get('Dhcp4', {}).get('hooks-libraries', ()):
        if hook.get('parameters', {}).get('name') == HOOK_SCRIPT:
            return True
    return False


def hostname(value):
    """Accept DNS hostnames only; lease data must never introduce hosts-file syntax."""
    value = value.lower().removesuffix('.')
    if not value or len(value) > 253:
        return None
    for label in value.split('.'):
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label):
            return None
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    return None


def domain(section, inherited=''):
    """Use the same server/shared-network/subnet domain inheritance as Kea."""
    for option in section.get('option-data', ()):
        if option.get('name') == 'domain-name':
            return option['data']
    return inherited


def subnet_domains(server):
    result = {}
    server_domain = domain(server)
    for network in server.get('shared-networks', ()):
        network_domain = domain(network, server_domain)
        for subnet in network.get('subnet4', ()):
            result[subnet['id']] = domain(subnet, network_domain)
    return result


def lease_names(lease, suffix):
    """Keep a reported FQDN; qualify a short name using its DHCP domain."""
    name = hostname(lease.get('hostname', ''))
    if name is None:
        return []
    if '.' not in name and suffix:
        name = hostname(f'{name}.{suffix.rstrip(".")}')
        if name is None:
            return []

    names = [name]
    if '.' in name:
        names.append(name.split('.', 1)[0])
    return names


def records(configuration, *, now=None):
    """Rebuild from current leases, never from potentially reordered hook payloads."""
    if not enabled(configuration):
        return []

    server = configuration['Dhcp4']
    domains = subnet_domains(server)
    result = []
    for lease in kea_leases.current_leases(server['lease-database']['name'], 4, now=now):
        if lease['state'] != 0 or lease['subnet_id'] not in domains:
            continue
        names = lease_names(lease, domains[lease['subnet_id']])
        if names:
            result.append((lease['address'], names))
    return result


def reconcile(configuration_path=CONFIGURATION, hosts_path='/etc/hosts', *, now=None):
    """Preserve the previous hosts file on read errors; atomically replace on success."""
    from nvyr.helpers.template import write

    configuration_path = Path(configuration_path)
    hosts_path = Path(hosts_path)
    with hosts.locked(hosts_path):
        try:
            configuration = json.loads(configuration_path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            configuration = {}

        text = hosts_path.read_text(encoding='utf-8') if hosts_path.exists() else ''
        desired = hosts.with_dhcp(text, records(configuration, now=now))
        if desired != text:
            mode = hosts_path.stat().st_mode & 0o777 if hosts_path.exists() else 0o644
            write(hosts_path, desired, mode=mode)


def hook_main():
    """Kea runs this asynchronously; systemd coalesces simultaneous update requests."""
    if len(sys.argv) != 2 or sys.argv[1] not in EVENTS:
        raise SystemExit('Unsupported DHCP host update event')
    subprocess.run(['/usr/bin/systemctl', '--no-block', 'start', SERVICE], check=True, timeout=10)


def main():
    try:
        reconcile()
    except (OSError, ValueError, RouterError) as error:
        print(f'Cannot update DHCP hosts: {error}', file=sys.stderr)
        raise SystemExit(1) from error
