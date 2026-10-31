#!/usr/bin/env python3
"""Read-only DHCPv4 and DHCPv6 lease, allocation-range and listener views."""

import ipaddress
import json
import time

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError, RouterError
from nvyr.helpers import kea
from nvyr.helpers.kea_leases import current_leases, pool_bounds
from nvyr.helpers.output import elapsed_time
from nvyr.op_scripts import services


def selected_servers(configuration, family, vrf, shared_network):
    service = 'dhcp-server' if family == 4 else 'dhcpv6-server'
    scopes = {'default': configuration} | configuration.get('vrf', {}).get('name', {})
    selected = []
    for name, scope in sorted(scopes.items()):
        section = scope.get('service', {}).get(service)
        if section is None or (vrf is not None and name != vrf):
            continue
        if shared_network is not None and shared_network not in section.get('shared-network', {}):
            continue
        selected.append((name, section))
    if not selected and (vrf is not None or shared_network is not None):
        raise OperationalError('No configured DHCP server matches that selection.')
    return selected


def subnet_index(server, family, shared_network):
    result = {}
    for shared in server.get('shared-networks', []):
        if shared_network is not None and shared['name'] != shared_network:
            continue
        for subnet in shared.get(f'subnet{family}', []):
            result[subnet['id']] = (shared['name'], subnet)
    return result


def lease_rows(vrf, leases, subnets, shared_network):
    rows = []
    for lease in leases:
        scope = subnets.get(lease['subnet_id'])
        if scope is None and shared_network is not None:
            continue
        pool, subnet = scope if scope else (None, {})
        rows.append({
            'vrf': vrf, 'pool': pool, 'subnet': subnet.get('subnet'),
            'address': lease['address'], 'mac': lease.get('hwaddr') or None,
            'hostname': lease.get('hostname') or None, 'duid': lease.get('duid') or None,
            'iaid': lease.get('iaid'), 'status': lease['status'],
            'expires_in': lease['expires_in'], 'infinite': lease['infinite'],
        })
    return rows


def pool_rows(vrf, leases, subnets):
    """Count active and declined addresses separately; reservations outside ranges do not consume them."""
    rows = []
    for subnet_id, (pool, subnet) in subnets.items():
        for allocation in subnet.get('pools', []):
            first, last = pool_bounds(allocation['pool'])
            assigned = declined = 0
            for lease in leases:
                if lease['subnet_id'] != subnet_id or lease.get('lease_type', 0) != 0:
                    continue
                if first <= int(ipaddress.ip_address(lease['address'])) <= last:
                    if lease['status'] == 'Declined':
                        declined += 1
                    else:
                        assigned += 1
            total = last - first + 1
            rows.append({'vrf': vrf, 'pool': pool, 'subnet': subnet['subnet'],
                         'range': allocation['pool'], 'assigned': assigned, 'declined': declined,
                         'total': total, 'used_percent': 100 * (assigned + declined) / total})
    return rows


def listener_rows(vrf, native, server, shared_network):
    status = kea.control(native, 'status-get', timeout=2)
    sockets = status.get('arguments', {}).get('sockets', {})
    listeners = server['interfaces-config']['interfaces']
    waiting = kea.waiting_for_carrier(status, listeners)
    devices = kea.inventory()
    selected_interface = None
    if shared_network is not None:
        shared = next((item for item in server.get('shared-networks', [])
                       if item['name'] == shared_network), None)
        if shared is None:
            return []
        selected_interface = shared.get('interface')
        # IPv4 subnet selection can be address-based; do not invent an exclusive listener association.
        if selected_interface is None:
            raise OperationalError('This pool has no exclusive interface binding; use the server listeners view.')

    rows = []
    for listener in listeners:
        interface, _, address = listener.partition('/')
        if selected_interface is not None and interface != selected_interface:
            continue
        if sockets.get('status') == 'ready':
            state = 'Listening'
        elif interface in waiting:
            state = 'Waiting for carrier'
        else:
            state = 'Not ready'
        addresses = [address] if address else []
        if not address or ipaddress.ip_address(address).version == 6:
            # A DHCPv6 unicast binding supplements, rather than replaces, the link-local socket.
            addresses.extend(value for value in devices.get(interface, {}).get('addresses', [])
                             if ipaddress.ip_address(value).version == 6
                             and ipaddress.ip_address(value).is_link_local and value not in addresses)
        for bound_address in addresses or [None]:
            rows.append({'vrf': vrf, 'interface': interface, 'address': bound_address,
                         'state': state, 'detail': '; '.join(str(value) for value in sockets.get('errors', []))})
    return rows


def display(records, view, family):
    if not records:
        return f'No DHCP {view} found.\n'
    if view == 'leases':
        fields = [('VRF', 'vrf'), ('Pool', 'pool'), ('Subnet', 'subnet'), ('Address', 'address')]
        fields += [('MAC address', 'mac'), ('Hostname', 'hostname')] if family == 4 else [('DUID', 'duid'), ('IAID', 'iaid')]
        fields += [('State', 'status'), ('Expires in', 'expires_in')]
    elif view == 'pools':
        fields = [('VRF', 'vrf'), ('Pool', 'pool'), ('Subnet', 'subnet'), ('Range', 'range'),
                  ('Assigned', 'assigned'), ('Declined', 'declined'), ('Total', 'total'), ('Used', 'used_percent')]
    else:
        fields = [('VRF', 'vrf'), ('Interface', 'interface'), ('Address', 'address'),
                  ('State', 'state'), ('Detail', 'detail')]
    rows = []
    for record in records:
        row = []
        for _, key in fields:
            value = record.get(key)
            if key == 'expires_in':
                value = 'Never' if record['infinite'] else elapsed_time(value)
            elif key == 'used_percent':
                value = f'{value:.1f}%'
            row.append('—' if value is None else value)
        rows.append(row)
    return tabulate(rows, headers=[label for label, _ in fields], disable_numparse=True) + '\n'


@opmode.command
def show(family: int, view: str, vrf: str | None = None, shared_network: str | None = None,
         raw: bool = False):
    if family not in (4, 6) or view not in ('leases', 'pools', 'listeners'):
        raise OperationalError('Select DHCP family 4 or 6 and leases, pools or listeners.')
    selected = selected_servers(services.running_configuration(), family, vrf, shared_network)
    records = []
    disabled = []
    now = time.time()
    for name, section in selected:
        if 'disable' in section:
            disabled.append(name)
            continue
        native = kea.RUNTIME / (kea.instance_name(family, name) + '.sock')
        try:
            server = kea.control(native, 'config-get', timeout=2)['arguments'][f'Dhcp{family}']
            if view == 'listeners':
                records.extend(listener_rows(name, native, server, shared_network))
                continue
            subnets = subnet_index(server, family, shared_network)
            leases = current_leases(server['lease-database']['name'], family, now)
            if view == 'leases':
                records.extend(lease_rows(name, leases, subnets, shared_network))
            else:
                records.extend(pool_rows(name, leases, subnets))
        except (OSError, RouterError, ValueError, KeyError) as error:
            raise OperationalError(f'DHCPv{family} server {name}: {error}') from error
    if raw:
        return json.dumps({'records': records, 'disabled_servers': disabled})
    output = display(records, view, family)
    if disabled:
        output += '\nDisabled servers omitted: ' + ', '.join(disabled) + '\n'
    return output


if __name__ == '__main__':
    opmode.run()
