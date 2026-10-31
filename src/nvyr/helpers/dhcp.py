"""DHCPv4 protocol adapter. udhcpc negotiates; netlinkd alone programs the host.

Lease hooks only write events, so stopping a client never waits on the daemon
that requested its termination. Generation and ifindex fence stale clients.
"""

import ipaddress
import json
from pathlib import Path
import secrets
import socket
import time

from nvyr.errors import RouterError
from nvyr.storage import atomic_json
from nvyr.helpers.netlink import interface_name
from nvyr.helpers.process import cmd
from nvyr.helpers.dhcp_options import client_arguments, client_options, verify_packet_budget

RUNTIME = Path('/run/nvyr-netlink')


def lease_event(event, environment, *, now=None):
    result = {'token': environment['NVYR_DHCP_TOKEN'],
              'index': int(environment['NVYR_DHCP_INDEX']), 'event': event}

    if event not in ('bound', 'renew'):
        return result

    address = ipaddress.IPv4Interface(f"{environment['ip']}/{environment['subnet']}")
    duration = int(environment['lease'])
    if duration <= 0:
        raise ValueError('DHCP lease duration must be positive')

    acquired = time.monotonic() if now is None else now
    result.update(address=str(address), expires=acquired + duration,
                  acquired=acquired, duration=duration)
    if environment.get('serverid'):
        result['server'] = str(ipaddress.IPv4Address(environment['serverid']))
    result['domain'] = environment.get('domain') or None
    routes = []

    if 'staticroutes' in environment:
        words = environment['staticroutes'].split()
        if len(words) % 2:
            raise ValueError('Invalid DHCP classless routes')

        pairs = zip(words[::2], words[1::2])
    else:
        # Prefer the first advertised router, as networkd did without multipath.
        pairs = [('0.0.0.0/0', environment['router'].split()[0])] if environment.get('router', '').strip() else []

    for destination, gateway in pairs:
        gateway = str(ipaddress.IPv4Address(gateway))
        routes.append({'dst': str(ipaddress.IPv4Network(destination, strict=False)),
                       'gateway': None if gateway == '0.0.0.0' else gateway,
                       'protocol': 16, 'metric': 1024 + result['index']})

    result['routes'] = routes

    if environment.get('mtu'):
        result['mtu'] = int(environment['mtu'])

    # Retain information for consumers without taking over router DNS policy.
    result['dns'] = [str(ipaddress.IPv4Address(value)) for value in environment.get('dns', '').split()]

    return result


class DHCP:
    def __init__(self, directory=RUNTIME, *, run=cmd):
        self.directory = Path(directory)
        self.run = run
        self.checked = {}

    def _path(self, group, name):
        return self.directory / group / (interface_name(name) + '.json')

    def _read(self, group, name):
        path = self._path(group, name)
        return json.loads(path.read_text()) if path.exists() else None

    def start(self, name, index, mac, options=None):
        wire = client_options(options or {})
        verify_packet_budget(wire)
        current = self._read('clients', name)
        if (current is None or current['index'] != index or current['mac'] != mac
                or current.get('options') != wire):
            self.stop(name)
            current = {'index': index, 'mac': mac, 'token': secrets.token_hex(16), 'options': wire}
            atomic_json(self._path('clients', name), current)

        # systemd restarts failed clients. Also repair an externally stopped unit,
        # without spawning systemctl on every link notification/lease poll.
        if time.monotonic() >= self.checked.get(name, 0):
            self.run(['systemctl', 'start', f'nvyr-dhcp4@{name}.service'])
            self.checked[name] = time.monotonic() + 30

    def stop(self, name):
        self.checked.pop(name, None)

        if self._read('clients', name) is not None:
            self.run(['systemctl', 'stop', f'nvyr-dhcp4@{name}.service'])
            self._path('clients', name).unlink(missing_ok=True)

        self._path('leases', name).unlink(missing_ok=True)

    def control(self, name, action, index, mac):
        """Signal only the current client; lease hooks remain the source of truth."""
        signals = {'release': 'SIGUSR2', 'renew': 'SIGUSR1'}
        if action not in signals:
            raise RouterError(f'Unknown DHCP action {action!r}')

        current = self._read('clients', name)
        if not current or current['index'] != index or current['mac'] != mac:
            raise RouterError(f'{name}: no current DHCPv4 client; wait for interface reconciliation')

        self.run(['systemctl', 'kill', '--kill-whom=main', f'--signal={signals[action]}',
                  f'nvyr-dhcp4@{name}.service'])

    def lease(self, name, index):
        client, event = self._read('clients', name), self._read('leases', name)
        if (not client or not event or client['index'] != index or event['index'] != index
                or client['token'] != event['token'] or event['event'] not in ('bound', 'renew')
                or event['expires'] <= time.monotonic()):
            return None

        return event


def client_main():
    import os
    import sys

    name = interface_name(sys.argv[1])
    data = json.loads((RUNTIME / 'clients' / (name + '.json')).read_text())
    if socket.if_nametoindex(name) != data['index']:
        raise RouterError(f'{name}: DHCP client interface was replaced')

    os.environ.update(NVYR_DHCP_TOKEN=data['token'], NVYR_DHCP_INDEX=str(data['index']))
    os.execv('/usr/sbin/udhcpc', client_arguments(name, data['options']))


def hook_main():
    import os
    import sys

    event = sys.argv[1]
    if event not in ('bound', 'renew', 'deconfig', 'nak'):
        return

    name = interface_name(os.environ['interface'])
    record = lease_event(event, os.environ)
    client_path = RUNTIME / 'clients' / (name + '.json')
    if not client_path.exists():
        return

    client = json.loads(client_path.read_text())
    if client['token'] == record['token'] and client['index'] == record['index']:
        atomic_json(RUNTIME / 'leases' / (name + '.json'), record)
