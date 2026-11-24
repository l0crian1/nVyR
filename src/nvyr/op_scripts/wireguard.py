#!/usr/bin/env python3
"""WireGuard diagnostics and explicit endpoint refresh; never display stored secrets."""

import subprocess
import time

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers import wireguard
from nvyr.helpers.strip_private import strip_ip, strip_value
from nvyr.helpers.process import cmd


@opmode.command
def generate(kind: str):
    if kind == 'preshared-key':
        return cmd(['wg', 'genpsk']).strip()
    if kind != 'key-pair':
        raise OperationalError('Choose key-pair or preshared-key')
    private = cmd(['wg', 'genkey']).strip()
    public = subprocess.run(['wg', 'pubkey'], input=private + '\n', capture_output=True,
                            text=True, timeout=5, check=True).stdout.strip()
    return f'Private key: {private}\nPublic key:  {public}'


@opmode.command
def show(interface: str = None, peer: str = None, detail: bool = False, strip_private: str = None):
    names = [interface] if interface else cmd(['wg', 'show', 'interfaces']).split()
    rows, sections = [], []
    for name in names:
        native = wireguard.state(name)
        configured = wireguard.manifest(name).get('peers', {})
        by_key = {settings['public-key']: label for label, settings in configured.items()}
        if peer and peer not in configured:
            raise OperationalError(f'{name}: peer {peer} is not enabled')
        if detail:
            sections.append(tabulate([['Interface', name], ['Public key', strip_value(native['public-key'], strip_private)],
                ['Listen port', native['listen-port']], ['Firewall mark', native['firewall-mark']]], tablefmt='presto'))
        for key, data in native['peers'].items():
            label = by_key.get(key, key)
            if peer and peer != label:
                continue
            age = f"{max(0, int(time.time()) - data['handshake'])}s ago" if data['handshake'] else 'Never'
            label = strip_value(label, strip_private)
            endpoint = data['endpoint'] or '-'
            if strip_private and data['endpoint']:
                host, _, port = endpoint.rpartition(':')
                if host.startswith('['):
                    host = '[' + strip_ip(host[1:-1], strip_private) + ']'
                else:
                    host = strip_ip(host, strip_private)
                endpoint = f'{host}:{port}'
            rows.append([name, label, endpoint, age, data['received'], data['sent']])
            if detail:
                sections.append(tabulate([['Peer', label], ['Public key', strip_value(key, strip_private)],
                    ['Endpoint', endpoint], ['Allowed IPs', ', '.join(strip_ip(ip, strip_private) for ip in data['allowed-ips']) or '-'],
                    ['Latest handshake', age], ['Received bytes', data['received']], ['Sent bytes', data['sent']],
                    ['Persistent keepalive', data['keepalive']], ['Preshared key', 'Configured' if data['preshared'] else 'None']],
                    tablefmt='presto'))
        if not native['peers'] and not detail:
            rows.append([name, '-', '-', 'No peers', 0, 0])
    if detail:
        return '\n\n'.join(sections) or 'No WireGuard interfaces.'
    return tabulate(rows, headers=['Interface', 'Peer', 'Endpoint', 'Latest handshake', 'RX bytes', 'TX bytes']) if rows else 'No WireGuard interfaces.'


@opmode.command
def refresh(interface: str, peer: str = None, scheduled: bool = False, unresolved: bool = False):
    return wireguard.refresh(interface, peer, scheduled, unresolved)


if __name__ == '__main__':
    opmode.run()
