#!/usr/bin/env python3
"""Key generation and read-only MACsec diagnostics."""

import json
import secrets

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.helpers import macsec
from nvyr.helpers.strip_private import strip_mac, strip_value
from nvyr.helpers.process import cmd, rc_cmd


@opmode.command
def generate(bits: int = 128):
    if bits not in (128, 256):
        raise OperationalError('Choose a 128-bit or 256-bit CAK')
    return f'ckn {secrets.token_hex(16)} cak {secrets.token_hex(bits // 8)}'


def agreement(name, parent):
    control = macsec.DIRECTORY / name / 'ctrl'
    if not parent or not (control / parent).is_socket():
        return {}
    # configd has a private /tmp. Use a reply socket visible to the supplicant.
    code, output = rc_cmd(['wpa_cli', '-s', '/run/nvyr', '-p', str(control), '-i', parent, 'status'])
    return dict(line.split('=', 1) for line in output.splitlines() if '=' in line) if code == 0 else {}


def display_sci(value, mode=None):
    sci = int(value, 16).to_bytes(8, 'big')
    return f"{strip_mac(sci[:6].hex(':'), mode)}@{int.from_bytes(sci[6:], 'big')}"


def counters_table(channel, mode=None):
    name = channel['ifname']
    rows = []
    for scope, record in [(name, channel), *((display_sci(peer['sci'], mode), peer) for peer in channel.get('rx_sc', []))]:
        rows.extend((scope, key, value) for key, value in record.items()
                    if key.startswith(('OutPkts', 'InPkts', 'OutOctets', 'InOctets')))
    return tabulate(rows, headers=('Channel', 'Counter', 'Value'))


@opmode.command
def show(interface: str = None, detail: bool = False, counters: bool = False, strip_private: str = None):
    links = json.loads(cmd(['ip', '-j', 'link', 'show', 'type', 'macsec']))
    parents = {link['ifname']: link.get('link', '') for link in links}
    if interface and interface not in parents:
        raise OperationalError(f'{interface}: MACsec interface does not exist')
    channels = json.loads(cmd(['ip', '-s', '-j', 'macsec', 'show', *([interface] if interface else [])]))
    rows = []
    for channel in channels:
        if counters:
            return counters_table(channel, strip_private)
        name = channel['ifname']
        parent = parents.get(name, '')
        status = agreement(name, parent)
        peers = ', '.join(display_sci(peer['sci'], strip_private) for peer in channel.get('rx_sc', []) if peer['active'])
        secured = status.get('Secured', 'Unavailable')
        server = status.get('key_server_sci', '-') if status.get('is_elected') == 'Yes' else '-'
        if '@' in server:
            mac, port = server.split('@', 1)
            server = f'{strip_mac(mac, strip_private)}@{port}'
        if detail:
            return tabulate([
                ('Interface', name), ('Source interface', parent), ('Secured', secured),
                ('Local SCI', display_sci(channel['sci'], strip_private)), ('Peer SCI', peers or '-'), ('Key server SCI', server),
                ('Local key server', status.get('is_key_server', '-')), ('CKN', strip_value(status['ckn'], strip_private) if status.get('ckn') else '-'),
                ('Cipher', channel['cipher_suite']), ('Transmit mode', 'encrypt' if channel['encrypt'] else 'integrity-only'),
                ('Encoding SA', channel['encoding_sa']), ('Replay protection', 'on' if channel['replay'] else 'off'),
                ('Replay window', channel.get('window', '-')),
            ], tablefmt='presto', disable_numparse=True)
        rows.append((name, parent, secured, peers or '-', server))
    return tabulate(rows, headers=('Interface', 'Source interface', 'Secured', 'Peer SCI', 'Key server SCI'),
                    disable_numparse=True) if rows else 'No MACsec interfaces.'


if __name__ == '__main__':
    opmode.run()
