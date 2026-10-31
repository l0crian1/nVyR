"""Shared, isolated Kea HA topology and relayed DHCP client exchanges."""

import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

from nvyr.config_scripts import service_dhcp
from nvyr.errors import RouterError
from nvyr.helpers import kea
from nvyr.schema import Schema
from nvyr.tree import lookup


def run(*arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout


def option(code, value, family):
    header = struct.pack('!BB' if family == 4 else '!HH', code, len(value))
    return header + value


def options(data, family):
    """Decode the DHCP option lengths, including IPv4 padding/end markers."""
    result = {}
    while data:
        if family == 4 and data[0] == 255:
            break
        if family == 4 and data[0] == 0:
            data = data[1:]
            continue
        width = 2 if family == 4 else 4
        assert len(data) >= width, 'Truncated DHCP option header'
        code, length = struct.unpack('!BB' if family == 4 else '!HH', data[:width])
        assert len(data) >= width + length, 'Truncated DHCP option value'
        result[code] = data[width:width + length]
        data = data[width + length:]
    return result


def client_packet(family, identifier, relay, seconds, offer=None):
    """Construct only the DHCP fields this isolated relay scenario needs."""
    hardware = b'\x02\x00' + identifier.to_bytes(4, 'big')
    if family == 4:
        header = struct.pack('!BBBBIHH4s4s4s4s16s64s128s',
                             1, 1, 6, 1, identifier, seconds, 0,
                             bytes(4), bytes(4), bytes(4), socket.inet_aton(relay),
                             hardware, bytes(64), bytes(128))
        payload = option(53, bytes([3 if offer else 1]), 4)
        if offer:
            payload += option(50, socket.inet_aton(offer['address']), 4)
            payload += option(54, offer['server-id'], 4)
        return header + b'\x63\x82\x53\x63' + payload + b'\xff'

    duid = struct.pack('!HH', 3, 1) + hardware
    message = bytes([3 if offer else 1]) + identifier.to_bytes(3, 'big')
    message += option(1, duid, 6)
    if offer:
        message += option(2, offer['server-id'], 6)
    message += option(8, struct.pack('!H', seconds * 100), 6)
    message += option(3, struct.pack('!III', 1, 0, 0), 6)
    header = bytes([12, 0]) + socket.inet_pton(socket.AF_INET6, relay)
    header += socket.inet_pton(socket.AF_INET6, 'fe80::abcd')
    return header + option(9, message, 6)


def decode_reply(family, data):
    if family == 4:
        assert len(data) >= 240 and data[0] == 2 and data[236:240] == b'\x63\x82\x53\x63'
        fields = options(data[240:], 4)
        return {'type': fields[53][0], 'client': int.from_bytes(data[4:8], 'big'),
                'address': socket.inet_ntoa(data[16:20]), 'server-id': fields[54]}

    assert len(data) >= 34 and data[0] == 13, 'Expected DHCPv6 Relay-reply'
    message = options(data[34:], 6)[9]
    fields = options(message[4:], 6)
    association = fields.get(3, b'')
    addresses = options(association[12:], 6) if len(association) >= 12 else {}
    return {'type': message[0], 'client': int.from_bytes(message[1:4], 'big'),
            'server-id': fields[2],
            'address': socket.inet_ntop(socket.AF_INET6, addresses[5][:16]) if 5 in addresses else None}


def exchange(family, subnet, count, offset=0, seconds=0):
    """Send concurrent relayed clients to both peers; return grants, not offers.

    Uses standard-library UDP/packet encoding so installed functional tests do
    not depend on Scapy or add a packet-building dependency to the router image.
    """
    network = f'192.0.{subnet}.' if family == 4 else f'2001:db8:{subnet}::'
    local = network + ('254' if family == 4 else 'fe')
    peers = [network + '1', network + '2']
    port = 67 if family == 4 else 547

    def receive(connection):
        messages = []
        while True:
            try:
                data, source = connection.recvfrom(8192)
            except socket.timeout:
                return messages
            packet = decode_reply(family, data)
            packet['server'] = source[0]
            messages.append(packet)

    with socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM) as connection:
        connection.bind((local, port))
        connection.settimeout(1)
        grants = []
        # Keep concurrent bursts below Kea's default 64-packet worker queue.
        # This checks allocation correctness, not loss under DHCP overload.
        for start in range(offset + 1, offset + count + 1, 32):
            for identifier in range(start, min(start + 32, offset + count + 1)):
                message = client_packet(family, identifier, local, seconds)
                for peer in peers:
                    connection.sendto(message, (peer, port))

            offers = [offer for offer in receive(connection) if offer['type'] == 2 and offer['address']]
            for offer in offers:
                request = client_packet(family, offer['client'], local, seconds, offer)
                connection.sendto(request, (offer['server'], port))
            if offers:
                grants.extend(receive(connection))

        return [{key: grant[key] for key in ('client', 'address', 'server')}
                for grant in grants if grant['type'] == (5 if family == 4 else 7) and grant['address']]


class Topology:
    """Four peers share one isolated fabric for both families and both HA modes."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.prefix = f'nvyr-ha-{os.getpid()}'
        self.fabric = self.prefix + '-fabric'
        self.namespaces = []
        self.servers = {}
        self.schema = Schema.bundled()

    def namespace(self, name):
        run('ip', 'netns', 'add', name)
        self.namespaces.append(name)
        run('ip', '-n', name, 'link', 'set', 'lo', 'up')

    def prepare(self):
        self.namespace(self.fabric)
        run('ip', '-n', self.fabric, 'link', 'add', 'lan', 'type', 'bridge')
        run('ip', '-n', self.fabric, 'link', 'set', 'lan', 'up')
        for subnet, mode in ((2, 'active-active'), (3, 'active-passive')):
            run('ip', '-n', self.fabric, 'address', 'add', f'192.0.{subnet}.254/24', 'dev', 'lan')
            run('ip', '-n', self.fabric, '-6', 'address', 'add', f'2001:db8:{subnet}::fe/64', 'dev', 'lan', 'nodad')
            for member in (1, 2):
                namespace = f'{self.prefix}-{subnet}-{member}'
                self.namespace(namespace)
                port = f'p{subnet}{member}'
                run('ip', '-n', self.fabric, 'link', 'add', port, 'type', 'veth', 'peer', 'name', 'lan', 'netns', namespace)
                run('ip', '-n', self.fabric, 'link', 'set', port, 'master', 'lan')
                run('ip', '-n', self.fabric, 'link', 'set', port, 'up')
                run('ip', '-n', namespace, 'link', 'set', 'lan', 'up')
                if mode == 'active-passive':
                    run('ip', '-n', namespace, 'link', 'add', 'HA', 'type', 'vrf', 'table', '100')
                    run('ip', '-n', namespace, 'link', 'set', 'HA', 'up')
                    run('ip', '-n', namespace, 'link', 'set', 'lan', 'master', 'HA')
                run('ip', '-n', namespace, 'address', 'add', f'192.0.{subnet}.{member}/24', 'dev', 'lan')
                run('ip', '-n', namespace, '-6', 'address', 'add', f'2001:db8:{subnet}::{member}/64', 'dev', 'lan', 'nodad')
                for family in (4, 6):
                    self.start(family, subnet, member, mode, namespace)
        self.wait_states()

    def start(self, family, subnet, member, mode, namespace):
        owner = service_dhcp.service_name(family)
        prefix = f'192.0.{subnet}.0/24' if family == 4 else f'2001:db8:{subnet}::/64'
        stem = f'192.0.{subnet}.' if family == 4 else f'2001:db8:{subnet}::'
        partner = 3 - member
        roles = {1: 'primary', 2: 'secondary' if mode == 'active-active' else 'standby'}
        explicit = {'service': {owner: {
            'listen-interface': ['lan'],
            'shared-network': {'LAN': {'interface': 'lan', 'subnet': {prefix: {
                'range': [stem + '100-' + stem + '109', stem + '120-' + stem + '129'],
            }}}},
            'ha': {'name': f'R{member}', 'mode': mode, 'role': roles[member], 'source-address': stem + str(member),
                   'peer': {f'R{partner}': {'address': stem + str(partner), 'role': roles[partner]}}},
        }}}
        if family == 6:
            # Relays use unicast here; the ordinary interface listener receives
            # directly connected multicast clients instead.
            explicit['service'][owner].pop('listen-interface')
            explicit['service'][owner]['listen-address'] = [stem + str(member)]
        self.schema.validate_configuration(explicit)
        section = lookup(self.schema.defaults(explicit), ('service', owner))
        vrf = 'HA' if mode == 'active-passive' else 'default'
        devices = {'lan': {'vrf': vrf, 'up': True, 'addresses': [f'192.0.{subnet}.{member}', f'2001:db8:{subnet}::{member}', 'fe80::1']}}
        folder = self.directory / f'{family}-{subnet}-{member}'
        folder.mkdir(mode=0o700)
        context = SimpleNamespace(state_directory=folder, check_only=False, report=lambda text: None)
        configuration = {'family': family, 'servers': {vrf: section}, 'devices': devices,
                         'log-level': 'info', 'rebind': False, 'ha-listeners': []}
        service_dhcp.verify(configuration, context)
        native = json.loads(next(iter(service_dhcp.generate(configuration, context).desired.values())))
        server = native[f'Dhcp{family}']
        server['lease-database']['name'] = str(folder / 'leases.csv')
        server['control-sockets'][0]['socket-name'] = str(folder / 'control.sock')
        server['loggers'][0]['output-options'] = [{'output': 'stdout'}]
        if family == 4:
            server['interfaces-config']['dhcp-socket-type'] = 'udp'
        path = folder / 'config.json'
        path.write_text(json.dumps(native))
        env = os.environ | {'KEA_CONTROL_SOCKET_DIR': str(folder), 'KEA_PIDFILE_DIR': str(folder), 'KEA_DHCP_DATA_DIR': str(folder)}
        command = ['ip', 'netns', 'exec', namespace]
        if vrf != 'default':
            command += ['ip', 'vrf', 'exec', vrf]
        command += [f'/usr/sbin/kea-dhcp{family}', '-c', str(path)]
        output = (folder / 'output').open('w')
        process = subprocess.Popen(command, env=env, stdout=output, stderr=subprocess.STDOUT)
        self.servers[family, subnet, member] = {'process': process, 'output': output, 'folder': folder, 'command': command, 'env': env}

    def control(self, family, subnet, member, command, arguments=None):
        server = self.servers[family, subnet, member]
        return kea.control(server['folder'] / 'control.sock', command, arguments)

    def state(self, family, subnet, member):
        return self.control(family, subnet, member, 'ha-heartbeat')['arguments']['state']

    def wait_states(self, expected=None, timeout=60):
        expected = expected or {key: 'load-balancing' if key[1] == 2 else 'hot-standby' for key in self.servers}
        deadline = time.monotonic() + timeout
        states = {}
        while time.monotonic() < deadline:
            for key in expected:
                server = self.servers[key]
                if server['process'].poll() is not None:
                    raise AssertionError((server['folder'] / 'output').read_text())
                try:
                    states[key] = self.state(*key)
                except (OSError, RouterError):
                    states[key] = 'starting'
            if states == expected:
                return
            time.sleep(0.2)
        raise AssertionError(f'HA state timeout: {states}; expected {expected}')

    def clients(self, family, subnet, count, offset=0, seconds=0):
        return json.loads(run('ip', 'netns', 'exec', self.fabric, sys.executable,
                              str(Path(__file__).resolve()), str(family), str(subnet),
                              str(count), str(offset), str(seconds)))

    def close(self):
        for server in self.servers.values():
            if server['process'].poll() is None:
                server['process'].terminate()
        for server in self.servers.values():
            try:
                server['process'].wait(timeout=10)
            except subprocess.TimeoutExpired:
                server['process'].kill()
                server['process'].wait()
            server['output'].close()
        for namespace in reversed(self.namespaces):
            run('ip', 'netns', 'delete', namespace)


if __name__ == '__main__':
    print(json.dumps(exchange(*(int(value) for value in sys.argv[1:]))))
