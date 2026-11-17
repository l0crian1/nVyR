"""Live connection exchanges shared by acceptance and functional logging checks."""

from pathlib import Path
import socket

from nvyr.helpers.process import cmd
from smoketests.assertions import assert_equal, assert_in
from smoketests.support import wait_for


CONNTRACK_LOG = Path('/var/log/nvyr/conntrack.log')


def connection_exchange(family='ipv4', protocol='udp', *, source=None):
    """Exchange payloads in both directions, then delete only this entry."""
    af = socket.AF_INET if family == 'ipv4' else socket.AF_INET6
    address = '127.0.0.1' if family == 'ipv4' else '::1'
    source = source or address
    kind = socket.SOCK_DGRAM if protocol == 'udp' else socket.SOCK_STREAM
    with socket.socket(af, kind) as server, socket.socket(af, kind) as client:
        server.settimeout(2)
        client.settimeout(2)
        server.bind((address, 0))
        destination_port = server.getsockname()[1]
        client.bind((source, 0))
        source_port = client.getsockname()[1]
        if protocol == 'udp':
            client.sendto(b'nvyr-conntrack-request', server.getsockname())
            payload, peer = server.recvfrom(128)
            assert_equal(payload, b'nvyr-conntrack-request')
            server.sendto(b'nvyr-conntrack-reply', peer)
            assert_equal(client.recv(128), b'nvyr-conntrack-reply')
        else:
            server.listen(1)
            client.connect(server.getsockname())
            accepted, _ = server.accept()
            with accepted:
                accepted.settimeout(2)
                client.sendall(b'nvyr-conntrack-request')
                assert_equal(accepted.recv(128), b'nvyr-conntrack-request')
                accepted.sendall(b'nvyr-conntrack-reply')
                assert_equal(client.recv(128), b'nvyr-conntrack-reply')

        selector = ['-f', family, '-p', protocol, '-s', source, '-d', address,
                    '--sport', str(source_port), '--dport', str(destination_port)]
        cmd(['conntrack', '-D', *selector])
    return f'SRC={source} DST={address} PROTO={protocol.upper()} SPT={source_port} DPT={destination_port}'


def check_connection_events(family='ipv4', protocol='udp'):
    """Require new records with accounting; archived records cannot satisfy this."""
    offset = CONNTRACK_LOG.stat().st_size if CONNTRACK_LOG.exists() else 0
    identity = connection_exchange(family, protocol)

    def records():
        text = CONNTRACK_LOG.read_bytes()[offset:].decode() if CONNTRACK_LOG.exists() else ''
        return [line for line in text.splitlines() if identity in line]

    lines = wait_for(records, lambda lines: any('[DESTROY]' in line for line in lines),
                     description='connection destroy record')
    for event in ('NEW', 'DESTROY'):
        assert_in(f'[{event}]', '\n'.join(lines))
    destroyed = next(line for line in lines if '[DESTROY]' in line)
    original, reply = destroyed.split(', REPLY:', 1)
    for direction in (original, reply):
        fields = dict(item.split('=', 1) for item in direction.split() if '=' in item)
        assert int(fields['PKTS']) > 0, destroyed
        assert int(fields['BYTES']) > 0, destroyed
    return lines
