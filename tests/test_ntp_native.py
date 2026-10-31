"""Opt-in isolated native Chrony exchange tests; no daemon can adjust host time.

Run inside a disposable privileged Linux test container with Chrony installed:
NVYR_NTP_NATIVE=1 python3 -m pytest -q tests/test_ntp_native.py
"""

from contextlib import contextmanager
import csv
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

import pytest

from nvyr.config_scripts import system_ntp
from nvyr.op_scripts import ntp as operational
from smoketests.assertions import assert_ntp_response

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NTP_NATIVE') != '1',
                                reason='requires an explicitly selected native Chrony container')


def command(*arguments):
    return subprocess.check_output(arguments, text=True, stderr=subprocess.STDOUT).strip()


def wait_for_source(socket, address):
    """Wait for actual NTP replies, not just a configured source in chronyc."""
    deadline = time.monotonic() + 15
    while True:
        output = command('chronyc', '-h', str(socket), '-c', 'sources')
        rows = list(csv.reader(output.splitlines()))
        if any(row[2] == address and int(row[5]) > 0 and int(row[3]) == 8 for row in rows):
            return
        if time.monotonic() >= deadline:
            pytest.fail(f'No NTP response from {address}: {output}')
        time.sleep(0.1)


@contextmanager
def daemon(directory, configuration, *, extra=(), vrf=None, namespace=None, resolver=None, user='root'):
    """Use the production formatter with private file paths and clock control disabled."""
    import pwd

    directory.mkdir(mode=0o700)
    account = pwd.getpwnam(user)
    os.chown(directory, account.pw_uid, account.pw_gid)
    socket = directory / 'chronyd.sock'
    text = system_ntp.render_service(configuration)
    text = text.replace('/run/nvyr-chrony/chronyd.pid', str(directory / 'chronyd.pid'))
    text = text.replace('/run/nvyr-chrony/chronyd.sock', str(socket))
    text = text.replace('/config/ntp', str(directory))
    path = directory / 'chrony.conf'
    path.write_text(text + '\n' + '\n'.join(extra) + '\n')
    command('chronyd', '-p', '-f', str(path))

    argv = ['chronyd', '-d', '-x', '-u', user, '-f', str(path)]
    if vrf:
        argv = ['ip', 'vrf', 'exec', vrf, *argv]
    if namespace:
        argv = ['ip', 'netns', 'exec', namespace, *argv]
    if resolver:
        # A private mount changes this process's resolver without touching the host.
        argv = ['unshare', '--mount', '--propagation', 'private', 'sh', '-c',
                'mount --bind "$1" /etc/resolv.conf; shift; exec "$@"',
                'ntp-test', str(resolver), *argv]

    with (directory / 'log').open('w') as log:
        process = subprocess.Popen(argv, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 5
            while not socket.exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    pytest.fail((directory / 'log').read_text())
                time.sleep(0.05)
            yield socket
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)


def test_native_ipv4_exchange(tmp_path):
    """An IPv4 allow-client and singleton listener serve a real NTP request."""
    server = {'listen-address': {'ipv4': '127.0.0.1'}, 'allow-client': ['127.0.0.1']}
    with daemon(tmp_path / 'server', server, extra=['port 41123', 'local stratum 8']):
        with daemon(tmp_path / 'client', {}, extra=['server 127.0.0.1 port 41123 iburst']) as socket:
            wait_for_source(socket, '127.0.0.1')


def test_native_ipv6_exchange(tmp_path):
    """The IPv6 listener serves a real IPv6 client independently of IPv4."""
    server = {'listen-address': {'ipv6': '::1'}, 'allow-client': ['::1']}
    with daemon(tmp_path / 'server', server, extra=['port 41123', 'local stratum 8']):
        with daemon(tmp_path / 'client', {}, extra=['server ::1 port 41123 iburst']) as socket:
            wait_for_source(socket, '::1')


def check_serving_reports(address, socket, monkeypatch):
    """Read real Chrony CSV before and after a packet, using the production parser."""
    monkeypatch.setattr(operational, 'SOCKET', str(socket))
    assert json.loads(operational.clients(raw=True)) == []
    before = json.loads(operational.server_statistics(raw=True))

    assert_ntp_response(address, port=41123)

    clients = json.loads(operational.clients(raw=True))
    assert len(clients) == 1
    assert clients[0]['Client'] == address
    assert clients[0]['Requests'] == 1
    assert clients[0]['Rate-limited'] == 0
    assert clients[0]['Last seen (s)'] is not None
    assert address in operational.clients()
    after = json.loads(operational.server_statistics(raw=True))
    assert after['NTP requests received'] == before['NTP requests received'] + 1

    assert 'NTP requests received' in operational.server_statistics()
    assert 'NTS-KE connections accepted' in operational.server_statistics(detail=True)
    assert json.loads(operational.clients(raw=True))[0]['Requests'] == 1
    assert json.loads(operational.server_statistics(raw=True))['NTP requests received'] == after['NTP requests received']


def test_native_ipv4_serving_reports(tmp_path, monkeypatch):
    """Record an IPv4 client even when the server has no synchronized upstream."""
    configuration = {'listen-address': {'ipv4': '127.0.0.1'}, 'allow-client': ['127.0.0.1']}
    with daemon(tmp_path / 'server', configuration, extra=['port 41123']) as socket:
        check_serving_reports('127.0.0.1', socket, monkeypatch)


def test_native_ipv6_serving_reports(tmp_path, monkeypatch):
    """Numeric IPv6 client reports work against the actual Chrony control socket."""
    configuration = {'listen-address': {'ipv6': '::1'}, 'allow-client': ['::1']}
    with daemon(tmp_path / 'server', configuration, extra=['port 41123']) as socket:
        check_serving_reports('::1', socket, monkeypatch)


@contextmanager
def vrf_network():
    """Create an off-router peer reachable only through the test VRF."""
    command('ip', 'link', 'add', 'NTPNATIVE', 'type', 'vrf', 'table', '41976')
    try:
        command('ip', 'link', 'set', 'NTPNATIVE', 'up')
        command('ip', 'netns', 'add', 'NTPPEER')
        try:
            command('ip', 'link', 'add', 'ntpnative0', 'type', 'veth', 'peer', 'name', 'ntpnative1')
            command('ip', 'link', 'set', 'ntpnative1', 'netns', 'NTPPEER')
            command('ip', 'link', 'set', 'ntpnative0', 'master', 'NTPNATIVE')
            command('ip', 'address', 'add', '198.18.196.1/24', 'dev', 'ntpnative0')
            command('ip', 'link', 'set', 'ntpnative0', 'up')
            command('ip', '-n', 'NTPPEER', 'address', 'add', '198.18.196.2/24', 'dev', 'ntpnative1')
            command('ip', '-n', 'NTPPEER', 'link', 'set', 'ntpnative1', 'up')
            command('ip', '-n', 'NTPPEER', 'link', 'set', 'lo', 'up')
            command('ip', 'address', 'add', '2001:db8:196::1/64', 'dev', 'ntpnative0', 'nodad')
            command('ip', '-n', 'NTPPEER', 'address', 'add', '2001:db8:196::2/64', 'dev', 'ntpnative1', 'nodad')
            yield
        finally:
            command('ip', 'netns', 'del', 'NTPPEER')
    finally:
        command('ip', 'link', 'del', 'NTPNATIVE')


def test_native_vrf_upstream_exchange(tmp_path):
    """The configured VRF client reaches an upstream through its member interface."""
    with vrf_network():
        server = {'listen-address': {'ipv4': '198.18.196.2'}, 'allow-client': ['198.18.196.0/24']}
        with daemon(tmp_path / 'server', server, namespace='NTPPEER',
                    extra=['port 41123', 'local stratum 8']):
            with daemon(tmp_path / 'client', {'vrf': 'NTPNATIVE'}, vrf='NTPNATIVE',
                        extra=['server 198.18.196.2 port 41123 iburst']) as socket:
                wait_for_source(socket, '198.18.196.2')
                pid = (tmp_path / 'client' / 'chronyd.pid').read_text().strip()
                assert command('ip', 'vrf', 'identify', pid) == 'NTPNATIVE'


def test_native_vrf_downstream_exchange(tmp_path):
    """A VRF listener answers a real client connected through its member interface."""
    with vrf_network():
        server = {'vrf': 'NTPNATIVE', 'listen-address': {'ipv4': '198.18.196.1'},
                  'allow-client': ['198.18.196.0/24']}
        with daemon(tmp_path / 'server', server, vrf='NTPNATIVE',
                    extra=['port 41123', 'local stratum 8']):
            with daemon(tmp_path / 'client', {}, namespace='NTPPEER',
                        extra=['server 198.18.196.1 port 41123 iburst']) as socket:
                wait_for_source(socket, '198.18.196.1')


def test_native_ipv6_vrf_upstream_exchange(tmp_path):
    """An IPv6 upstream can be acquired over a VRF member interface."""
    with vrf_network():
        server = {'listen-address': {'ipv6': '2001:db8:196::2'}, 'allow-client': ['2001:db8:196::/64']}
        with daemon(tmp_path / 'server', server, namespace='NTPPEER',
                    extra=['port 41123', 'local stratum 8']):
            with daemon(tmp_path / 'client', {'vrf': 'NTPNATIVE'}, vrf='NTPNATIVE',
                        extra=['server 2001:db8:196::2 port 41123 iburst']) as socket:
                wait_for_source(socket, '2001:db8:196::2')


def test_native_ipv6_vrf_downstream_exchange(tmp_path):
    """An IPv6 VRF listener answers a peer through the actual member interface."""
    with vrf_network():
        server = {'vrf': 'NTPNATIVE', 'listen-address': {'ipv6': '2001:db8:196::1'},
                  'allow-client': ['2001:db8:196::/64']}
        with daemon(tmp_path / 'server', server, vrf='NTPNATIVE',
                    extra=['port 41123', 'local stratum 8']):
            with daemon(tmp_path / 'client', {}, namespace='NTPPEER',
                        extra=['server 2001:db8:196::1 port 41123 iburst']) as socket:
                wait_for_source(socket, '2001:db8:196::1')


def test_native_privilege_drop():
    """The packaged runtime ownership supports sockets and state after dropping root."""
    import pwd

    with tempfile.TemporaryDirectory(prefix='nvyr-ntp-native-', dir='/run') as temporary:
        directory = Path(temporary)
        account = pwd.getpwnam('_chrony')
        os.chown(directory, account.pw_uid, account.pw_gid)
        with daemon(directory / 'daemon', {}, user='_chrony') as socket:
            assert 'Not synchronised' in command('chronyc', '-h', str(socket), 'tracking')
            pid = (directory / 'daemon' / 'chronyd.pid').read_text().strip()
            assert f'Uid:\t{account.pw_uid}\t' in Path(f'/proc/{pid}/status').read_text()


def test_native_vrf_dns(tmp_path):
    """The resolver child reaches a DNS server available only inside the chosen VRF."""
    dns = tmp_path / 'dns.py'
    dns.write_text('''import socket
import struct

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("198.18.196.2", 53))
while True:
    query, peer = sock.recvfrom(4096)
    end = 12
    while query[end]:
        end += query[end] + 1
    end += 1
    kind = struct.unpack("!H", query[end:end + 2])[0]
    question = query[12:end + 4]
    answer = b""
    if kind == 1:
        answer = b"\\xc0\\x0c" + struct.pack("!HHIH", 1, 1, 30, 4) + socket.inet_aton("198.18.196.2")
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, int(bool(answer)), 0, 0)
    sock.sendto(header + question + answer, peer)
''')
    resolver = tmp_path / 'resolv.conf'
    resolver.write_text('nameserver 198.18.196.2\noptions timeout:1 attempts:2\n')

    with vrf_network():
        process = subprocess.Popen(['ip', 'netns', 'exec', 'NTPPEER', 'python3', str(dns)])
        try:
            server = {'listen-address': {'ipv4': '198.18.196.2'}, 'allow-client': ['198.18.196.0/24']}
            with daemon(tmp_path / 'server', server, namespace='NTPPEER',
                        extra=['port 41123', 'local stratum 8']):
                with daemon(tmp_path / 'client', {'vrf': 'NTPNATIVE'}, vrf='NTPNATIVE', resolver=resolver,
                            extra=['server source.ntp.test port 41123 iburst']) as socket:
                    wait_for_source(socket, '198.18.196.2')
        finally:
            process.terminate()
            process.wait(timeout=5)


def test_native_vrf_nts(tmp_path):
    """TLS key exchange and authenticated NTP both use the selected routing domain."""
    certificate = tmp_path / 'certificate.pem'
    key = tmp_path / 'key.pem'
    command('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=source.ntp.test', '-addext', 'subjectAltName=IP:198.18.196.2',
            '-keyout', str(key), '-out', str(certificate))

    with vrf_network():
        server = {'listen-address': {'ipv4': '198.18.196.2'}, 'allow-client': ['198.18.196.0/24']}
        with daemon(tmp_path / 'server', server, namespace='NTPPEER', extra=[
                'port 41123', 'local stratum 8', 'ntsport 41460',
                f'ntsservercert {certificate}', f'ntsserverkey {key}']):
            with daemon(tmp_path / 'client', {'vrf': 'NTPNATIVE'}, vrf='NTPNATIVE', extra=[
                    f'ntstrustedcerts {certificate}',
                    'server 198.18.196.2 port 41123 nts ntsport 41460 iburst']) as socket:
                wait_for_source(socket, '198.18.196.2')
                assert ',NTS,' in command('chronyc', '-h', str(socket), '-c', 'authdata')
