"""Opt-in native zone/NAT tests; run in a disposable root network namespace."""

import os
from pathlib import Path
import subprocess
import time
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import vrf_conntrack
from tests.test_vrf_rules_live import routing, run

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_VRF_RULE_TEST') != '1',
                                reason='requires an isolated root network namespace')


def install(configuration, directory):
    """Exercise the normal config script, template renderer and nftables loader."""
    context = SimpleNamespace(effective=configuration, state_directory=directory)
    gathered = vrf_conntrack.get_config(context)
    vrf_conntrack.verify(gathered, context)
    generated = vrf_conntrack.generate(gathered, context)
    vrf_conntrack.apply(generated, context)


@pytest.fixture
def internet(routing, tmp_path, monkeypatch):
    """A local upstream namespace proves NAT without contacting the Internet."""
    # Ordinary engine tests replace this manager; native tests need its real loader.
    monkeypatch.setattr(vrf_conntrack.nftables, 'manager', vrf_conntrack.nftables.Manager())

    peer = subprocess.Popen(['unshare', '-n', 'sleep', '120'])
    try:
        for _ in range(100):
            if os.readlink(f'/proc/{peer.pid}/ns/net') != os.readlink('/proc/self/ns/net'):
                break
            time.sleep(.01)
        else:
            raise AssertionError('Peer network namespace did not start')

        prefix = ['nsenter', '-t', str(peer.pid), '-n']
        run('ip', 'link', 'add', 'wan', 'type', 'veth', 'peer', 'name', 'upstream')
        run('ip', 'link', 'set', 'upstream', 'netns', str(peer.pid))
        run('ip', 'address', 'add', '198.51.100.1/24', 'dev', 'wan')
        run('ip', '-6', 'address', 'add', '2001:db8:ffff::1/64', 'dev', 'wan', 'nodad')
        run('ip', 'link', 'set', 'wan', 'up')
        run(*prefix, 'ip', 'link', 'set', 'lo', 'up')
        run(*prefix, 'ip', 'address', 'add', '198.51.100.2/24', 'dev', 'upstream')
        run(*prefix, 'ip', '-6', 'address', 'add', '2001:db8:ffff::2/64', 'dev', 'upstream', 'nodad')
        run(*prefix, 'ip', 'link', 'set', 'upstream', 'up')
        run('ip', 'route', 'add', 'default', 'via', '192.0.2.1', 'dev', 'right', 'table', '101')
        run('ip', '-6', 'route', 'add', 'default', 'via', '2001:db8::1', 'dev', 'right', 'table', '101')
        Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
        Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')
        for name in ('all', 'wan', 'left', 'right'):
            Path(f'/proc/sys/net/ipv4/conf/{name}/rp_filter').write_text('0')

        nat = '''table inet test_nat {
 chain postrouting { type nat hook postrouting priority srcnat; policy accept;
 oifname "wan" masquerade
 }
}'''
        subprocess.run(['nft', '-f', '-'], input=nat, check=True, text=True)
        config = {'vrf': {'name': {'BLUE': {'table': '101'}, 'RED': {'table': '102'}}},
                  'interfaces': {'virtual-ethernet': {'right': {'vrf': 'BLUE'}}}}
        install(config, tmp_path)
        yield prefix, config
    finally:
        subprocess.run(['nft', 'delete', 'table', 'inet', 'test_nat'], capture_output=True)
        subprocess.run(['nft', 'delete', 'table', 'inet', 'nvyr_vrf_conntrack'], capture_output=True)
        subprocess.run(['ip', 'link', 'del', 'wan'], capture_output=True)
        peer.terminate()
        peer.wait(timeout=5)


def test_ipv4_nat_across_vrf_and_default(internet):
    """The VRF and default passes use separate entries and masquerade replies return."""
    run('ip', 'vrf', 'exec', 'BLUE', 'ping', '-n', '-c', '2', '-W', '2', '198.51.100.2')
    entries = run('conntrack', '-L', '-f', 'ipv4', '-p', 'icmp', '-o', 'extended')
    assert 'dst=198.51.100.1' in entries
    assert 'zone=1' in entries


def test_ipv6_nat_across_vrf_and_default(internet):
    """The same inet map supports IPv6 NAT and the VRF return path."""
    run('ip', 'vrf', 'exec', 'BLUE', 'ping', '-6', '-n', '-c', '2', '-W', '2', '2001:db8:ffff::2')
    entries = run('conntrack', '-L', '-f', 'ipv6', '-p', 'icmpv6', '-o', 'extended')
    assert 'dst=2001:db8:ffff::1' in entries
    assert 'zone=1' in entries


def exchange(internet, transport):
    """Exchange application data with a disposable upstream TCP or UDP echo server."""
    prefix, config = internet
    kind = 'SOCK_STREAM' if transport == 'tcp' else 'SOCK_DGRAM'
    server_code = f'''import socket
s=socket.socket(socket.AF_INET,socket.{kind})
s.settimeout(10)
s.bind(('198.51.100.2',30443))
if s.type == socket.SOCK_STREAM:
 s.listen(1)
 print('ready',flush=True)
 connection,address=s.accept()
 connection.sendall(connection.recv(100))
 connection.close()
else:
 print('ready',flush=True)
 data,address=s.recvfrom(100)
 s.sendto(data,address)
s.close()
'''
    server = subprocess.Popen([*prefix, 'python3', '-c', server_code], stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    try:
        assert server.stdout.readline().strip() == 'ready'
        client_code = f'''import socket
s=socket.socket(socket.AF_INET,socket.{kind})
s.settimeout(5)
s.connect(('198.51.100.2',30443))
s.sendall(b'nvyr-zone-test')
assert s.recv(100)==b'nvyr-zone-test'
s.close()
'''
        run('ip', 'vrf', 'exec', 'BLUE', 'python3', '-c', client_code)
        assert server.wait(timeout=10) == 0, server.stderr.read()
        entries = run('conntrack', '-L', '-f', 'ipv4', '-p', transport, '-o', 'extended')
        assert 'dst=198.51.100.1' in entries and 'zone=1' in entries
    finally:
        if server.poll() is None:
            server.terminate()
            server.wait(timeout=5)


def test_tcp_nat_across_vrf_and_default(internet):
    """TCP completes a handshake and carries data through both conntrack zones."""
    exchange(internet, 'tcp')


def test_udp_nat_across_vrf_and_default(internet):
    """UDP replies are translated back and delivered to the VRF socket."""
    exchange(internet, 'udp')


def test_reapply_keeps_active_nat_connection(internet, tmp_path):
    """Updating map membership preserves existing IDs and established NAT state."""
    prefix, config = internet
    ping = subprocess.Popen(['ip', 'vrf', 'exec', 'BLUE', 'ping', '-n', '-c', '6', '-i', '.2',
                             '-W', '2', '198.51.100.2'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(.4)
        config['vrf']['name']['AAA'] = {'table': '4294967295'}
        install(config, tmp_path)
        output, errors = ping.communicate(timeout=10)
        assert ping.returncode == 0 and ', 0% packet loss' in output, (output, errors)
    finally:
        if ping.poll() is None:
            ping.kill()
            ping.wait()


def test_notrack_remains_effective(internet):
    """Automatic assignment preserves the user's raw-hook notrack statement."""
    rules = '''table inet test_notrack {
 chain output { type filter hook output priority raw; policy accept;
 ip daddr 192.0.2.1 notrack
 ip saddr 192.0.2.1 notrack
 }
 chain prerouting { type filter hook prerouting priority raw; policy accept;
 ip saddr 192.0.2.1 notrack
 ip daddr 192.0.2.1 notrack
 }
}'''
    subprocess.run(['nft', '-f', '-'], input=rules, check=True, text=True)
    try:
        run('ip', 'vrf', 'exec', 'BLUE', 'ping', '-n', '-e', '30100', '-c', '2', '-W', '2', '192.0.2.1')
        entries = run('conntrack', '-L', '-p', 'icmp', '-o', 'extended')
        assert 'id=30100' not in entries
    finally:
        run('nft', 'delete', 'table', 'inet', 'test_notrack')


@pytest.fixture
def overlap(internet, tmp_path):
    """RED uses exactly BLUE's endpoint addresses, with a separate peer cable."""
    prefix, config = internet
    peer_pid = prefix[2]
    run('ip', 'link', 'add', 'redport', 'type', 'veth', 'peer', 'name', 'redpeer')
    try:
        run('ip', 'link', 'set', 'redpeer', 'netns', peer_pid)
        run('ip', 'link', 'set', 'redport', 'master', 'RED')
        run('ip', 'address', 'add', '192.0.2.2/24', 'dev', 'redport')
        run('ip', '-6', 'address', 'add', '2001:db8::2/64', 'dev', 'redport', 'nodad')
        run(*prefix, 'ip', 'address', 'add', '192.0.2.1/24', 'dev', 'redpeer')
        run(*prefix, 'ip', '-6', 'address', 'add', '2001:db8::1/64', 'dev', 'redpeer', 'nodad')
        config['interfaces']['virtual-ethernet']['redport'] = {'vrf': 'RED'}
        install(config, tmp_path)
        run('ip', 'link', 'set', 'redport', 'up')
        run(*prefix, 'ip', 'link', 'set', 'redpeer', 'up')
        Path('/proc/sys/net/ipv4/conf/redport/rp_filter').write_text('0')
        yield
    finally:
        run('ip', 'link', 'del', 'redport')


def test_ipv4_identical_tuples_in_two_vrfs(overlap):
    """The same addresses, protocol and ICMP identifier produce distinct connections."""
    run('ip', 'vrf', 'exec', 'BLUE', 'ping', '-n', '-e', '30101', '-c', '2', '-W', '2', '192.0.2.1')
    run('ip', 'vrf', 'exec', 'RED', 'ping', '-n', '-e', '30101', '-c', '2', '-W', '2', '192.0.2.1')
    entries = run('conntrack', '-L', '-f', 'ipv4', '-p', 'icmp', '-o', 'extended')
    connections = [line for line in entries.splitlines() if 'id=30101 ' in line]
    assert any('zone=1 ' in line and '[UNREPLIED]' not in line for line in connections)
    assert any('zone=2 ' in line and '[UNREPLIED]' not in line for line in connections)


def test_ipv6_identical_tuples_in_two_vrfs(overlap):
    """IPv6 connections with identical tuples are isolated by the same map."""
    run('ip', 'vrf', 'exec', 'BLUE', 'ping', '-6', '-n', '-e', '30102', '-c', '2', '-W', '2', '2001:db8::1')
    run('ip', 'vrf', 'exec', 'RED', 'ping', '-6', '-n', '-e', '30102', '-c', '2', '-W', '2', '2001:db8::1')
    entries = run('conntrack', '-L', '-f', 'ipv6', '-p', 'icmpv6', '-o', 'extended')
    connections = [line for line in entries.splitlines() if 'id=30102 ' in line]
    assert any('zone=1 ' in line and '[UNREPLIED]' not in line for line in connections)
    assert any('zone=2 ' in line and '[UNREPLIED]' not in line for line in connections)
