"""Opt-in checks of the installed router baseline in a disposable container."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from nvyr.protocol import Client

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged systemd container')


def run(*args, **kwargs):
    return subprocess.run(args, text=True, capture_output=True, check=True, **kwargs).stdout


def wait_for(predicate):
    deadline = time.monotonic() + 20

    while not predicate():
        assert time.monotonic() < deadline, 'Router startup did not converge'

        time.sleep(.1)


def test_installed_baseline_existing_and_new_links_and_forwarding():
    assert Path('/.dockerenv').exists() and os.geteuid() == 0

    script = r'''
import json, subprocess, sys, time
from pathlib import Path
def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True).stdout
def value(key):
    return Path('/proc/sys/' + key).read_text().strip()
baseline = '/usr/lib/sysctl.d/50-nvyr-router.conf'
run('ip', 'link', 'add', 'before.0', 'type', 'dummy')
run('sysctl', '-w', 'net.ipv4.ip_forward=0', 'net.ipv6.conf.all.forwarding=0',
    'net.ipv4.conf.before/0.rp_filter=1', 'net.ipv4.conf.before/0.send_redirects=1',
    'net.ipv4.icmp_ratelimit=2000')
run('/usr/lib/systemd/systemd-sysctl', baseline)
# Detailed firewall settings belong to configd, not the early router baseline.
assert value('net/ipv4/icmp_ratelimit') == '2000'
run('ip', 'link', 'add', 'after0', 'type', 'dummy')
for family in ('ipv4', 'ipv6'):
    for name in ('all', 'default', 'lo', 'before.0', 'after0'):
        prefix = f'net/{family}/conf/{name}/'
        assert value(prefix + 'forwarding') == '1', prefix
        # IPv4 all gates stay open so per-interface values can override defaults.
        gate = '1' if family == 'ipv4' and name == 'all' else '0'
        assert value(prefix + 'accept_redirects') == gate, prefix
        assert value(prefix + 'accept_source_route') == gate, prefix
        if family == 'ipv4':
            for option in ('rp_filter', 'send_redirects'):
                assert value(prefix + option) == '0', prefix + option
            assert value(prefix + 'bc_forwarding') == ('1' if name == 'all' else '0')
assert value('net/ipv4/ip_forward') == '1'
assert value('net/ipv4/ip_no_pmtu_disc') == '0'
assert value('net/ipv4/ip_forward_use_pmtu') == '0'
assert value('net/ipv6/conf/after0/accept_ra') == '1'
assert value('net/ipv6/conf/after0/disable_ipv6') == '0'
assert value('net/ipv6/conf/after0/accept_dad') != '0'
run('nft', 'add', 'table', 'inet', 'old_rules')
run('nft', 'add', 'chain', 'inet', 'old_rules', 'old_chain')
for _ in range(2):
    run('nft', '--file', '/usr/lib/nvyr/router.nft')
    entries = json.loads(run('nft', '-j', 'list', 'ruleset'))['nftables'][1:]
    assert len(entries) == 1 and entries[0]['table']['name'] == 'nvyr_filter', entries
    assert entries[0]['table']['family'] == 'inet'
# Exercise real IPv4 and IPv6 transit through this namespace using two peers.
peers = []
try:
    for index in (1, 2):
        peer = subprocess.Popen(['unshare', '-n', 'sleep', '60'])
        peers.append(peer)
        deadline = time.monotonic() + 3
        while Path(f'/proc/{peer.pid}/ns/net').readlink() == Path('/proc/self/ns/net').readlink():
            assert time.monotonic() < deadline
            time.sleep(.01)
        run('ip', 'link', 'add', f'router{index}', 'type', 'veth', 'peer', 'name', f'peer{index}')
        run('ip', 'link', 'set', f'peer{index}', 'netns', str(peer.pid))
        prefix = ('nsenter', '-t', str(peer.pid), '-n')
        for command in [('link', 'set', f'peer{index}', 'up'),
                        ('address', 'add', f'192.0.{index}.2/24', 'dev', f'peer{index}'),
                        ('address', 'add', f'2001:db8:{index}::2/64', 'dev', f'peer{index}', 'nodad'),
                        ('route', 'add', 'default', 'via', f'192.0.{index}.1'),
                        ('-6', 'route', 'add', 'default', 'via', f'2001:db8:{index}::1')]:
            run(*prefix, 'ip', *command)
        run('ip', 'address', 'add', f'192.0.{index}.1/24', 'dev', f'router{index}')
        run('ip', 'address', 'add', f'2001:db8:{index}::1/64', 'dev', f'router{index}', 'nodad')
        run('ip', 'link', 'set', f'router{index}', 'up')
    for family, address in [('AF_INET', '192.0.2.2'), ('AF_INET6', '2001:db8:2::2')]:
        receive = f"import socket; s=socket.socket(socket.{family},socket.SOCK_DGRAM); s.bind(('{address}',9999)); s.settimeout(5); print('ready',flush=True); assert s.recv(100)==b'router'"
        receiver = subprocess.Popen(['nsenter', '-t', str(peers[1].pid), '-n', sys.executable, '-c', receive],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert receiver.stdout.readline().strip() == 'ready'
            send = f"import socket; s=socket.socket(socket.{family},socket.SOCK_DGRAM); s.sendto(b'router',('{address}',9999))"
            run('nsenter', '-t', str(peers[0].pid), '-n', sys.executable, '-c', send)
            stdout, stderr = receiver.communicate(timeout=10)
            assert receiver.returncode == 0, stdout + stderr
        finally:
            if receiver.poll() is None:
                receiver.kill()
                receiver.wait()
finally:
    for peer in peers:
        peer.terminate()
        peer.wait(timeout=5)
'''
    result = subprocess.run(['unshare', '-n', sys.executable, '-c', script],
                            text=True, capture_output=True, timeout=60)

    assert result.returncode == 0, result.stdout + result.stderr


def test_service_restart_replays_policy_but_configd_restart_does_not_flush():
    assert Path('/.dockerenv').exists() and os.geteuid() == 0

    def execute(command):
        client = Client('/run/nvyr/configd.sock')
        client.request('open')

        try:
            return client.request('execute', text=command)
        finally:
            client.close()

    def ready():
        try:
            execute('show running-configuration')
            return True
        except (OSError, RuntimeError):
            return False

    def rules():
        return json.loads(run('nft', '-j', 'list', 'ruleset'))['nftables'][1:]

    wait_for(ready)

    assert not json.loads(execute('show running-configuration')['text']).get('firewall'), 'Requires empty firewall configuration'

    client = Client('/run/nvyr/configd.sock')
    client.request('open')

    try:
        client.request('execute', text='set firewall ipv4 forward filter rule 10 action accept')
        result = client.request('commit')

        assert result['results']['firewall']['success'], result

        client.request('execute', text='save')
    finally:
        client.close()

    try:
        run('nft', 'add', 'table', 'inet', 'init_sentinel')
        run('systemctl', 'restart', 'nvyr-configd.service')
        wait_for(ready)

        assert any(item.get('table', {}).get('name') == 'init_sentinel' for item in rules())

        previous_pid = run('systemctl', 'show', '--value', '-p', 'MainPID', 'nvyr-configd.service')
        run('systemctl', 'restart', 'nftables.service')
        wait_for(ready)

        assert previous_pid != run('systemctl', 'show', '--value', '-p', 'MainPID', 'nvyr-configd.service')
        assert not any(item.get('table', {}).get('name') == 'init_sentinel' for item in rules())
        assert any(item.get('rule', {}).get('comment') == '10|' for item in rules())
        assert run('systemctl', 'show', '--value', '-p', 'CanReload', 'nftables.service').strip() == 'no'
    finally:
        client = Client('/run/nvyr/configd.sock')
        client.request('open')

        try:
            client.request('execute', text='delete firewall')
            result = client.request('commit')

            assert result['results']['firewall']['success'], result

            client.request('execute', text='save')
        finally:
            client.close()


def test_failed_nft_baseline_blocks_configd_start():
    assert Path('/.dockerenv').exists() and os.geteuid() == 0

    directory = Path('/run/systemd/system/nftables.service.d')
    override = directory / '99-nvyr-test-failure.conf'

    assert not override.exists()

    directory.mkdir(parents=True, exist_ok=True)

    try:
        run('systemctl', 'stop', 'nftables.service')
        override.write_text('[Service]\nExecStart=\nExecStart=/bin/false\n')
        run('systemctl', 'daemon-reload')
        failed = subprocess.run(['systemctl', 'start', 'nvyr-configd.service'],
                                text=True, capture_output=True)

        assert failed.returncode != 0, failed.stdout + failed.stderr
        assert run('systemctl', 'show', '--value', '-p', 'ActiveState', 'nftables.service').strip() == 'failed'
        assert run('systemctl', 'show', '--value', '-p', 'MainPID', 'nvyr-configd.service').strip() == '0'
    finally:
        override.unlink(missing_ok=True)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'reset-failed', 'nftables.service', 'nvyr-configd.service')
        run('systemctl', 'start', 'nvyr-configd.service')
        wait_for(lambda: Path('/run/nvyr/configd.sock').exists())
