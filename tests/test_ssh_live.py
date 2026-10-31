"""Opt-in SSH lifecycle checks against the installed daemon in the test container."""

import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time

import pytest

from nvyr.protocol import Client

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged SSH container')


def run(*argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, **kwargs).stdout


def banner(address):
    try:
        with socket.create_connection((address, 22), timeout=.5) as connection:
            return connection.recv(128).startswith(b'SSH-2.0-')
    except OSError:
        return False


def wait_for(predicate):
    deadline = time.monotonic() + 15

    while not predicate():
        assert time.monotonic() < deadline, 'SSH state did not converge'

        time.sleep(.1)


def test_installed_ssh_listeners_login_rollback_restart_and_removal(tmp_path):
    assert Path('/.dockerenv').exists() and os.geteuid() == 0

    client = Client('/run/nvyr/configd.sock')
    client.request('open')

    def execute(text):
        return client.request('execute', text=text)

    def commit():
        result = client.request('commit')

        assert all(value['success'] for value in result['results'].values()), result

    # A fresh image now enables managed SSH with the initial administrator.
    execute('delete service ssh')
    commit()

    assert not banner('127.0.0.1'), 'Test requires no unmanaged SSH listener'

    user = 'nvyrsshtest'
    created = False

    try:
        execute('set service ssh')
        commit()

        assert banner('127.0.0.1') and banner('::1')

        # This SSH transport test enrolls a host account in the permitted access
        # group. Full config-driven account/role behavior has its own live test.
        run('useradd', '-m', '-s', '/bin/sh', '-G', 'nvyr-access', user)
        created = True
        run('chpasswd', input=f'{user}:{secrets.token_hex(32)}\n')
        key = tmp_path / 'client_key'
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key))
        authorized = Path('/home') / user / '.ssh'
        authorized.mkdir(mode=0o700)
        (authorized / 'authorized_keys').write_text(key.with_suffix('.pub').read_text())
        (authorized / 'authorized_keys').chmod(0o600)
        run('chown', '-R', f'{user}:{user}', str(authorized))
        output = run('ssh', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                     '-o', 'StrictHostKeyChecking=accept-new', '-o', f'UserKnownHostsFile={tmp_path / "known_hosts"}',
                     '-i', str(key), user+'@127.0.0.1', 'id', '-un')

        assert output.strip() == user

        execute('set service ssh listen-address ::1')
        commit()

        assert banner('::1') and not banner('127.0.0.1')

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind(('127.0.0.1', 22))
            occupied.listen()
            execute('set service ssh listen-address 127.0.0.1')
            failed = client.request('commit')['results']['ssh']

            assert not failed['success'] and 'previous service configuration restored' in failed['error']
            assert 'did not bind all configured addresses' in failed['error']
            assert banner('::1')

            execute('discard')

        execute('set service ssh listen-address 127.0.0.1')
        commit()

        assert banner('127.0.0.1') and banner('::1')

        execute('delete service ssh listen-address ::1')
        commit()

        assert banner('127.0.0.1') and not banner('::1')

        execute('delete service ssh')
        client.request('execute', text='commit-confirm 0.02', confirmation={'confirm_minutes': .02})

        assert not banner('127.0.0.1')

        wait_for(lambda: any(event['type'] == 'confirmed-rollback' for event in client.request('status')['events']))

        assert banner('127.0.0.1')

        execute('save')
        host_key = Path('/var/lib/nvyr/ssh/host_ed25519_key')
        identity = hashlib.sha256(host_key.read_bytes()).digest()
        client.close()
        run('systemctl', 'restart', 'nvyr-configd')
        wait_for(lambda: Path('/run/nvyr/configd.sock').exists())
        client = Client('/run/nvyr/configd.sock')
        client.request('open')

        assert banner('127.0.0.1')
        assert hashlib.sha256(host_key.read_bytes()).digest() == identity

        # A local address created in the same commit is available before SSH verify/apply.
        execute('set interfaces dummy dum94 address 198.18.94.1/32')
        execute('delete service ssh listen-address 127.0.0.1')
        execute('set service ssh listen-address 198.18.94.1')
        commit()

        assert banner('198.18.94.1') and not banner('127.0.0.1')

        execute('delete service ssh')
        commit()

        assert not banner('198.18.94.1') and not Path('/run/nvyr-ssh/default.conf').exists()
    finally:
        try:
            execute('discard')
            execute('delete service ssh')
            execute('delete interfaces dummy dum94')
            commit()
            execute('save')
        finally:
            client.close()

            if created:
                run('userdel', '-r', user)


def test_generated_service_manager_lifecycle(tmp_path):
    """Exercise generated text, stable keys, partial-bind rollback and removal."""
    from types import SimpleNamespace
    from nvyr.config_scripts import service_ssh
    from nvyr.helpers import ssh
    from nvyr.errors import RouterError

    assert Path('/.dockerenv').exists() and os.geteuid() == 0
    runtime = Path('/run/nvyr-ssh/default.conf')
    assert not runtime.exists(), 'Use a disposable container without a configured SSH service'
    manager = ssh.Manager()

    def plan(current, previous):
        gathered = service_ssh.get_config(SimpleNamespace(
            effective={'service': {'ssh': current}} if current is not None else {},
            previous_effective={'service': {'ssh': previous}} if previous is not None else {},
        ))
        return service_ssh.generate(gathered, SimpleNamespace(state_directory=tmp_path))

    original = {'listen-address': ['127.0.0.1']}
    try:
        manager.apply(plan(original, None), tmp_path)
        assert banner('127.0.0.1')
        key = ssh.host_key(tmp_path).read_bytes()
        pid = run('systemctl', 'show', '-p', 'MainPID', '--value', 'nvyr-ssh@default.service')
        manager.apply(plan(original, original), tmp_path)
        assert run('systemctl', 'show', '-p', 'MainPID', '--value', 'nvyr-ssh@default.service') == pid

        # Simulate a selected address disappearing after configuration verification.
        incomplete = {'listen-address': ['127.0.0.1', '198.18.255.254']}
        with pytest.raises(RouterError, match='previous service configuration restored'):
            manager.apply(plan(incomplete, original), tmp_path)
        assert banner('127.0.0.1')
        assert runtime.read_text() == plan(original, original).desired
        assert ssh.host_key(tmp_path).read_bytes() == key
    finally:
        manager.apply(plan(None, original), tmp_path, recovery=True)

    assert not runtime.exists()
    assert not banner('127.0.0.1')
