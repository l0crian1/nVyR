"""Opt-in account lifecycle suite in a fresh disposable systemd test image.

Covers PAM/SSH, passwords, developer sudo, isolated role sessions, role revocation,
account persistence and configd restart. Incompatible with an existing configd
state directory or listener. Use NVYR_LOGIN_TEST=1 only in that prepared image;
the normal functional suite leaves existing host authentication untouched."""

import json
import os
from pathlib import Path
import pwd
import select
import socket
import subprocess
import sys
import time

import pytest

from nvyr.helpers.template import render
from nvyr.protocol import Client

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_LOGIN_TEST') != '1',
                                reason='requires a fresh disposable systemd account/SSH test image')


def wait_for(predicate):
    deadline = time.monotonic() + 15

    while not predicate():
        assert time.monotonic() < deadline, 'Timed out waiting for login test service'

        time.sleep(.05)


def test_real_accounts_passwords_cli_roles_revocation_and_restart(tmp_path):
    assert Path('/proc/1/comm').read_text().strip() == 'systemd' and os.geteuid() == 0
    assert not Path('/run/nvyr/configd.sock').exists()
    assert not Path('/var/lib/nvyr/state.json').exists(), 'Requires fresh account state'

    from nvyr.storage import atomic_json
    from nvyr.helpers import developer_access, session_runtime

    atomic_json(developer_access.RUNTIME / 'boot.json', {'enabled': True}, mode=0o644)
    session_runtime.prepare()

    # Keep only account handling real; this test must not configure host networking.
    startup = ('from nvyr.helpers import interfaces, nftables, ssh, frr_reload; '
               'frr_reload.manager.apply=lambda *a, **k: None; '
               'from nvyr.helpers import logging_runtime; '
               'logging_runtime.apply=lambda *a, **k: None; '
               'logging_runtime.prepare_groups=lambda *a, **k: None; '
               'logging_runtime.cleanup=lambda *a, **k: None; '
               'interfaces.manager.apply=lambda *a, **k: None; '
               'interfaces.manager.validate=lambda *a, **k: None; '
               'interfaces.manager.request=lambda *a, **k: {}; '
               'nftables.manager.apply=lambda *a, **k: None; ssh.manager.apply=lambda *a, **k: None; '
               'from nvyr.daemon import main; main()')
    logfile = (tmp_path/'configd.log').open('w+')

    def start():
        process = subprocess.Popen([sys.executable, '-c', startup, '--group', 'nvyr-access'], stdout=logfile, stderr=logfile)

        def ready():
            if process.poll() is not None:
                logfile.seek(0)
                pytest.fail(logfile.read())

            return Path('/run/nvyr/configd.sock').exists()

        wait_for(ready)

        return process

    daemon = start()
    sshd = None
    client = Client('/run/nvyr/configd.sock')
    client.request('open')

    def execute(text):
        return client.request('execute', text=text)

    def commit():
        value = client.request('commit')

        assert all(result['success'] for result in value['results'].values()), value

    def user(name, role):
        execute(f'set system login user {name} authentication plaintext-password test-password')
        execute(f'set system login user {name} role {role}')

    def ssh(name, command=None, password='test-password', *, extra=(), input=None):
        argv = ['sshpass', '-e', 'ssh', '-p', '2222', '-o', 'StrictHostKeyChecking=no',
                '-o', 'UserKnownHostsFile=/dev/null', '-o', 'PreferredAuthentications=password',
                *extra, name+'@127.0.0.1']

        if command is not None:
            argv.append(command)

        return subprocess.run(argv, input=input, text=True, capture_output=True, timeout=15,
                              env=os.environ | {'SSHPASS': password})

    try:
        assert pwd.getpwnam('nvyr').pw_shell == '/usr/bin/nvyr-login'

        key = tmp_path/'hostkey'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True)
        config = tmp_path/'sshd.conf'
        config.write_text(render('ssh/sshd_config.j2', {'configuration': {}, 'host_key': str(key)}).replace('Port 22\n', 'Port 2222\n'))
        Path('/run/sshd').mkdir(exist_ok=True)
        sshd = subprocess.Popen(['/usr/sbin/sshd', '-D', '-e', '-f', str(config)], stdout=logfile, stderr=logfile)

        def listening():
            try:
                with socket.create_connection(('127.0.0.1', 2222), timeout=.1):
                    return True
            except OSError:
                return False

        wait_for(listening)
        result = ssh('nvyr', 'id -un', password='nvyr')

        assert result.returncode == 0 and result.stdout.strip() == 'nvyr', result.stderr

        result = ssh('nvyr', 'sudo -S -k id -u', password='nvyr', input='nvyr\n')

        assert result.returncode == 0 and result.stdout.strip() == '0', result.stderr

        # Interactive developer SSH enters the host CLI without an extra nvyr command.
        result = ssh('nvyr', password='nvyr', extra=('-tt',), input='show version\rexit\r')
        assert result.returncode == 0 and 'Build date |' in result.stdout, result.stdout + result.stderr

        user('netadmin', 'net-admin')
        user('observer', 'read-only')
        user('replacement', 'dev-admin')
        commit()

        for name in ('netadmin', 'observer'):
            assert ssh(name, 'id').returncode != 0
            assert ssh(name, 'sftp', extra=('-s',)).returncode != 0
            assert ssh(name, extra=('-W', '127.0.0.1:2222')).returncode != 0

            result = subprocess.run(['runuser', '-u', name, '--', 'sudo', '-n', 'id'], capture_output=True)

            assert result.returncode != 0

        result = ssh('observer', extra=('-tt',), input='show version\rconfigure\rshell\rexit\r')

        assert 'Version    |' in result.stdout and 'Permission denied' in result.stdout, result.stdout + result.stderr

        execute('exit')  # Release root's commit lock to the real net-admin CLI.
        result = ssh('netadmin', extra=('-tt',), input='configure\rset system host-name role-test\rcommit\rexit\rexit\r')
        client.request('open')

        assert json.loads(execute('show running-configuration')['text'])['system']['host-name'] == 'role-test', result.stdout + result.stderr

        # PAM console login exercises the actual login shell and CLI, not su bypass.
        import pty

        pid, terminal = pty.fork()
        if pid == 0:
            os.execv('/bin/login', ['login'])

        data = bytearray()

        def until(marker):
            deadline = time.monotonic() + 15

            while marker not in data:
                assert time.monotonic() < deadline, data.decode(errors='replace')

                if select.select([terminal], [], [], .2)[0]:
                    data.extend(os.read(terminal, 65536))

            data.clear()

        try:
            until(b'login:')
            os.write(terminal, b'nvyr\r')
            until(b'Password:')
            os.write(terminal, b'nvyr\r')
            until(b':~$')
            os.write(terminal, b'show version\r')
            until(b'Build date |')
        finally:
            os.kill(pid, 9)
            os.waitpid(pid, 0)
            os.close(terminal)

        execute('set system login user nvyr authentication plaintext-password changed-password')
        commit()

        assert ssh('nvyr', 'id', password='nvyr').returncode != 0
        assert ssh('nvyr', 'id', password='changed-password').returncode == 0

        execute('delete system login user nvyr')
        commit()

        with pytest.raises(KeyError):
            pwd.getpwnam('nvyr')

        uid = pwd.getpwnam('netadmin').pw_uid
        client.close()
        daemon.terminate()
        daemon.wait(timeout=10)

        # A killed daemon can leave its socket; main unlinks it under its lock.
        Path('/run/nvyr/configd.sock').unlink(missing_ok=True)
        daemon = start()
        client = Client('/run/nvyr/configd.sock')
        client.request('open')

        assert pwd.getpwnam('netadmin').pw_uid == uid

        with pytest.raises(KeyError):
            pwd.getpwnam('nvyr')

        assert ssh('replacement', 'id -un').stdout.strip() == 'replacement'

        # Demotion terminates an already-running unrestricted Linux session.
        sleeper = subprocess.Popen(['sshpass', '-e', 'ssh', '-p', '2222', '-o', 'StrictHostKeyChecking=no',
                                    '-o', 'UserKnownHostsFile=/dev/null', 'replacement@127.0.0.1', 'sleep 60'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   env=os.environ | {'SSHPASS': 'test-password'})

        try:
            wait_for(lambda: subprocess.run(['pgrep', '-u', str(pwd.getpwnam('replacement').pw_uid), 'sleep'],
                                            capture_output=True).returncode == 0)

            # Keep another administrator before demoting replacement.
            execute('set system login user netadmin role sys-admin')
            execute('set system login user replacement role read-only')
            commit()

            assert sleeper.wait(timeout=5) != 0
            assert ssh('replacement', 'id').returncode != 0
        finally:
            if sleeper.poll() is None:
                sleeper.kill()
                sleeper.wait(timeout=5)

        # Linux shadow and all durable nVyR records contain only hashed credentials.
        for path in Path('/var/lib/nvyr').rglob('*.json'):
            assert 'test-password' not in path.read_text() and 'changed-password' not in path.read_text()

        assert subprocess.run(['traceroute', '-4', '-m', '1', '127.0.0.1'], capture_output=True).returncode == 0
        assert subprocess.run(['traceroute', '-6', '-m', '1', '::1'], capture_output=True).returncode == 0
    finally:
        client.close()
        daemon.terminate()
        daemon.wait(timeout=10)

        if sshd:
            sshd.terminate()
            sshd.wait(timeout=10)

        logfile.close()
