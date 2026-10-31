"""Password SSH transport for the external runner; credentials stay in memory."""

import shlex
import subprocess
import time


PASSWORD_PROMPT = 'NVYR_ACCEPTANCE_PASSWORD:'
READY = 'NVYR_ACCEPTANCE_READY\n'


class PasswordSSH:
    def __init__(self, destination, password, *, port=22):
        import paramiko

        self.paramiko = paramiko
        self.password = password
        username, separator, hostname = destination.rpartition('@')
        self.username = username if separator else 'nvyr'
        self.hostname = hostname.strip('[]')
        self.port = port
        if not self.username or not self.hostname:
            raise ValueError('Specify a username and router address')

    def execute(self, command, *, root, payload='', timeout=30):
        """Wait for sudo authentication before delivering the agent's JSON input."""
        client = self.paramiko.SSHClient()
        client.load_system_host_keys()
        # Server host keys verify the destination; login uses only the supplied password.
        client.set_missing_host_key_policy(self.paramiko.RejectPolicy())
        try:
            client.connect(
                self.hostname, port=self.port,
                username=self.username, password=self.password,
                look_for_keys=False, allow_agent=False,
                timeout=min(5, timeout), auth_timeout=min(15, timeout),
                banner_timeout=min(15, timeout),
            )
            client.get_transport().set_keepalive(5)
            inner = f"printf {shlex.quote(READY)} >&2; {command}"
            remote = 'sh -c ' + shlex.quote(inner)
            if not root:
                remote = f'sudo -S -p {shlex.quote(PASSWORD_PROMPT)} ' + remote

            channel = client.get_transport().open_session(timeout=timeout)
            channel.settimeout(timeout)
            channel.exec_command(remote)
            return self.exchange(channel, payload, timeout)
        finally:
            client.close()

    def exchange(self, channel, payload, timeout):
        """Drain both streams so large diagnostic responses cannot deadlock SSH."""
        deadline = time.monotonic() + timeout
        stdout = bytearray()
        stderr = bytearray()
        authenticated = False
        password_sent = False
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError('SSH command timed out')
            if channel.recv_ready():
                stdout.extend(channel.recv(65536))
            if channel.recv_stderr_ready():
                stderr.extend(channel.recv_stderr(65536))

            if not authenticated:
                prompt = PASSWORD_PROMPT.encode()
                if prompt in stderr:
                    if password_sent:
                        raise ValueError('Sudo rejected the supplied password')
                    stderr[:] = stderr.replace(prompt, b'', 1)
                    channel.sendall((self.password + '\n').encode())
                    password_sent = True

                ready = READY.encode()
                if ready in stderr:
                    stderr[:] = stderr.replace(ready, b'', 1)
                    channel.sendall(payload.encode())
                    channel.shutdown_write()
                    authenticated = True

            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                return subprocess.CompletedProcess(
                    'ssh', channel.recv_exit_status(),
                    stdout.decode('utf-8', errors='replace'),
                    stderr.decode('utf-8', errors='replace'),
                )
            time.sleep(0.01)
