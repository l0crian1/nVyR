"""Instance-scoped OpenSSH configuration and compensating service application."""

from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import tempfile

from nvyr.errors import RecoveryError, RouterError
from nvyr.storage import sync_directory
from nvyr.helpers.process import cmd, run
from nvyr.helpers.template import write


@dataclass(frozen=True)
class Plan:
    instance: str
    desired: str | None
    previous: str | None


def host_key(state_directory):
    # sshd runs under systemd, whose working directory differs from a development CLI.
    return Path(state_directory).resolve() / 'ssh' / 'host_ed25519_key'


class Manager:
    def __init__(self, directory='/run/nvyr-ssh', *, run=run):
        self.directory = Path(directory)
        self.run = run

    def _path(self, instance):
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}', instance):
            raise RouterError(f'Invalid SSH instance {instance!r}')

        return self.directory / (instance + '.conf')

    def _active(self, unit):
        return self.run(['systemctl', 'is-active', '--quiet', unit]) == 0

    def _key(self, state_directory):
        key = host_key(state_directory)
        if key.exists():
            return

        key.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Keys are generated per deployed router, never baked into the image.
        with tempfile.TemporaryDirectory(prefix='.key-', dir=key.parent) as work:
            candidate = Path(work) / key.name
            if self.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(candidate)]):
                raise RouterError('Could not generate the SSH host key')

            with candidate.open('rb') as stream:
                os.fsync(stream.fileno())

            os.replace(candidate, key)
            sync_directory(key.parent)

    def _install(self, unit, path, configuration):
        if configuration is None:
            if self.run(['systemctl', 'stop', unit], timeout=20):
                raise RouterError('Could not stop the SSH service')

            path.unlink(missing_ok=True)
            sync_directory(path.parent)
        else:
            write(path, configuration)

            # Operator changes/compensation must not hit automatic restart limits.
            # A never-loaded instance has no failed state to reset.
            self.run(['systemctl', 'reset-failed', unit])

            # Type=notify waits until sshd has opened its listening sockets.
            if self.run(['systemctl', 'restart', unit], timeout=20) or not self._active(unit):
                raise RouterError('Could not start the SSH service')

            self._check_listeners(unit, path)

    def _check_listeners(self, unit, path):
        # sshd can report ready even when only some requested addresses bound.
        # Compare its parsed configuration with sockets owned by this listener.
        effective = cmd(['/usr/sbin/sshd', '-T', '-f', str(path)])
        expected = {ipaddress.ip_address(line.split()[1].rsplit(':', 1)[0].strip('[]'))
                    for line in effective.splitlines() if line.startswith('listenaddress ')}
        pid = cmd(['systemctl', 'show', '--property=MainPID', '--value', unit]).strip()
        if not pid.isdecimal() or int(pid) <= 0 or not expected:
            raise RouterError('Cannot verify SSH listener state')

        actual = set()

        for version in {address.version for address in expected}:
            sockets = cmd(['ss', '-H', '-lntp', f'-{version}', 'sport = :22'])

            for line in sockets.splitlines():
                if not re.search(r'\bpid=' + re.escape(pid) + r'\b', line):
                    continue

                host = line.split()[3].rsplit(':', 1)[0].strip('[]')
                actual.add(ipaddress.ip_address(('0.0.0.0' if version == 4 else '::') if host == '*' else host))

        if actual != expected:
            missing = ', '.join(sorted(str(address) for address in expected - actual))
            raise RouterError('SSH did not bind all configured addresses' + (f': {missing}' if missing else ' (unexpected listener addresses)'))

    def apply(self, plan, state_directory, *, recovery=False):
        path = self._path(plan.instance)
        unit = f'nvyr-ssh@{plan.instance}.service'
        if plan.desired is None and not path.exists() and not self._active(unit):
            return

        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)

        if plan.desired is not None:
            for stock in ('ssh.service', 'ssh.socket'):
                if self._active(stock):
                    raise RouterError(f'{stock} is already active outside nVyR management; stop it before configuring service ssh')

            self._key(state_directory)

            with tempfile.TemporaryDirectory(prefix='.check-', dir=self.directory) as work:
                candidate = Path(work) / 'sshd_config'
                write(candidate, plan.desired)

                if self.run(['/usr/sbin/sshd', '-t', '-f', str(candidate)]):
                    raise RouterError('SSH rejected the proposed configuration')

            if path.exists() and path.read_text() == plan.desired and self._active(unit):
                try:
                    self._check_listeners(unit, path)
                    return
                except RouterError:
                    pass  # Reconcile an active daemon with incomplete listeners.

        try:
            self._install(unit, path, plan.desired)
        except Exception as error:
            if recovery:
                raise RecoveryError(f'SSH recovery failed: {error}') from error

            try:
                self._install(unit, path, plan.previous)
            except Exception as rollback:
                raise RecoveryError(f'SSH apply failed ({error}); restoring the previous service also failed ({rollback}). Restart configd after correcting the service failure.') from rollback

            raise RouterError(f'SSH apply failed; previous service configuration restored: {error}') from error


manager = Manager()
