"""Validated, compensating Chrony lifecycle and VRF-aware service launcher."""

from dataclasses import dataclass
from pathlib import Path
import subprocess
import tempfile

from nvyr.errors import RecoveryError, RouterError
from nvyr.helpers.process import cmd, run
from nvyr.helpers.template import write
from nvyr.storage import sync_directory

CONFIGURATION = Path('/run/nvyr-ntp/chrony.conf')
SOCKET = '/run/nvyr-chrony/chronyd.sock'
UNIT = 'nvyr-ntp.service'


@dataclass(frozen=True)
class Plan:
    desired: str | None
    previous: str | None


class Manager:
    def __init__(self, directory='/run/nvyr-ntp', *, run=run, cmd=cmd):
        self.directory = Path(directory)
        self.run = run
        self.cmd = cmd

    def _active(self, unit=UNIT):
        return self.run(['systemctl', 'is-active', '--quiet', unit]) == 0

    def _install(self, configuration):
        path = self.directory / 'chrony.conf'
        if configuration is None:
            if self.run(['systemctl', 'stop', UNIT], timeout=20):
                raise RouterError('Could not stop NTP')
            path.unlink(missing_ok=True)
            sync_directory(path.parent)
            return

        write(path, configuration)
        self.run(['systemctl', 'reset-failed', UNIT])
        if self.run(['systemctl', 'restart', UNIT], timeout=20) or not self._active():
            raise RouterError('Could not start NTP')

        # Readiness means the daemon responds, not that remote sources are reachable.
        self.cmd(['chronyc', '-h', SOCKET, 'tracking'], timeout=5)

    def apply(self, plan, *, recovery=False):
        path = self.directory / 'chrony.conf'
        if plan.desired is None and not path.exists() and not self._active():
            return

        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if plan.desired is not None:
            for stock in ('chrony.service', 'systemd-timesyncd.service', 'ntp.service', 'ntpsec.service'):
                if self._active(stock):
                    raise RouterError(f'{stock} is already controlling time outside nVyR')

            with tempfile.TemporaryDirectory(prefix='.check-', dir=self.directory) as temporary:
                candidate = Path(temporary) / 'chrony.conf'
                write(candidate, plan.desired)
                self.cmd(['/usr/sbin/chronyd', '-p', '-f', str(candidate)], timeout=10)

            if path.exists() and path.read_text() == plan.desired and self._active():
                self.cmd(['chronyc', '-h', SOCKET, 'tracking'], timeout=5)
                return

        try:
            self._install(plan.desired)
        except Exception as error:
            if recovery:
                raise RecoveryError(f'NTP recovery failed: {error}') from error

            try:
                self._install(plan.previous)
            except Exception as rollback:
                raise RecoveryError(f'NTP apply failed ({error}); restoring the previous configuration failed ({rollback})') from rollback

            raise RouterError(f'NTP apply failed; previous configuration restored: {error}') from error


def launch_command(configuration, *, restarted):
    """Bind DNS resolution as well as NTP/NTS sockets to the selected VRF."""
    command = ['/usr/sbin/chronyd', '-f', str(CONFIGURATION), '-u', '_chrony']
    if restarted:
        command.append('-R')

    for line in configuration.splitlines():
        fields = line.split()
        if fields and fields[0] == 'binddevice':
            command = ['/usr/sbin/ip', 'vrf', 'exec', fields[1], *command]
            break

    return command


def main():
    # Keep the marker outside RuntimeDirectory so service restarts/removal do not
    # enable another abrupt clock step. /run clears it naturally at the next boot.
    marker = CONFIGURATION.parent / 'started'
    command = launch_command(CONFIGURATION.read_text(), restarted=marker.exists())
    subprocess.run(command, check=True)
    marker.touch(mode=0o600)


manager = Manager()
