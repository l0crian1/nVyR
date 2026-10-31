"""Exercise packaged recovery policies using isolated, real systemd services.

The probes use unique unit names and private files; installed router daemons and
network configuration are untouched. Run explicitly with NVYR_RECOVERY_TEST=1.
"""

import configparser
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get('NVYR_RECOVERY_TEST') != '1',
    reason='requires explicit root access to a running systemd 257 instance',
)

DAEMONS = ('nvyr-interface-naming', 'nvyr-netlinkd', 'nvyr-configd')
RESTART_OPTIONS = (
    'Restart', 'RestartMode', 'RestartSec', 'RestartSteps', 'RestartMaxDelaySec',
)

PROBE = '''
import os
from pathlib import Path
import socket
import sys
import time

root = Path(sys.argv[1])
attempts = root / 'attempts'
attempt = int(attempts.read_text()) + 1 if attempts.exists() else 1
pending = root / 'attempts.pending'
pending.write_text(str(attempt))
pending.replace(attempts)

if (root / 'fail').exists():
    print('Injected startup failure', flush=True)
    sys.exit(1)

with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
    target = os.environ['NOTIFY_SOCKET']
    channel.connect('\\0' + target[1:] if target.startswith('@') else target)
    channel.sendall(b'READY=1')

while True:
    time.sleep(1)
'''


def systemctl(*arguments):
    """Bound every control request so a failed recovery produces a test failure."""
    result = subprocess.run(
        ['systemctl', *arguments], capture_output=True, text=True, timeout=15,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


class RecoveryServices:
    """Keep probe mechanics separate from the failure scenarios below."""

    def __init__(self, root, names):
        self.root = root
        self.names = names

    def state(self, daemon):
        output = systemctl(
            'show', self.names[daemon], '-p', 'ActiveState', '-p', 'SubState',
            '-p', 'MainPID', '-p', 'NRestarts', '-p', 'RestartUSecNext',
        )
        return dict(line.split('=', 1) for line in output.splitlines())

    def wait(self, predicate, timeout=45):
        """Poll observable service state, with unit diagnostics on timeout."""
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            if predicate():
                return

            time.sleep(.1)

        states = {daemon: self.state(daemon) for daemon in DAEMONS}
        pytest.fail(f'Recovery timed out: {states}')

    def start(self):
        systemctl('start', '--no-block', self.names['nvyr-configd'])

    def wait_ready(self):
        self.wait(lambda: all(self.state(name)['ActiveState'] == 'active' for name in DAEMONS))

    def fail(self, daemon):
        (self.root / daemon / 'fail').touch()

    def repair(self, daemon):
        (self.root / daemon / 'fail').unlink()

    def attempts(self, daemon):
        path = self.root / daemon / 'attempts'
        return int(path.read_text()) if path.exists() else 0

    def crash(self, daemon):
        systemctl('kill', '--kill-whom=main', '--signal=KILL', self.names[daemon])

    def check_crash_recovery(self, daemon):
        """A single crash must not restart either of the healthy peers."""
        self.start()
        self.wait_ready()
        before = {name: self.state(name)['MainPID'] for name in DAEMONS}

        self.crash(daemon)
        self.wait(lambda: self.attempts(daemon) >= 2)
        self.wait_ready()

        assert self.state(daemon)['MainPID'] != before[daemon]
        assert int(self.state(daemon)['NRestarts']) >= 1

        for peer in DAEMONS:
            if peer != daemon:
                assert self.state(peer)['MainPID'] == before[peer]


@pytest.fixture
def recovery_services():
    """Copy actual dependency and retry declarations into disposable test units."""
    assert os.geteuid() == 0 and Path('/run/systemd/system').is_dir()
    repository = Path(__file__).resolve().parents[1]
    identifier = f'nvyr-recovery-{uuid.uuid4().hex}'
    root = Path('/run') / identifier
    root.mkdir()
    probe = root / 'probe.py'
    probe.write_text(PROBE)
    names = {daemon: f'{identifier}-{daemon}.service' for daemon in DAEMONS}
    paths = []

    try:
        for daemon in DAEMONS:
            source = configparser.ConfigParser(interpolation=None, strict=False)
            source.optionxform = str
            source.read(repository / 'packaging' / f'{daemon}.service')
            work = root / daemon
            work.mkdir()
            lines = ['[Unit]', f'StartLimitIntervalSec={source["Unit"]["StartLimitIntervalSec"]}']

            # Preserve relationships among our three daemons, without starting or
            # stopping any installed router prerequisites during this test.
            for relationship in ('Requires', 'Wants', 'After', 'Before'):
                dependencies = source['Unit'].get(relationship, '').split()
                selected = [names[name] for name in DAEMONS if f'{name}.service' in dependencies]
                lines.append(f'{relationship}={" ".join(selected)}')

            lines.extend([
                '[Service]', f'Type={source["Service"]["Type"]}',
                'NotifyAccess=main', f'ExecStart={sys.executable} {probe} {work}',
            ])
            lines.extend(f'{key}={source["Service"][key]}' for key in RESTART_OPTIONS)
            path = Path('/run/systemd/system') / names[daemon]
            path.write_text('\n'.join(lines) + '\n')
            paths.append(path)

        systemctl('daemon-reload')
        yield RecoveryServices(root, names)
    finally:
        systemctl('stop', *names.values())

        for path in paths:
            path.unlink(missing_ok=True)

        systemctl('daemon-reload')

        for work in root.iterdir():
            if work.is_dir():
                for path in work.iterdir():
                    path.unlink()

                work.rmdir()
            else:
                work.unlink()

        root.rmdir()


def test_naming_failure_keeps_dependent_startup_pending(recovery_services):
    """Naming retries must unblock both consumers without another start request."""
    services = recovery_services
    services.fail('nvyr-interface-naming')
    services.start()
    services.wait(lambda: services.attempts('nvyr-interface-naming') >= 2)

    assert services.attempts('nvyr-netlinkd') == 0
    assert services.attempts('nvyr-configd') == 0

    services.repair('nvyr-interface-naming')
    services.wait_ready()


def test_netlink_failure_keeps_configd_startup_pending(recovery_services):
    """Configd must wait for Netlink readiness, despite its weaker Wants edge."""
    services = recovery_services
    services.fail('nvyr-netlinkd')
    services.start()
    services.wait(lambda: services.attempts('nvyr-netlinkd') >= 2)

    assert services.state('nvyr-interface-naming')['ActiveState'] == 'active'
    assert services.attempts('nvyr-configd') == 0

    services.repair('nvyr-netlinkd')
    services.wait_ready()


def test_configd_startup_failure_recovers_with_backoff(recovery_services):
    """Repeated recovery failures stay retriable and increase the retry delay."""
    services = recovery_services
    services.fail('nvyr-configd')
    services.start()
    services.wait(lambda: services.attempts('nvyr-configd') >= 2)

    assert services.state('nvyr-configd')['RestartUSecNext'] != '5s'
    assert services.attempts('nvyr-interface-naming') == 1
    assert services.attempts('nvyr-netlinkd') == 1

    services.repair('nvyr-configd')
    services.wait_ready()


def test_naming_crash_does_not_stop_healthy_daemons(recovery_services):
    """Naming recovery must leave existing interface and config processes alone."""
    recovery_services.check_crash_recovery('nvyr-interface-naming')


def test_netlink_crash_does_not_stop_configd(recovery_services):
    """A Netlink crash must not tear down configuration sessions."""
    recovery_services.check_crash_recovery('nvyr-netlinkd')


def test_configd_crash_does_not_restart_interface_managers(recovery_services):
    """Configuration recovery must not restart healthy interface services."""
    recovery_services.check_crash_recovery('nvyr-configd')


def test_explicit_stop_is_not_restarted(recovery_services):
    """An administrator can stop all three daemons without a recovery loop."""
    services = recovery_services
    services.start()
    services.wait_ready()
    systemctl('stop', *services.names.values())
    time.sleep(6)

    for daemon in DAEMONS:
        assert services.state(daemon)['ActiveState'] == 'inactive'
        assert services.attempts(daemon) == 1


def test_stop_during_retry_cancels_automatic_recovery(recovery_services):
    """Stopping during the retry delay must cancel the scheduled restart."""
    services = recovery_services
    services.fail('nvyr-configd')
    services.start()
    services.wait(lambda: services.state('nvyr-configd')['SubState'] == 'auto-restart')
    systemctl('stop', services.names['nvyr-configd'])
    services.repair('nvyr-configd')
    time.sleep(6)

    assert services.state('nvyr-configd')['ActiveState'] == 'inactive'
    assert services.attempts('nvyr-configd') == 1
