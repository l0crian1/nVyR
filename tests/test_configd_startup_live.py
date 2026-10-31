"""Exercise configd's startup ordering in an isolated systemd container."""

import os
from pathlib import Path
import subprocess
import uuid

import pytest


pytestmark = pytest.mark.skipif(
    os.environ.get('NVYR_NETWORK_TEST') != '1',
    reason='requires isolated privileged systemd container',
)


@pytest.fixture
def startup_units():
    assert Path('/.dockerenv').exists() and os.geteuid() == 0

    repository = Path(__file__).resolve().parents[1]
    identifier = f'nvyr-startup-{uuid.uuid4().hex}'
    loader_name = f'{identifier}-conntrack.service'
    daemon_name = f'{identifier}-configd.service'
    unit_directory = Path('/run/systemd/system')
    work = Path('/run') / identifier
    work.mkdir()

    def start(*, loader_fails=False, check_kernel_protection=False):
        # A missing regular file models the sysctl appearing on module load,
        # without unloading a module shared with the container host.
        accounting = work / 'accounting'
        loader = (repository / 'packaging/nvyr-conntrack.service').read_text()
        loader = loader.replace('nvyr-configd.service', daemon_name)
        command = '/usr/bin/false' if loader_fails else f'/usr/bin/touch {accounting}'
        loader = loader.replace('/usr/sbin/modprobe nf_conntrack', command)
        # This probe models module readiness without touching shared host modules
        # or capturing the container host's automatic conntrack capacities.
        loader = loader.replace('ExecStart=/usr/sbin/modprobe nf_log_syslog\n', '')
        loader = loader.replace('ExecStart=/usr/bin/nvyr-kernel-settings\n', '')
        (unit_directory / loader_name).write_text(loader)

        probe = work / 'probe.py'
        probe.write_text(
            'from pathlib import Path\n'
            f'Path({str(accounting)!r}).write_text("started")\n'
        )

        if check_kernel_protection:
            with probe.open('a') as stream:
                stream.write(
                    'accounting = Path("/proc/sys/net/netfilter/nf_conntrack_acct")\n'
                    'accounting.write_text(accounting.read_text())\n'
                    'echo = Path("/proc/sys/net/ipv4/icmp_echo_ignore_all")\n'
                    'echo.write_text(echo.read_text())\n'
                    'echo6 = Path("/proc/sys/net/ipv6/icmp/echo_ignore_all")\n'
                    'echo6.write_text(echo6.read_text())\n'
                    'try:\n'
                    '    with open("/proc/sys/vm/swappiness", "w"):\n'
                    '        raise AssertionError("Unrelated sysctl is writable")\n'
                    'except PermissionError:\n'
                    '    pass\n'
                    'except OSError as error:\n'
                    '    assert error.errno == 30, error\n'
                )

        # Keep the real service's sandbox and prerequisite declarations. Replace
        # unrelated router services and the daemon with a small startup probe.
        source = (repository / 'packaging/nvyr-configd.service').read_text()
        lines = []

        for line in source.splitlines():
            if line.startswith(('Wants=', 'PartOf=', 'Before=', 'Restart')):
                continue

            if line.startswith(('After=', 'Requires=')):
                key, value = line.split('=', 1)
                dependencies = value.split()
                selected = loader_name if 'nvyr-conntrack.service' in dependencies else ''
                line = f'{key}={selected}'
            elif line == 'Type=notify':
                line = 'Type=oneshot'
            elif line.startswith('ExecStart='):
                line = f'ExecStart=/usr/bin/python3 {probe}'
            elif line.startswith('Group='):
                line = 'Group=root'
            elif line.startswith(('RuntimeDirectory=', 'StateDirectory=')):
                line = line.split('=', 1)[0] + '='
            elif line.startswith('ReadWritePaths='):
                if '/proc/sys/' in line and check_kernel_protection:
                    lines.append(line)

                line = f'ReadWritePaths={accounting}'

            lines.append(line)

        (unit_directory / daemon_name).write_text('\n'.join(lines) + '\n')
        subprocess.run(['systemctl', 'daemon-reload'], check=True)
        result = subprocess.run(
            ['systemctl', 'start', daemon_name], text=True, capture_output=True,
        )
        return result, accounting

    yield start

    subprocess.run(['systemctl', 'stop', daemon_name, loader_name], check=True)

    for name in (daemon_name, loader_name):
        failed = subprocess.run(['systemctl', 'is-failed', '--quiet', name])
        if failed.returncode == 0:
            subprocess.run(['systemctl', 'reset-failed', name], check=True)

        (unit_directory / name).unlink()

    subprocess.run(['systemctl', 'daemon-reload'], check=True)

    for path in work.iterdir():
        path.unlink()

    work.rmdir()


def test_missing_accounting_file_is_created_before_configd_sandbox(startup_units):
    result, accounting = startup_units()

    assert result.returncode == 0, result.stderr
    assert accounting.read_text() == 'started'


def test_module_initialization_failure_blocks_configd(startup_units):
    result, accounting = startup_units(loader_fails=True)

    assert result.returncode != 0
    assert not accounting.exists()


def test_network_settings_writable_with_unrelated_kernel_trees_protected(startup_units):
    assert Path('/proc/sys/net/netfilter/nf_conntrack_acct').exists()

    result, accounting = startup_units(check_kernel_protection=True)

    assert result.returncode == 0, result.stderr
    assert accounting.read_text() == 'started'
