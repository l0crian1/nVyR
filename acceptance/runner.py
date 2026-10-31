"""Run from another machine so the controller survives the router's reboot."""

import argparse
import getpass
import json
import os
from pathlib import Path
import time
import uuid


class RemoteError(RuntimeError):
    """An SSH transport or router phase failed; no automatic rollback is implied."""


class Router:
    def __init__(self, host, *, port=22, root=False):
        if not host or host.startswith('-') or any(char.isspace() for char in host):
            raise ValueError('Use user@hostname or user@address as the destination')
        self.host = host
        self.port = port
        self.root = root
        self.password_transport = None

    def authenticate(self):
        """Prompt once for the lab router password and check SSH/sudo before preparation."""
        try:
            from acceptance.ssh_password import PasswordSSH

            password = getpass.getpass(f'Password for {self.host} (SSH and sudo): ')
            self.password_transport = PasswordSSH(self.host, password, port=self.port)
            result = self.password_transport.execute('true', root=self.root)
        except ImportError as error:
            raise RemoteError('Password login needs Paramiko: run python -m pip install paramiko') from error
        except Exception as error:
            raise RemoteError(f'Password authentication failed: {error}') from error
        if result.returncode:
            raise RemoteError(result.stderr.strip() or 'Sudo access check failed')

    def call(self, action, run_id, *, timeout=1800, options=None):
        """Send arguments on stdin rather than interpolating them into a shell command."""
        request = {'action': action, 'run_id': run_id}
        if options is not None:
            request['options'] = options
        try:
            process = self.password_transport.execute(
                'cd /usr/lib/nvyr && exec python3 -m acceptance.agent',
                root=self.root, payload=json.dumps(request), timeout=timeout,
            )
        except Exception as error:
            raise RemoteError(str(error)) from error

        try:
            response = json.loads(process.stdout)
        except ValueError as error:
            raise RemoteError(f'SSH/agent exited {process.returncode}: {process.stderr or process.stdout}') from error
        if process.returncode or not response.get('ok'):
            raise RemoteError(response.get('error', process.stderr))
        return response['result']


def write_artifact(directory, name, value):
    """Save each phase immediately, including failures, outside the rebooting machine."""
    path = directory / name
    with path.open('w', encoding='utf-8') as stream:
        os.chmod(path, 0o600)
        json.dump(value, stream, indent=2)
        stream.write('\n')


def show_checks(result):
    """Stream named results without dumping configuration or credentials to the console."""
    for check in result.get('checks', []):
        print(f" {check['check']:<50} | {check['status']}", flush=True)
        if check.get('reason'):
            print(f"   {check['reason']}", flush=True)


def await_reboot(router, run_id, previous_boot, *, timeout, interval=3):
    """Tolerate SSH downtime, but require a new boot and healthy services by the deadline."""
    deadline = time.monotonic() + timeout
    last_error = 'Router has not rebooted'
    while time.monotonic() < deadline:
        try:
            remaining = max(1, deadline - time.monotonic())
            status = router.call('ready', run_id, timeout=min(30, remaining))
            if status.get('ready') and status.get('boot_id') != previous_boot:
                return status
            last_error = 'Router still has the original boot ID or is not ready'
        except RemoteError as error:
            last_error = str(error)
        time.sleep(min(interval, max(0, deadline - time.monotonic())))
    raise RemoteError(f'Reboot/recovery deadline exceeded: {last_error}')


def collect(router, run_id, directory, name):
    """Keep a failed diagnostics connection visible without masking the original failure."""
    try:
        result = router.call('diagnostics', run_id, timeout=420)
    except RemoteError as error:
        result = {'error': str(error)}
    write_artifact(directory, name, result)
    return result


def run(router, run_id, directory, *, options, timeout=600):
    """A successful test includes restoration; failure leaves the test state for inspection."""
    report = {'run_id': run_id, 'status': 'FAIL', 'phase': 'prepare'}
    try:
        print('Preparing and verifying the combined configuration...', flush=True)
        before = router.call('prepare', run_id, options=options)
        write_artifact(directory, 'before.json', before)
        show_checks(before)

        # Secure the original snapshots externally before taking the host offline.
        snapshots = collect(router, run_id, directory, 'before-diagnostics.json')
        if 'original.json' not in snapshots.get('records', {}):
            raise RemoteError('Could not retrieve the original configuration backup; reboot not requested')

        report['phase'] = 'reboot'
        print('Rebooting; waiting for a new boot and recovered services...', flush=True)
        router.call('reboot', run_id)
        resumed = await_reboot(router, run_id, before['boot_id'], timeout=timeout)
        write_artifact(directory, 'reconnected.json', resumed)

        report['phase'] = 'verify'
        print('Verifying restored configuration and native state...', flush=True)
        after = router.call('verify', run_id)
        write_artifact(directory, 'after.json', after)
        show_checks(after)
        collect(router, run_id, directory, 'after-diagnostics.json')

        report['phase'] = 'restore'
        restored = router.call('restore', run_id)
        write_artifact(directory, 'restored.json', restored)
        report.update(status='PASSED', phase='complete')
        print('Original running and saved configurations restored.', flush=True)
    except (Exception, KeyboardInterrupt) as error:
        report['error'] = str(error) or 'Runner interrupted'
        evidence = collect(router, run_id, directory, 'failure-diagnostics.json')
        print(f"FAIL during {report['phase']}: {report['error']}", flush=True)
        records = evidence.get('records', {})
        if report['phase'] == 'verify' and 'after.json' in records:
            show_checks(records['after.json'])
        elif report['phase'] == 'prepare' and 'before.json' in records:
            show_checks({'checks': records['before.json']})
        print('Configuration and backups retained for inspection; use restore when ready.', flush=True)
    finally:
        write_artifact(directory, 'result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description='External nVyR save/reboot acceptance runner')
    parser.add_argument('action', choices=('run', 'verify', 'restore', 'diagnostics'))
    parser.add_argument('host', help='administrator@hostname or administrator@address (default user: nvyr)')
    parser.add_argument('--run-id', help='Existing run UUID for verify/restore/diagnostics')
    parser.add_argument('--port', type=int, default=22)
    parser.add_argument('--root', action='store_true', help='SSH account is root; do not invoke sudo')
    parser.add_argument('--timeout', type=int, default=600, help='Maximum reboot/recovery wait in seconds')
    parser.add_argument('--ethernet-interface', help='Required spare physical port for a comprehensive run')
    parser.add_argument('--container-image', default='alpine', help='Preloaded Alpine-compatible image (never pulled)')
    parser.add_argument('--artifacts', type=Path, default=Path('acceptance-results'))
    parser.add_argument('--disposable', action='store_true', help='Acknowledge save/reboot or restore on a test router')
    args = parser.parse_args()

    if args.action in ('run', 'restore') and not args.disposable:
        parser.error('run/restore modifies a router; explicitly select a disposable test router with --disposable')
    if args.action == 'run' and args.run_id:
        parser.error('run creates a fresh run ID; use verify or restore to inspect an existing run')
    if args.action == 'run' and not args.ethernet_interface:
        parser.error('--ethernet-interface is required; select a spare physical port')
    if args.action != 'run' and not args.run_id:
        parser.error('--run-id is required for an existing run')
    if args.timeout < 1 or not 1 <= args.port <= 65535:
        parser.error('Use a positive timeout and a port from 1 to 65535')

    os.umask(0o077)
    run_id = args.run_id or str(uuid.uuid4())
    try:
        if str(uuid.UUID(run_id)) != run_id:
            raise ValueError('Run ID must be a canonical UUID')
        router = Router(args.host, port=args.port, root=args.root)
    except ValueError as error:
        parser.error(str(error))

    try:
        router.authenticate()
    except (RemoteError, OSError) as error:
        print(f'Access check failed: {error}\nNo router configuration was changed.', flush=True)
        return 1

    directory = args.artifacts / run_id
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    print(f'Run: {run_id}\nArtifacts: {directory.resolve()}', flush=True)
    if args.action == 'run':
        options = {'ethernet': args.ethernet_interface, 'image': args.container_image}
        result = run(router, run_id, directory, options=options, timeout=args.timeout)
        return 0 if result['status'] == 'PASSED' else 1

    try:
        result = router.call(args.action, run_id)
        write_artifact(directory, f'{args.action}-{time.time_ns()}.json', result)
        show_checks(result)
        print(f'{args.action}: completed', flush=True)
        return 0
    except RemoteError as error:
        collect(router, run_id, directory, 'failure-diagnostics.json')
        print(str(error), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
