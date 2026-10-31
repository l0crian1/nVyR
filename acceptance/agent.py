"""Router-side phases invoked by the external acceptance runner over SSH."""

import base64
from contextlib import redirect_stdout
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import traceback
import uuid

from acceptance import baseline, snapshots
from acceptance.checks import CheckSkipped
from nvyr.config_session import ConfigurationSession
from nvyr.storage import atomic_json, read_saved, sync_directory


ROOT = Path('/config/acceptance')
SAVED = Path('/config/nvyr-saved-config')
SERVICES = ('nvyr-configd', 'nvyr-netlinkd', 'frr', 'nftables')


def command(argv):
    """Bound every diagnostic/system action and retain its actual error output."""
    result = subprocess.run(argv, text=True, capture_output=True, timeout=45)
    if result.returncode:
        raise RuntimeError(f'{argv[0]} exited {result.returncode}: {result.stdout}{result.stderr}')
    return result.stdout.strip()


def identity():
    """A new SSH connection alone does not prove that the machine rebooted."""
    return {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def run_directory(run_id):
    """Accept only canonical UUIDs as persistent directory names."""
    if str(uuid.UUID(run_id)) != run_id:
        raise ValueError('Invalid acceptance run ID')
    return ROOT / run_id


def read_record(directory, name):
    """Read a previously durable phase record."""
    return json.loads((directory / name).read_text())


def check_idle():
    """A pending commit-confirm rollback must not race the acceptance test."""
    if Path('/var/lib/nvyr/confirmed.json').exists():
        raise RuntimeError('Resolve the pending commit-confirm before running acceptance tests')


def observations(options):
    """Run independent named checks so one failure does not hide the rest."""
    results = []
    for check in baseline.CHECKS:
        started = time.monotonic()
        try:
            check(options)
            result = {'check': check.__name__, 'status': 'PASSED'}
        except CheckSkipped as error:
            result = {'check': check.__name__, 'status': 'SKIPPED', 'reason': str(error)}
        except Exception as error:
            result = {'check': check.__name__, 'status': 'FAIL', 'reason': str(error)}
        result['seconds'] = round(time.monotonic() - started, 3)
        results.append(result)
    return results


def require_passed(results):
    """Allow explicit prerequisite skips, but never save/reboot a broken scenario."""
    failed = [result['check'] for result in results if result['status'] not in ('PASSED', 'SKIPPED')]
    if failed:
        raise AssertionError('Failed checks: ' + ', '.join(failed))


def prepare(directory, options):
    """Back up both configurations, apply one baseline, verify it, then save it."""
    check_idle()
    directory.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.mkdir(mode=0o700)
    options = dict(options, assets='boot-' + directory.name)
    baseline.validate_options(options)
    atomic_json(directory / 'options.json', options)

    with ConfigurationSession(timeout=1800) as config:
        config.request_lock()
        original = config.get_config()
        baseline.preflight(original, options)
        saved = base64.b64encode(SAVED.read_bytes()).decode() if SAVED.exists() else None
        backup = {'running': original, 'saved_bytes': saved, **identity()}
        atomic_json(directory / 'original.json', backup)

        baseline.prepare_assets(options)
        baseline.configure(config, options)
        config.commit(comment='Boot acceptance baseline')
        expected = config.get_config()
        atomic_json(directory / 'expected.json', expected)

        results = observations(options)
        atomic_json(directory / 'before.json', results)
        require_passed(results)
        atomic_json(directory / 'before-native.json', snapshots.capture())
        config.save()
        if read_saved(SAVED)[0] != expected:
            raise AssertionError('Saved configuration differs from the committed baseline')

    result = {'checks': results, **identity()}
    atomic_json(directory / 'prepared.json', result)
    return result


def reboot(directory):
    """Queue one reboot only after the baseline and its persisted copy passed."""
    check_idle()
    prepared = read_record(directory, 'prepared.json')
    if identity()['boot_id'] != prepared['boot_id']:
        raise RuntimeError('This run has already crossed a reboot; verify it instead')
    if (directory / 'reboot.json').exists():
        raise RuntimeError('Reboot was already requested for this run')

    with ConfigurationSession() as config:
        config.request_lock()
        expected = read_record(directory, 'expected.json')
        if config.get_config() != expected or read_saved(SAVED)[0] != expected:
            raise RuntimeError('Configuration changed after preparation; refusing to reboot')

        # The transient timer survives the SSH connection and gives the reply time to drain.
        command(['systemd-run', '--quiet', f'--unit=nvyr-acceptance-{directory.name}',
                 '--on-active=5s', '/usr/bin/systemctl', 'reboot'])
        result = {'scheduled': True, **identity()}
        atomic_json(directory / 'reboot.json', result)
        return result


def ready(directory):
    """Report readiness only after a new kernel boot and successful daemon recovery."""
    previous = read_record(directory, 'original.json')['boot_id']
    current = identity()
    if current['boot_id'] == previous:
        return {'ready': False, **current}

    # systemctl succeeds if ANY requested unit is active, so inspect every result.
    states = command(['systemctl', 'is-active', *SERVICES]).splitlines()
    if states != ['active'] * len(SERVICES):
        raise RuntimeError(f'Services have not all recovered: {dict(zip(SERVICES, states))}')
    with ConfigurationSession() as config:
        config.get_config()
    return {'ready': True, **current}


def verify(directory):
    """Compare persisted/loaded configuration and all native baseline observations."""
    # Verification after a new boot is distinct from checking the original commit.
    if not ready(directory)['ready']:
        raise RuntimeError('Router has not rebooted for this run')

    expected = read_record(directory, 'expected.json')
    with ConfigurationSession(timeout=1800) as config:
        config.request_lock()
        results = []
        for name, actual in (('running_configuration', config.get_config()),
                             ('saved_configuration', read_saved(SAVED)[0])):
            result = {'check': name, 'status': 'PASSED'}
            # Both copies must match; a working dataplane cannot hide persistence drift.
            if actual != expected:
                result.update(status='FAIL', reason='Configuration differs from the pre-reboot baseline')
            results.append(result)

        results.extend(observations(read_record(directory, 'options.json')))
        try:
            native = snapshots.capture()
            atomic_json(directory / 'after-native.json', native)
            results.extend(snapshots.compare(read_record(directory, 'before-native.json'), native))
        except Exception as error:
            results.append({'check': 'native_snapshot', 'status': 'FAIL', 'reason': str(error)})

    result = {'checks': results, **identity()}
    atomic_json(directory / 'after.json', result)
    require_passed(results)
    return result


def restore_saved(encoded):
    """Restore exact original bytes, including metadata, without applying saved-only changes."""
    if encoded is None:
        SAVED.unlink(missing_ok=True)
        sync_directory(SAVED.parent)
        return

    descriptor, temporary = tempfile.mkstemp(prefix='.acceptance-', dir=SAVED.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.chmod(temporary, 0o600)
            stream.write(base64.b64decode(encoded, validate=True))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, SAVED)
        sync_directory(SAVED.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def restore(directory):
    """Restore running and saved separately so pre-existing unsaved changes stay unsaved."""
    check_idle()
    original = read_record(directory, 'original.json')
    with ConfigurationSession(timeout=1800) as config:
        config.request_lock()
        config.load(original['running'], replace=True)
        config.commit(comment='Restore before boot acceptance')
        if config.get_config() != original['running']:
            raise AssertionError('Original running configuration was not restored')
        restore_saved(original['saved_bytes'])
        actual = base64.b64encode(SAVED.read_bytes()).decode() if SAVED.exists() else None
        if actual != original['saved_bytes']:
            raise AssertionError('Original saved configuration was not restored')

    result = {'restored': True, **identity()}
    atomic_json(directory / 'restored.json', result)
    return result


def diagnostics(directory):
    """Collect startup evidence even when the configuration API is unavailable."""
    result = {'records': {}, 'commands': {}}
    for path in directory.glob('*.json'):
        result['records'][path.name] = json.loads(path.read_text())

    commands = {
        'services': ['systemctl', 'status', '--no-pager', '--full', *SERVICES],
        'journal': ['journalctl', '-b', '--no-pager', '-n', '1000',
                    '-u', 'nvyr-configd', '-u', 'nvyr-netlinkd', '-u', 'frr'],
        'kernel': ['uname', '-a'],
        'logging_services': ['systemctl', 'status', '--no-pager', '--full', 'rsyslog', 'nvyr-nflog@*'],
        'configd_file_log': ['tail', '-n', '200', '/var/log/nvyr/configd.log'],
        'netlink_file_log': ['tail', '-n', '200', '/var/log/nvyr/netlinkd.log'],
        'links': ['ip', '-j', '-d', 'address', 'show'],
        'routes4': ['ip', '-4', '-j', 'route', 'show', 'table', 'all'],
        'routes6': ['ip', '-6', '-j', 'route', 'show', 'table', 'all'],
        'firewall': ['nft', '-j', 'list', 'ruleset'],
        'frr': ['vtysh', '-c', 'show running-config'],
        'containers': ['podman', 'ps', '-a', '--format', 'json'],
        'container_journal': ['journalctl', '-b', '--no-pager', '-n', '200',
                              '-u', 'nvyr-container-*'],
        'container_networks': ['podman', 'network', 'inspect', 'BOOTNET', 'BOOTVRF'],
    }
    for name, argv in commands.items():
        try:
            result['commands'][name] = command(argv)
        except Exception as error:
            result['commands'][name] = str(error)
    return result


def main():
    """Keep stdout a single JSON document; lifecycle output belongs on stderr."""
    os.umask(0o077)
    directory = None
    try:
        if os.geteuid() != 0:
            raise PermissionError('The acceptance agent requires root')
        request = json.load(sys.stdin)
        directory = run_directory(request['run_id'])
        actions = {'prepare': prepare, 'reboot': reboot, 'ready': ready,
                   'verify': verify, 'restore': restore, 'diagnostics': diagnostics}
        with redirect_stdout(sys.stderr):
            if request['action'] == 'prepare':
                result = prepare(directory, request.get('options', {}))
            else:
                result = actions[request['action']](directory)
        response = {'ok': True, 'result': result}
    except Exception as error:
        response = {'ok': False, 'error': str(error), 'traceback': traceback.format_exc()}
        if directory is not None and directory.is_dir():
            atomic_json(directory / 'error.json', response)

    print(json.dumps(response))
    return 0 if response['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
