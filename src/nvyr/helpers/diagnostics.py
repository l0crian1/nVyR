"""Fixed diagnostic inventory with bounded subprocesses and private archives."""

from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import tarfile
import time
import uuid

from nvyr.errors import OperationalError


DIRECTORY = Path('/config/diagnostics')
REPORT_TIMEOUT = 10
TOTAL_TIMEOUT = 60
REPORT_BYTES = 1024 * 1024
TOTAL_BYTES = 8 * 1024 * 1024


def reports():
    """Only approved observations: no logs, configuration, environments or argv dumps."""
    return [
        ('version', ['/usr/bin/python3', '-c',
                     'from nvyr.helpers import build_metadata; '
                     'print(build_metadata.format_version(build_metadata.read()))']),
        ('kernel', ['uname', '-a']),
        ('uptime', ['uptime']),
        ('cpu', ['system.nvyr.op', 'cpu']),
        ('memory', ['free', '-h']),
        ('storage', ['system.nvyr.op', 'storage']),
        ('processes', ['system.nvyr.op', 'processes', '--sort', 'cpu']),
        ('services', ['services.nvyr.op', 'show']),
        ('failed-units', ['systemctl', '--failed', '--all', '--no-pager', '--plain']),
        ('images', ['images.nvyr.op', 'show']),
        ('links', ['ip', '-j', '-s', '-d', 'link', 'show']),
        ('addresses', ['ip', '-j', 'address', 'show']),
        ('ipv4-routes', ['ip', '-j', '-4', 'route', 'show', 'table', 'all']),
        ('ipv6-routes', ['ip', '-j', '-6', 'route', 'show', 'table', 'all']),
        ('ipv4-policy-routing', ['ip', '-j', '-4', 'rule', 'show']),
        ('ipv6-policy-routing', ['ip', '-j', '-6', 'rule', 'show']),
        ('vrfs', ['vrf.nvyr.op', 'show']),
        ('containers', ['podman', 'ps', '--all', '--format',
                        'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Networks}}']),
        ('container-networks', ['podman', 'network', 'ls']),
    ]


def capture(arguments, *, timeout, maximum):
    """Drain one pipe incrementally; never let communicate() buffer unbounded output."""
    started = time.monotonic()
    deadline = started + timeout
    output = bytearray()
    status = 'ok'
    environment = dict(os.environ, LC_ALL='C', SYSTEMD_COLORS='0', TERM='dumb', HOME='/root')
    try:
        process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, start_new_session=True, env=environment)
    except OSError as error:
        return b'', {'status': 'error', 'error': str(error), 'returncode': None,
                     'seconds': round(time.monotonic() - started, 3), 'bytes': 0}

    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map() or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = 'timed-out'
                    break
                for key, events in selector.select(min(remaining, 0.1)):
                    data = os.read(key.fileobj.fileno(), min(65536, maximum - len(output) + 1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    space = maximum - len(output)
                    output.extend(data[:space])
                    if len(data) > space:
                        status = 'truncated'
                        break
                if status == 'truncated':
                    break
    finally:
        # Kill the entire command group, including children left behind by an exited parent.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.stdout.close()
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            status = 'timed-out'

    if status == 'ok' and process.returncode:
        status = 'error'
    return bytes(output), {'status': status, 'returncode': process.returncode,
                           'seconds': round(time.monotonic() - started, 3), 'bytes': len(output)}


def _directory(path):
    """Hold a checked directory descriptor; /config children may be user-created links."""
    path.mkdir(mode=0o700, exist_ok=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        os.close(descriptor)
        raise OperationalError(f'Diagnostic directory must be root-owned and not writable by others: {path}')
    return descriptor


def _add_file(archive, name, content):
    entry = tarfile.TarInfo(name)
    entry.size = len(content)
    entry.mode = 0o600
    archive.addfile(entry, io.BytesIO(content))


def collect(*, directory=DIRECTORY, inventory=None, report_timeout=REPORT_TIMEOUT,
            total_timeout=TOTAL_TIMEOUT, report_bytes=REPORT_BYTES, total_bytes=TOTAL_BYTES,
            progress=print):
    """Publish a complete archive even when individual reports fail or exhaust budgets."""
    if inventory is None:
        inventory = reports()

    directory = Path(directory)
    descriptor = _directory(directory)
    created = datetime.now(timezone.utc)
    name = 'nvyr-diagnostics-' + created.strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:12] + '.tar.gz'
    temporary = '.' + name + '.partial'
    manifest = {'created': created.isoformat(), 'limits': {
        'report_seconds': report_timeout, 'total_seconds': total_timeout,
        'report_bytes': report_bytes, 'total_bytes': total_bytes}, 'reports': []}
    started = time.monotonic()
    remaining_bytes = total_bytes
    try:
        file_descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                  0o600, dir_fd=descriptor)
        with os.fdopen(file_descriptor, 'wb') as destination:
            with tarfile.open(fileobj=destination, mode='w:gz') as archive:
                for title, arguments in inventory:
                    remaining_time = total_timeout - (time.monotonic() - started)
                    record = {'name': title, 'command': arguments}
                    if remaining_time <= 0 or remaining_bytes <= 0:
                        reason = 'Collection time limit' if remaining_time <= 0 else 'Collection output limit'
                        record.update(status='skipped', reason=reason, bytes=0)
                    else:
                        progress(f'Collecting {title}...', flush=True)
                        content, result = capture(arguments, timeout=min(report_timeout, remaining_time),
                                                  maximum=min(report_bytes, remaining_bytes))
                        record.update(result, file=title + '.txt')
                        remaining_bytes -= len(content)
                        _add_file(archive, record['file'], content)
                    manifest['reports'].append(record)

                manifest['seconds'] = round(time.monotonic() - started, 3)
                _add_file(archive, 'manifest.json', json.dumps(manifest, indent=2).encode())
            destination.flush()
            os.fsync(destination.fileno())
        os.rename(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
    finally:
        try:
            os.unlink(temporary, dir_fd=descriptor)
        except FileNotFoundError:
            pass
        os.close(descriptor)
    return directory / name, manifest


def main():
    try:
        path, manifest = collect()
    except (OSError, OperationalError) as error:
        raise SystemExit(f'Diagnostic collection failed: {error}') from error

    incomplete = sum(item['status'] != 'ok' for item in manifest['reports'])
    print(f'\nDiagnostic archive: {path}')
    print(f'{len(manifest["reports"])} reports; {incomplete} incomplete. See manifest.json for collection results.')
    print('The archive is readable by root only.')


if __name__ == '__main__':
    main()
