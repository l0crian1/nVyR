"""Stream native trace events without changing the installed firewall ruleset."""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import selectors
import stat
import subprocess
import time

from nvyr.errors import OperationalError
from nvyr.helpers import firewall_scope
from nvyr.helpers.firewall_trace_parser import event_fields


DIRECTORY = Path('/config/traces')
EVENT = re.compile(r'^trace id (\S+) (\S+) (\S+) (\S+) (packet|conntrack|rule|verdict|policy)(?::)?(?: (.*))?$')
COMMENT = re.compile(r'\bcomment ("(?:[^"\\]|\\.)*")')


def event_record(line):
    """Keep native evidence intact while exposing stable fields to API consumers."""
    record = {'timestamp': datetime.now(timezone.utc).isoformat(), 'raw': line}
    match = EVENT.fullmatch(line)
    if match is None:
        record['event'] = 'native'
        return record

    identifier, family, table, chain, kind, detail = match.groups()
    record.update(id=identifier, family=family, table=table, chain=chain,
                  event=kind, detail=detail or '')
    record.update(event_fields(kind, detail or ''))
    comment = COMMENT.search(detail or '') if kind == 'rule' else None
    if comment:
        try:
            record['comment'] = json.loads(comment[1])
        except ValueError:
            pass  # Non-JSON native escapes remain available in the original event.

    path = rule_path(table, chain, record.get('comment', ''))
    if path:
        record['path'] = path
    if kind == 'rule' and table in firewall_scope.TABLES:
        expression = record.get('expression', '')
        prefix = 'firewall fail-safe' if table == firewall_scope.FAILSAFE_TABLE else 'firewall'
        if expression.startswith('ct state vmap '):
            record['path'] = prefix + ' global-options state-policy'
        if record.get('comment', '').startswith('global-offload|'):
            record['path'] = prefix + ' global-options flowtable'
        record['references'] = object_paths(expression, prefix)
        verdict = record.get('verdict', '')
        if verdict.startswith(('jump ', 'goto ')):
            target = rule_path(table, verdict.split(' ', 1)[1], '')
            if target:
                record['target-path'] = target
    return record


def rule_path(table, chain, comment):
    """Identify configured rules from native chain names and installed comments."""
    if table not in firewall_scope.TABLES:
        return None

    prefix = 'firewall fail-safe' if table == firewall_scope.FAILSAFE_TABLE else 'firewall'
    hooks = ('input', 'forward', 'output', 'ingress', 'prerouting', 'output_raw')
    if chain in hooks:
        family, suffix = 'inet', chain
    else:
        family, separator, suffix = chain.partition('_')
        if not separator or family not in ('ipv4', 'ipv6', 'inet'):
            return None

    if suffix.startswith('name_'):
        path = f'{prefix} {family} name {suffix[5:]}'
    elif suffix in hooks:
        hook = 'output' if suffix == 'output_raw' else suffix
        priority = 'raw' if suffix in ('prerouting', 'output_raw') else 'filter'
        path = f'{prefix} {family} {hook} {priority}'
    elif table == firewall_scope.MAIN_TABLE and chain in ('ipv4_nat_prerouting', 'ipv4_nat_postrouting'):
        direction = 'source' if chain.endswith('postrouting') else 'destination'
        path = 'nat ' + direction
    else:
        return None

    number = comment.partition('|')[0]
    if number.isdecimal():
        return path + ' rule ' + number
    if number == 'default':
        return path + ' default-action'
    return path


def object_paths(expression, prefix='firewall'):
    """Expose referenced nVyR objects without guessing which map/set element matched."""
    result = []
    names = re.findall(r'@([A-Za-z_][A-Za-z0-9_-]*)', expression)
    names.extend(re.findall(r'\b(?:counter|quota|limit) name "?([A-Za-z_][A-Za-z0-9_-]*)', expression))
    for name in names:
        family = re.fullmatch(r'(ipv4|ipv6|inet)_(map|match_group|icmp_group|address_group|domain_group|limit_group)_(.+)', name)
        singleton = re.fullmatch(r'(interface_group|port_group|mac_group|counter_group|quota_group)_(.+)', name)
        if family:
            nfproto, kind, identifier = family.groups()
            path = f'{prefix} group {kind.replace("_", "-")} {nfproto} {identifier}'
        elif singleton:
            kind, identifier = singleton.groups()
            path = f'{prefix} group {kind.replace("_", "-")} {identifier}'
        elif name.startswith('flowtable_'):
            path = prefix + ' flowtable ' + name[len('flowtable_'):]
        elif re.fullmatch(r'ipv[46]_zone_(input|output|forward)', name):
            path = prefix + ' zone-policy'
        else:
            continue
        if path not in result:
            result.append(path)
    return result


def chain_snapshot():
    """Record native hook identity without copying rules, counters or group members."""
    try:
        result = subprocess.run(['nft', '-j', 'list', 'chains'], text=True, capture_output=True, timeout=15)
    except subprocess.TimeoutExpired:
        raise OperationalError('Timed out reading trace chain metadata.') from None
    if result.returncode:
        raise OperationalError(result.stderr.strip() or 'Cannot read trace chain metadata.')
    chains = []
    try:
        document = json.loads(result.stdout)
    except ValueError:
        raise OperationalError('Invalid native JSON while reading trace chain metadata.') from None
    for item in document.get('nftables', []):
        chain = item.get('chain')
        if chain:
            chains.append({key: chain[key] for key in
                           ('family', 'table', 'name', 'hook', 'prio', 'type', 'policy', 'handle')
                           if key in chain})
    return chains


def trace_target(path):
    """Require a simple capture filename in the persistent trace directory."""
    target = Path(path)
    if target.parent != DIRECTORY or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', target.name):
        raise OperationalError('Trace files must be directly under /config/traces/.')
    return target


@contextmanager
def read_capture(path):
    """Open only regular capture files, without following filesystem redirects."""
    target = trace_target(path)
    try:
        directory = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            descriptor = os.open(target.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        finally:
            os.close(directory)
        with os.fdopen(descriptor, 'r', encoding='utf-8') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise OperationalError('Trace capture must be a regular file.')
            yield stream
    except OSError as error:
        raise OperationalError(f'Cannot read trace capture: {error}') from None


@contextmanager
def capture_file(path):
    """Create an exclusive private file through a checked directory descriptor."""
    if path is None:
        yield None
        return

    target = trace_target(path)

    DIRECTORY.mkdir(mode=0o700, exist_ok=True)
    directory = os.open(DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(directory)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
            raise OperationalError('Trace directory must be owned by the service user and not writable by others.')

        descriptor = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            yield stream
    finally:
        os.close(directory)


def display_event(record):
    """Show the native event and its configuration location without hiding details."""
    if 'path' not in record:
        return record['raw']
    return f"{record['id']} | {record['path']} | {record['event']} {record['detail']}"


def monitor(*, duration=None, save=None, arguments=None, output=print):
    """Drain both pipes until the deadline or cancellation, then reap the monitor."""
    count = 0
    interrupted = False
    native = arguments is None
    arguments = arguments or ['nft', '-a', '-n', 'monitor', 'trace']

    def emit(line, destination):
        nonlocal count
        if not line.strip():
            return
        record = event_record(line)
        if destination is not None:
            destination.write(json.dumps(record, ensure_ascii=False) + '\n')
            destination.flush()
        output(display_event(record), flush=True)
        count += 1

    try:
        with capture_file(save) as destination:
            if destination is not None:
                metadata = {'event': 'capture', 'format': 1,
                            'timestamp': datetime.now(timezone.utc).isoformat(),
                            'kernel': platform.release(),
                            'chains': chain_snapshot() if native else []}
                destination.write(json.dumps(metadata) + '\n')
                destination.flush()
            process = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL='C'))
            deadline = None if duration is None else time.monotonic() + duration
            pending = b''
            errors = bytearray()
            timed_out = False
            try:
                output('Monitoring firewall traces. Press Ctrl+C to stop. Configured nftrace rules remain enabled.', flush=True)
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
                    selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
                    while selector.get_map():
                        remaining = None if deadline is None else deadline - time.monotonic()
                        if remaining is not None and remaining <= 0:
                            timed_out = True
                            break

                        for key, _ in selector.select(remaining):
                            data = os.read(key.fileobj.fileno(), 65536)
                            if not data:
                                selector.unregister(key.fileobj)
                                continue
                            if key.data == 'stderr':
                                errors.extend(data[:max(0, 8192 - len(errors))])
                                continue

                            pending += data
                            lines = pending.split(b'\n')
                            pending = lines.pop()
                            for line in lines:
                                emit(line.decode('utf-8', errors='replace'), destination)
                            if len(pending) > 1024 * 1024:
                                raise OperationalError('Native trace event exceeds 1 MiB.')
            except KeyboardInterrupt:
                interrupted = True
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                process.stdout.close()
                process.stderr.close()

            # Preserve a final unterminated event only after normal native EOF.
            if pending and not timed_out and not interrupted:
                emit(pending.decode('utf-8', errors='replace'), destination)
            if errors or (process.returncode and not timed_out and not interrupted):
                message = errors.decode('utf-8', errors='replace').strip()
                raise OperationalError(message or f'nft monitor exited with status {process.returncode}.')
            if destination is not None:
                reason = 'interrupted' if interrupted else 'duration' if timed_out else 'eof'
                destination.write(json.dumps({'event': 'capture-end', 'reason': reason, 'events': count,
                                              'timestamp': datetime.now(timezone.utc).isoformat()}) + '\n')
    except OSError as error:
        raise OperationalError(f'Cannot capture firewall trace: {error}') from None
    finally:
        output(f'Captured {count} trace events.', flush=True)

    if save:
        output(f'Saved trace: {save}', flush=True)
    return 130 if interrupted else 0
