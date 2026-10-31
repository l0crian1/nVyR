"""Install log collectors, retain NFLOG identities, and reopen rotated writers."""

import argparse
import errno
import json
import logging
from logging.handlers import SysLogHandler
import os
from pathlib import Path
import stat
import time

from nvyr.errors import RouterError
from nvyr.helpers import logging_formatters as formats
from nvyr.helpers.process import cmd
from nvyr.storage import atomic_json
from nvyr.tree import lookup


RUNTIME = Path('/run/nvyr-logging')
STATE = Path('/var/lib/nvyr/logging')
LOGS = Path(formats.ROOT)
NFLOG_STATUS = Path('/proc/net/netfilter/nfnetlink_log')


def configure_python(identifier):
    """Preserve real Python severities when forwarding messages to the collector."""
    handler = SysLogHandler(address='/dev/log')
    handler.setFormatter(logging.Formatter(identifier + ': %(name)s: %(message)s'))
    logging.basicConfig(level=logging.DEBUG, handlers=[handler], force=True)


def groups(configuration):
    result = {}
    for scope, section in (('normal', configuration.get('firewall', {})),
                           ('failsafe', lookup(configuration, ('firewall', 'fail-safe'), {}))):
        for name, options in section.get('group', {}).get('log-group', {}).items():
            result[f'{scope}:{name}'] = options
    return result


def identities(configuration, previous):
    """Never recycle IDs: old rules and archived records retain their identity."""
    result = dict(previous)
    used = set(result.values())
    available = iter(number for number in range(1, 65536) if number not in used)
    for name in sorted(groups(configuration)):
        if name not in result:
            try:
                result[name] = next(available)
            except StopIteration as error:
                raise RouterError('NFLOG group identifiers are exhausted.') from error
    return result


def registry(state=STATE):
    path = Path(state) / 'groups.json'
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise RouterError(f'Cannot read persistent NFLOG identifier registry: {error}') from error
    if (not isinstance(value, dict) or any(not isinstance(key, str) or type(number) is not int
                                         or not 1 <= number <= 65535 for key, number in value.items())
            or len(set(value.values())) != len(value)):
        raise RouterError('Invalid persistent NFLOG identifier registry.')
    return value


def group_path(key):
    scope, name = key.split(':', 1)
    prefix = 'group-' if scope == 'normal' else 'failsafe-group-'
    return LOGS / 'firewall' / (prefix + name + '.log')


def nft_groups(configuration, state=STATE, scope='normal'):
    """Resolve stable NFLOG numbers for the renderer without changing the registry."""
    names = identities(configuration, registry(state))
    result = {}
    for key, options in groups(configuration).items():
        area, name = key.split(':', 1)
        if area != scope:
            continue
        result[name] = {
            'id': names[key],
            'snaplen': options.get('snaplen', '65535'),
            'queue-threshold': options.get('queue-threshold', '1'),
        }
    return result


def _directories():
    RUNTIME.mkdir(mode=0o755, parents=True, exist_ok=True)
    for relative in ('', 'firewall', 'containers', 'dhcp-server', 'dhcpv6-server'):
        path = LOGS / relative
        path.mkdir(mode=0o750, parents=True, exist_ok=True)
        # All operational users may read logs; only root-owned writers may change them.
        import grp
        os.chown(path, 0, grp.getgrnam('nvyr-access').gr_gid)


def _write(path, contents):
    from nvyr.helpers.template import write
    write(path, contents, mode=0o640)


def install(files, *, activate=True):
    """Validate collector configuration before replacing active routing files."""
    _directories()
    candidate = RUNTIME / 'rsyslog.check.conf'
    _write(candidate, files['rsyslog'])
    cmd(['rsyslogd', '-N1', '-f', str(candidate)])

    target = RUNTIME / 'rsyslog.conf'
    collector_changed = not target.exists() or target.read_text() != candidate.read_text()
    _write(RUNTIME / 'rsyslog.conf', candidate.read_text())
    _write(RUNTIME / 'logrotate.conf', files['logrotate'])

    if activate:
        cmd(['systemctl', 'restart' if collector_changed else 'start', 'rsyslog.service'])


def prepare_groups(configuration, state=STATE):
    """Prepare packet consumers before committing the native firewall rules."""
    if not groups(configuration):
        return
    _directories()
    names = identities(configuration, registry(state))
    atomic_json(Path(state) / 'groups.json', names)
    for key in groups(configuration):
        number = names[key]
        path = RUNTIME / f'nflog-{number}.conf'
        contents = formats.ulogd(number, group_path(key))
        changed = not path.exists() or path.read_text() != contents
        _write(path, contents)
        command = 'restart' if changed else 'start'
        cmd(['systemctl', command, f'nvyr-nflog@{number}.service'])
        wait_for_group(number)

    # Old subscriptions remain until the consuming firewall transaction succeeds.


def wait_for_group(number):
    """A started process is not ready until the kernel reports its subscription."""
    unit = f'nvyr-nflog@{number}.service'
    pid = cmd(['systemctl', 'show', '--property=MainPID', '--value', unit]).strip()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if NFLOG_STATUS.exists():
            for line in NFLOG_STATUS.read_text().splitlines():
                fields = line.split()
                if len(fields) >= 2 and fields[:2] == [str(number), pid]:
                    return
        time.sleep(0.05)
    raise RouterError(f'{unit}: collector did not bind its NFLOG group')


class FrrLogging:
    """Own only FRR's syslog target inside the shared integrated configuration."""

    def select(self, text, scopes):
        return {'global': sorted(line for line in text.splitlines()
                                 if line == 'log syslog' or line.startswith('log syslog '))}

    def replace(self, text, desired):
        lines = [line for line in text.splitlines()
                 if line != 'log syslog' and not line.startswith('log syslog ') and line.strip() != 'end']
        return '\n'.join([*lines, *desired.get('global', []), 'end', ''])


def cleanup(configuration, state=STATE, *, scope=None):
    """Release removed subscriptions only after nftables has dropped references."""
    names = registry(state)
    keep = {names[key] for key in groups(configuration) if key in names}
    selected = {number for key, number in names.items() if scope is None or key.startswith(scope + ':')}
    for path in RUNTIME.glob('nflog-*.conf'):
        number = int(path.stem.split('-')[1])
        if number in selected and number not in keep:
            cmd(['systemctl', 'stop', f'nvyr-nflog@{number}.service'])
            path.unlink()


def reopen_containers(run=cmd):
    """Ask Conmon to reopen k8s-file logs without truncation or workload restart.

    Conmon's documented terminal control FIFO uses event 2 for log reopening.
    Podman reports each live OCI bundle as StaticDir; only managed containers
    with our exact log path participate in rotation.
    """
    records = json.loads(run(['podman', 'ps', '--filter', 'label=nvyr.managed=true', '--format=json']))
    if not records:
        return
    names = [record['Id'] for record in records]
    for container in json.loads(run(['podman', 'inspect', *names])):
        name = container['Name']
        expected = str(LOGS / 'containers' / (name + '.log'))
        log_config = container.get('HostConfig', {}).get('LogConfig', {})
        if log_config.get('Path') != expected or not container.get('State', {}).get('Running'):
            continue
        fifo = Path(container['StaticDir']) / 'ctl'
        try:
            descriptor = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        except OSError as error:
            # The container may have exited since inspection; its next start
            # opens the new path. Other errors indicate rotation really failed.
            if error.errno in (errno.ENOENT, errno.ENXIO):
                continue
            raise
        try:
            if not stat.S_ISFIFO(os.fstat(descriptor).st_mode):
                raise RouterError(f'Container log control path is not a FIFO: {fifo}')
            os.write(descriptor, b'2 0 0\n')
        finally:
            os.close(descriptor)


def reopen():
    """Rotation never restarts routing daemons, packet collectors or workloads."""
    failures = []

    def attempt(operation):
        try:
            operation()
        except Exception as error:
            failures.append(str(error))

    # A failed writer must not prevent unrelated writers from reopening files.
    attempt(lambda: cmd(['systemctl', 'kill', '--kill-whom=main', '--signal=HUP', 'rsyslog.service']))

    def reopen_packet_logs():
        units = cmd(['systemctl', 'list-units', '--state=running', '--no-legend', '--plain',
                     'nvyr-nflog@*.service'])
        for line in units.splitlines():
            unit = line.split()[0]
            attempt(lambda: cmd(['systemctl', 'kill', '--kill-whom=main', '--signal=HUP', unit]))

    attempt(reopen_packet_logs)
    attempt(reopen_containers)
    if failures:
        raise RouterError('Log reopening failed: ' + '; '.join(failures))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('operation', choices=['prepare', 'reopen'])
    operation = parser.parse_args().operation
    if operation == 'prepare':
        install(formats.render({}), activate=False)
    else:
        reopen()
