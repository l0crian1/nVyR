"""Root-only interface control socket and rtnetlink notification event loop."""

import argparse
import errno
import fcntl
import logging
import os
from pathlib import Path
import selectors
import signal
import socket
import struct
import time

from nvyr.errors import RecoveryError, RouterError, ValidationError
from nvyr.helpers.dhcp import DHCP
from nvyr.helpers.dns import Resolver
from nvyr.helpers.interfaces import require_named
from nvyr.helpers.link_manager import Manager
from nvyr.helpers.netlink import Kernel
from nvyr.protocol import encode, receive

log = logging.getLogger(__name__)
SOCKET = '/run/nvyr-netlink/control.sock'


class Schedule:
    """Bounded burst coalescing, targeted lease/retry work and a loss safety audit."""

    def __init__(self, now):
        self.audit = now
        self.maintenance = now + 2
        self.retry = now + 5
        self.dirty = set()
        self.due = float('inf')

    def notify(self, names, now):
        if names:
            self.dirty.update(names)
            self.due = min(self.due, now + .2)  # Never postpone under a steady burst.

    def lost(self, now):
        log.debug('Kernel notifications lost; scheduling inventory audit')
        self.audit = min(self.audit, now + .2)

    def run(self, manager, now):
        full = now >= self.audit
        retry = now >= self.retry
        names = set()

        if now >= self.due or full:
            names.update(self.dirty)
            self.dirty.clear()
            self.due = float('inf')

        if now >= self.maintenance:
            names.update(manager.dhcp_names)
            self.maintenance = now + 2

        if retry:
            names.update(manager.failures.keys() & manager.claims.keys())
            self.retry = now + 5

        if full or names or ('DNS' in manager.failures and retry):
            log.debug('Scheduled reconciliation: audit=%s, interfaces=%d', full, len(names))

            try:
                manager.reconcile(None if full else names)
            except Exception as error:
                # A failed dump must not kill the event loop or busy-loop.
                log.exception('Kernel inventory failed; retrying in five seconds')
                manager.error = f'Kernel inventory: {error}'
                self.audit = time.monotonic() + 5

                return

        if full:
            self.audit = time.monotonic() + 60

    def timeout(self, manager, now):
        return max(0, min(.5, self.audit - now, self.due - now,
                          self.maintenance - now if manager.dhcp_names else .5,
                          self.retry - now if manager.failures else .5))


def receive_events(events, marshal, manager, schedule):
    """Drain a bounded batch; overflow/truncation requires an inventory resync."""
    for _ in range(256):
        try:
            data, _, flags, sender = events.recvmsg(1024 * 1024)
        except BlockingIOError:
            break
        except OSError as error:
            if error.errno != errno.ENOBUFS:
                raise

            schedule.lost(time.monotonic())
            break

        if sender[0] != 0:
            continue

        if flags & socket.MSG_TRUNC:
            schedule.lost(time.monotonic())
            continue

        try:
            messages = list(marshal.parse(data))
            if any(m.get('header', {}).get('type') == 4 or m.get('header', {}).get('error') for m in messages):
                schedule.lost(time.monotonic())

            schedule.notify(manager.affected(messages), time.monotonic())
        except Exception:
            log.exception('Could not decode kernel notification; scheduling inventory audit')
            schedule.lost(time.monotonic())


def dispatch(manager, request):
    if request.get('version') != 1:
        raise ValidationError('Unsupported netlinkd protocol version')

    operation = request.get('operation')
    if operation == 'status':
        return manager.status()

    if operation == 'replace-kernel-settings':
        return manager.replace_kernel_settings(request.get('values'))

    if operation == 'dns-status':
        if manager.resolver is None:
            raise RouterError('System resolver management is unavailable')
        result = manager.resolver.observation()
        result['error'] = manager.failures.get('DNS')
        return result

    if operation in ('dhcp-release', 'dhcp-renew'):
        manager.dhcp_control(request.get('interface'), operation.removeprefix('dhcp-'))
        return {}

    if operation not in ('replace', 'validate', 'replace-dns'):
        raise ValidationError(f'Unknown netlinkd operation {operation!r}')

    recovery = request.get('recovery', False)
    if type(recovery) is not bool:
        raise ValidationError('recovery must be a boolean')

    if operation == 'replace-dns':
        if manager.resolver is None:
            raise RouterError('System resolver management is unavailable')

        manager.resolver.replace(request.get('sources'), recovery=recovery)

        return {}

    with manager.kernel.snapshot():
        if operation == 'replace':
            manager.replace(request.get('owner'), request.get('links'), recovery=recovery)
        else:
            # Configd checks references against its proposed configuration. A new
            # VRF need not exist yet during commit check; apply requires it.
            manager.validate(request.get('owner'), request.get('links'), recovery=recovery,
                             require_external=False)

    return {}


class Server:
    def __init__(self, manager, path=SOCKET):
        self.manager, self.path = manager, Path(path)
        self.running = True

    @staticmethod
    def authorized(connection):
        pid, uid, gid = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        return uid == 0

    def handle(self, connection):
        with connection:
            connection.settimeout(5)

            if not self.authorized(connection):
                return

            try:
                result = dispatch(self.manager, receive(connection))
                response = {'version': 1, 'result': result}
            except Exception as error:
                log.exception('Interface request failed')
                response = {'version': 1, 'error': str(error), 'recovery': isinstance(error, RecoveryError)}

            try:
                connection.sendall(encode(response))
            except OSError:
                # A lost reply is ambiguous to the caller; its configd journal
                # will resend the authoritative recovery target.
                log.warning('Interface request reply could not be delivered')

    def run(self, *, ready=None):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Hold a separate inode lock: never unlink a live daemon's socket.
        with (self.path.parent / 'daemon.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener, \
                    socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as events, \
                    selectors.DefaultSelector() as selector:
                self.path.unlink(missing_ok=True)
                listener.bind(str(self.path))
                os.chmod(self.path, 0o600)
                listener.listen(16)
                listener.setblocking(False)

                # Subscribe before the initial audit so changes during a dump
                # remain queued. Do not suppress ENOBUFS notification loss.
                events.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                events.bind((0, 1 | 0x10 | 0x40 | 0x100 | 0x400))
                events.setblocking(False)
                selector.register(listener, selectors.EVENT_READ, 'client')
                selector.register(events, selectors.EVENT_READ, 'kernel')

                if self.manager.resolver is not None:
                    self.manager.resolver.reconcile()

                if ready:
                    ready()

                from pyroute2.netlink.rtnl.marshal import MarshalRtnl

                marshal = MarshalRtnl()
                schedule = Schedule(time.monotonic())

                try:
                    while self.running:
                        for key, _ in selector.select(schedule.timeout(self.manager, time.monotonic())):
                            if key.data == 'client':
                                connection, _ = listener.accept()
                                self.handle(connection)
                            else:
                                receive_events(events, marshal, self.manager, schedule)

                        schedule.run(self.manager, time.monotonic())
                finally:
                    self.path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', default=SOCKET)
    parser.add_argument('--state-dir', default='/var/lib/nvyr-netlink')
    parser.add_argument('--resolver-file', default='/run/nvyr-resolver/resolv.conf')
    args = parser.parse_args()

    from nvyr.helpers.logging_runtime import configure_python
    configure_python('nvyr-netlinkd')

    # pyroute2 DEBUG includes every decoded message, overwhelming the useful
    # nVyR diagnostics on large systems. Keep its warnings/errors visible.
    logging.getLogger('pyroute2').setLevel(logging.WARNING)

    kernel = Kernel()
    manager = Manager(kernel, DHCP(), args.state_dir, naming=require_named)
    manager.resolver = Resolver(args.state_dir, manager.dns_servers, boot=manager.boot, path=args.resolver_file)
    server = Server(manager, args.socket)

    def stop(signum, frame):
        server.running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def ready():
        address = os.environ.get('NOTIFY_SOCKET')
        if address:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notification:
                notification.connect('\0' + address[1:] if address.startswith('@') else address)
                notification.sendall(b'READY=1')

    try:
        server.run(ready=ready)
    finally:
        kernel.close()


if __name__ == '__main__':
    main()
