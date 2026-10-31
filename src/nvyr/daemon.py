"""Linux Unix-socket server. A connection owns its session; EOF expires that VTY."""

import argparse
import asyncio
import fcntl
import logging
import os
from pathlib import Path
import pwd
import socket
import struct

from nvyr.controller import Controller
from nvyr.engine import Engine, DEFAULT_SESSION_TIMEOUT
from nvyr.errors import RouterError, ValidationError
from nvyr.modules import registry
from nvyr.protocol import MAX_FRAME, TEXT_CHUNK, VERSION, decode, encode
from nvyr.schema import Schema
from nvyr.storage import Store
from nvyr.helpers import access, accounts, passwords
from nvyr.helpers.terminal import execute as execute_terminal

log = logging.getLogger(__name__)


def peer_ssh_address(pid):
    """Best-effort SSH origin for display only, never authentication."""
    try:
        environment = Path(f'/proc/{pid}/environ').read_bytes().split(b'\0')
    except OSError:
        return None  # Local processes or restricted/disappeared /proc entries.

    values = dict(entry.split(b'=', 1) for entry in environment if b'=' in entry)
    for name in (b'SSH_CONNECTION', b'SSH_CLIENT'):
        fields = values.get(name, b'').split()
        if not fields:
            continue

        try:
            address = fields[0].decode('ascii')
        except UnicodeError:
            continue

        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(family, address)
            except OSError:
                continue

            return address

    return None


def peer_identity(writer):
    connection = writer.get_extra_info("socket")
    pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))

    try:
        user = pwd.getpwuid(uid).pw_name
    except KeyError:
        raise RouterError('This Linux account no longer exists') from None

    try:
        vty = os.readlink(f"/proc/{pid}/fd/0")
    except OSError:
        vty = "unknown"

    address = peer_ssh_address(pid)
    from nvyr.helpers.session_runtime import metadata
    session_metadata = metadata(pid, uid)
    if session_metadata:
        vty, address = session_metadata
    if address:
        vty += f' from {address}'

    return user, f"{vty} (pid {pid}, uid {uid})"


class Server:
    def __init__(self, engine, *, identity=peer_identity):
        self.engine = engine
        self.controller = Controller(engine)
        self.identity = identity
        self.connections = set()

    async def execute(self, writer, request_id, text, session, confirmation):
        """Relay worker feedback without making a lost terminal fail a commit."""
        loop = asyncio.get_running_loop()
        disconnected = False

        async def send(message):
            nonlocal disconnected
            if disconnected:
                return

            try:
                for offset in range(0, len(message), TEXT_CHUNK):
                    writer.write(encode({'id': request_id, 'text': message[offset:offset + TEXT_CHUNK]}))
                    await asyncio.wait_for(writer.drain(), timeout=5)
            except (OSError, TimeoutError):
                # Feedback is optional transport output; the durable transaction
                # must finish even if its caller disconnects or stops reading.
                disconnected = True
                writer.close()
                log.debug('Commit feedback connection closed; continuing operation')

        def report(message):
            asyncio.run_coroutine_threadsafe(send(message), loop).result()

        return await asyncio.to_thread(self.controller.execute, text, session,
                                       confirmation=confirmation, on_text=report)

    async def handle(self, reader, writer):
        session = None
        self.connections.add(writer)
        initial_event_id = self.engine.event_id

        try:
            user, vty = self.identity(writer)

            while True:
                header = await reader.readexactly(4)
                size = struct.unpack("!I", header)[0]
                if not 0 < size <= MAX_FRAME:
                    break

                request = decode(await reader.readexactly(size))
                request_id = request.get("id")

                try:
                    access.role.set(access.peer_role(self.engine, user))
                    access.principal.set((self.engine, user))
                    access.terminal.set(vty.split(' ', 1)[0] if vty.startswith('/dev/') else '')

                    if session and access.role.get() == 'read-only':
                        self.engine.close(session)
                        session = None

                    if request.get("version") != VERSION:
                        raise RouterError("The CLI and configuration service use incompatible versions. Update them together and reconnect.")

                    operation = request.get("operation")
                    if operation == 'disable_developer_access':
                        from nvyr.helpers import developer_access
                        result = developer_access.schedule_disable(self.engine)
                    elif operation == "open":
                        if session:
                            raise RouterError("You are already in configuration mode. Use exit before opening another session.")

                        session = self.engine.open(user, vty, bool(request.get("draft")), timeout=request.get('timeout'))
                        result = session.identity() | {"commit_id": session.commit_id}
                    elif operation == 'close':
                        if session:
                            self.engine.close(session)
                            session = None

                        result = {}
                    elif operation == 'commit':
                        if not session:
                            raise RouterError('Open a configuration session before committing')

                        seconds = request.get('n')
                        if seconds is not None and (type(seconds) not in (int, float) or
                                not 0 < seconds <= 86400):
                            raise ValidationError('Commit-confirm timeout must be greater than zero and no more than 86400 seconds')

                        minutes = seconds / 60 if seconds is not None else None

                        # Supplying n is the programmatic caller's explicit request
                        # for commit-confirm. Stale-candidate confirmation remains
                        # enforced by Engine.commit; never retry it automatically.
                        result = await asyncio.to_thread(self.engine.commit, session,
                                                         minutes=minutes, confirmed_minutes=minutes,
                                                         comment=request.get('comment'))
                    elif operation == "complete":
                        result = await asyncio.to_thread(self.controller.completion, request["text"], session, explicit=bool(request.get("explicit")), space=bool(request.get("space")), tab=bool(request.get("tab")))
                    elif operation == 'clear-firewall-group':
                        from nvyr.helpers.firewall_runtime import clear

                        result = await asyncio.to_thread(clear, self.engine, self.controller.operational, request['text'])
                    elif operation in ('geoip-update', 'geoip-status'):
                        from nvyr.helpers.geoip import manager

                        action = manager.update if operation == 'geoip-update' else manager.status
                        result = await asyncio.to_thread(action, self.engine)
                    elif operation in ('domain-group-update', 'domain-group-status'):
                        from nvyr.helpers.domain_groups import manager

                        action = manager.update if operation == 'domain-group-update' else manager.status
                        result = await asyncio.to_thread(action, self.engine, request.get('family'), request.get('name'))
                    elif operation == "status":
                        after = request.get("after")
                        result = self.engine.status(session, after=initial_event_id if after is None else after)
                        result['hostname'] = socket.gethostname()
                    elif operation == "execute":
                        result = await self.execute(writer, request_id, request['text'], session, request.get('confirmation'))
                        if result.get('event') == 'command':
                            # Never accept argv/environment/identity from the client.
                            # Controller resolved this command from the installed tree
                            # after the same role checks used for captured execution.
                            result['returncode'] = await execute_terminal(
                                reader, writer, request_id, result.pop('argv'), result.pop('timeout'),
                                lambda: self.controller.authorize_terminal(request['text'], session))

                        if result.get("event") == "leave":
                            self.engine.close(session)
                            session = None
                    elif operation == 'get_config':
                        if not session:
                            raise RouterError('Open a configuration session before retrieving configuration')

                        configuration = await asyncio.to_thread(
                            self.controller.get_config, session, request.get('source', 'running'))
                        result = {'configuration': configuration}
                    elif operation == "load":
                        if not session:
                            raise RouterError("Enter configuration mode before loading")

                        errors = await asyncio.to_thread(self.controller.load, session, request["content"], set_format=bool(request.get("set_format")), replace=bool(request.get("replace")))
                        result = {"errors": errors}
                    else:
                        raise RouterError("This request is not supported. Check that the CLI and configuration service use compatible versions.")

                    text = result.pop("text", "")

                    for offset in range(0, len(text), TEXT_CHUNK):
                        writer.write(encode({"id": request_id, "text": text[offset:offset+TEXT_CHUNK]}))
                        await writer.drain()

                    writer.write(encode({"id": request_id, "done": True, "result": result}))
                except RouterError as error:
                    writer.write(encode({"id": request_id, "error": error.as_dict()}))
                except Exception:
                    if passwords.sensitive_line(str(request)):
                        log.error('Unexpected credential RPC failure (input omitted)')
                    else:
                        log.exception("Unexpected RPC failure")

                    error = RouterError("The router could not complete this request. Check the system logs for details before trying again.")
                    writer.write(encode({"id": request_id, "error": error.as_dict()}))

                await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, RouterError):
            pass
        finally:
            if session:
                self.engine.close(session)

            self.connections.discard(writer)
            writer.close()

            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def timer(self):
        while True:
            await asyncio.sleep(0.25)

            try:
                await asyncio.to_thread(self.engine.tick)
            except Exception:
                log.exception("Configuration timer processing failed; retrying")
                await asyncio.sleep(5)


async def serve(engine, path, *, group=None):
    path = Path(path)
    created = not path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)

    if group and created:
        import grp

        os.chown(path.parent, -1, grp.getgrnam(group).gr_gid)

    # Hold a process lock before touching the socket. Never unlink another daemon.
    with open(path.parent / (path.name + ".lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path.unlink(missing_ok=True)
        server = Server(engine)
        listener = await asyncio.start_unix_server(server.handle, path=str(path))
        os.chmod(path, 0o660)

        if group:
            import grp

            os.chown(path, -1, grp.getgrnam(group).gr_gid)

        address = os.environ.get('NOTIFY_SOCKET')
        if address:
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notification:
                notification.connect('\0' + address[1:] if address.startswith('@') else address)
                notification.sendall(b'READY=1')

        timer = asyncio.create_task(server.timer())

        try:
            async with listener:
                await listener.serve_forever()
        finally:
            timer.cancel()

            for connection in server.connections.copy():
                connection.close()

            path.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description="nVyR configuration daemon")
    parser.add_argument("--socket", default="/run/nvyr/configd.sock")
    parser.add_argument("--state", default="/var/lib/nvyr")
    parser.add_argument("--saved", help="Saved configuration path (default: /config/nvyr-saved-config for the system service)")
    parser.add_argument("--group", help="Group granted socket access; roles are checked per request")
    parser.add_argument('--session-timeout', type=float, default=DEFAULT_SESSION_TIMEOUT,
                        help='Default total configuration session lifetime in seconds (28800 = 8 hours)')
    args = parser.parse_args()

    from nvyr.helpers.logging_runtime import configure_python
    configure_python('nvyr-configd')

    schema = Schema.bundled()
    saved = args.saved or ('/config/nvyr-saved-config' if Path(args.state) == Path('/var/lib/nvyr') else None)
    directory = Path(args.state)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Lock before persistent state initialization and recovery.
    with open(directory / "daemon.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        store = Store(directory, saved_path=saved)
        accounts.initialize(store)
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        engine = Engine(schema, registry(schema), store, boot_id=boot_id, session_timeout=args.session_timeout)

        try:
            asyncio.run(serve(engine, args.socket, group=args.group))
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
