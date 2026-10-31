"""Relay a daemon-owned operational process through the authenticated CLI socket."""

import asyncio
import base64
import codecs
import errno
import fcntl
import os
import pty
import re
import select
import signal
import struct
import sys
import termios
import threading
import tty

from nvyr.errors import RouterError
from nvyr.helpers import access
from nvyr.protocol import MAX_FRAME, TEXT_CHUNK, decode, encode, receive


async def _control(reader, request_id):
    size = struct.unpack('!I', await reader.readexactly(4))[0]
    if not 0 < size <= MAX_FRAME:
        raise RouterError('Invalid terminal control frame')

    message = decode(await reader.readexactly(size))
    if message.get('id') != request_id:
        raise RouterError('Terminal control does not match the active command')

    return message


def _resize(fd, message):
    rows, columns = message.get('rows', 24), message.get('columns', 80)
    if any(type(value) is not int or not 1 <= value <= 65535 for value in (rows, columns)):
        raise RouterError('Invalid terminal dimensions')

    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, columns, 0, 0))


async def _ready(fd, *, writing=False):
    loop = asyncio.get_running_loop()
    future = loop.create_future()
    add = loop.add_writer if writing else loop.add_reader
    remove = loop.remove_writer if writing else loop.remove_reader
    add(fd, lambda: future.done() or future.set_result(None))

    try:
        await future
    finally:
        remove(fd)


async def execute(reader, writer, request_id, argv, timeout, authorize):
    """Only the server's schema-resolved argv enters this privileged boundary."""
    writer.write(encode({'id': request_id, 'terminal': True}))
    await writer.drain()

    try:
        settings = await asyncio.wait_for(_control(reader, request_id), 10)
    except asyncio.TimeoutError:
        raise RouterError('The CLI did not attach to the operational terminal') from None

    if settings.get('terminal') != 'start':
        raise RouterError('Expected terminal start acknowledgement')

    term = settings.get('term', 'dumb')
    if not isinstance(term, str) or not re.fullmatch(r'[a-zA-Z0-9+_.-]{1,64}', term):
        raise RouterError('Invalid terminal type')

    authorize()  # Account/role may have changed while the client attached.
    master, slave = pty.openpty()
    process, tasks = None, []
    incoming, finishing = None, False

    def kill(sig):
        if process is not None:
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                pass

    async def output():
        decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')

        while True:
            try:
                chunk = os.read(master, TEXT_CHUNK)
            except BlockingIOError:
                await _ready(master)
                continue
            except OSError as error:
                if error.errno != errno.EIO:
                    raise

                chunk = b''  # Linux PTY EOF after the slave closes.

            text = decoder.decode(chunk, final=not chunk)
            if text:
                writer.write(encode({'id': request_id, 'text': text}))
                await writer.drain()

            if not chunk:
                return

    async def controls():
        while True:
            message = await _control(reader, request_id)
            operation = message.get('terminal')
            if operation == 'finish' and finishing:
                return

            if finishing and operation in {'input', 'resize', 'interrupt'}:
                continue  # Drain input already in flight when the command ended.

            if operation == 'resize':
                _resize(master, message)
            elif operation == 'interrupt':
                kill(signal.SIGINT)
            elif operation == 'input':
                try:
                    data = base64.b64decode(message['data'], validate=True)
                except (ValueError, TypeError, KeyError):
                    raise RouterError('Invalid terminal input') from None

                if len(data) > TEXT_CHUNK:
                    raise RouterError('Terminal input chunk is too large')

                while data and not finishing:
                    try:
                        data = data[os.write(master, data):]
                    except BlockingIOError:
                        try:
                            await asyncio.wait_for(_ready(master, writing=True), .1)
                        except asyncio.TimeoutError:
                            pass  # Notice command completion even during a large paste.
            else:
                raise RouterError('Unsupported terminal control')

    async def completion():
        status = await process.wait()

        # Do not leave descendants running if an operational wrapper exits early.
        kill(signal.SIGKILL)

        return 128 - status if status < 0 else status

    try:
        _resize(slave, settings)
        os.set_blocking(master, False)

        # A fresh interpreter acquires the controlling PTY before exec. Avoid
        # preexec_fn: configd uses threads, so Python work after fork is unsafe.
        process = await asyncio.create_subprocess_exec(
            sys.executable, '-m', 'nvyr.helpers.terminal', *argv,
            stdin=slave, stdout=slave, stderr=slave, start_new_session=True,
            env=dict(access.command_environment(), TERM=term))
        os.close(slave)
        slave = None

        finished = asyncio.create_task(completion())
        outgoing = asyncio.create_task(output())
        incoming = asyncio.create_task(controls())
        tasks = [finished, outgoing, incoming]

        async def relay():
            pending = set(tasks)

            while finished in pending or outgoing in pending:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)

                for task in done:
                    task.result()  # Propagate disconnects and protocol errors.

            return finished.result()

        try:
            status = await asyncio.wait_for(relay(), timeout)
        except asyncio.TimeoutError:
            raise RouterError(f'Operational command did not finish within {timeout:g} seconds') from None

        return status
    finally:
        finishing = True
        kill(signal.SIGKILL)

        for task in tasks:
            if task is not incoming:
                task.cancel()

        await asyncio.gather(*(task for task in tasks if task is not incoming), return_exceptions=True)

        if process is not None:
            await process.wait()

        # Finish handshake keeps late keystrokes out of the next RPC request and
        # avoids cancelling a reader in the middle of a length-prefixed frame.
        try:
            if incoming is not None:
                if not incoming.done():
                    writer.write(encode({'id': request_id, 'terminal_end': True}))
                    await writer.drain()
                    await asyncio.wait_for(incoming, 10)
                else:
                    writer.close()  # Broken connection or invalid control protocol.
        finally:
            if incoming is not None:
                incoming.cancel()
                await asyncio.gather(incoming, return_exceptions=True)

            os.close(master)

            if slave is not None:
                os.close(slave)


def attach(sock, request_id, output):
    """Client terminal relay; never launches an executable or changes identity."""

    def send(operation, **fields):
        sock.sendall(encode({'id': request_id, 'terminal': operation, **fields}))

    descriptor, saved = None, None

    try:
        candidate = sys.stdin.fileno()
        if os.isatty(candidate):
            descriptor = candidate
            saved = termios.tcgetattr(descriptor)
    except (OSError, ValueError, AttributeError):
        pass

    def dimensions():
        if descriptor is not None:
            size = os.get_terminal_size(descriptor)
            return {'rows': size.lines or 24, 'columns': size.columns or 80}

        return {'rows': 24, 'columns': 80}

    handlers = {}
    interrupted, resized = False, False

    def interrupt(*args):
        nonlocal interrupted
        interrupted = True

    def resize(*args):
        nonlocal resized
        resized = True

    try:
        if saved is not None:
            tty.setraw(descriptor)

        if threading.current_thread() is threading.main_thread():
            handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGWINCH)}
            signal.signal(signal.SIGINT, interrupt)
            signal.signal(signal.SIGWINCH, resize)

        send('start', term=os.environ.get('TERM') or 'dumb', **dimensions())

        while True:
            # Signal handlers only set flags: nested sendall calls could interleave
            # frames. A short select timeout also handles non-terminal SIGINT.
            if interrupted:
                send('interrupt')
                interrupted = False

            if resized:
                send('resize', **dimensions())
                resized = False

            ready, _, _ = select.select([sock] + ([descriptor] if descriptor is not None else []), [], [], .1)
            if sock in ready:
                message = receive(sock)
                if message.get('id') != request_id:
                    raise RouterError('Terminal response does not match the active command')

                if 'text' in message:
                    output(message['text'])

                if message.get('terminal_end'):
                    send('finish')
                    return message

                if 'error' in message:
                    return message

            if descriptor in ready:
                data = os.read(descriptor, TEXT_CHUNK)
                send('input', data=base64.b64encode(data or b'\x04').decode('ascii'))

                if not data:
                    descriptor = None
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)

        if saved is not None:
            termios.tcsetattr(candidate, termios.TCSADRAIN, saved)


if __name__ == '__main__':
    # This helper has no elevated installation permissions. Its only privileged
    # caller is configd, which supplied argv after schema and role authorization.
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)

    try:
        os.execvp(sys.argv[1], sys.argv[1:])
    except OSError as error:
        print(f'Cannot run {sys.argv[1]!r}: {error.strerror}', file=sys.stderr)
        raise SystemExit(127) from None
