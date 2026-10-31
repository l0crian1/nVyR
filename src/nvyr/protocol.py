"""Versioned length-prefixed JSON frames, bounded requests and streamed output."""

import json
import socket
import struct
import threading
from nvyr.errors import RouterError, SessionExpiredError

VERSION = 2
MAX_FRAME = 64 * 1024 * 1024
TEXT_CHUNK = 32 * 1024


def encode(message):
    payload = json.dumps(message, ensure_ascii=False).encode("utf-8")
    if len(payload) > MAX_FRAME:
        raise RouterError(f"RPC message size {len(payload):,} bytes exceeds the {MAX_FRAME // (1024 * 1024)} MiB limit ({MAX_FRAME:,} bytes).")

    return struct.pack("!I", len(payload)) + payload


def decode(payload):
    try:
        message = json.loads(payload)
    except (ValueError, UnicodeError):
        raise RouterError("The router sent an unreadable response. Reconnect and check that the CLI and configuration service use the same version.") from None

    if not isinstance(message, dict):
        raise RouterError("The router response could not be understood. Reconnect and check the software versions.")

    return message


def receive(sock):
    def exact(length):
        parts = bytearray()

        while len(parts) < length:
            chunk = sock.recv(length - len(parts))
            if not chunk:
                raise EOFError("Connection to the router's configuration service was closed.")

            parts.extend(chunk)

        return bytes(parts)

    length = struct.unpack("!I", exact(4))[0]
    if length > MAX_FRAME:
        raise RouterError(f"RPC message size {length:,} bytes exceeds the {MAX_FRAME // (1024 * 1024)} MiB limit ({MAX_FRAME:,} bytes).")
    if length == 0:
        raise RouterError("The router response is empty. Reconnect and check the system logs.")

    return decode(exact(length))


class Client:
    """No configuration cache. Only request metadata and the current output chunk."""

    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.connect(str(path))
        self.counter = 0
        self._request_lock = threading.Lock()

    def close(self):
        self.socket.close()

    def request(self, operation, *, on_text=None, on_terminal=None, **arguments):
        # Idle-prompt polling and foreground completion/commands share one connection.
        with self._request_lock:
            return self._request(operation, on_text=on_text, on_terminal=on_terminal, **arguments)

    def _request(self, operation, *, on_text=None, on_terminal=None, **arguments):
        self.counter += 1
        request_id = self.counter
        self.socket.sendall(encode({"version": VERSION, "id": request_id, "operation": operation, **arguments}))
        for_message = [] if on_text is None else None
        output = on_text if on_text is not None else for_message.append

        while True:
            message = receive(self.socket)
            if message.get("id") != request_id:
                raise RouterError("The router response did not match this request. Reconnect before making further changes.")

            if message.get('terminal'):
                from nvyr.helpers.terminal import attach

                try:
                    message = attach(self.socket, request_id, on_terminal or output)
                except BaseException:
                    self.close()  # Disconnect cancels the daemon-owned process group.
                    raise

            if "error" in message:
                error = message["error"]
                error_type = SessionExpiredError if error['code'] == SessionExpiredError.code else RouterError
                exception = error_type(error["message"], token=error.get("token"), start=error.get("start"), details=error.get("details"))
                exception.code = error["code"]
                raise exception

            if "text" in message:
                if on_text:
                    on_text(message["text"])
                else:
                    for_message.append(message["text"])

            if message.get("done"):
                result = message.get("result", {})

                if for_message:
                    result["text"] = "".join(for_message)

                return result
