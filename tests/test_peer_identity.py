"""Lock-owner labels use kernel credentials and optional SSH origin metadata."""

from pathlib import Path
import socket
import struct
from types import SimpleNamespace

import pytest

from nvyr.daemon import peer_identity
from nvyr.errors import ConfirmationRequired, LockError


@pytest.fixture
def peer(monkeypatch):
    def credentials(level, option, length):
        assert (level, option, length) == (socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        return struct.pack('3i', 1234, 1000, 1000)

    def account(uid):
        assert uid == 1000
        return SimpleNamespace(pw_name='nvyr')

    monkeypatch.setattr('nvyr.daemon.pwd.getpwuid', account)
    monkeypatch.setattr('nvyr.daemon.os.readlink', lambda path: '/dev/pts/0')
    return SimpleNamespace(get_extra_info=lambda name: SimpleNamespace(getsockopt=credentials))


@pytest.mark.parametrize('environment, address', [
    (b'SSH_CONNECTION=192.0.2.10 53000 192.0.2.1 22\0USER=forged\0', '192.0.2.10'),
    (b'SSH_CONNECTION=2001:db8::10 53000 2001:db8::1 22\0', '2001:db8::10'),
    (b'SSH_CLIENT=192.0.2.11 53000 22\0', '192.0.2.11'),
    (b'USER=forged\0', None),
    (b'SSH_CONNECTION=not-an-address 1 2 3\0', None),
    (b'SSH_CONNECTION=\xff 1 2 3\0', None),
    (b'SSH_CONNECTION=\x1b[31m192.0.2.10 1 2 3\0', None),
])
def test_peer_label_includes_valid_ssh_origin_without_trusting_environment_user(peer, monkeypatch, environment, address):
    def read(path):
        assert path == Path('/proc/1234/environ')
        return environment

    monkeypatch.setattr(Path, 'read_bytes', read)
    origin = f' from {address}' if address else ''

    assert peer_identity(peer) == ('nvyr', f'/dev/pts/0{origin} (pid 1234, uid 1000)')


@pytest.mark.parametrize('error', [PermissionError, FileNotFoundError])
def test_peer_label_survives_unavailable_environment_and_terminal(peer, monkeypatch, error):
    def unavailable(*args):
        raise error()

    monkeypatch.setattr(Path, 'read_bytes', unavailable)
    monkeypatch.setattr('nvyr.daemon.os.readlink', unavailable)

    assert peer_identity(peer) == ('nvyr', 'unknown (pid 1234, uid 1000)')


def test_lock_errors_and_takeover_prompt_include_user_and_address(peer, monkeypatch, engine):
    monkeypatch.setattr(Path, 'read_bytes', lambda path: b'SSH_CONNECTION=192.0.2.10 53000 192.0.2.1 22\0')
    user, label = peer_identity(peer)
    owner = engine.open(user, label)
    other = engine.open('automation', 'local-script')

    for operation, exception in [(engine.commit, LockError), (engine.request_lock, ConfirmationRequired)]:
        with pytest.raises(exception) as error:
            operation(other)

        assert 'nvyr on /dev/pts/0 from 192.0.2.10' in str(error.value)
        assert error.value.details == owner.identity()
