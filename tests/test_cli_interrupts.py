"""SIGINT must not abandon configuration RPC frames or cancel applying commits."""

import signal

import pytest

from nvyr.cli import CLI
from nvyr.errors import RouterError
from nvyr.protocol import Client
from tests.test_integration import daemon


class InterruptedSocket:
    """Deliver SIGINT after consuming a partial header and then a partial body."""

    def __init__(self, socket):
        self.socket = socket
        self.reads = 0

    def __getattr__(self, name):
        return getattr(self.socket, name)

    def recv(self, length):
        chunk = self.socket.recv(min(length, 2 if self.reads < 2 else 7))
        self.reads += 1

        if self.reads in {1, 3}:
            signal.raise_signal(signal.SIGINT)

        return chunk


@pytest.mark.parametrize('command', ['commit', 'commit-confirm 1', 'commit-conf 1',
                                     'commit comment "Test change"',
                                     'commit-confirm 1 comment "Test change"'])
def test_commit_preserves_partial_frames_and_connection(daemon, command):
    client = Client(daemon)
    messages = []
    cli = CLI(client, emit=messages.append, ask=lambda _: True)
    previous = signal.getsignal(signal.SIGINT)

    try:
        cli.submit('configure\nset system host-name routernew')
        client.socket = InterruptedSocket(client.socket)
        cli.submit(command)

        assert messages.count('Commit in progress') == 2
        assert any('completed in' in message for message in messages)
        assert not any('interrupted.' in message for message in messages)
        assert signal.getsignal(signal.SIGINT) is previous
        assert not cli.done
        assert cli.commit_id == client.request('status')['commit_id']
        running = client.request('execute', text='show running-configuration | commands').get('text', '')
        assert 'set system host-name routernew' in running

        if command.startswith('commit-conf'):
            cli.submit('confirm')
            assert any('Commit confirmed' in message for message in messages)
    finally:
        client.close()


def test_interrupt_during_apply_does_not_cancel_or_rollback(controller, engine, session):
    messages = []
    previous = signal.getsignal(signal.SIGINT)

    class LocalClient:
        def request(self, operation, *, text, confirmation, on_text, on_terminal):
            result = controller.execute(text, session, confirmation=confirmation, on_text=on_text)
            on_text(result.pop('text'))
            return result

    def apply(generated, context):
        assert engine.busy
        signal.raise_signal(signal.SIGINT)
        signal.raise_signal(signal.SIGINT)
        assert engine.busy

    engine.modules['system'].apply = apply
    controller.execute('set system host-name routerdone', session)
    cli = CLI(LocalClient(), emit=messages.append)
    cli.mode = 'normal'
    cli.submit('commit')

    assert messages.count('Commit in progress') == 2
    assert engine.running['system']['host-name'] == 'routerdone'
    assert not engine.busy and not engine.unhealthy
    assert engine.store.read('transaction.json') is None
    assert signal.getsignal(signal.SIGINT) is previous


def test_insertion_stops_after_current_response_and_keeps_candidate(daemon):
    client = Client(daemon)
    messages = []
    cli = CLI(client, emit=messages.append)
    previous = signal.getsignal(signal.SIGINT)

    try:
        cli.submit('configure')
        client.socket = InterruptedSocket(client.socket)
        cli.submit('se system host-name accepted-router\nset interfaces dummy dum123')

        assert messages[-1] == (
            'Command insertion interrupted. Changes already accepted remain in the candidate.\n\n'
            'Use compare to review them before committing.')
        assert signal.getsignal(signal.SIGINT) is previous
        candidate = client.request('execute', text='show candidate-configuration | commands')['text']
        assert 'set system host-name accepted-router' in candidate
        assert 'dum123' not in candidate
        assert not cli.done and cli.mode == 'normal'

        cli.submit('set interfaces dummy dum456')
        candidate = client.request('execute', text='show candidate-configuration | commands')['text']
        assert 'dum456' in candidate
    finally:
        client.close()


def test_confirmation_prompt_is_interruptible_and_connection_reusable(daemon):
    client = Client(daemon)
    previous = signal.getsignal(signal.SIGINT)

    def ask(message):
        assert signal.getsignal(signal.SIGINT) is previous
        raise KeyboardInterrupt

    cli = CLI(client, emit=lambda _: None, ask=ask)
    try:
        cli.submit('configure\nset system host-name pending-router')

        with pytest.raises(KeyboardInterrupt):
            cli.submit('commit-confirm 1')

        running = client.request('execute', text='show running-configuration | commands').get('text', '')
        assert 'pending-router' not in running
        candidate = client.request('execute', text='show candidate-configuration | commands')['text']
        assert 'pending-router' in candidate
    finally:
        client.close()


def test_interrupted_load_finishes_before_stopping_insertion(daemon, tmp_path):
    path = tmp_path / 'commands.set'
    path.write_text('set system host-name loaded\nset interfaces dummy dum11\n')
    client = Client(daemon)
    messages = []
    cli = CLI(client, emit=messages.append)

    try:
        cli.submit('configure')
        client.socket = InterruptedSocket(client.socket)
        cli.submit(f'load set {path}\nset interfaces dummy dum12')

        candidate = client.request('execute', text='show candidate-configuration | commands')['text']
        assert 'host-name loaded' in candidate and 'dum11' in candidate and 'dum12' not in candidate
        assert messages[-1].startswith('Command insertion interrupted.')
    finally:
        client.close()


def test_failed_commit_restores_handler_and_reports_failure():
    previous = signal.getsignal(signal.SIGINT)
    messages = []

    class LocalClient:
        def request(self, *args, **kwargs):
            signal.raise_signal(signal.SIGINT)
            raise RouterError('Commit failed: backend unavailable')

    cli = CLI(LocalClient(), emit=messages.append)
    cli.mode = 'normal'
    cli.submit('commit')

    assert messages == ['Commit in progress', 'Commit failed: backend unavailable']
    assert signal.getsignal(signal.SIGINT) is previous


@pytest.mark.parametrize('mode, command', [(None, 'ping 127.0.0.1'), ('normal', 'run ping 127.0.0.1'),
                                          ('normal', 'shellcmd sleep 5'), ('normal', 'commit check')])
def test_other_execution_paths_retain_interrupt_handler(mode, command):
    previous = signal.getsignal(signal.SIGINT)

    class LocalClient:
        def request(self, *args, **kwargs):
            assert signal.getsignal(signal.SIGINT) is previous
            raise KeyboardInterrupt

    cli = CLI(LocalClient(), emit=lambda _: None)
    cli.mode = mode

    with pytest.raises(KeyboardInterrupt):
        cli.submit(command)

    assert signal.getsignal(signal.SIGINT) is previous
