"""Exercise controller authentication without modifying or rebooting a router."""

import json
from types import SimpleNamespace
import unittest
import sys
from unittest.mock import patch

from acceptance import runner
from acceptance.ssh_password import PasswordSSH, PASSWORD_PROMPT, READY


class Channel:
    """Model sudo's password prompt followed by agent readiness and JSON output."""
    def __init__(self, password_required=True, reject=False):
        self.error = PASSWORD_PROMPT.encode() if password_required else READY.encode()
        self.output = b''
        self.sent = []
        self.done = False
        self.reject = reject

    def recv_ready(self):
        return bool(self.output)

    def recv_stderr_ready(self):
        return bool(self.error)

    def recv(self, count):
        value, self.output = self.output[:count], self.output[count:]
        return value

    def recv_stderr(self, count):
        value, self.error = self.error[:count], self.error[count:]
        return value

    def sendall(self, data):
        self.sent.append(data)
        if data == b'secret\n':
            self.error = (PASSWORD_PROMPT if self.reject else READY).encode()

    def shutdown_write(self):
        self.output = b'{"ok": true, "result": {}}'
        self.done = True

    def exit_status_ready(self):
        return self.done

    def recv_exit_status(self):
        return 0


class TransportTests(unittest.TestCase):
    def transport(self):
        transport = PasswordSSH.__new__(PasswordSSH)
        transport.password = 'secret'
        return transport

    def test_sudo_password_precedes_json(self):
        """The agent receives JSON only after sudo has consumed the password."""
        channel = Channel()
        result = self.transport().exchange(channel, '{"action":"ready"}', 1)
        self.assertEqual(channel.sent, [b'secret\n', b'{"action":"ready"}'])
        self.assertTrue(json.loads(result.stdout)['ok'])
        self.assertEqual(result.stderr, '')

    def test_nopasswd_does_not_send_password_to_agent(self):
        """Root or passwordless sudo must not receive a password in its JSON stream."""
        channel = Channel(password_required=False)
        self.transport().exchange(channel, '{}', 1)
        self.assertEqual(channel.sent, [b'{}'])

    def test_wrong_sudo_password_stops_before_request(self):
        """Reject failed privilege escalation without sending a configuration action."""
        channel = Channel(reject=True)
        with self.assertRaisesRegex(ValueError, 'Sudo rejected'):
            self.transport().exchange(channel, '{}', 1)
        self.assertEqual(channel.sent, [b'secret\n'])

    def test_password_prompts_once_for_repeated_calls(self):
        """Every run uses the password directly, including later reconnections."""
        success = SimpleNamespace(returncode=0, stdout='{"ok":true,"result":{}}', stderr='')
        with patch.object(runner.getpass, 'getpass', return_value='secret') as prompt:
            with patch('acceptance.ssh_password.PasswordSSH') as transport:
                transport.return_value.execute.return_value = success
                router = runner.Router('nvyr@router')
                router.authenticate()
                router.call('ready', 'run-id')
                router.call('ready', 'run-id')
                prompt.assert_called_once()
                transport.assert_called_once_with('nvyr@router', 'secret', port=22)
                self.assertEqual(transport.return_value.execute.call_count, 3)

    def test_password_authentication_failure_stops_preparation(self):
        """Failed login must not fall back to keys or start configuration changes."""
        with patch.object(runner.getpass, 'getpass', return_value='wrong'):
            with patch('acceptance.ssh_password.PasswordSSH') as transport:
                transport.return_value.execute.side_effect = ValueError('Authentication failed')
                with self.assertRaisesRegex(runner.RemoteError, 'Authentication failed'):
                    runner.Router('nvyr@router').authenticate()

    def test_access_failure_does_not_enter_run(self):
        """Authentication failure must not print that test configuration was retained."""
        arguments = ['runner', 'run', 'nvyr@router', '--ethernet-interface', 'eth1', '--disposable']
        with patch.object(sys, 'argv', arguments):
            with patch.object(runner.Router, 'authenticate', side_effect=runner.RemoteError('denied')):
                with patch.object(runner, 'run') as run:
                    self.assertEqual(runner.main(), 1)
                    run.assert_not_called()
