"""Exercise the standalone helper against local services, never public targets."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
from pathlib import Path
import shutil
import socket
import socketserver
import threading

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import pytest

from nvyr.helpers.process import CommandError, CommandResult


@pytest.fixture
def helpers():
    path = Path(__file__).parents[1] / 'docs/dev/examples/automation/nvyr_helpers.py'
    specification = importlib.util.spec_from_file_location('nvyr_helpers', path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


@pytest.fixture
def http_server():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(int(self.path.removeprefix('/')))
            self.end_headers()

        def do_POST(self):
            received.append(self.rfile.read(int(self.headers['Content-Length'])))
            self.send_response(int(self.path.removeprefix('/')))
            self.end_headers()

        def log_message(self, *arguments):
            pass

    with ThreadingHTTPServer(('127.0.0.1', 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address[1], received
        finally:
            server.shutdown()
            thread.join()


@pytest.fixture
def dns_server(helpers, monkeypatch):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            wire, connection = self.request
            request = dns.message.from_wire(wire)
            reply = dns.message.make_response(request)
            question = request.question[0]
            if str(question.name) == 'present.test.':
                kind = dns.rdatatype.to_text(question.rdtype)
                value = '2001:db8::1' if kind == 'AAAA' else '192.0.2.1'
                reply.answer.append(dns.rrset.from_text(question.name, 60, 'IN', kind, value))
            else:
                reply.set_rcode(dns.rcode.NXDOMAIN)
            connection.sendto(reply.to_wire(), self.client_address)

    with socketserver.UDPServer(('127.0.0.1', 0), Handler) as server:
        original = helpers.dns.resolver.Resolver

        def resolver(**arguments):
            result = original(**arguments)
            result.port = server.server_address[1]
            return result

        monkeypatch.setattr(helpers.dns.resolver, 'Resolver', resolver)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield
        finally:
            server.shutdown()
            thread.join()


@pytest.mark.skipif(not shutil.which('curl'), reason='requires curl')
def test_http_statuses_and_literal_notification_body(helpers, http_server):
    port, received = http_server
    url = f'http://127.0.0.1:{port}'
    assert helpers.http_test([url + '/503', url + '/204'], retries=1, source_address='127.0.0.1')
    assert helpers.http_test([url + '/302'], retries=1)
    assert not helpers.http_test([url + '/404'], retries=1)

    message = '@not-a-file\nQuotes " and shell text $(echo ignored); stay literal.'
    assert helpers.ntfy(message, url + '/200', source_address='127.0.0.1') is None
    assert received == [message.encode()]
    with pytest.raises(CommandError):
        helpers.ntfy('rejected', url + '/500')


def test_http_partial_response_is_not_success(helpers, monkeypatch):
    monkeypatch.setattr(helpers, 'cli_cmd', lambda *args, **kwargs: CommandResult('200', 'transfer timed out', 28))
    assert not helpers.http_test(['http://localhost'], retries=1)


def test_dns_answers_failover_and_absent_records(helpers, dns_server):
    assert helpers.dns_test(['127.0.0.2', '127.0.0.1'], 'present.test', retries=1,
                            source_address='127.0.0.1')
    assert helpers.dns_test(['127.0.0.1'], 'present.test', retries=1, record_type='AAAA')
    assert not helpers.dns_test(['127.0.0.1'], 'absent.test', retries=1)


def test_tcp_connect_and_refusal(helpers, http_server):
    port, _ = http_server
    assert helpers.port_test(port, '127.0.0.1', source_address='127.0.0.1', retries=1)

    # Reserving an unlistened TCP port makes refusal deterministic without another service.
    with socket.socket() as closed:
        closed.bind(('127.0.0.1', 0))
        assert not helpers.port_test(closed.getsockname()[1], '127.0.0.1', retries=1)


@pytest.mark.skipif(not shutil.which('ping'), reason='requires iputils-ping')
def test_ping_localhost(helpers):
    assert helpers.ping_test(['127.0.0.1'], source_address='127.0.0.1', retries=1)


def test_ping_retries_keep_arguments_literal_and_do_not_sleep_after_last_round(helpers, monkeypatch):
    calls, waits = [], []

    def run(arguments):
        calls.append(arguments)
        return 1

    monkeypatch.setattr(helpers, 'run', run)
    monkeypatch.setattr(helpers, 'sleep', waits.append)
    target = 'literal;not-a-shell-command'

    assert not helpers.ping_test(iter([target]), source_address='eth0', retries=3, interval=2)
    assert waits == [2, 2]
    assert len(calls) == 3
    assert calls[0] == ['ping', '-c', '1', '-W', '0.5', '-I', 'eth0', '--', target]


def test_syslog_closes_even_when_logging_fails(helpers, monkeypatch):
    closed = []
    monkeypatch.setattr(helpers, 'openlog', lambda *args: None)
    monkeypatch.setattr(helpers, 'closelog', lambda: closed.append(True))

    def fail(*args):
        raise OSError('syslog unavailable')

    monkeypatch.setattr(helpers, 'syslog', fail)
    with pytest.raises(OSError):
        helpers.log_message('test', 'health-check')
    assert closed == [True]
