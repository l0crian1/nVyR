"""NTP serving reports preserve Chrony's counters, units and failure states."""

import json

import pytest

from nvyr import opmode
from nvyr.errors import RouterError
from nvyr.helpers import access
from nvyr.op_scripts import ntp
from nvyr.schema import Schema
from nvyr.lexer import lex


def test_client_units_and_numeric_addresses(monkeypatch):
    """Convert log2 intervals, preserve IPv6 and omit command-only clients."""
    rows = [
        ['192.0.2.10', '120', '4', '6', '7', '12', '0', '0', '127', '4294967295'],
        ['2001:db8::10', '20', '0', '-2', '127', '0', '0', '0', '127', '4294967295'],
        ['192.0.2.11', '0', '0', '127', '127', '4294967295', '5', '0', '6', '1'],
    ]
    monkeypatch.setattr(ntp, 'report', lambda *args, **kwargs: rows)

    data = json.loads(ntp.clients(raw=True))
    assert data == [
        {'Client': '192.0.2.10', 'Requests': 120, 'Rate-limited': 4,
         'Interval (s)': 64, 'Last seen (s)': 12},
        {'Client': '2001:db8::10', 'Requests': 20, 'Rate-limited': 0,
         'Interval (s)': 0.25, 'Last seen (s)': 0},
    ]
    output = ntp.clients()
    assert '2001:db8::10' in output
    assert '0.25' in output
    assert '192.0.2.11' not in output


def test_unknown_client_times(monkeypatch):
    """Unknown intervals and last-seen values remain unknown, not zero."""
    rows = [['192.0.2.10', '1', '0', '127', '127', '4294967295', '0', '0', '127', '4294967295']]
    monkeypatch.setattr(ntp, 'report', lambda *args, **kwargs: rows)

    data = json.loads(ntp.clients(raw=True))[0]
    assert data['Interval (s)'] is None
    assert data['Last seen (s)'] is None
    assert '—' in ntp.clients()


def test_no_recorded_clients(monkeypatch):
    """An empty report has a useful message and an empty API list."""
    monkeypatch.setattr(ntp, 'report', lambda *args, **kwargs: [])
    assert ntp.clients() == 'No NTP clients recorded.\n'
    assert json.loads(ntp.clients(raw=True)) == []


def test_server_statistics_summary_detail_and_raw(monkeypatch):
    """Map all native fields in order and retain integer precision above 2**53."""
    values = [2 ** 60, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
    monkeypatch.setattr(ntp, 'report', lambda *args, **kwargs: [[str(value) for value in values]])

    data = json.loads(ntp.server_statistics(raw=True))
    assert data['NTP requests received'] == 2 ** 60
    assert data['Client records dropped'] == 5
    assert data['NTS-KE connections accepted'] == 6
    assert data['Authenticated NTP requests'] == 8
    assert data['NTP timestamp span (s)'] == 11
    assert data['NTP hardware TX timestamps'] == 17
    assert len(data) == 17
    assert json.loads(ntp.server_statistics(raw=True, detail=True)) == data

    summary = ntp.server_statistics()
    detail = ntp.server_statistics(detail=True)
    assert ' | ' in summary
    assert len(summary.splitlines()) == 5
    assert str(2 ** 60) in summary
    assert 'NTS-KE' not in summary
    assert 'Command requests received' not in summary
    assert len(detail.splitlines()) == 17
    assert 'NTP hardware TX timestamps' in detail


@pytest.mark.parametrize('rows', [[], [['0'] * 16], [['0'] * 18], [['0'] * 17] * 2,
                                 [['-1'] * 17], [['invalid'] * 17]])
def test_invalid_server_statistics(monkeypatch, rows):
    """Reject malformed reports instead of mislabelling values or hiding failures."""
    monkeypatch.setattr(ntp, 'report', lambda *args, **kwargs: rows)
    with pytest.raises(RouterError, match='Unexpected Chrony server statistics response'):
        ntp.server_statistics()


@pytest.mark.parametrize('field,value', [(1, '-1'), (2, 'invalid'), (3, '128'),
                                        (3, '-129'), (5, '-1')])
def test_invalid_client_numbers(monkeypatch, field, value):
    """Invalid numbers produce a readable command error."""
    row = ['192.0.2.1', '1', '0', '6', '127', '1', '0', '0', '127', '4294967295']
    row[field] = value
    monkeypatch.setattr(ntp, 'report', lambda *args, **kwargs: [row])
    with pytest.raises(RouterError, match='Unexpected Chrony clients response'):
        ntp.clients()


def test_invalid_client_columns(monkeypatch):
    """Do not interpret an incomplete native response as an empty client list."""
    monkeypatch.setattr(ntp, 'report', lambda *args, **kwargs: [['192.0.2.1', '1']])
    with pytest.raises(RouterError, match='Unexpected Chrony clients response'):
        ntp.clients()


def test_serving_reports_use_managed_socket_without_reset(monkeypatch, tmp_path):
    """Both reports are numeric, local, read-only requests to the managed daemon."""
    socket = tmp_path / 'chronyd.sock'
    socket.touch()
    monkeypatch.setattr(ntp, 'SOCKET', str(socket))
    calls = []

    def command(argv, **kwargs):
        calls.append((argv, kwargs))
        if argv[-1] == 'clients':
            return '127.0.0.1,1,0,127,127,0,0,0,127,4294967295\n'
        return ','.join(['0'] * 17) + '\n'

    monkeypatch.setattr(ntp, 'cmd', command)
    ntp.clients()
    ntp.server_statistics()
    assert calls == [
        (['chronyc', '-h', str(socket), '-c', '-n', 'clients'], {'timeout': 5}),
        (['chronyc', '-h', str(socket), '-c', '-n', 'serverstats'], {'timeout': 5}),
    ]


def test_serving_reports_when_service_stopped(monkeypatch, tmp_path):
    """A stopped service must not look like a running service with zero traffic."""
    monkeypatch.setattr(ntp, 'SOCKET', str(tmp_path / 'absent.sock'))
    with pytest.raises(RouterError, match='NTP is not running'):
        ntp.clients()
    with pytest.raises(RouterError, match='NTP is not running'):
        ntp.server_statistics()


def test_serving_report_command_failure(monkeypatch, tmp_path):
    """Socket and daemon failures propagate without silently fabricating an empty report."""
    socket = tmp_path / 'chronyd.sock'
    socket.touch()
    monkeypatch.setattr(ntp, 'SOCKET', str(socket))

    def fail(*args, **kwargs):
        raise RouterError('Cannot talk to daemon')

    monkeypatch.setattr(ntp, 'cmd', fail)
    with pytest.raises(RouterError, match='Cannot talk to daemon'):
        ntp.clients()
    with pytest.raises(RouterError, match='Cannot talk to daemon'):
        ntp.server_statistics()


def test_serving_command_paths_and_completion(controller):
    """The public tree exposes summary/detail, leaving raw for API callers."""
    schema = Schema.bundled('operational')
    clients = schema.resolve(lex('show ntp clients')).node
    summary = schema.resolve(lex('show ntp server statistics')).node
    detail = schema.resolve(lex('show ntp server statistics detail')).node
    assert clients['command']['argv'] == ['ntp.nvyr.op', 'clients']
    assert summary['command']['argv'] == ['ntp.nvyr.op', 'server_statistics']
    assert detail['command']['argv'] == ['ntp.nvyr.op', 'server_statistics', '--detail']

    completion = controller.completion('show ntp ', explicit=True)
    assert {'clients', 'server', 'sources'} <= dict(completion['candidates']).keys()
    completion = controller.completion('show ntp server statistics ', explicit=True)
    assert 'detail' in dict(completion['candidates'])
    assert 'raw' not in dict(completion['candidates'])


def test_serving_commands_allow_operators(controller, monkeypatch):
    """Read-only reports use normal operator permissions and the expected argv."""
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'report\n')
    token = access.role.set('read-only')
    try:
        assert controller.execute('show ntp clients')['text'] == 'report\n'
        assert controller.execute('show ntp server statistics')['text'] == 'report\n'
        assert controller.execute('show ntp server statistics detail')['text'] == 'report\n'
    finally:
        access.role.reset(token)

    assert calls == [
        ['ntp.nvyr.op', 'clients'],
        ['ntp.nvyr.op', 'server_statistics'],
        ['ntp.nvyr.op', 'server_statistics', '--detail'],
    ]


def test_serving_script_dispatch(monkeypatch, capsys):
    """The standalone script accepts the raw/detail flags used by API and smoke callers."""
    monkeypatch.setattr(ntp, 'report', lambda *args, **kwargs: [['0'] * 17])
    opmode.run(['server_statistics', '--raw', '--detail'], namespace=vars(ntp))
    assert json.loads(capsys.readouterr().out)['NTP requests received'] == 0

    monkeypatch.setattr(ntp, 'report', lambda *args, **kwargs: [])
    opmode.run(['clients', '--raw'], namespace=vars(ntp))
    assert json.loads(capsys.readouterr().out) == []
