"""DHCP operational authorization, signaling and interface ownership checks."""

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import access
from nvyr.helpers.dhcp import DHCP
from nvyr.netlink_daemon import dispatch
from nvyr.op_scripts import dhcp
from tests.test_netlink import backend


@pytest.mark.parametrize(('action', 'signal'), [('release', 'SIGUSR2'), ('renew', 'SIGUSR1')])
def test_signals_only_current_service_main_process(tmp_path, action, signal):
    calls = []
    client = DHCP(tmp_path, run=calls.append)
    client.start('eth1.10', 42, '02:00:00:00:00:01')
    token = client._read('clients', 'eth1.10')['token']
    calls.clear()

    client.control('eth1.10', action, 42, '02:00:00:00:00:01')
    assert calls == [['systemctl', 'kill', '--kill-whom=main', f'--signal={signal}',
                      'nvyr-dhcp4@eth1.10.service']]
    assert client._read('clients', 'eth1.10')['token'] == token


def test_stale_client_and_service_failures_are_reported(tmp_path):
    calls = []
    client = DHCP(tmp_path, run=calls.append)
    with pytest.raises(RouterError, match='no current DHCPv4 client'):
        client.control('eth1', 'release', 1, 'mac')
    client.start('eth1', 1, 'mac')
    calls.clear()
    with pytest.raises(RouterError, match='no current DHCPv4 client'):
        client.control('eth1', 'renew', 2, 'mac')
    with pytest.raises(RouterError, match='no current DHCPv4 client'):
        client.control('eth1', 'renew', 1, 'different')
    assert not calls

    def fail(arguments):
        raise RouterError('Service is not running')

    client.run = fail
    with pytest.raises(RouterError, match='Service is not running'):
        client.control('eth1', 'release', 1, 'mac')


def test_daemon_requires_enabled_owned_client_and_no_recovery(backend, monkeypatch):
    calls = []
    monkeypatch.setattr(backend.dhcp, 'control', lambda *args: calls.append(args), raising=False)
    request = {'version': 1, 'operation': 'dhcp-renew', 'interface': 'eth1'}
    with pytest.raises(RouterError, match='not enabled'):
        dispatch(backend, request)

    backend.replace('ethernet', {'eth1': {'kind': 'ethernet', 'dhcp4': True}})
    device = backend.kernel.device('eth1')
    dispatch(backend, request)
    assert calls == [('eth1', 'renew', device['index'], device['attributes']['mac'])]
    backend.state['pending']['ethernet'] = {}
    with pytest.raises(RouterError, match='recovery is required'):
        dispatch(backend, request)
    backend.state['pending'].clear()

    backend.replace('ethernet', {'eth1': {'kind': 'ethernet', 'dhcp4': True, 'disabled': True}})
    with pytest.raises(RouterError, match='not enabled'):
        dispatch(backend, request)
    assert len(calls) == 1


@pytest.mark.parametrize('action', ['release', 'renew'])
def test_script_requests_action_and_reports_request(monkeypatch, capsys, action):
    requests = []
    monkeypatch.setattr(dhcp.manager, 'request', lambda op, **args: requests.append((op, args)))
    getattr(dhcp, action)('br0')
    assert requests == [(f'dhcp-{action}', {'interface': 'br0'})]
    assert 'requested on br0' in capsys.readouterr().out


@pytest.mark.parametrize('action', ['release', 'renew'])
def test_cli_access_arguments_and_completion(controller, session, monkeypatch, action):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError, match='requires net-admin'):
            controller.execute(f'{action} dhcp interface eth1')
    finally:
        access.role.reset(token)
    assert not calls

    token = access.role.set('net-admin')
    try:
        controller.execute(f'{action} dhcp interface eth1')
        controller.execute(f'run {action} dhcp interface eth1', session)
        assert calls == [['dhcp.nvyr.op', action, 'eth1']] * 2
        controller.operational.suggestors['interfaces'] = lambda: ['eth1', 'br0', 'eth1.10']
        choices = dict(controller.completion(f'{action} dhcp interface ', explicit=True)['candidates'])
        assert {'eth1', 'br0', 'eth1.10'} <= choices.keys()
    finally:
        access.role.reset(token)
