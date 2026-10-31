"""DHCP option validation, wire encodings and local lease policy."""

import time

import pytest

from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import dhcp_options, interfaces
from nvyr.helpers.dhcp import DHCP, lease_event
from tests.test_netlink import backend


def test_wire_options_encode_identifiers_and_rfc3004_user_class(monkeypatch):
    monkeypatch.setattr(dhcp_options.socket, 'gethostname', lambda: 'router')
    options = dhcp_options.normalize({'client-id': {'text': 'WAN client'}, 'host-name': 'edge.example',
                                      'vendor-class-id': 'ISP:vendor', 'user-class': 'customer'})
    arguments = dhcp_options.client_arguments('eth1', options)
    assert '61:0057414e20636c69656e74' in arguments
    assert '12:656467652e6578616d706c65' in arguments
    assert arguments[arguments.index('-V') + 1] == 'ISP:vendor'
    assert '77:08637573746f6d6572' in arguments
    assert '12:726f75746572' in dhcp_options.client_arguments('eth1', {})
    assert '61:01020000000001' in dhcp_options.client_arguments('eth1', {'client-id': {'hex': '01:02:00:00:00:00:01'}})


@pytest.mark.parametrize('options', [
    {'client-id': {}}, {'client-id': {'text': 'x', 'hex': '00:01'}},
    {'client-id': {'hex': '01'}}, {'client-id': {'hex': '00:zz'}},
    {'client-id': {'text': 'é' * 128}}, {'user-class': 'x' * 255},
    {'vendor-class-id': 'x' * 256}, {'host-name': 'bad name'}, {'host-name': 'x\0y'},
    {'default-route-distance': 0}, {'default-route-distance': 255},
    {'default-route-distance': True}, {'mtu': False}, {'reject': '192.0.2.1'},
])
def test_invalid_options_rejected(options):
    with pytest.raises(ValidationError):
        dhcp_options.normalize(options)


def test_route_policy_changes_do_not_restart_client_but_identity_changes_do(tmp_path):
    calls = []
    client = DHCP(tmp_path, run=calls.append)
    client.start('eth1', 2, 'mac', {})
    token = client._read('clients', 'eth1')['token']
    calls.clear()
    client.start('eth1', 2, 'mac', {'default-route-distance': 10, 'no-default-route': True, 'mtu': True})
    assert not calls
    assert client._read('clients', 'eth1')['token'] == token

    client.start('eth1', 2, 'mac', {'user-class': 'new-class'})
    assert client._read('clients', 'eth1')['token'] != token
    assert calls[0] == ['systemctl', 'stop', 'nvyr-dhcp4@eth1.service']


def test_combined_identity_size_cannot_overflow_client_packet():
    with pytest.raises(ValidationError, match='identity options require.*maximum 240'):
        dhcp_options.normalize({'host-name': 'edge', 'client-id': {'text': 'x' * 100},
                                'vendor-class-id': 'v' * 100, 'user-class': 'u' * 100})


def test_default_distance_and_no_default_route_cover_classless_and_router_options():
    environment = {'NVYR_DHCP_TOKEN': 'test', 'NVYR_DHCP_INDEX': '2', 'ip': '192.0.2.2',
                   'subnet': '255.255.255.0', 'lease': '300', 'router': '192.0.2.1', 'mtu': '1400'}
    lease = lease_event('bound', environment)
    assert dhcp_options.lease_routes(lease, {})[0]['metric'] == (210 << 24) | 1026
    assert dhcp_options.lease_routes(lease, {'default-route-distance': 10})[0]['metric'] == (10 << 24) | 1026
    assert not dhcp_options.lease_routes(lease, {'no-default-route': True})
    assert lease['routes'][0]['metric'] == 1026  # Policy never changes the lease record.
    assert lease['mtu'] == 1400

    lease = lease_event('bound', environment | {'staticroutes': '0.0.0.0/0 192.0.2.1 198.51.100.0/24 192.0.2.1'})
    routes = dhcp_options.lease_routes(lease, {'no-default-route': True})
    assert [route['dst'] for route in routes] == ['198.51.100.0/24']


def test_leased_mtu_restored_on_option_removal_and_expiration(backend, monkeypatch):
    definition = {'kind': 'ethernet', 'dhcp4': True, 'attributes': {'mtu': 1500},
                  'dhcp-options': {'mtu': True}}
    backend.dhcp.events['eth1'] = {'address': '192.0.2.2/24', 'routes': [], 'mtu': 1400,
                                  'expires': time.monotonic() + 300}
    backend.replace('ethernet', {'eth1': definition})
    assert backend.kernel.device('eth1')['attributes']['mtu'] == 1400

    writes = []
    original = backend.kernel.link
    monkeypatch.setattr(backend.kernel.ipr, 'link', lambda *args, **kwargs: (writes.append(kwargs), original(*args, **kwargs)))
    backend.reconcile()
    assert not any('mtu' in write for write in writes)

    definition['dhcp-options'] = {}
    backend.replace('ethernet', {'eth1': definition})
    assert backend.kernel.device('eth1')['attributes']['mtu'] == 1500
    definition['dhcp-options'] = {'mtu': True}
    backend.replace('ethernet', {'eth1': definition})
    backend.dhcp.events.clear()
    backend.reconcile()
    assert backend.kernel.device('eth1')['attributes']['mtu'] == 1500


def test_invalid_server_mtu_is_reported(backend):
    backend.dhcp.events['eth1'] = {'address': '192.0.2.2/24', 'routes': [], 'mtu': 900,
                                  'expires': time.monotonic() + 300}
    with pytest.raises(RouterError, match='DHCP MTU must be between'):
        backend.replace('ethernet', {'eth1': {'kind': 'ethernet', 'dhcp4': True, 'dhcp-options': {'mtu': True}}})


@pytest.mark.parametrize('path', [
    'interfaces ethernet eth1', 'interfaces bridge br1',
    'interfaces ethernet eth1 vif 10', 'interfaces virtual-ethernet veth1 vif 10',
    'interfaces bridge br1 vif 10',
])
def test_shared_schema_options_and_anchoring(controller, session, engine, path):
    controller.execute(f'set {path} address dhcp dhcp-options host-name edge user-class customer vendor-class-id ISP mtu no-default-route', session)
    controller.execute(f'set {path} dhcp-options client-id text "WAN client"', session)
    values = engine.view(session)
    # Walk the explicit candidate; defaults are tested through the shared model below.
    for part in path.split():
        values = values[part]
    options = interfaces.settings({'test': values})['test'].dhcp_options
    assert options['host-name'] == 'edge'
    assert options['client-id'] == {'text': 'WAN client'}
    assert options['default-route-distance'] == 210


def test_cli_invalid_distance_and_hex_rejected(controller, session):
    with pytest.raises(ValidationError):
        controller.execute('set interfaces ethernet eth1 dhcp-options default-route-distance 255', session)
    with pytest.raises(ValidationError):
        controller.execute('set interfaces ethernet eth1 dhcp-options client-id hex 01:zz', session)
