"""Require the approved inputs and keep a lab run away from management resources."""

import json
from pathlib import Path

import pytest

from acceptance import baseline


OPTIONS = {'ethernet': 'eth1', 'image': 'alpine', 'assets': 'boot-00000000-0000-0000-0000-000000000001'}


@pytest.fixture
def inventory(monkeypatch):
    state = {'links': [
        {'ifname': 'eth0', 'link_type': 'ether', 'addr_info': [{'local': '10.0.101.28', 'prefixlen': 24}]},
        {'ifname': 'eth1', 'link_type': 'ether', 'addr_info': []},
    ], 'routes': [{'dst': 'default', 'gateway': '10.0.101.1'}], 'routes6': [], 'calls': []}

    def command(argv):
        state['calls'].append(argv)
        if argv[0] == 'ip':
            if 'address' in argv:
                return json.dumps(state['links'])
            return json.dumps(state['routes6'] if '-6' in argv else state['routes'])
        return '[]'

    exists = Path.exists
    monkeypatch.setattr(Path, 'exists', lambda path: True if path == Path('/sys/class/net/eth1/device') else exists(path))
    monkeypatch.setattr(baseline, 'cmd', command)
    return state


def test_preflight_requires_explicit_spare_and_preloaded_image(inventory):
    baseline.preflight({'interfaces': {'ethernet': {'eth0': {'address': ['10.0.101.28/24']}}}}, OPTIONS)
    assert ['podman', 'image', 'inspect', 'alpine'] in inventory['calls']
    assert not any('pull' in command for command in inventory['calls'])
    with pytest.raises(ValueError, match='spare physical'):
        baseline.preflight({}, {**OPTIONS, 'ethernet': ''})


def test_preflight_refuses_management_port(inventory):
    inventory['links'][1]['addr_info'] = [{'local': '10.0.101.28', 'prefixlen': 24}]
    with pytest.raises(ValueError, match='management port'):
        baseline.preflight({}, OPTIONS)


def test_preflight_refuses_existing_policy(inventory):
    with pytest.raises(ValueError, match='clean lab firewall'):
        baseline.preflight({'firewall': {'ipv4': {'input': {}}}}, OPTIONS)


def test_preflight_refuses_native_address_and_route_collisions(inventory):
    inventory['links'][0]['addr_info'] = [{'local': '198.18.196.5', 'prefixlen': 24}]
    with pytest.raises(ValueError, match='address space already in use'):
        baseline.preflight({}, OPTIONS)
    inventory['links'][0]['addr_info'] = []
    inventory['routes'] = [{'dst': '198.18.195.0/24'}]
    with pytest.raises(ValueError, match='overlaps route'):
        baseline.preflight({}, OPTIONS)


def test_preflight_refuses_port_consumers_even_without_an_address(inventory):
    with pytest.raises(ValueError, match='spare port'):
        baseline.preflight({'interfaces': {'ethernet': {'eth1': {'vrf': 'RED'}}}}, OPTIONS)


def test_preflight_allows_kernel_ipv6_routes_on_spare_port(inventory):
    """A carrier-up spare port naturally has these routes before the test starts."""
    inventory['links'][1]['addr_info'] = [{'local': 'fe80::5a47:caff:fe74:f250', 'prefixlen': 64}]
    inventory['routes6'] = [
        {'dst': 'fe80::/64', 'dev': 'eth1', 'protocol': 'kernel', 'metric': 256},
        {'type': 'anycast', 'dst': 'fe80::', 'dev': 'eth1', 'table': 'local', 'protocol': 'kernel'},
        {'type': 'local', 'dst': 'fe80::5a47:caff:fe74:f250', 'dev': 'eth1', 'table': 'local', 'protocol': 'kernel'},
        {'type': 'multicast', 'dst': 'ff00::/8', 'dev': 'eth1', 'table': 'local', 'protocol': 'kernel'},
    ]

    baseline.preflight({}, OPTIONS)


def test_preflight_refuses_static_link_local_route(inventory):
    inventory['routes6'] = [{'dst': 'fe80::/64', 'dev': 'eth1', 'protocol': 'static'}]

    with pytest.raises(ValueError, match='spare port eth1 already has routes'):
        baseline.preflight({}, OPTIONS)


def test_preflight_refuses_ipv6_default_route(inventory):
    inventory['routes6'] = [{'dst': 'default', 'dev': 'eth1', 'gateway': 'fe80::1', 'protocol': 'ra'}]

    with pytest.raises(ValueError, match='spare port eth1 already has routes'):
        baseline.preflight({}, OPTIONS)


def test_preflight_refuses_kernel_global_ipv6_route(inventory):
    inventory['routes6'] = [{'dst': '2001:db8:50::/64', 'dev': 'eth1', 'protocol': 'kernel'}]

    with pytest.raises(ValueError, match='spare port eth1 already has routes'):
        baseline.preflight({}, OPTIONS)


def test_preflight_refuses_ipv4_link_local_route(inventory):
    inventory['routes'] = [{'dst': '169.254.0.0/16', 'dev': 'eth1', 'protocol': 'kernel'}]

    with pytest.raises(ValueError, match='spare port eth1 already has routes'):
        baseline.preflight({}, OPTIONS)


def test_preflight_refuses_reserved_table_even_for_automatic_route(inventory):
    inventory['routes6'] = [{'dst': 'fe80::/64', 'dev': 'eth1', 'table': 41995, 'protocol': 'kernel'}]

    with pytest.raises(ValueError, match='VRF table already has routes'):
        baseline.preflight({}, OPTIONS)


def test_preflight_refuses_link_local_route_in_custom_table(inventory):
    inventory['routes6'] = [{'dst': 'fe80::/64', 'dev': 'eth1', 'table': 100, 'protocol': 'kernel'}]

    with pytest.raises(ValueError, match='spare port eth1 already has routes'):
        baseline.preflight({}, OPTIONS)


def test_preflight_refuses_link_local_route_with_gateway(inventory):
    inventory['routes6'] = [{'dst': 'fe80::/64', 'dev': 'eth1', 'gateway': 'fe80::1', 'protocol': 'kernel'}]

    with pytest.raises(ValueError, match='spare port eth1 already has routes'):
        baseline.preflight({}, OPTIONS)


def test_every_fixture_is_literal_cli_with_only_approved_placeholders():
    commands = list(baseline.commands(OPTIONS))
    assert len(commands) > 300
    assert all(line.startswith('set ') and '@' not in line for _, _, line in commands)
    assert {filename for filename, _, _ in commands} == set(baseline.CONFIG_FILES)
