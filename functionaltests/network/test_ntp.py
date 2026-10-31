"""Chrony IPv4/IPv6 sources, listeners, clients, statistics, pools and lifecycle.

Compatible listeners and access rules are installed together. Client-only mode,
empty history, listener replacement and VRF binding require service transitions,
but the NTPTEST routing domain and dum977 are retained throughout the package.
"""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.tree import lookup
from nvyr.errors import RouterError
from nvyr.helpers.process import cmd
from smoketests.assertions import (
    assert_config_names_unused, assert_equal, assert_in, assert_ntp_client_access,
    assert_ntp_configuration, assert_ntp_vrf, assert_ntp_serving_activity, assert_raises,
)


def test_ipv4_server_and_client_access(config):
    """IPv4 source/listener configuration starts without requiring a reachable upstream."""
    # Installed once by configs/network-services.conf.
    assert_ntp_configuration('server 192.0.2.123 iburst prefer', 'bindaddress 127.0.0.1')
    assert_ntp_client_access('192.0.2.10', allowed=True)
    assert_ntp_client_access('198.51.100.10', allowed=False)


def test_ipv6_server_and_client_access(config):
    """IPv6 listeners and client networks are independent of IPv4 settings."""
    # Installed once by configs/network-services.conf.
    assert_ntp_configuration('server 2001:db8::123 iburst', 'bindaddress ::1')
    assert_ntp_client_access('2001:db8::10', allowed=True)
    assert_ntp_client_access('2001:db8:1::10', allowed=False)


def test_client_only_and_operational_status(config):
    """A service with no allow-client denies requests and exposes unsynchronized status."""
    config.delete('delete system ntp')
    config.set('set system ntp server 192.0.2.123')
    config.commit()
    assert_ntp_client_access('127.0.0.1', allowed=False)
    assert_in('Status', cmd(['ntp.nvyr.op', 'tracking']))
    assert_in('192.0.2.123', cmd(['ntp.nvyr.op', 'sources']))


def test_ipv4_client_activity_and_server_statistics(config):
    """A real IPv4 client request appears in serving reports without needing an upstream."""
    # Installed once by configs/network-services.conf.

    assert_ntp_serving_activity('127.0.0.1')


def test_ipv6_client_activity_and_server_statistics(config):
    """A real IPv6 request is identified by its numeric address and counted by the server."""
    # Installed once by configs/network-services.conf.

    assert_ntp_serving_activity('::1')


def test_no_ntp_clients_recorded(config):
    """A fresh client-only daemon reports an empty client list, not an error."""
    config.delete('delete system ntp')
    config.set('set system ntp server 192.0.2.123')
    config.commit()

    assert_equal(cmd(['ntp.nvyr.op', 'clients']).strip(), 'No NTP clients recorded.')
    assert_equal(cmd(['ntp.nvyr.op', 'clients', '--raw']).strip(), '[]')


def test_vrf_binding_and_dependency(config):
    """The service binds to an existing VRF which cannot be deleted while referenced."""
    config.delete('delete system ntp')
    config.set('set system ntp vrf NTPTEST')
    config.set('set system ntp listen-address ipv4 198.18.197.1')
    config.set('set system ntp allow-client 198.18.197.0/24')
    config.commit()
    assert_ntp_configuration('binddevice NTPTEST', 'bindacqdevice NTPTEST')
    assert_ntp_vrf('NTPTEST')

    with assert_raises(RouterError, match='referenc'):
        config.delete('delete vrf name NTPTEST')


def test_service_removal(config):
    """Removing the NTP subtree stops the managed daemon without saving anything."""
    # Installed once by configs/network-services.conf.
    assert_ntp_configuration('server 192.0.2.123 iburst prefer')
    config.delete('delete system ntp')
    config.commit()
    assert_equal(cmd(['systemctl', 'show', '--property=ActiveState', '--value', 'nvyr-ntp.service']).strip(), 'inactive')


def test_pool_and_nts_without_dns(config):
    """Unresolvable authenticated sources remain configured without blocking commit."""
    # Installed once by configs/network-services.conf.
    assert_ntp_configuration('server time.example.invalid iburst prefer nts',
                             'pool pool.example.invalid iburst nts')


def test_listener_replacement(config):
    """Setting the same family again replaces its singleton binding."""
    config.set('set system ntp listen-address ipv4 127.0.0.1')
    config.set('set system ntp listen-address ipv4 0.0.0.0')
    config.set('set system ntp allow-client 127.0.0.1')
    config.commit()
    assert_ntp_configuration('bindaddress 0.0.0.0', absent=('bindaddress 127.0.0.1',))
    assert_equal(lookup(config.get_config(), ('system', 'ntp', 'listen-address', 'ipv4')), '0.0.0.0')
