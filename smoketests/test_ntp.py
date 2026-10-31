"""Chrony configuration, client access, VRF binding and validation on a live router."""

from copy import deepcopy

import pytest

if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from nvyr.tree import lookup
from smoketests.assertions import (
    assert_config_commit_rejected, assert_config_names_unused, assert_equal, assert_ntp_directives,
    assert_raises,
)
from smoketests.support import configuration_case, prepared_test


@pytest.fixture(scope='module')
def ntp_suite(config, request):
    """Remove existing NTP configuration once; restore it when this module exits."""
    original = config.get_config()
    baseline = deepcopy(original)
    baseline.get('system', {}).pop('ntp', None)

    def standup(session):
        """Remove only the prior NTP subtree before exercising this feature."""
        session.load(baseline, replace=True)
        session.commit()

    def cleanup(session):
        """Restore the original tree even after a rejected candidate or partial commit."""
        session.discard()
        session.load(original, replace=True)
        session.commit()

    def stop(message):
        """Stop subsequent tests if restoring the router fails."""
        request.session.shouldstop = message

    with prepared_test(config, standup, cleanup, stop=stop):
        yield config.get_config()


@pytest.fixture(autouse=True)
def ntp_environment(config, request, ntp_suite):
    """Restore case settings in one commit while retaining unchanged suite objects."""
    with configuration_case(config, request, ntp_suite):
        yield


def test_pool_and_nts_without_dns(config):
    """Unresolvable authenticated sources remain configured without blocking commit."""
    config.set('set system ntp server time.example.invalid nts prefer')
    config.set('set system ntp pool pool.example.invalid nts')
    config.commit()
    assert_ntp_directives('server time.example.invalid iburst prefer nts',
                             'pool pool.example.invalid iburst nts')


def test_listener_replacement(config):
    """Setting the same family again replaces its singleton binding."""
    config.set('set system ntp listen-address ipv4 127.0.0.1')
    config.set('set system ntp listen-address ipv4 0.0.0.0')
    config.set('set system ntp allow-client 127.0.0.1')
    config.commit()
    assert_ntp_directives('bindaddress 0.0.0.0', absent=('bindaddress 127.0.0.1',))
    assert_equal(lookup(config.get_config(), ('system', 'ntp', 'listen-address', 'ipv4')), '0.0.0.0')


def test_missing_vrf_rejected(config):
    """A dependency reference does not authorize starting in a nonexistent VRF."""
    assert_config_names_unused(config.get_config(), 'NTPMISSING')
    config.set('set system ntp vrf NTPMISSING')
    assert_config_commit_rejected(config, 'VRF is not configured')


def test_unassigned_listener_rejected(config):
    """An explicit listener must be local to the selected routing domain."""
    config.set('set system ntp listen-address ipv4 192.0.2.249')
    assert_config_commit_rejected(config, 'address is not assigned')


def test_ipv4_listener_family_validation(config):
    """An IPv6 address is rejected before entering an IPv4 listener candidate."""
    with assert_raises(RouterError):
        config.set('set system ntp listen-address ipv4 2001:db8::1')


def test_ipv6_listener_family_validation(config):
    """An IPv4 address is rejected before entering an IPv6 listener candidate."""
    with assert_raises(RouterError):
        config.set('set system ntp listen-address ipv6 192.0.2.1')


def test_ipv4_listener_and_client_acl(config):
    """IPv4 source, listener and ACL translate into Chrony directives."""
    config.set('set system ntp server 192.0.2.123 prefer')
    config.set('set system ntp listen-address ipv4 127.0.0.1')
    config.set('set system ntp allow-client 192.0.2.0/24')
    config.commit()

    assert_ntp_directives('server 192.0.2.123 iburst prefer', 'bindaddress 127.0.0.1',
                         'allow 192.0.2.0/24')


def test_ipv6_listener_and_client_acl(config):
    """IPv6 source, listener and ACL translate independently of IPv4."""
    config.set('set system ntp server 2001:db8::123')
    config.set('set system ntp listen-address ipv6 ::1')
    config.set('set system ntp allow-client 2001:db8::/64')
    config.commit()

    assert_ntp_directives('server 2001:db8::123 iburst', 'bindaddress ::1',
                         'allow 2001:db8::/64')


def test_vrf_configuration_and_dependency(config):
    """VRF binding directives and dependency protection need no serving traffic."""
    assert_config_names_unused(config.get_config(), 'NTPTEST', 'dum977')
    config.set('set vrf name NTPTEST table 41977')
    config.set('set interfaces dummy dum977 vrf NTPTEST address 198.18.197.1/24')
    config.set('set system ntp vrf NTPTEST')
    config.set('set system ntp listen-address ipv4 198.18.197.1')
    config.set('set system ntp allow-client 198.18.197.0/24')
    config.commit()

    assert_ntp_directives('binddevice NTPTEST', 'bindacqdevice NTPTEST')
    with assert_raises(RouterError, match='referenc'):
        config.delete('delete vrf name NTPTEST')
