"""Reject self-peering without preventing peers in separate routing domains."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.config_session import CommitError
from nvyr.helpers.process import cmd
from nvyr.tree import lookup
from smoketests.assertions import (
    assert_bgp_commands, assert_config_names_unused, assert_not_in, assert_raises, link_inventory,
)
from smoketests.support import configuration_case, prepared_test
from smoketests.test_bgp import bgp_suite


@pytest.fixture(scope='module')
def neighbor_suite(config, request, bgp_suite):
    """Retain the dummy and VRF across self-peering checks; no live peers are needed."""
    assert_config_names_unused(config.get_config(), 'dum41040')
    assert_config_names_unused(config.get_config(), 'dum41041')
    assert_not_in('dum41040', link_inventory())
    assert_not_in('dum41041', link_inventory())

    def standup(session):
        session.set('set interfaces dummy dum41040 vrf NVYRBGP')
        session.commit()

        # Runtime-only addresses must not race netlinkd restoring a managed link.
        cmd(['ip', 'link', 'add', 'dum41041', 'type', 'dummy'])
        cmd(['ip', 'link', 'set', 'dum41041', 'master', 'NVYRBGP', 'up'])

    def cleanup(session):
        session.discard()
        if 'dum41041' in link_inventory():
            cmd(['ip', 'link', 'delete', 'dum41041'])

        if lookup(session.get_config(), ('interfaces', 'dummy', 'dum41040'), None) is not None:
            session.delete('delete interfaces dummy dum41040')
            session.commit()

    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, standup, cleanup, stop=stop):
        yield config.get_config()


@pytest.fixture(autouse=True)
def neighbor_interfaces(config, request, neighbor_suite):
    """Reset addresses and membership without removing the dummy between cases."""
    with configuration_case(config, request, neighbor_suite):
        yield


def test_ipv4_configured_local_neighbor_rejected(config):
    """Addresses added in the same commit cannot become local IPv4 peers."""
    config.set('set interfaces dummy dum41040 address 198.18.40.1/32')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 198.18.40.1 remote-as 65000')
    with assert_raises(CommitError, match='assigned to the local system in VRF NVYRBGP'):
        config.commit()


def test_ipv6_configured_local_neighbor_rejected(config):
    """Canonical IPv6 comparison rejects an equivalent spelling of a local address."""
    config.set('set interfaces dummy dum41040 address 2001:db8:4040::1/128')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8:4040:0::1 remote-as 65000')
    with assert_raises(CommitError, match='assigned to the local system in VRF NVYRBGP'):
        config.commit()


def test_ipv4_runtime_local_neighbor_rejected(config):
    """An address absent from configuration, like a DHCP lease, is still local."""
    cmd(['ip', 'address', 'add', '198.18.40.1/32', 'dev', 'dum41041'])
    try:
        config.set('set vrf name NVYRBGP protocols bgp neighbor 198.18.40.1 remote-as 65000')
        with assert_raises(CommitError, match='assigned to the local system in VRF NVYRBGP'):
            config.commit()
    finally:
        cmd(['ip', 'address', 'del', '198.18.40.1/32', 'dev', 'dum41041'])


def test_ipv6_runtime_local_neighbor_rejected(config):
    """A runtime-only IPv6 address is checked against its live VRF membership."""
    cmd(['ip', '-6', 'address', 'add', '2001:db8:4040::1/128', 'dev', 'dum41041', 'nodad'])
    try:
        config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8:4040::1 remote-as 65000')
        with assert_raises(CommitError, match='assigned to the local system in VRF NVYRBGP'):
            config.commit()
    finally:
        cmd(['ip', '-6', 'address', 'del', '2001:db8:4040::1/128', 'dev', 'dum41041'])


def test_ipv4_other_vrf_neighbor_allowed(config):
    """A peer address owned by the default VRF remains usable from a named VRF."""
    config.delete('delete interfaces dummy dum41040 vrf')
    config.set('set interfaces dummy dum41040 address 198.18.40.1/32')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 198.18.40.1 remote-as 65000')
    config.commit()
    assert_bgp_commands('neighbor 198.18.40.1 remote-as 65000')


def test_ipv6_other_vrf_neighbor_allowed(config):
    """IPv6 peers in another routing domain are not mistaken for self-peering."""
    config.delete('delete interfaces dummy dum41040 vrf')
    config.set('set interfaces dummy dum41040 address 2001:db8:4040::1/128')
    config.set('set vrf name NVYRBGP protocols bgp neighbor 2001:db8:4040::1 remote-as 65000')
    config.commit()
    assert_bgp_commands('neighbor 2001:db8:4040::1 remote-as 65000')
