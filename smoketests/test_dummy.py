"""Dummy interface features exercised through configd and native kernel state."""

import pytest

if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_config_commit_rejected, assert_link, assert_link_absent,
    assert_configured_link_addresses, assert_raises,
)
from smoketests.interface_support import interface_case, interface_suite


@pytest.fixture(scope='module')
def dummy_suite(config, request):
    """Create the baseline once; remove the test device after this script finishes."""
    with interface_suite(config, request, {'dummy': ['dum990']},
                         ['set interfaces dummy dum990']) as reset:
        yield reset


@pytest.fixture(autouse=True)
def dummy_environment(request, dummy_suite):
    """Reset configuration between functions while retaining the native dummy."""
    with interface_case(request, dummy_suite):
        yield


def test_create_and_delete(config):
    """An empty instance creates an up dummy with the direct MTU default."""
    assert_link('dum990', kind='dummy', mtu=1500, up=True)

    config.delete('delete interfaces dummy dum990')
    config.commit()

    assert_link_absent('dum990')


def test_ipv4_addresses(config):
    """Multiple IPv4 prefixes coexist; deleting one retains the other."""
    config.set('set interfaces dummy dum990 address 198.18.110.1/24')
    config.set('set interfaces dummy dum990 address 198.18.111.1/24')
    config.commit()

    assert_configured_link_addresses('dum990', '198.18.110.1/24', '198.18.111.1/24')

    config.delete('delete interfaces dummy dum990 address 198.18.110.1/24')
    config.commit()

    assert_configured_link_addresses('dum990', '198.18.111.1/24', absent=('198.18.110.1/24',))


def test_ipv6_addresses(config):
    """Multiple IPv6 prefixes coexist and individual deletion reaches the kernel."""
    config.set('set interfaces dummy dum990 address 2001:db8:110::1/64')
    config.set('set interfaces dummy dum990 address 2001:db8:111::1/64')
    config.commit()

    assert_configured_link_addresses('dum990', '2001:db8:110::1/64', '2001:db8:111::1/64')

    config.delete('delete interfaces dummy dum990 address 2001:db8:110::1/64')
    config.commit()

    assert_configured_link_addresses('dum990', '2001:db8:111::1/64', absent=('2001:db8:110::1/64',))


def test_mtu_and_default(config):
    """Removing an explicit MTU reapplies the direct default."""
    config.set('set interfaces dummy dum990 mtu 9000')
    config.commit()

    assert_link('dum990', mtu=9000)

    config.delete('delete interfaces dummy dum990 mtu')
    config.commit()

    assert_link('dum990', mtu=1500)


def test_mac_and_baseline(config):
    """Removing an override restores the device's original generated MAC."""
    original = assert_link('dum990')['address']

    config.set('set interfaces dummy dum990 mac 02:00:00:00:11:01')
    config.commit()

    assert_link('dum990', mac='02:00:00:00:11:01')

    config.delete('delete interfaces dummy dum990 mac')
    config.commit()

    assert_link('dum990', mac=original)


def test_description(config):
    """Descriptions become Linux interface aliases and can be removed."""
    config.set('set interfaces dummy dum990 description "Dummy smoketest link"')
    config.commit()

    assert_link('dum990', description='Dummy smoketest link')

    config.delete('delete interfaces dummy dum990 description')
    config.commit()

    assert_link('dum990', description='')


def test_disable_and_reenable(config):
    """Disabling withdraws addresses; enabling reinstalls the retained configuration."""
    config.set('set interfaces dummy dum990 address 198.18.110.1/24')
    config.set('set interfaces dummy dum990 disable')
    config.commit()

    assert_link('dum990', up=False)
    assert_configured_link_addresses('dum990', absent=('198.18.110.1/24',))

    config.delete('delete interfaces dummy dum990 disable')
    config.commit()

    assert_link('dum990', up=True)
    assert_configured_link_addresses('dum990', '198.18.110.1/24')


def test_link_group(config):
    """The unsigned Linux group ID supports its maximum and removal resets zero."""
    config.set('set interfaces dummy dum990 link-group 4294967295')
    config.commit()

    assert_link('dum990', group=4294967295)

    config.delete('delete interfaces dummy dum990 link-group')
    config.commit()

    assert_link('dum990', group=0)


def test_vrf_attach_move_and_detach(config):
    """Moving an interface preserves addresses while changing its routing domain."""
    config.set('set vrf name NVYRIFSMOKE table 41010')
    config.set('set vrf name NVYRIFSMOKE2 table 41011')
    config.set('set interfaces dummy dum990 address 198.18.110.1/24')
    config.set('set interfaces dummy dum990 vrf NVYRIFSMOKE')
    config.commit()

    assert_link('dum990', master='NVYRIFSMOKE')

    config.set('set interfaces dummy dum990 vrf NVYRIFSMOKE2')
    config.commit()

    assert_link('dum990', master='NVYRIFSMOKE2')
    assert_configured_link_addresses('dum990', '198.18.110.1/24')

    config.delete('delete interfaces dummy dum990 vrf')
    config.commit()

    assert_link('dum990', master='')
    assert_configured_link_addresses('dum990', '198.18.110.1/24')


def test_missing_vrf_rejected(config):
    """Verification rejects membership in a VRF absent from the proposed config."""
    config.set('set interfaces dummy dum990 vrf NVYRIFSMOKE')

    assert_config_commit_rejected(config, 'not configured')
    assert_link('dum990', master='')


def test_invalid_address_rejected(config):
    """The schema rejects malformed addresses at command entry."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set interfaces dummy dum990 address 192.0.2.256/24')


def test_invalid_mtu_rejected(config):
    """An MTU below the supported IPv6 minimum never reaches apply."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set interfaces dummy dum990 mtu 1279')


def test_multicast_mac_rejected(config):
    """Interface MAC addresses must be unicast."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set interfaces dummy dum990 mac 01:00:5e:00:00:01')


def test_dhcp_rejected(config):
    """Dummy interfaces deliberately support static addresses only."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set interfaces dummy dum990 address dhcp')
