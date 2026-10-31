"""VRF device lifecycle, routing-table selection, and validation."""

import pytest

if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_config_commit_rejected, assert_kernel_route, assert_link, assert_link_absent,
    assert_configured_link_addresses, assert_raises, assert_vrf_conntrack_zone, assert_equal,
    assert_not_equal,
)
from smoketests.interface_support import interface_test


@pytest.fixture(autouse=True)
def vrf_environment(config, request):
    """Reserve fresh VRFs and a CLI-owned member without changing existing VRFs."""
    with interface_test(config, request, {'dummy': ['dum990']}):
        yield


def test_create_multiple_and_delete(config):
    """Each configured name creates an independent up VRF with its requested table."""
    config.set('set vrf name NVYRIFSMOKE table 41010')
    config.set('set vrf name NVYRIFSMOKE2 table 41011')
    config.commit()

    assert_link('NVYRIFSMOKE', kind='vrf', up=True, table=41010)
    assert_link('NVYRIFSMOKE2', kind='vrf', up=True, table=41011)


    config.delete('delete vrf name NVYRIFSMOKE')
    config.commit()

    assert_link_absent('NVYRIFSMOKE')
    assert_link('NVYRIFSMOKE2', table=41011)


def test_automatic_conntrack_zones_and_membership(config):
    """VRF identities stay stable while members attach, move and detach."""
    config.set('set vrf name NVYRIFSMOKE table 41010')
    config.set('set vrf name NVYRIFSMOKE2 table 41011')
    config.set('set interfaces dummy dum990 vrf NVYRIFSMOKE')
    config.commit()

    first = assert_vrf_conntrack_zone('NVYRIFSMOKE', 'dum990')
    second = assert_vrf_conntrack_zone('NVYRIFSMOKE2')
    assert_not_equal(first, second)

    config.set('set interfaces dummy dum990 vrf NVYRIFSMOKE2')
    config.commit()
    assert_equal(assert_vrf_conntrack_zone('NVYRIFSMOKE'), first)
    assert_equal(assert_vrf_conntrack_zone('NVYRIFSMOKE2', 'dum990'), second)

    config.delete('delete interfaces dummy dum990 vrf')
    config.commit()
    assert_vrf_conntrack_zone('NVYRIFSMOKE2', absent=('dum990',))


def test_ipv4_connected_route(config):
    """A member's connected IPv4 route belongs to the selected VRF table."""
    config.set('set vrf name NVYRIFSMOKE table 41010')
    config.set('set interfaces dummy dum990 vrf NVYRIFSMOKE address 198.18.110.1/24')
    config.commit()

    assert_link('dum990', master='NVYRIFSMOKE')
    assert_kernel_route('198.18.110.0/24', 'dev dum990', vrf='NVYRIFSMOKE')


def test_ipv6_connected_route(config):
    """A member's connected IPv6 route belongs to the selected VRF table."""
    config.set('set vrf name NVYRIFSMOKE table 41010')
    config.set('set interfaces dummy dum990 vrf NVYRIFSMOKE address 2001:db8:110::1/64')
    config.commit()

    assert_configured_link_addresses('dum990', '2001:db8:110::1/64')
    assert_kernel_route('2001:db8:110::/64', 'dev dum990', vrf='NVYRIFSMOKE')


def test_member_prevents_deletion(config):
    """The dependency registrar rejects deleting a VRF still used by an interface."""
    config.set('set vrf name NVYRIFSMOKE table 41010')
    config.set('set interfaces dummy dum990 vrf NVYRIFSMOKE')
    config.commit()

    with assert_raises(RouterError, match='referenced'):
        config.delete('delete vrf name NVYRIFSMOKE')


def test_detach_then_delete(config):
    """Removing membership releases the reference and leaves the member in default VRF."""
    config.set('set vrf name NVYRIFSMOKE table 41010')
    config.set('set interfaces dummy dum990 vrf NVYRIFSMOKE')
    config.commit()

    config.delete('delete interfaces dummy dum990 vrf')
    config.commit()

    config.delete('delete vrf name NVYRIFSMOKE')
    config.commit()

    assert_link('dum990', master='')
    assert_link_absent('NVYRIFSMOKE')


def test_missing_table_rejected(config):
    """An empty VRF instance lacks the required routing-table identifier."""
    config.set('set vrf name NVYRIFSMOKE')

    assert_config_commit_rejected(config, 'routing table is required')
    assert_link_absent('NVYRIFSMOKE')


def test_duplicate_table_rejected(config):
    """Two names cannot claim the same routing table in one candidate."""
    config.set('set vrf name NVYRIFSMOKE table 41010')
    config.set('set vrf name NVYRIFSMOKE2 table 41010')

    assert_config_commit_rejected(config, 'already configured for VRF')
    assert_link_absent('NVYRIFSMOKE')
    assert_link_absent('NVYRIFSMOKE2')


def test_table_change_rejected(config):
    """Changing an existing table requires deleting and committing the VRF first."""
    config.set('set vrf name NVYRIFSMOKE table 41010')
    config.commit()

    config.set('set vrf name NVYRIFSMOKE table 41011')

    assert_config_commit_rejected(config, 'table cannot be changed in place')
    assert_link('NVYRIFSMOKE', table=41010)


def test_recreate_with_different_table(config):
    """A separately committed deletion permits reuse of the name with a new table."""
    config.set('set vrf name NVYRIFSMOKE table 41010')
    config.commit()

    config.delete('delete vrf name NVYRIFSMOKE')
    config.commit()

    config.set('set vrf name NVYRIFSMOKE table 41011')
    config.commit()

    assert_link('NVYRIFSMOKE', table=41011)


def test_reserved_table_rejected(config):
    """The discontiguous table validator excludes Linux's reserved table IDs."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set vrf name NVYRIFSMOKE table 254')


def test_low_table_rejected(config):
    """IDs below nVyR's permitted VRF range are rejected during command entry."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set vrf name NVYRIFSMOKE table 99')


def test_overflow_table_rejected(config):
    """Routing tables cannot exceed the unsigned 32-bit kernel identifier."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set vrf name NVYRIFSMOKE table 4294967296')


def test_reserved_name_rejected(config):
    """The built-in default routing domain cannot be created as a named VRF."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set vrf name default table 41010')
