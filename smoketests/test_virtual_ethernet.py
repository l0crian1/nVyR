"""Virtual Ethernet pairs, independent endpoints, and pair verification."""

import pytest

if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_config_commit_rejected, assert_link, assert_link_absent,
    assert_configured_link_addresses, assert_raises, assert_equal, assert_vlan,
)
from smoketests.interface_support import interface_case, interface_suite


@pytest.fixture(scope='module')
def virtual_ethernet_suite(config, request):
    """Reserve all endpoint names and keep one reciprocal pair for this script."""
    commands = [
        'set interfaces virtual-ethernet veth990 peer-name veth991',
        'set interfaces virtual-ethernet veth991 peer-name veth990',
    ]
    with interface_suite(config, request, {'virtual-ethernet': ['veth990', 'veth991', 'veth992']},
                         commands) as reset:
        yield reset


@pytest.fixture(autouse=True)
def virtual_ethernet_environment(request, virtual_ethernet_suite):
    """Clear endpoint settings after every function without replacing the pair."""
    with interface_case(request, virtual_ethernet_suite):
        yield


def test_pair_creation_and_deletion(config):
    """Both native endpoints are connected and removed by one configuration commit."""
    assert_link('veth990', kind='veth', peer='veth991', up=True)
    assert_link('veth991', kind='veth', peer='veth990', up=True)

    config.delete('delete interfaces virtual-ethernet veth990')
    config.delete('delete interfaces virtual-ethernet veth991')
    config.commit()

    assert_link_absent('veth990')
    assert_link_absent('veth991')


def test_ipv4_addresses(config):
    """Endpoint IPv4 addresses are independent and individual prefixes can be removed."""
    config.set('set interfaces virtual-ethernet veth990 address 198.18.110.0/31')
    config.set('set interfaces virtual-ethernet veth991 address 198.18.110.1/31')
    config.commit()

    assert_configured_link_addresses('veth990', '198.18.110.0/31')
    assert_configured_link_addresses('veth991', '198.18.110.1/31')

    config.delete('delete interfaces virtual-ethernet veth990 address 198.18.110.0/31')
    config.commit()

    assert_configured_link_addresses('veth990', absent=('198.18.110.0/31',))
    assert_configured_link_addresses('veth991', '198.18.110.1/31')


def test_ipv6_addresses(config):
    """Each endpoint supports IPv6 and removal does not affect its peer's prefix."""
    config.set('set interfaces virtual-ethernet veth990 address 2001:db8:110::/127')
    config.set('set interfaces virtual-ethernet veth991 address 2001:db8:110::1/127')
    config.commit()

    assert_configured_link_addresses('veth990', '2001:db8:110::/127')
    assert_configured_link_addresses('veth991', '2001:db8:110::1/127')

    config.delete('delete interfaces virtual-ethernet veth990 address 2001:db8:110::/127')
    config.commit()

    assert_configured_link_addresses('veth990', absent=('2001:db8:110::/127',))


def test_endpoint_attributes(config):
    """MTU, MAC, alias and link-group apply to the specified endpoint."""
    config.set('set interfaces virtual-ethernet veth990 mtu 9000 mac 02:00:00:00:11:02')
    config.set('set interfaces virtual-ethernet veth990 description "Veth smoketest" link-group 101')
    config.commit()

    assert_link('veth990', mtu=9000, mac='02:00:00:00:11:02', description='Veth smoketest', group=101)
    assert_link('veth991', mtu=1500, description='', group=0)


def test_attribute_removal(config):
    """Removing overrides restores original attributes without replacing the pair."""
    original = assert_link('veth990')['address']

    config.set('set interfaces virtual-ethernet veth990 mtu 9000 mac 02:00:00:00:11:02')
    config.set('set interfaces virtual-ethernet veth990 description "Veth smoketest" link-group 101')
    config.commit()

    config.delete('delete interfaces virtual-ethernet veth990 mtu')
    config.delete('delete interfaces virtual-ethernet veth990 mac')
    config.delete('delete interfaces virtual-ethernet veth990 description')
    config.delete('delete interfaces virtual-ethernet veth990 link-group')
    config.commit()

    assert_link('veth990', mtu=1500, mac=original, description='', group=0, peer='veth991')


def test_disable_and_reenable(config):
    """Administrative disable affects one endpoint while retaining the pair."""
    config.set('set interfaces virtual-ethernet veth990 disable')
    config.commit()

    assert_link('veth990', up=False, peer='veth991')
    assert_link('veth991', up=True, peer='veth990')

    config.delete('delete interfaces virtual-ethernet veth990 disable')
    config.commit()

    assert_link('veth990', up=True)


def test_missing_peer_rejected(config):
    """An endpoint requires an explicit peer-name before application."""
    config.delete('delete interfaces virtual-ethernet veth990 peer-name')
    assert_config_commit_rejected(config, 'peer-name is required')


def test_self_peer_rejected(config):
    """A new endpoint cannot refer to itself."""
    config.set('set interfaces virtual-ethernet veth992 peer-name veth992')

    assert_config_commit_rejected(config, 'own peer')


def test_unpaired_endpoint_rejected(config):
    """The other endpoint must exist and point back to the new endpoint."""
    config.set('set interfaces virtual-ethernet veth992 peer-name veth990')

    assert_config_commit_rejected(config, 'configure virtual-ethernet')


def test_single_endpoint_deletion_rejected(config):
    """Deleting one endpoint must not silently delete the still-configured peer."""
    config.delete('delete interfaces virtual-ethernet veth990')
    assert_config_commit_rejected(config, 'configure virtual-ethernet')
    assert_link('veth990', peer='veth991')
    assert_link('veth991', peer='veth990')


def test_peer_change_rejected(config):
    """A different reciprocal pair still requires a separately committed deletion."""
    config.delete('delete interfaces virtual-ethernet veth991')
    config.set('set interfaces virtual-ethernet veth990 peer-name veth992')
    config.set('set interfaces virtual-ethernet veth992 peer-name veth990')

    assert_config_commit_rejected(config, 'delete and commit the pair')


def test_missing_vrf_rejected(config):
    """VRF membership is validated independently of valid pair definitions."""
    config.set('set interfaces virtual-ethernet veth990 vrf NVYRIFSMOKE')

    assert_config_commit_rejected(config, 'not configured')


def test_invalid_peer_name_rejected(config):
    """Peer names follow the virtual Ethernet naming policy."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set interfaces virtual-ethernet veth990 peer-name eth0')


def test_vif_attributes_and_mtu_inheritance(config):
    """VLAN settings stay on the child and parent/child indices survive changes."""
    parent_index = assert_link('veth990')['ifindex']
    config.set('set interfaces virtual-ethernet veth990 mtu 9000 vif 10 description "Tagged users" link-group 42')
    config.commit()
    child_index = assert_vlan('veth990.10', 'veth990', 10, mtu=9000, description='Tagged users', group=42)['ifindex']

    config.set('set interfaces virtual-ethernet veth990 vif 10 mtu 1400 mac 02:00:00:00:11:10 disable')
    config.commit()
    assert_vlan('veth990.10', 'veth990', 10, mtu=1400, mac='02:00:00:00:11:10', up=False)

    config.delete('delete interfaces virtual-ethernet veth990 vif 10 mtu')
    config.delete('delete interfaces virtual-ethernet veth990 vif 10 disable')
    config.commit()
    assert_equal(assert_vlan('veth990.10', 'veth990', 10, mtu=9000, up=True)['ifindex'], child_index)
    assert_equal(assert_link('veth990')['ifindex'], parent_index)


def test_vif_parent_deletion(config):
    """Removing the pair removes both endpoints' children in the same commit."""
    config.set('set interfaces virtual-ethernet veth990 vif 10')
    config.set('set interfaces virtual-ethernet veth991 vif 10')
    config.commit()

    config.delete('delete interfaces virtual-ethernet veth990')
    config.delete('delete interfaces virtual-ethernet veth991')
    config.commit()
    assert_link_absent('veth990.10')
    assert_link_absent('veth991.10')


def test_vif_oversized_mtu_rejected(config):
    """An explicit child MTU cannot exceed its parent's configured MTU."""
    config.set('set interfaces virtual-ethernet veth990 vif 10 mtu 9000')
    assert_config_commit_rejected(config, 'MTU cannot exceed parent')


def test_vif_missing_vrf_rejected(config):
    """Child membership must resolve even when the parent has no VRF."""
    config.set('set interfaces virtual-ethernet veth990 vif 10 vrf NVYRIFSMOKE')
    assert_config_commit_rejected(config, 'not configured')


def test_vif_reserved_tag_rejected(config):
    """The reserved 4095 tag cannot enter the candidate configuration."""
    with assert_raises(RouterError, match='Invalid value'):
        config.set('set interfaces virtual-ethernet veth990 vif 4095')
