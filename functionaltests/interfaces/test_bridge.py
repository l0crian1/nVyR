"""Bridge DHCP lifecycle, operational tables, addresses, admin state and VIFs.

All address families, bridges, cables and both shared VRFs are configured once.
Each test uses dedicated links/subnets so disabling, moving or changing VLANs
cannot disturb another case. The explicit VRF creation/deletion case alone owns
disposable routing domains. No other case recreates a VRF.
"""

import json
import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.helpers.process import cmd
from nvyr.op_scripts import bridge as bridge_op
from smoketests.assertions import (
    assert_bridge_mac, assert_equal, assert_dhcp_client, assert_link, assert_link_addresses, assert_bridge_vlans,
)


def test_dhcp_client_start_and_stop(config):
    """DHCPv4 uses the bridge device and stops when its address setting is removed."""
    # Installed once by configs/interfaces.conf.
    assert_dhcp_client('br43150', active=True)

    config.delete('delete interfaces bridge br43150 address dhcp')
    config.commit()
    assert_dhcp_client('br43150', active=False)


def test_operational_views_and_clear_preserves_static(config):
    """Operational queries expose native data and clearing learned entries retains policy."""
    # Installed once by configs/interfaces.conf.
    # Exercise installed entry points so raw serialization cannot be bypassed by Python calls.
    records = json.loads(cmd(['bridge.nvyr.op', 'show', '--bridge', 'br43160', '--raw']))
    assert_equal(records[0]['ifname'], 'br43160')
    members = json.loads(cmd(['bridge.nvyr.op', 'show', '--bridge', 'br43160', '--section', 'member', '--raw']))
    assert_equal(len(members), 2)
    bridge_op.show('br43160', section='vlan')
    bridge_op.show('br43160', section='spanning-tree')
    bridge_op.show('br43160', section='mac')
    bridge_op.show('br43160', section='multicast')
    bridge_op.clear('br43160')
    assert_bridge_mac('br43160', '02:00:00:00:99:10', port='dum43160')


def test_ipv4_addresses(config):
    """Bridge IPv4 addresses are installed and individually removable."""
    # Installed once by configs/interfaces.conf.
    assert_link_addresses('br43170', '198.18.34.1/24')
    config.delete('delete interfaces bridge br43170 address 198.18.34.1/24')
    config.commit()
    assert_link_addresses('br43170', absent=('198.18.34.1/24',))


def test_ipv6_addresses(config):
    """Bridge IPv6 addresses complete duplicate-address detection."""
    # Installed once by configs/interfaces.conf.
    assert_link_addresses('br43180', '2001:db8:24::1/64')


def test_disable_and_reenable(config):
    """Disabling removes L3 addresses; enabling restores them on the same bridge."""
    # Installed once by configs/interfaces.conf.
    assert_link('br43190', up=False)
    config.delete('delete interfaces bridge br43190 disable')
    config.commit()
    assert_link('br43190', up=True)
    assert_link_addresses('br43190', '198.18.38.1/24')


def test_ipv4_vif(config):
    """A bridge VIF receives its address and implicit local VLAN membership."""
    # Installed once by configs/interfaces.conf.
    assert_link('br43200.10', kind='vlan')
    assert_link_addresses('br43200.10', '198.18.40.1/24')
    assert_bridge_vlans('br43200', {10: (False, False)})


def test_ipv6_vif(config):
    """An IPv6 bridge VIF shares the general VLAN-child lifecycle."""
    # Installed once by configs/interfaces.conf.
    assert_link_addresses('br43210.10', '2001:db8:2a::1/64')
