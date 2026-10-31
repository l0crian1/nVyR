"""Veth peer/VIF details, addresses and IPv4/IPv6 connectivity across VRFs.

All address families, bridges, cables and both shared VRFs are configured once.
Each test uses dedicated links/subnets so disabling, moving or changing VLANs
cannot disturb another case. The explicit VRF creation/deletion case alone owns
disposable routing domains. No other case recreates a VRF.
"""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.helpers.process import cmd
from smoketests.assertions import assert_link, assert_link_addresses, assert_vlan, assert_in


def test_operational_peer_and_link_group(config):
    """Detailed display resolves the reciprocal peer and the Linux group number."""
    # Installed once by configs/interfaces.conf.

    output = cmd(['interfaces.nvyr.op', 'show', '--intf_name', 'veth43050', '--detail'])
    assert_in('Peer', output)
    assert_in('veth43051', output)
    assert_in('Link-group', output)
    assert_in('42', output)


def test_operational_vif_detail(config):
    """A scoped VIF display includes its parent, tag and link-local IPv6 address."""
    # Installed once by configs/interfaces.conf.
    assert_link_addresses('veth43060.10', '2001:db8:c::1/64')

    output = cmd(['interfaces.nvyr.op', 'show', '--intf_name', 'veth43060.10', '--detail'])
    assert_in('Parent', output)
    assert_in('veth43060', output)
    assert_in('VLAN ID', output)
    assert_in('802.1Q', output)
    assert_in('IPv6 link-local', output)
    assert_in('fe80:', output)


def test_ipv4_between_default_and_vrf(config):
    """Default-local addresses must not intercept packets arriving from a VRF peer."""
    # Installed once by configs/interfaces.conf.

    cmd(['ping', '-I', 'veth43070', '-n', '-c', '2', '-W', '2', '198.18.14.1'])
    cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-n', '-c', '2', '-W', '2', '198.18.14.0'])


def test_ipv6_between_default_and_vrf(config):
    """IPv6 also traverses the cable in both directions across the default/VRF boundary."""
    # Installed once by configs/interfaces.conf.

    cmd(['ping', '-6', '-I', 'veth43080', '-n', '-c', '2', '-W', '2', '2001:db8:10::1'])
    cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-6', '-n', '-c', '2', '-W', '2', '2001:db8:10::'])


def test_ipv4_between_vrfs(config):
    """IPv4 packets traverse the virtual cable between independent routing domains."""
    # Installed once by configs/interfaces.conf.

    assert_link('veth43090', master='NVYRIFSMOKE')
    assert_link('veth43091', master='NVYRIFSMOKE2')

    cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-n', '-c', '1', '-W', '2', '198.18.18.1'])


def test_ipv6_between_vrfs(config):
    """IPv6 packets traverse the pair after address detection completes."""
    # Installed once by configs/interfaces.conf.

    assert_link_addresses('veth43100', '2001:db8:14::/127')
    assert_link_addresses('veth43101', '2001:db8:14::1/127')

    cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-6', '-n', '-c', '1', '-W', '2', '2001:db8:14::1'])


def test_vif_ipv4_between_vrfs(config):
    """Tagged IPv4 crosses the veth pair while parent interfaces stay outside VRFs."""
    # Installed once by configs/interfaces.conf.

    assert_vlan('veth43110.10', 'veth43110', 10, master='NVYRIFSMOKE')
    assert_vlan('veth43111.10', 'veth43111', 10, master='NVYRIFSMOKE2')
    assert_link('veth43110', master='')
    cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-n', '-c', '1', '-W', '2', '198.18.22.1'])


def test_vif_ipv6_between_vrfs(config):
    """Tagged IPv6 works after address detection on both VLAN interfaces."""
    # Installed once by configs/interfaces.conf.

    assert_link_addresses('veth43120.10', '2001:db8:18::/127')
    assert_link_addresses('veth43121.10', '2001:db8:18::1/127')
    cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-6', '-n', '-c', '1', '-W', '2', '2001:db8:18::1'])


def test_ipv4_addresses(config):
    """Endpoint IPv4 addresses are independent and individual prefixes can be removed."""
    # Installed once by configs/interfaces.conf.

    assert_link_addresses('veth43130', '198.18.26.0/31')
    assert_link_addresses('veth43131', '198.18.26.1/31')

    config.delete('delete interfaces virtual-ethernet veth43130 address 198.18.26.0/31')
    config.commit()

    assert_link_addresses('veth43130', absent=('198.18.26.0/31',))
    assert_link_addresses('veth43131', '198.18.26.1/31')


def test_ipv6_addresses(config):
    """Each endpoint supports IPv6 and removal does not affect its peer's prefix."""
    # Installed once by configs/interfaces.conf.

    assert_link_addresses('veth43140', '2001:db8:1c::/127')
    assert_link_addresses('veth43141', '2001:db8:1c::1/127')

    config.delete('delete interfaces virtual-ethernet veth43140 address 2001:db8:1c::/127')
    config.commit()

    assert_link_addresses('veth43140', absent=('2001:db8:1c::/127',))
