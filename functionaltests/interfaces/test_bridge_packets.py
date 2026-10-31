"""IPv4/IPv6 forwarding, VLAN separation, port isolation and learned-MAC cleanup.

All address families, bridges, cables and both shared VRFs are configured once.
Each test uses dedicated links/subnets so disabling, moving or changing VLANs
cannot disturb another case. The explicit VRF creation/deletion case alone owns
disposable routing domains. No other case recreates a VRF.
"""

import pytest


if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from nvyr.helpers.process import cmd, rc_cmd
from nvyr.op_scripts import bridge as bridge_op
from smoketests.assertions import (
    assert_bridge_mac, assert_equal, assert_link, assert_link_addresses,
    assert_ping_reply,
)


def test_ipv4_forwarding_and_learning(config):
    """IPv4 crosses the bridge and learns the source MAC on the receiving port."""
    # Installed once by configs/interfaces.conf.

    cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-n', '-c', '1', '-W', '2', '198.18.44.2'])
    source = assert_link('veth43221')['address']
    assert_bridge_mac('br43220', source, port='veth43220')

    # An unrelated bridge change must preserve learned state and the device itself.
    index = assert_link('br43220')['ifindex']
    config.set('set interfaces bridge br43220 description "Retain learned forwarding"')
    config.commit()
    assert_equal(assert_link('br43220')['ifindex'], index)
    assert_bridge_mac('br43220', source, port='veth43220')


def test_ipv6_forwarding(config):
    """IPv6 neighbor discovery and unicast packets cross the bridge."""
    # Installed once by configs/interfaces.conf.
    assert_link_addresses('veth43231', '2001:db8:2e::1/64')
    assert_link_addresses('veth43233', '2001:db8:2e::2/64')

    cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-6', '-n', '-c', '1', '-W', '2', '2001:db8:2e::2'])


def test_ipv4_access_to_tagged_vlan(config):
    """An access PVID inserts VLAN 10 and the trunk delivers it to a peer VIF."""
    # Installed once by configs/interfaces.conf.

    cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-n', '-c', '1', '-W', '2', '198.18.48.2'])
    source = assert_link('veth43241')['address']
    assert_bridge_mac('br43240', source, port='veth43240', vlan=10)


def test_ipv6_access_to_tagged_vlan(config):
    """Access-to-trunk VLAN classification also carries IPv6 traffic."""
    # Installed once by configs/interfaces.conf.
    assert_link_addresses('veth43251', '2001:db8:32::1/64')
    assert_link_addresses('veth43253.10', '2001:db8:32::2/64')

    cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-6', '-n', '-c', '1', '-W', '2', '2001:db8:32::2'])


def test_vlan_separation(config):
    """Different access VLANs cannot exchange packets despite sharing an IP subnet."""
    # Installed once by configs/interfaces.conf.

    status, output = rc_cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-n', '-c', '1', '-W', '1', '198.18.52.2'])
    assert_equal(status, 1, msg=output)

    # Moving the second port into the same VLAN restores actual connectivity.
    config.delete('delete interfaces bridge br43260 member interface veth43262 vlan 20')
    config.set('set interfaces bridge br43260 member interface veth43262 vlan 10 pvid untagged')
    config.commit()

    # The blocked probe's pending ARP failure can outlive the VLAN change.
    assert_ping_reply('198.18.52.2', vrf='NVYRIFSMOKE')


def test_port_isolation(config):
    """Two isolated ports cannot communicate until one port's isolation is removed."""
    # Installed once by configs/interfaces.conf.

    status, output = rc_cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-n', '-c', '1', '-W', '1', '198.18.54.2'])
    assert_equal(status, 1, msg=output)
    config.delete('delete interfaces bridge br43270 member interface veth43272 isolated')
    config.commit()

    # Allow a fresh ARP resolution after the deliberately blocked probe expires.
    assert_ping_reply('198.18.54.2', vrf='NVYRIFSMOKE')


def test_clear_learned_macs_preserves_static(config):
    """Operational cleanup removes learned entries while retaining configured policy."""
    # Installed once by configs/interfaces.conf.
    cmd(['ip', 'vrf', 'exec', 'NVYRIFSMOKE', 'ping', '-n', '-c', '1', '-W', '2', '198.18.56.2'])
    source = assert_link('veth43281')['address']
    assert_bridge_mac('br43280', source, port='veth43280')

    bridge_op.clear('br43280', member='veth43280')
    assert_bridge_mac('br43280', source, port='veth43280', present=False)
    assert_bridge_mac('br43280', '02:00:00:00:99:99', port='veth43280')
