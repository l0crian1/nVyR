"""Firewall inclusions on the shared routed-network scenario.

IPv4/IPv6 address, interface and port inclusion plus reference removal.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_equal, assert_not_equal, assert_raises, assert_firewall_object, firewall_object_handle,
)
from smoketests.firewall_support import send_firewall_udp


def test_address_inclusion_ipv4(config):
    """Nested IPv4 membership drops packets, then a child edit updates every consumer."""
    # Baseline: configs/network-features.conf (FN17).

    assert_firewall_object('set', 'ipv4_address_group_FN17ALLOWED', '127.0.0.2', '192.0.2.1')
    assert_equal(send_firewall_udp(1, port=54068), 0)
    parent = firewall_object_handle('set', 'ipv4_address_group_FN17ALLOWED')
    caller = firewall_object_handle('chain', 'ipv4_name_FN17OUTER')
    unrelated = firewall_object_handle('set', 'port_group_FN17UNRELATED')

    # Editing only the leaf group must rebuild both parent sets and nested callers.
    config.delete('delete firewall group address-group ipv4 FN17HOSTS address 127.0.0.2')
    config.set('set firewall group address-group ipv4 FN17HOSTS address 192.0.2.2')
    config.commit()

    assert_equal(send_firewall_udp(1, port=54068), 1)
    assert_firewall_object('set', 'ipv4_address_group_FN17ALLOWED', '192.0.2.2', absent=('127.0.0.2',))
    assert_not_equal(firewall_object_handle('set', 'ipv4_address_group_FN17ALLOWED'), parent)
    assert_not_equal(firewall_object_handle('chain', 'ipv4_name_FN17OUTER'), caller)
    assert_equal(firewall_object_handle('set', 'port_group_FN17UNRELATED'), unrelated)


def test_address_inclusion_ipv6(config):
    """IPv6 parents combine local and included members and refresh packet matches."""
    # Baseline: configs/network-features.conf (FN18).

    assert_firewall_object('set', 'ipv6_address_group_FN18ALLOWED', '::1', '2001:db8::1')
    assert_equal(send_firewall_udp(1, family='ipv6', port=54072), 0)

    config.delete('delete firewall group address-group ipv6 FN18HOSTS address ::1')
    config.set('set firewall group address-group ipv6 FN18HOSTS address 2001:db8::2')
    config.commit()

    assert_equal(send_firewall_udp(1, family='ipv6', port=54072), 1)
    assert_firewall_object('set', 'ipv6_address_group_FN18ALLOWED', '2001:db8::2')


def test_interface_inclusion(config):
    """Interface inclusion expands names into the parent used by an output rule."""
    # Baseline: configs/network-features.conf (FN19).

    assert_firewall_object('set', 'interface_group_FN19LOCAL', '"lo"', '"dum998"')
    assert_equal(send_firewall_udp(1, port=54076), 0)

    config.delete('delete firewall group interface-group FN19LOCAL include-group FN19LOOPBACK')
    config.commit()

    assert_equal(send_firewall_udp(1, port=54076), 1)
    assert_firewall_object('set', 'interface_group_FN19LOCAL', '"dum998"', absent=('"lo"',))


def test_port_inclusion_and_reference_removal(config):
    """Port ranges merge; removing one inclusion preserves the other dependency."""
    # Baseline: configs/network-features.conf (FN20).

    assert_firewall_object('set', 'port_group_FN20ALLOWED', '443', '54079-54081')
    assert_equal(send_firewall_udp(1, port=54080), 0)
    with assert_raises(RouterError, match='referenced'):
        config.delete('delete firewall group port-group FN20WEB')

    config.delete('delete firewall group port-group FN20ALLOWED include-group FN20TEST')
    config.delete('delete firewall group port-group FN20ALLOWED port 54080')
    config.delete('delete firewall group port-group FN20TEST')
    config.commit()

    assert_equal(send_firewall_udp(1, port=54080), 1)
    assert_firewall_object('set', 'port_group_FN20ALLOWED', '443', absent=('54080',))
    with assert_raises(RouterError, match='referenced'):
        config.delete('delete firewall group port-group FN20WEB')
