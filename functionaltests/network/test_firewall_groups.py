"""Firewall groups on the shared routed-network scenario.

Source/destination address and tuple learning, including runtime preservation.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from smoketests.assertions import (
    assert_equal, assert_in, assert_firewall_object, firewall_listing, firewall_object_handle,
)
from smoketests.firewall_support import send_firewall_udp


def test_dynamic_learning_and_preservation_address_group_source_address(config):
    """Packet updates learn real members, refresh timeouts and survive unrelated commits."""
    # Baseline: configs/network-features.conf (FN10).

    assert_firewall_object('set', 'ipv4_address_group_FN10LEARN', 'dynamic', 'timeout', 'size 128')
    assert_equal(send_firewall_udp(1, port=54040), 1)
    assert_in('elements =', firewall_listing('set', 'ipv4_address_group_FN10LEARN', state=True))
    original = firewall_object_handle('set', 'ipv4_address_group_FN10LEARN')
    config.set('set firewall ipv4 name UNRELATED rule 31010 action accept')

    config.commit()

    assert_equal(firewall_object_handle('set', 'ipv4_address_group_FN10LEARN'), original)
    assert_in('elements =', firewall_listing('set', 'ipv4_address_group_FN10LEARN', state=True))


def test_dynamic_learning_and_preservation_address_group_destination_address(config):
    """Packet updates learn real members, refresh timeouts and survive unrelated commits."""
    # Baseline: configs/network-features.conf (FN11).

    assert_firewall_object('set', 'ipv4_address_group_FN11LEARN', 'dynamic', 'timeout', 'size 128')
    assert_equal(send_firewall_udp(1, port=54044), 1)
    assert_in('elements =', firewall_listing('set', 'ipv4_address_group_FN11LEARN', state=True))
    original = firewall_object_handle('set', 'ipv4_address_group_FN11LEARN')
    config.set('set firewall ipv4 name UNRELATED rule 31110 action accept')

    config.commit()

    assert_equal(firewall_object_handle('set', 'ipv4_address_group_FN11LEARN'), original)
    assert_in('elements =', firewall_listing('set', 'ipv4_address_group_FN11LEARN', state=True))


def test_dynamic_learning_and_preservation_match_group_match_group(config):
    """Packet updates learn real members, refresh timeouts and survive unrelated commits."""
    # Baseline: configs/network-features.conf (FN12).

    assert_firewall_object('set', 'ipv4_match_group_FN12LEARN', 'dynamic', 'timeout', 'size 128')
    assert_equal(send_firewall_udp(1, port=54048), 1)
    assert_in('elements =', firewall_listing('set', 'ipv4_match_group_FN12LEARN', state=True))
    original = firewall_object_handle('set', 'ipv4_match_group_FN12LEARN')
    config.set('set firewall ipv4 name UNRELATED rule 31210 action accept')

    config.commit()

    assert_equal(firewall_object_handle('set', 'ipv4_match_group_FN12LEARN'), original)
    assert_in('elements =', firewall_listing('set', 'ipv4_match_group_FN12LEARN', state=True))
