"""Firewall on the shared routed-network scenario.

Shared/per-source limits, cross-family quotas, counters and runtime reset.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

from contextlib import closing
import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.protocol import Client
from smoketests.assertions import (
    assert_equal, assert_in, assert_firewall_rule, assert_firewall_counter, firewall_object_handle,
)
from smoketests.firewall_support import send_firewall_udp


def test_shared_per_key_limit(config):
    """Two consumers use one dynamic bucket object rather than independent allowances."""
    # Baseline: configs/network-features.conf (FN1).

    assert_equal(send_firewall_udp(2, port=54004), 1)
    assert_firewall_counter('FN1DROPPED', 1)
    assert_firewall_rule('ipv4_output', 30110, 'update @ipv4_limit_group_FN1SHARED')
    assert_firewall_rule('ipv4_output', 30120, 'update @ipv4_limit_group_FN1SHARED')


def test_per_source_limit_packet_behavior(config):
    """Each source has its own two-packet bucket; excess traffic reaches the drop counter."""
    # Baseline: configs/network-features.conf (FN2).

    assert_equal(send_firewall_udp(3, source='127.0.0.2', port=54008), 2)
    assert_equal(send_firewall_udp(3, source='127.0.0.3', port=54008), 2)
    assert_firewall_counter('FN2DROPPED', 2)


def test_shared_quota_counter_reset_and_display(config):
    """Two families share one allowance; clear affects only the specified named state."""
    # Baseline: configs/network-features.conf (FN3).

    assert_equal(send_firewall_udp(1, port=54012), 1)
    assert_equal(send_firewall_udp(1, family='ipv6', port=54012), 1)
    assert_equal(send_firewall_udp(1, port=54012), 1)
    assert_firewall_counter('FN3TOTAL', 2)
    assert_firewall_counter('FN3OTHER', 1)

    # Replacing a consumer must not refill the shared quota or clear its counter.
    original = firewall_object_handle('quota', 'quota_group_FN3SHARED')
    config.set('set firewall ipv4 output filter rule 30310 description "rebuilt consumer"')

    config.commit()

    assert_equal(firewall_object_handle('quota', 'quota_group_FN3SHARED'), original)
    assert_firewall_counter('FN3TOTAL', 2)

    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text='show firewall group quota-group FN3SHARED')['text']

        assert_in('Smoke quota', output)
        client.request('execute', text='clear firewall counter FN3TOTAL')
        client.request('execute', text='clear firewall quota FN3SHARED')

    assert_firewall_counter('FN3TOTAL', 0)
    assert_firewall_counter('FN3OTHER', 1)
    assert_equal(send_firewall_udp(1, port=54012), 1)
    assert_firewall_counter('FN3TOTAL', 1)
