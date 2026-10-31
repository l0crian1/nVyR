"""Firewall runtime on the shared routed-network scenario.

IPv4/IPv6 learned-address deletion, tuple deletion, flush and relearning.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

import pytest


if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from contextlib import closing

from nvyr.errors import RouterError
from nvyr.protocol import Client
from smoketests.assertions import (
    assert_equal, assert_in, assert_not_in, assert_raises,
    firewall_listing, firewall_object_handle,
)
from smoketests.firewall_support import send_firewall_udp


def test_clear_dynamic_address_group_ipv4(config):
    """Delete one learned address, preserve others, then flush without replacing the set."""
    # Baseline: configs/network-features.conf (FN13).

    assert_equal(send_firewall_udp(1, source='127.0.0.2', port=54052), 1)
    assert_equal(send_firewall_udp(1, source='127.0.0.3', port=54052), 1)
    handle = firewall_object_handle('set', 'ipv4_address_group_FN13LEARN')
    chain = firewall_listing('chain', 'ipv4_output', handles=True)
    running = config.get_config()

    with closing(Client('/run/nvyr/configd.sock')) as client:
        client.request('execute', text='clear firewall group address-group ipv4 FN13LEARN member 127.0.0.2')
        listing = firewall_listing('set', 'ipv4_address_group_FN13LEARN', state=True)
        assert_not_in('127.0.0.2', listing)
        assert_in('127.0.0.3', listing)

        # Repeating the request is safe after deletion or natural expiration.
        client.request('execute', text='clear firewall group address-group ipv4 FN13LEARN member 127.0.0.2')
        client.request('execute', text='clear firewall group address-group ipv4 FN13LEARN learned')

    assert_not_in('elements =', firewall_listing('set', 'ipv4_address_group_FN13LEARN', state=True))
    assert_equal(firewall_object_handle('set', 'ipv4_address_group_FN13LEARN'), handle)
    assert_equal(firewall_listing('chain', 'ipv4_output', handles=True), chain)
    assert_equal(config.get_config(), running)

    # Clearing membership leaves the packet-path learning rule active.
    assert_equal(send_firewall_udp(1, port=54052), 1)
    assert_in('127.0.0.2', firewall_listing('set', 'ipv4_address_group_FN13LEARN', state=True))


def test_clear_dynamic_address_group_ipv6(config):
    """IPv6 address cleanup supports exact deletion, relearning and a full runtime clear."""
    # Baseline: configs/network-features.conf (FN14).

    assert_equal(send_firewall_udp(1, family='ipv6', port=54056), 1)
    handle = firewall_object_handle('set', 'ipv6_address_group_FN14LEARN')
    with closing(Client('/run/nvyr/configd.sock')) as client:
        client.request('execute', text='clear firewall group address-group ipv6 FN14LEARN member ::1')
        assert_not_in('elements =', firewall_listing('set', 'ipv6_address_group_FN14LEARN', state=True))
        assert_equal(send_firewall_udp(1, family='ipv6', port=54056), 1)
        client.request('execute', text='clear firewall group address-group ipv6 FN14LEARN learned')

    assert_not_in('elements =', firewall_listing('set', 'ipv6_address_group_FN14LEARN', state=True))
    assert_equal(firewall_object_handle('set', 'ipv6_address_group_FN14LEARN'), handle)


def test_clear_dynamic_match_group_ipv4(config):
    """Complete keys delete one tuple; incomplete keys and static groups remain protected."""
    # Baseline: configs/network-features.conf (FN15).

    assert_equal(send_firewall_udp(1, source='127.0.0.2', port=54060), 1)
    assert_equal(send_firewall_udp(1, source='127.0.0.3', port=54060), 1)
    handle = firewall_object_handle('set', 'ipv4_match_group_FN15LEARN')
    with closing(Client('/run/nvyr/configd.sock')) as client:
        with assert_raises(RouterError, match='exactly these member fields'):
            client.request('execute', text='clear firewall group match-group ipv4 FN15LEARN member source-address 127.0.0.2')
        with assert_raises(RouterError, match='not dynamic'):
            client.request('execute', text='clear firewall group address-group ipv4 FN15STATIC learned')

        client.request('execute', text='clear firewall group match-group ipv4 FN15LEARN member destination-port 54060 protocol udp source-address 127.0.0.2')
        listing = firewall_listing('set', 'ipv4_match_group_FN15LEARN', state=True)
        assert_not_in('127.0.0.2', listing)
        assert_in('127.0.0.3', listing)
        client.request('execute', text='clear firewall group match-group ipv4 FN15LEARN learned')

    assert_not_in('elements =', firewall_listing('set', 'ipv4_match_group_FN15LEARN', state=True))
    assert_in('192.0.2.1', firewall_listing('set', 'ipv4_address_group_FN15STATIC'))
    assert_equal(firewall_object_handle('set', 'ipv4_match_group_FN15LEARN'), handle)


def test_clear_dynamic_match_group_ipv6(config):
    """Clear a concatenated IPv6 key and all learned entries without replacing its set."""
    # Baseline: configs/network-features.conf (FN16).

    assert_equal(send_firewall_udp(1, family='ipv6', port=54064), 1)
    handle = firewall_object_handle('set', 'ipv6_match_group_FN16LEARN')
    with closing(Client('/run/nvyr/configd.sock')) as client:
        client.request('execute', text='clear firewall group match-group ipv6 FN16LEARN member source-address ::1 protocol udp destination-port 54064')
        assert_not_in('elements =', firewall_listing('set', 'ipv6_match_group_FN16LEARN', state=True))
        assert_equal(send_firewall_udp(1, family='ipv6', port=54064), 1)
        client.request('execute', text='clear firewall group match-group ipv6 FN16LEARN learned')

    assert_not_in('elements =', firewall_listing('set', 'ipv6_match_group_FN16LEARN', state=True))
    assert_equal(firewall_object_handle('set', 'ipv6_match_group_FN16LEARN'), handle)
