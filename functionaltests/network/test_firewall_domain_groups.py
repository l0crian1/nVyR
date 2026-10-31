"""Firewall domain groups on the shared routed-network scenario.

IPv4/IPv6 DNS resolution, nonfatal lookup failure and group inclusion.

Each case owns distinct rules,
objects and packet ports in configs/network-features.conf. Configuration changes
are restored without recreating the routing topology. No incompatible topology.
"""

from contextlib import closing

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.errors import RouterError
from nvyr.protocol import Client
from smoketests.assertions import (
    assert_equal, assert_in, assert_true, assert_raises,
    assert_firewall_object, assert_firewall_rule, firewall_object_handle,
)


def request(operation, **arguments):
    """Exercise configd's runtime path used by the manual operational command."""
    with closing(Client('/run/nvyr/configd.sock')) as client:
        return client.request(operation, **arguments)


def test_domain_group_ipv4(config):
    """IPv4 resolution populates an address set and refresh preserves its handle."""
    # Baseline: configs/network-features.conf (FN40).

    request('domain-group-update', family='ipv4', name='FN40DNS_TEST')
    status = request('domain-group-status', family='ipv4', name='FN40DNS_TEST')
    assert_true(bool(status['domains'][0].get('addresses')), 'This test requires working IPv4 DNS resolution')
    assert_firewall_object('set', 'ipv4_domain_group_FN40DNS_TEST', 'type ipv4_addr', 'elements =')
    assert_firewall_rule('ipv4_name_FN40DNS_TEST', 34010, '@ipv4_domain_group_FN40DNS_TEST')
    handle = firewall_object_handle('set', 'ipv4_domain_group_FN40DNS_TEST')

    request('domain-group-update', family='ipv4', name='FN40DNS_TEST')
    assert_equal(firewall_object_handle('set', 'ipv4_domain_group_FN40DNS_TEST'), handle)


def test_domain_group_ipv6(config):
    """AAAA answers populate a separate IPv6 set with negative rule references."""
    # Baseline: configs/network-features.conf (FN41).

    request('domain-group-update', family='ipv6', name='FN41DNS_TEST')
    status = request('domain-group-status', family='ipv6', name='FN41DNS_TEST')
    assert_true(bool(status['domains'][0].get('addresses')), 'This test requires working AAAA resolution')
    assert_firewall_object('set', 'ipv6_domain_group_FN41DNS_TEST', 'type ipv6_addr', 'elements =')
    assert_firewall_rule('ipv6_name_FN41DNS_TEST', 34110, '!= @ipv6_domain_group_FN41DNS_TEST')


def test_domain_group_failed_lookup_is_nonfatal(config):
    """A reserved nonexistent name cannot prevent committing a firewall."""
    # Baseline: configs/network-features.conf (FN42).

    result = request('domain-group-update', family='ipv4', name='FN42MISSING')
    assert_in('Warning:', result['text'])
    assert_firewall_object('set', 'ipv4_domain_group_FN42MISSING', 'type ipv4_addr')


def test_domain_group_inclusion(config):
    """A refresh propagates child domains to parent sets without rebuilding chains."""
    # Baseline: configs/network-features.conf (FN43).

    request('domain-group-update', family='ipv4', name='FN43CHILD')
    assert_firewall_object('set', 'ipv4_domain_group_FN43PARENT', 'elements =')
    with assert_raises(RouterError):
        config.delete('delete firewall group domain-group ipv4 FN43CHILD')
