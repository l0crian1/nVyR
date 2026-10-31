"""Installed ACL, prefix-list, AS-path/community-list and route-map displays.

Distinct FN44-FN53 objects are installed in configs/network-features.conf with the
shared network. Clearing a dedicated map counter leaves all other policy state
intact. Removing the policy subtree would conflict with the shared BGP peers.
"""

import json

import pytest


if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from nvyr.op_scripts import bgp, policy
from smoketests.assertions import assert_equal, assert_in


def test_ipv4_access_list(config):
    """Inspect the installed IPv4 ACL, including its native JSON rather than route matches."""
    # Baseline: configs/network-features.conf (FN44).

    assert_in('FN44NVYRPOLICYSMOKE', policy.show('show ip access-list'))
    data = json.loads(policy.show('show ip access-list FN44NVYRPOLICYSMOKE', raw=True))
    assert_equal(data['bgpd']['FN44NVYRPOLICYSMOKE']['rules'][0]['prefix'], '192.0.2.0/24')


def test_ipv6_access_list(config):
    """IPv6 ACL inspection uses the independent IPv6 policy namespace."""
    # Baseline: configs/network-features.conf (FN45).

    assert_in('FN45NVYRPOLICYSMOKE', policy.show('show ipv6 access-list'))
    data = json.loads(policy.show('show ipv6 access-list FN45NVYRPOLICYSMOKE', raw=True))
    assert_equal(data['bgpd']['FN45NVYRPOLICYSMOKE']['rules'][0]['prefix'], '2001:db8::/32')


def test_ipv4_prefix_list(config):
    """Sequence, detail, summary and prefix lookups preserve their native argument positions."""
    # Baseline: configs/network-features.conf (FN46).

    data = json.loads(policy.show('show ip prefix-list FN46NVYRPOLICYSMOKE seq 10', raw=True))
    assert_equal(data['bgpd']['FN46NVYRPOLICYSMOKE']['entries'][0]['sequenceNumber'], 10)
    assert_in('FN46NVYRPOLICYSMOKE', policy.show('show ip prefix-list summary FN46NVYRPOLICYSMOKE'))
    assert_in('FN46NVYRPOLICYSMOKE', policy.show('show ip prefix-list detail FN46NVYRPOLICYSMOKE'))
    assert_in('192.0.2.0/24', policy.show('show ip prefix-list FN46NVYRPOLICYSMOKE 192.0.2.0/24 first-match'))


def test_ipv6_prefix_list(config):
    """IPv6 sequence and prefix lookups remain distinct from IPv4 lists with the same name."""
    # Baseline: configs/network-features.conf (FN47).

    data = json.loads(policy.show('show ipv6 prefix-list FN47NVYRPOLICYSMOKE seq 10', raw=True))
    assert_equal(data['bgpd']['FN47NVYRPOLICYSMOKE']['entries'][0]['sequenceNumber'], 10)
    assert_in('FN47NVYRPOLICYSMOKE', policy.show('show ipv6 prefix-list summary FN47NVYRPOLICYSMOKE'))
    assert_in('FN47NVYRPOLICYSMOKE', policy.show('show ipv6 prefix-list detail FN47NVYRPOLICYSMOKE'))
    assert_in('2001:db8::/32', policy.show('show ipv6 prefix-list FN47NVYRPOLICYSMOKE 2001:db8::/32 longer'))


def test_as_path_list(config):
    """The list's regular expression is displayed directly, without filtering a BGP table."""
    # Baseline: configs/network-features.conf (FN48).

    data = json.loads(policy.show('show bgp as-path-access-list FN48NVYRPOLICYSMOKE', raw=True))
    assert_equal(data['FN48NVYRPOLICYSMOKE'][0]['regExp'], '^65001$')
    assert_in('FN48NVYRPOLICYSMOKE', policy.show('show ip as-path-access-list'))


def test_standard_community_list(config):
    """The detail keyword selects the definition instead of routes matching the list."""
    # Baseline: configs/network-features.conf (FN49).

    assert_in('FN49NVYRPOLICYSMOKE', bgp.show('show bgp community-list'))
    assert_in('permit 65000:100', bgp.show('show bgp community-list FN49NVYRPOLICYSMOKE detail'))


def test_expanded_community_list(config):
    """Expanded community definitions retain the configured regex."""
    # Baseline: configs/network-features.conf (FN50).

    assert_in('permit ^65000:', bgp.show('show bgp community-list FN50NVYRPOLICYSMOKE detail'))


def test_standard_large_community_list(config):
    """Large-community definitions show all three components without changing the native view."""
    # Baseline: configs/network-features.conf (FN51).

    assert_in('FN51NVYRPOLICYSMOKE', bgp.show('show bgp large-community-list'))
    assert_in('permit 65000:100:200', bgp.show('show bgp large-community-list FN51NVYRPOLICYSMOKE detail'))


def test_expanded_large_community_list(config):
    """Expanded large-community definitions display their regex rather than matching routes."""
    # Baseline: configs/network-features.conf (FN52).

    assert_in('permit ^65000:100:', bgp.show('show bgp large-community-list FN52NVYRPOLICYSMOKE detail'))


def test_route_map_definition_and_counter_reset(config):
    """Inspect native setters and reset only the reserved route-map, preserving its rules."""
    # Baseline: configs/network-features.conf (FN53).

    assert_in('FN53NVYRPOLICYSMOKE', policy.show('show route-map'))
    before = json.loads(policy.show('show route-map FN53NVYRPOLICYSMOKE', raw=True))
    assert_in('metric 50', before['bgpd']['FN53NVYRPOLICYSMOKE']['rules'][0]['setClauses'])

    policy.clear('clear route-map counters FN53NVYRPOLICYSMOKE')

    after = json.loads(policy.show('show route-map FN53NVYRPOLICYSMOKE', raw=True))
    assert_equal(after['bgpd']['FN53NVYRPOLICYSMOKE']['invoked'], 0)
    assert_equal(after['bgpd']['FN53NVYRPOLICYSMOKE']['rules'], before['bgpd']['FN53NVYRPOLICYSMOKE']['rules'])
