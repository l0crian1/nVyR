"""Policy replacement/withdrawal over the shared routed-network BGP sessions.

Each case has its own advertised prefix, import/export clauses and policy list.
Both families use the existing NVYRLEFT/NVYRRIGHT peers. Changing a list refreshes
only policy state; no transport setup or teardown occurs between test files.
VRF or transport deletion is incompatible; peer refresh is explicitly tested.
"""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from smoketests.assertions import assert_bgp_path


def test_ipv4_community_filter_and_refresh(config):
    """Match an advertised community, then withdraw the route when its list changes."""
    # Dedicated RNCHANGE1 policy is installed with the network baseline.
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.21/32', attributes={'locPrf': 250, 'community.string': '65062:100'})

    config.delete('delete policy community-list standard RNCHANGE1 rule 10 community 65062:100')
    config.set('set policy community-list standard RNCHANGE1 rule 10 community 65062:200')
    config.commit()
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.21/32', present=False)


def test_ipv4_as_path_filter_and_replace(config):
    """Match a prepended AS path and replace only the selected AS on import."""
    # Dedicated RNCHANGE2 policy is installed with the network baseline.
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.22/32', attributes={'aspath.string': '65062 64502 64502'})

    # Replacing the same list sequence must refresh and withdraw the route.
    config.set('set policy as-path-list RNCHANGE2 rule 10 regex "_64599_"')
    config.commit()
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.19.61.22/32', present=False)


def test_ipv6_community_filter_and_refresh(config):
    """Match an advertised community, then withdraw the route when its list changes."""
    # Dedicated RNCHANGE3 policy is installed with the network baseline.
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::23/128', attributes={'locPrf': 250, 'community.string': '65062:100'})

    config.delete('delete policy community-list standard RNCHANGE3 rule 10 community 65062:100')
    config.set('set policy community-list standard RNCHANGE3 rule 10 community 65062:200')
    config.commit()
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::23/128', present=False)


def test_ipv6_as_path_filter_and_replace(config):
    """Match a prepended AS path and replace only the selected AS on import."""
    # Dedicated RNCHANGE4 policy is installed with the network baseline.
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::24/128', attributes={'aspath.string': '65062 64502 64502'})

    # Replacing the same list sequence must refresh and withdraw the route.
    config.set('set policy as-path-list RNCHANGE4 rule 10 regex "_64599_"')
    config.commit()
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:63::24/128', present=False)
