"""Direct routing-policy feature checks through configd and native FRR."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.config_session import CommitError
from nvyr.errors import RouterError
from nvyr.tree import lookup
from smoketests.assertions import assert_config_names_unused, assert_frr_policy_commands, assert_raises
from smoketests.support import prepared_test


def standup(config, resources):
    """Reserve names without disturbing policies used by the router."""
    assert_config_names_unused(config.get_config(), 'NVYRPOLICYSMOKE', 'NVYRPOLICYMISSING', 'NVYRPOLICYCALL')
    resources['prepared'] = True


def cleanup(config, resources):
    """Remove consumer route-maps before lists and discard failed candidate edits."""
    if not resources['prepared']:
        return

    config.discard()
    running = config.get_config()
    paths = [
        ('policy', 'route-map', 'NVYRPOLICYSMOKE'),
        ('policy', 'route-map', 'NVYRPOLICYCALL'),
        ('policy', 'as-path-list', 'NVYRPOLICYSMOKE'),
        ('policy', 'community-list', 'standard', 'NVYRPOLICYSMOKE'),
        ('policy', 'community-list', 'expanded', 'NVYRPOLICYSMOKE'),
        ('policy', 'large-community-list', 'standard', 'NVYRPOLICYSMOKE'),
        ('policy', 'large-community-list', 'expanded', 'NVYRPOLICYSMOKE'),
        ('policy', 'access-list', 'ipv4', 'NVYRPOLICYSMOKE'),
        ('policy', 'access-list', 'ipv6', 'NVYRPOLICYSMOKE'),
        ('policy', 'prefix-list', 'ipv4', 'NVYRPOLICYSMOKE'),
        ('policy', 'prefix-list', 'ipv6', 'NVYRPOLICYSMOKE'),
    ]
    changed = False
    for path in paths:
        if lookup(running, path, None) is not None:
            config.delete('delete ' + ' '.join(path))
            changed = True
    if changed:
        config.commit()


@pytest.fixture(autouse=True)
def policy_environment(config, request):
    """Prepare and clean every function; the session fixture restores the full snapshot once."""
    def stop(message):
        """Stop the suite if cleanup cannot restore its baseline."""
        request.session.shouldstop = message

    resources = {'prepared': False}

    def prepare(session):
        """Claim reserved names only after preflight succeeds."""
        standup(session, resources)

    def restore(session):
        """Leave preexisting policies untouched if preflight failed."""
        cleanup(session, resources)

    with prepared_test(config, prepare, restore, stop=stop):
        yield


def test_access_list_ipv4_prefix(config):
    """A plain IPv4 ACL prefix retains more-specific route matching."""
    config.set('set policy access-list ipv4 NVYRPOLICYSMOKE rule 10 action permit prefix 10.0.0.0/8')
    config.commit()
    assert_frr_policy_commands('access-list NVYRPOLICYSMOKE seq 10 permit 10.0.0.0/8')


def test_access_list_ipv6_prefix(config):
    """An IPv6 ACL installs in the IPv6 native namespace."""
    config.set('set policy access-list ipv6 NVYRPOLICYSMOKE rule 10 action permit prefix 2001:db8::/32')
    config.commit()
    assert_frr_policy_commands('ipv6 access-list NVYRPOLICYSMOKE seq 10 permit 2001:db8::/32')


def test_access_list_ipv4_exact_and_any(config):
    """Exact-prefix permission and the explicit deny-any entry survive rendering."""
    config.set('set policy access-list ipv4 NVYRPOLICYSMOKE rule 10 action permit prefix 192.0.2.0/24 exact-match')
    config.set('set policy access-list ipv4 NVYRPOLICYSMOKE rule 20 action deny any')
    config.commit()
    assert_frr_policy_commands('access-list NVYRPOLICYSMOKE seq 10 permit 192.0.2.0/24 exact-match',
                               'access-list NVYRPOLICYSMOKE seq 20 deny any')


def test_access_list_ipv6_exact_and_any(config):
    """IPv6 exact matching and any use the corresponding native ACL forms."""
    config.set('set policy access-list ipv6 NVYRPOLICYSMOKE rule 10 action permit prefix 2001:db8::/32 exact-match')
    config.set('set policy access-list ipv6 NVYRPOLICYSMOKE rule 20 action deny any')
    config.commit()
    assert_frr_policy_commands('ipv6 access-list NVYRPOLICYSMOKE seq 10 permit 2001:db8::/32 exact-match',
                               'ipv6 access-list NVYRPOLICYSMOKE seq 20 deny any')


def test_access_list_ipv4_inverse_mask(config):
    """A noncontiguous inverse mask must remain a wildcard rather than become a prefix."""
    config.set('set policy access-list ipv4 NVYRPOLICYSMOKE rule 10 action permit address 10.0.20.0 wildcard-mask 0.0.255.0')
    config.commit()
    assert_frr_policy_commands('access-list NVYRPOLICYSMOKE seq 10 permit 10.0.0.0 0.0.255.0')
    assert_frr_policy_commands('access-list NVYRPOLICYSMOKE seq 10 permit 10.0.0.0 0.0.255.0', daemon='zebra')


def test_prefix_list_ipv4_length_range(config):
    """The IPv4 ge/le bounds are installed in both policy destinations."""
    config.set('set policy prefix-list ipv4 NVYRPOLICYSMOKE rule 10 action permit prefix 10.0.0.0/8 ge 16 le 24')
    config.commit()
    assert_frr_policy_commands('ip prefix-list NVYRPOLICYSMOKE seq 10 permit 10.0.0.0/8 ge 16 le 24')
    assert_frr_policy_commands('ip prefix-list NVYRPOLICYSMOKE seq 10 permit 10.0.0.0/8 ge 16 le 24', daemon='zebra')


def test_prefix_list_ipv6_length_range(config):
    """IPv6 supports its full prefix-length range independently of IPv4."""
    config.set('set policy prefix-list ipv6 NVYRPOLICYSMOKE rule 10 action permit prefix 2001:db8::/32 ge 48 le 128')
    config.commit()
    assert_frr_policy_commands('ipv6 prefix-list NVYRPOLICYSMOKE seq 10 permit 2001:db8::/32 ge 48 le 128')


def test_route_map_ipv4_list_references(config):
    """Create the lists and their route-map consumer in the same commit."""
    config.set('set policy prefix-list ipv4 NVYRPOLICYSMOKE rule 10 action permit prefix 10.0.0.0/8')
    config.set('set policy access-list ipv4 NVYRPOLICYSMOKE rule 10 action permit prefix 192.0.2.0/24')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match ipv4 prefix-list NVYRPOLICYSMOKE')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 match ipv4 next-hop access-list NVYRPOLICYSMOKE')
    config.commit()
    assert_frr_policy_commands('match ip address prefix-list NVYRPOLICYSMOKE', 'match ip next-hop NVYRPOLICYSMOKE')


def test_route_map_ipv6_list_references(config):
    """IPv6 route and next-hop references use their own family-specific lists."""
    config.set('set policy prefix-list ipv6 NVYRPOLICYSMOKE rule 10 action permit prefix 2001:db8::/32')
    config.set('set policy access-list ipv6 NVYRPOLICYSMOKE rule 10 action permit prefix 2001:db8:1::/48')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match ipv6 access-list NVYRPOLICYSMOKE')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 match ipv6 next-hop prefix-list NVYRPOLICYSMOKE')
    config.commit()
    assert_frr_policy_commands('match ipv6 address NVYRPOLICYSMOKE', 'match ipv6 next-hop prefix-list NVYRPOLICYSMOKE')


def test_route_map_match_attributes(config):
    """Generic route attributes remain separate matching conditions."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match interface lo metric 100 tag 200')
    config.commit()
    assert_frr_policy_commands('match interface lo', 'match metric 100', 'match tag 200')


def test_route_map_set_preferences(config):
    """Metric, local preference, weight and origin reach the BGP policy compiler."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set metric 50 local-preference 200 weight 100 origin igp')
    config.commit()
    assert_frr_policy_commands('set metric 50', 'set local-preference 200', 'set weight 100', 'set origin igp')


def test_route_map_set_ipv4_next_hop(config):
    """The IPv4 next-hop setter reaches BGP through native FRR commands."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set ipv4 next-hop address 192.0.2.1')
    config.commit()
    assert_frr_policy_commands('set ip next-hop 192.0.2.1')


def test_route_map_set_ipv6_next_hop(config):
    """The IPv6 next-hop setter uses the global next-hop field."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set ipv6 next-hop global 2001:db8::1')
    config.commit()
    assert_frr_policy_commands('set ipv6 next-hop global 2001:db8::1')


def test_route_map_as_path_order_and_duplicates(config):
    """AS prepending must keep repeated AS numbers and their original order."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set as-path prepend "65001 65002 65001"')
    config.commit()
    assert_frr_policy_commands('set as-path prepend 65001 65002 65001')


def test_route_map_standard_communities(config):
    """Repeated community settings collect values and additive preserves existing ones."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set community 65001:100')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 set community 65001:200')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 set community additive')
    config.commit()
    assert_frr_policy_commands('set community 65001:100 65001:200 additive')


def test_route_map_large_communities(config):
    """Large communities retain all three unsigned 32-bit components."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set large-community 65001:100:200')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 set large-community additive')
    config.commit()
    assert_frr_policy_commands('set large-community 65001:100:200 additive')


def test_route_map_reference_blocks_deletion(config):
    """The dependency registrar blocks deletion of a list still used by a route-map."""
    config.set('set policy prefix-list ipv4 NVYRPOLICYSMOKE rule 10 action permit prefix 10.0.0.0/8')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match ipv4 prefix-list NVYRPOLICYSMOKE')
    config.commit()
    with assert_raises(RouterError, match='referenc'):
        config.delete('delete policy prefix-list ipv4 NVYRPOLICYSMOKE')


def test_route_map_missing_reference_rejected(config):
    """A missing provider cannot silently become an ineffective route filter."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match ipv4 prefix-list NVYRPOLICYMISSING')
    with assert_raises(CommitError, match='not configured'):
        config.commit()


def test_access_list_missing_mask_rejected(config):
    """An incomplete wildcard comparison must fail before reaching FRR."""
    config.set('set policy access-list ipv4 NVYRPOLICYSMOKE rule 10 action permit address 10.0.0.0')
    with assert_raises(CommitError, match='together'):
        config.commit()


def test_access_list_conflicting_forms_rejected(config):
    """A rule cannot simultaneously match a prefix and any route."""
    config.set('set policy access-list ipv4 NVYRPOLICYSMOKE rule 10 action permit prefix 10.0.0.0/8 any')
    with assert_raises(CommitError, match='choose'):
        config.commit()


def test_prefix_list_impossible_range_rejected(config):
    """Contradictory prefix lengths are rejected by nVyR verification."""
    config.set('set policy prefix-list ipv4 NVYRPOLICYSMOKE rule 10 action permit prefix 10.0.0.0/8 ge 24 le 16')
    with assert_raises(CommitError, match='ge cannot exceed le'):
        config.commit()


def test_policy_missing_action_rejected(config):
    """No implicit permit is introduced for an unfinished policy rule."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 set metric 50')
    with assert_raises(CommitError, match='action permit or deny is required'):
        config.commit()


def test_route_map_additive_without_values_rejected(config):
    """Additive is a modifier and cannot form a complete community setter alone."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set community additive')
    with assert_raises(CommitError, match='at least one community'):
        config.commit()


def test_route_map_empty_match_rejected(config):
    """An unfinished match must not silently compile as a permit-all rule."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match ipv4 next-hop')
    with assert_raises(CommitError, match='at least one setting'):
        config.commit()


def test_route_map_empty_set_rejected(config):
    """An unfinished attribute setter must be reported before native apply."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set as-path')
    with assert_raises(CommitError, match='at least one setting'):
        config.commit()


def test_access_list_ipv4_empty_rejected(config):
    """An empty IPv4 ACL cannot be represented as a native policy."""
    config.set('set policy access-list ipv4 NVYRPOLICYSMOKE')
    with assert_raises(CommitError, match='at least one rule is required'):
        config.commit()


def test_access_list_ipv6_empty_rejected(config):
    """An IPv6 ACL description alone does not form a complete policy."""
    config.set('set policy access-list ipv6 NVYRPOLICYSMOKE description "No rules"')
    with assert_raises(CommitError, match='at least one rule is required'):
        config.commit()


def test_prefix_list_ipv4_empty_rejected(config):
    """Require an explicit IPv4 rule instead of an invisible empty prefix-list."""
    config.set('set policy prefix-list ipv4 NVYRPOLICYSMOKE')
    with assert_raises(CommitError, match='at least one rule is required'):
        config.commit()


def test_prefix_list_ipv6_empty_rejected(config):
    """Require an explicit IPv6 rule instead of an invisible empty prefix-list."""
    config.set('set policy prefix-list ipv6 NVYRPOLICYSMOKE')
    with assert_raises(CommitError, match='at least one rule is required'):
        config.commit()


def test_route_map_empty_rejected(config):
    """A route-map needs at least one native sequence."""
    config.set('set policy route-map NVYRPOLICYSMOKE')
    with assert_raises(CommitError, match='at least one rule is required'):
        config.commit()


def test_route_map_update_and_remove_setters(config):
    """Changing a sequence verdict and removing a setter must update native BGP state."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set local-preference 200 weight 100')
    config.commit()
    assert_frr_policy_commands('set local-preference 200', 'set weight 100')

    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action deny')
    config.delete('delete policy route-map NVYRPOLICYSMOKE rule 10 set weight')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 set local-preference 300')
    config.commit()
    assert_frr_policy_commands('route-map NVYRPOLICYSMOKE deny 10', 'set local-preference 300',
                               absent=('set weight 100', 'set local-preference 200'))


def test_prefix_list_ipv4_update(config):
    """Changing a prefix-list sequence replaces its previous native match."""
    config.set('set policy prefix-list ipv4 NVYRPOLICYSMOKE rule 10 action permit prefix 10.0.0.0/8')
    config.commit()

    config.set('set policy prefix-list ipv4 NVYRPOLICYSMOKE rule 10 action deny prefix 192.0.2.0/24')
    config.commit()
    assert_frr_policy_commands('ip prefix-list NVYRPOLICYSMOKE seq 10 deny 192.0.2.0/24',
                               absent=('ip prefix-list NVYRPOLICYSMOKE seq 10 permit 10.0.0.0/8',))


def test_prefix_list_ipv6_update(config):
    """IPv6 prefix replacement must retain the original sequence number."""
    config.set('set policy prefix-list ipv6 NVYRPOLICYSMOKE rule 10 action permit prefix 2001:db8::/32')
    config.commit()

    config.set('set policy prefix-list ipv6 NVYRPOLICYSMOKE rule 10 action deny prefix 2001:db8:1::/48')
    config.commit()
    assert_frr_policy_commands('ipv6 prefix-list NVYRPOLICYSMOKE seq 10 deny 2001:db8:1::/48',
                               absent=('ipv6 prefix-list NVYRPOLICYSMOKE seq 10 permit 2001:db8::/32',))


def test_community_list_standard(config):
    """Create and reference a standard community-list."""
    config.set('set policy community-list standard NVYRPOLICYSMOKE rule 10 action permit community 65000:100')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match community-list NVYRPOLICYSMOKE')
    config.commit()
    assert_frr_policy_commands('bgp community-list standard NVYRPOLICYSMOKE seq 10 permit 65000:100', 'match community NVYRPOLICYSMOKE')


def test_community_list_expanded(config):
    """Create and reference a expanded community-list."""
    config.set('set policy community-list expanded NVYRPOLICYSMOKE rule 10 action permit regex "^65000:"')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match community-list NVYRPOLICYSMOKE')
    config.commit()
    assert_frr_policy_commands('bgp community-list expanded NVYRPOLICYSMOKE seq 10 permit ^65000:', 'match community NVYRPOLICYSMOKE')


def test_community_list_exact_match(config):
    """Use exact-set matching for community-list."""
    config.set('set policy community-list standard NVYRPOLICYSMOKE rule 10 action permit community 65000:100')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match community-list NVYRPOLICYSMOKE exact-match')
    config.commit()
    assert_frr_policy_commands('match community NVYRPOLICYSMOKE exact-match')


def test_community_list_delete(config):
    """Delete only communities permitted by a community-list."""
    config.set('set policy community-list standard NVYRPOLICYSMOKE rule 10 action permit community 65000:100')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set community-delete NVYRPOLICYSMOKE')
    config.commit()
    assert_frr_policy_commands('set comm-list NVYRPOLICYSMOKE delete')


def test_large_community_list_standard(config):
    """Create and reference a standard large-community-list."""
    config.set('set policy large-community-list standard NVYRPOLICYSMOKE rule 10 action permit community 65000:100:200')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match large-community-list NVYRPOLICYSMOKE')
    config.commit()
    assert_frr_policy_commands('bgp large-community-list standard NVYRPOLICYSMOKE seq 10 permit 65000:100:200', 'match large-community NVYRPOLICYSMOKE')


def test_large_community_list_expanded(config):
    """Create and reference a expanded large-community-list."""
    config.set('set policy large-community-list expanded NVYRPOLICYSMOKE rule 10 action permit regex "^65000:"')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match large-community-list NVYRPOLICYSMOKE')
    config.commit()
    assert_frr_policy_commands('bgp large-community-list expanded NVYRPOLICYSMOKE seq 10 permit ^65000:', 'match large-community NVYRPOLICYSMOKE')


def test_large_community_list_exact_match(config):
    """Use exact-set matching for large-community-list."""
    config.set('set policy large-community-list standard NVYRPOLICYSMOKE rule 10 action permit community 65000:100:200')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match large-community-list NVYRPOLICYSMOKE exact-match')
    config.commit()
    assert_frr_policy_commands('match large-community NVYRPOLICYSMOKE exact-match')


def test_large_community_list_delete(config):
    """Delete only communities permitted by a large-community-list."""
    config.set('set policy large-community-list standard NVYRPOLICYSMOKE rule 10 action permit community 65000:100:200')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set large-community-delete NVYRPOLICYSMOKE')
    config.commit()
    assert_frr_policy_commands('set large-comm-list NVYRPOLICYSMOKE delete')


def test_as_path_list(config):
    """Create an ordered AS-path filter and use it in a route-map."""
    config.set('set policy as-path-list NVYRPOLICYSMOKE rule 10 action permit regex "_64501_"')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match as-path-list NVYRPOLICYSMOKE')
    config.commit()
    assert_frr_policy_commands('bgp as-path access-list NVYRPOLICYSMOKE seq 10 permit _64501_', 'match as-path NVYRPOLICYSMOKE')


def test_community_any(config):
    """Select any-member matching explicitly."""
    config.set('set policy community-list standard NVYRPOLICYSMOKE rule 10 action permit community 65000:100')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match community-list NVYRPOLICYSMOKE any')
    config.commit()
    assert_frr_policy_commands('match community NVYRPOLICYSMOKE any')


def test_as_path_count(config):
    """Install the as path count policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match as-path-count 3')
    config.commit()
    assert_frr_policy_commands('match as-path-count 3')


def test_match_local_preference(config):
    """Install the match local preference policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match local-preference 200')
    config.commit()
    assert_frr_policy_commands('match local-preference 200')


def test_match_peer_ipv4(config):
    """Install the match peer ipv4 policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match peer 192.0.2.1')
    config.commit()
    assert_frr_policy_commands('match peer 192.0.2.1')


def test_match_peer_ipv6(config):
    """Install the match peer ipv6 policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match peer 2001:db8::1')
    config.commit()
    assert_frr_policy_commands('match peer 2001:db8::1')


def test_match_source_peer(config):
    """Install the match source peer policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match source-peer PEERS')
    config.commit()
    assert_frr_policy_commands('match src-peer PEERS')


def test_match_next_hop_ipv4(config):
    """Install the match next hop ipv4 policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match ipv4 next-hop address 192.0.2.1')
    config.commit()
    assert_frr_policy_commands('match ip next-hop address 192.0.2.1')


def test_match_next_hop_ipv6(config):
    """Install the match next hop ipv6 policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match ipv6 next-hop address 2001:db8::1')
    config.commit()
    assert_frr_policy_commands('match ipv6 next-hop address 2001:db8::1')


def test_well_known_community(config):
    """Install the well known community policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set community no-export')
    config.commit()
    assert_frr_policy_commands('set community no-export')


def test_clear_community(config):
    """Install the clear community policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set community none')
    config.commit()
    assert_frr_policy_commands('set community none')


def test_clear_large_community(config):
    """Install the clear large community policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set large-community none')
    config.commit()
    assert_frr_policy_commands('set large-community none')


def test_prepend_last_as(config):
    """Install the prepend last as policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set as-path prepend-last-as 3')
    config.commit()
    assert_frr_policy_commands('set as-path prepend last-as 3')


def test_exclude_as_numbers(config):
    """Install the exclude as numbers policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set as-path exclude as-number 64501 as-number 64502')
    config.commit()
    assert_frr_policy_commands('set as-path exclude 64501 64502')


def test_exclude_all_as_numbers(config):
    """Install the exclude all as numbers policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set as-path exclude all')
    config.commit()
    assert_frr_policy_commands('set as-path exclude all')


def test_replace_as_number(config):
    """Install the replace as number policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set as-path replace as-number 64501 replacement 65000')
    config.commit()
    assert_frr_policy_commands('set as-path replace 64501 65000')


def test_replace_any_as_number(config):
    """Install the replace any as number policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set as-path replace any')
    config.commit()
    assert_frr_policy_commands('set as-path replace any')


def test_ipv4_peer_next_hop(config):
    """Install the ipv4 peer next hop policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set ipv4 next-hop peer-address')
    config.commit()
    assert_frr_policy_commands('set ip next-hop peer-address')


def test_ipv4_unchanged_next_hop(config):
    """Install the ipv4 unchanged next hop policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set ipv4 next-hop unchanged')
    config.commit()
    assert_frr_policy_commands('set ip next-hop unchanged')


def test_ipv6_peer_next_hop(config):
    """Install the ipv6 peer next hop policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set ipv6 next-hop peer-address')
    config.commit()
    assert_frr_policy_commands('set ipv6 next-hop peer-address')


def test_ipv6_prefer_global(config):
    """Install the ipv6 prefer global policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set ipv6 next-hop prefer-global')
    config.commit()
    assert_frr_policy_commands('set ipv6 next-hop prefer-global')


def test_ipv6_local_next_hop(config):
    """Install the ipv6 local next hop policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set ipv6 next-hop local fe80::1')
    config.commit()
    assert_frr_policy_commands('set ipv6 next-hop local fe80::1')


def test_increase_local_preference(config):
    """Install the increase local preference policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set local-preference +50')
    config.commit()
    assert_frr_policy_commands('set local-preference +50')


def test_decrease_local_preference(config):
    """Install the decrease local preference policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set local-preference -50')
    config.commit()
    assert_frr_policy_commands('set local-preference -50')


def test_increase_metric(config):
    """Install the increase metric policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set metric +20')
    config.commit()
    assert_frr_policy_commands('set metric +20')


def test_decrease_metric(config):
    """Install the decrease metric policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set metric -20')
    config.commit()
    assert_frr_policy_commands('set metric -20')


def test_continue_next(config):
    """Install the continue next policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit on-match next')
    config.commit()
    assert_frr_policy_commands('on-match next')


def test_continue_goto(config):
    """Install the continue goto policy operation."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit on-match goto 100')
    config.commit()
    assert_frr_policy_commands('on-match goto 100')


def test_as_path_exclude_list(config):
    """Select AS numbers through an AS-path list for exclude."""
    config.set('set policy as-path-list NVYRPOLICYSMOKE rule 10 action permit regex "_64501_"')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set as-path exclude as-path-list NVYRPOLICYSMOKE')
    config.commit()
    assert_frr_policy_commands('set as-path exclude as-path-access-list NVYRPOLICYSMOKE')


def test_as_path_replace_list(config):
    """Select AS numbers through an AS-path list for replace."""
    config.set('set policy as-path-list NVYRPOLICYSMOKE rule 10 action permit regex "_64501_"')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set as-path replace as-path-list NVYRPOLICYSMOKE')
    config.commit()
    assert_frr_policy_commands('set as-path replace as-path-access-list NVYRPOLICYSMOKE')


def test_call_policy(config):
    """Call a separately configured route-map."""
    config.set('set policy route-map NVYRPOLICYCALL rule 10 action permit')
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit call NVYRPOLICYCALL')
    config.commit()
    assert_frr_policy_commands('call NVYRPOLICYCALL')


def test_missing_as_path_list_rejected(config):
    """Reject missing as path list before applying policies."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match as-path-list NVYRPOLICYMISSING')
    with assert_raises(CommitError, match='not configured'):
        config.commit()


def test_missing_community_list_rejected(config):
    """Reject missing community list before applying policies."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit match community-list NVYRPOLICYMISSING')
    with assert_raises(CommitError, match='not configured'):
        config.commit()


def test_clear_and_add_rejected(config):
    """Reject clear and add before applying policies."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set community none community 65000:1')
    with assert_raises(CommitError, match='none cannot be combined'):
        config.commit()


def test_prepend_conflict_rejected(config):
    """Reject prepend conflict before applying policies."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set as-path prepend "65000" prepend-last-as 2')
    with assert_raises(CommitError, match='mutually exclusive'):
        config.commit()


def test_replace_without_selector_rejected(config):
    """Reject replace without selector before applying policies."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set as-path replace replacement 65000')
    with assert_raises(CommitError, match='exactly one selection'):
        config.commit()


def test_exclude_conflict_rejected(config):
    """Reject exclude conflict before applying policies."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set as-path exclude all as-number 64501')
    with assert_raises(CommitError, match='exactly one selection'):
        config.commit()


def test_ipv4_next_hop_conflict_rejected(config):
    """Reject ipv4 next hop conflict before applying policies."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set ipv4 next-hop address 192.0.2.1 peer-address')
    with assert_raises(CommitError, match='mutually exclusive'):
        config.commit()


def test_ipv6_invalid_local_rejected(config):
    """Reject a non-link-local next hop at CLI entry."""
    with assert_raises(RouterError, match='link-local'):
        config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set ipv6 next-hop local 2001:db8::1')


def test_ipv6_invalid_global_rejected(config):
    """Reject link-local addresses in the global next-hop slot at CLI entry."""
    with assert_raises(RouterError, match='non-link-local'):
        config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit set ipv6 next-hop global fe80::1')


def test_backward_goto_rejected(config):
    """Reject backward goto before applying policies."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit on-match goto 10')
    with assert_raises(CommitError, match='move forward'):
        config.commit()


def test_continuation_conflict_rejected(config):
    """Reject continuation conflict before applying policies."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit on-match next goto 100')
    with assert_raises(CommitError, match='exactly one'):
        config.commit()


def test_missing_called_policy_rejected(config):
    """Reject missing called policy before applying policies."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit call NVYRPOLICYMISSING')
    with assert_raises(CommitError, match='not configured'):
        config.commit()


def test_call_cycle_rejected(config):
    """Reject mutually recursive route-map calls."""
    config.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit call NVYRPOLICYCALL')
    config.set('set policy route-map NVYRPOLICYCALL rule 10 action permit call NVYRPOLICYSMOKE')
    with assert_raises(CommitError, match='call cycle'):
        config.commit()


def test_invalid_posix_regex_rejected(config):
    """Use POSIX compilation to reject an unfinished expression at CLI entry."""
    with assert_raises(RouterError, match='FRR regular expression'):
        config.set('set policy as-path-list NVYRPOLICYSMOKE rule 10 action permit regex "["')


def test_duplicate_community_list_name_rejected(config):
    """Standard and expanded lists cannot share a native name."""
    config.set('set policy community-list standard NVYRPOLICYSMOKE rule 10 action permit community 65000:1')
    config.set('set policy community-list expanded NVYRPOLICYSMOKE rule 10 action permit regex "65000:"')
    with assert_raises(CommitError, match='both standard and expanded'):
        config.commit()
