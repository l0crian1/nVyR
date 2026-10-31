"""Zone maps, per-family policy selection and validation on a live router."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_equal, assert_not_equal, assert_raises, assert_less, assert_in, assert_firewall_object,
    assert_firewall_commit_rejected, firewall_object_handle,
)
from smoketests.firewall_support import firewall_environment, firewall_suite, vrf_environment, firewall_vrf_suite


def test_ipv4_zone_accept_default_warning(config):
    """A permissive fallback reports a warning while still installing zone maps."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall ipv4 forward filter default-action accept')
    config.set('set firewall ipv6 forward filter default-action drop')

    result = config.commit()

    assert_equal(len(result['messages']), 1)
    assert_in('Warning: firewall ipv4 forward filter defaults to accept.', result['messages'][0])
    assert_firewall_object('chain', 'ipv4_forward', 'vmap @ipv4_zone_forward')


def test_ipv6_zone_accept_default_warning(config):
    """IPv6 warnings follow its own default without attributing them to IPv4."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall ipv4 forward filter default-action drop')
    config.set('set firewall ipv6 forward filter default-action accept')

    result = config.commit()

    assert_equal(len(result['messages']), 1)
    assert_in('Warning: firewall ipv6 forward filter defaults to accept.', result['messages'][0])
    assert_firewall_object('chain', 'ipv6_forward', 'vmap @ipv6_zone_forward')


def test_ipv4_zone_forward_policy_and_comments(config):
    """The pair map uses a policy in one direction and the destination default in reverse."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum999')
    config.set('set firewall ipv4 name WEB default-action accept')
    config.set('set firewall zone-policy from-zone USERS to-zone WAN ipv4-policy WEB')
    config.commit()

    assert_firewall_object('map', 'ipv4_zone_forward',
                           'counter',
                           'dum998.*dum999.*comment "USERS to WAN".*jump ipv4_name_WEB',
                           'dum999.*dum998.*comment "WAN to USERS".*drop')
    assert_firewall_object('chain', 'ipv4_forward', 'iifname . oifname vmap @ipv4_zone_forward')


def test_ipv6_zone_forward_policy_and_comments(config):
    """IPv6 has its own named target while the unassigned IPv4 pairing drops."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum999')
    config.set('set firewall ipv6 name WEB default-action accept')
    config.set('set firewall zone-policy from-zone USERS to-zone WAN ipv6-policy WEB')
    config.commit()

    assert_firewall_object('map', 'ipv6_zone_forward', 'counter', 'comment "USERS to WAN".*jump ipv6_name_WEB')
    assert_firewall_object('map', 'ipv4_zone_forward', 'comment "USERS to WAN".*drop')


def test_ipv4_zone_local_input_output(config):
    """Both input identities share a map, while local output has its own policy map."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv4 name IN default-action accept')
    config.set('set firewall ipv4 name OUT default-action drop')
    config.set('set firewall zone-policy from-zone USERS to-zone LOCAL ipv4-policy IN')
    config.set('set firewall zone-policy from-zone LOCAL to-zone USERS ipv4-policy OUT')
    config.commit()

    assert_firewall_object('chain', 'ipv4_input', 'iifname vmap @ipv4_zone_input', 'sdifname vmap @ipv4_zone_input')
    assert_firewall_object('map', 'ipv4_zone_input', 'dum998.*comment "USERS".*jump ipv4_name_IN')
    assert_firewall_object('map', 'ipv4_zone_output', 'dum998.*comment "USERS".*jump ipv4_name_OUT')


def test_ipv6_zone_local_input_output(config):
    """IPv6 uses the same two INPUT selectors and separate OUTPUT dispatch."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv6 name IN default-action accept')
    config.set('set firewall ipv6 name OUT default-action drop')
    config.set('set firewall zone-policy from-zone USERS to-zone LOCAL ipv6-policy IN')
    config.set('set firewall zone-policy from-zone LOCAL to-zone USERS ipv6-policy OUT')
    config.commit()

    assert_firewall_object('chain', 'ipv6_input', 'iifname vmap @ipv6_zone_input', 'sdifname vmap @ipv6_zone_input')
    assert_firewall_object('map', 'ipv6_zone_input', 'dum998.*comment "USERS".*jump ipv6_name_IN')
    assert_firewall_object('map', 'ipv6_zone_output', 'dum998.*comment "USERS".*jump ipv6_name_OUT')


def test_ipv4_zone_intra_policy_overrides_default(config):
    """An IPv4 intra-zone policy replaces its default without changing IPv6's default accept."""
    config.set('set firewall zone USERS interface dum998 interface dum999')
    config.set('set firewall ipv4 name INTERNAL default-action drop')
    config.set('set firewall zone USERS intra-zone ipv4-policy INTERNAL')
    config.commit()

    assert_firewall_object('map', 'ipv4_zone_forward', 'comment "USERS to USERS".*jump ipv4_name_INTERNAL')
    assert_firewall_object('map', 'ipv6_zone_forward', 'comment "USERS to USERS".*accept')


def test_ipv6_zone_intra_policy_overrides_default(config):
    """IPv6 policy selection is independent of the explicit default used for IPv4."""
    config.set('set firewall zone USERS interface dum998 interface dum999 intra-zone default-action drop')
    config.set('set firewall ipv6 name INTERNAL default-action accept')
    config.set('set firewall zone USERS intra-zone ipv6-policy INTERNAL')
    config.commit()

    assert_firewall_object('map', 'ipv6_zone_forward', 'comment "USERS to USERS".*jump ipv6_name_INTERNAL')
    assert_firewall_object('map', 'ipv4_zone_forward', 'comment "USERS to USERS".*drop')


def test_zone_policy_edit_preserves_unrelated_output(config):
    """Replacing a forward policy releases its map references without resetting output."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum999')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv4 name WEB default-action accept')
    config.set('set firewall zone-policy from-zone USERS to-zone WAN ipv4-policy WEB')
    config.commit()
    output = firewall_object_handle('chain', 'ipv4_output')

    config.set('set firewall ipv4 name WEB default-action drop')
    config.commit()
    assert_equal(firewall_object_handle('chain', 'ipv4_output'), output)
    assert_firewall_object('chain', 'ipv4_name_WEB', 'drop')


def test_zone_membership_must_be_unique(config):
    """The same interface cannot classify into two different zones."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum998')
    assert_firewall_commit_rejected(config, 'already belongs')


def test_zone_local_cannot_have_interfaces(config):
    """The local zone represents the router, not a list of devices."""
    config.set('set firewall zone LOCAL local-zone interface dum998')
    assert_firewall_commit_rejected(config, 'local-zone cannot have')


def test_zone_policy_references_and_family_validation(config):
    """A policy must exist in its chosen family; registered references protect valid targets."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum999')
    config.set('set firewall ipv4 name WEB default-action accept')
    config.set('set firewall zone-policy from-zone USERS to-zone WAN ipv6-policy WEB')
    assert_firewall_commit_rejected(config, 'ipv6 policy')
    config.delete('delete firewall zone-policy from-zone USERS to-zone WAN ipv6-policy')
    config.set('set firewall zone-policy from-zone USERS to-zone WAN ipv4-policy WEB')
    config.commit()

    with assert_raises(RouterError, match='referenced'):
        config.delete('delete firewall ipv4 name WEB')
    with assert_raises(RouterError, match='referenced'):
        config.delete('delete firewall zone WAN')


def test_zone_reject_default_is_not_configurable(config):
    """Reject is not a verdict-map value and has no synthetic-chain substitution."""
    with assert_raises(RouterError):
        config.set('set firewall zone USERS default-action reject')


def test_zone_requires_interface(config):
    """An ordinary zone cannot be committed without any members."""
    config.set('set firewall zone EMPTY')
    assert_firewall_commit_rejected(config, 'at least one interface is required')


def test_zone_requires_single_local_zone(config):
    """Two local identities would make local dispatch ambiguous."""
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall zone SECOND local-zone')
    assert_firewall_commit_rejected(config, 'only one local-zone')


def test_zone_local_cannot_have_intra_zone(config):
    """Router-local traffic cannot define interface-to-interface intra-zone policy."""
    config.set('set firewall zone LOCAL local-zone intra-zone default-action drop')
    assert_firewall_commit_rejected(config, 'local-zone cannot have')


def test_zone_pair_requires_source(config):
    """A directional policy cannot originate from an undefined zone."""
    config.set('set firewall zone WAN interface dum999')
    config.set('set firewall ipv4 name WEB default-action accept')
    config.set('set firewall zone-policy from-zone MISSING to-zone WAN ipv4-policy WEB')
    assert_firewall_commit_rejected(config, 'source zone is not configured')


def test_zone_pair_requires_destination(config):
    """A directional policy cannot target an undefined zone."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall ipv4 name WEB default-action accept')
    config.set('set firewall zone-policy from-zone USERS to-zone MISSING ipv4-policy WEB')
    assert_firewall_commit_rejected(config, 'destination zone is not configured')


def test_zone_pair_requires_to_zone(config):
    """An incomplete source pairing has no destination to install."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone-policy from-zone USERS')
    assert_firewall_commit_rejected(config, 'at least one to-zone policy is required')


def test_zone_pair_requires_policy(config):
    """An empty pair must not silently override the destination default."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum999')
    config.set('set firewall zone-policy from-zone USERS to-zone WAN')
    assert_firewall_commit_rejected(config, 'ipv4-policy or ipv6-policy is required')


def test_zone_pair_cannot_target_itself(config):
    """Same-zone traffic must use the single intra-zone configuration path."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall ipv4 name WEB default-action accept')
    config.set('set firewall zone-policy from-zone USERS to-zone USERS ipv4-policy WEB')
    assert_firewall_commit_rejected(config, 'use the zone intra-zone settings')


def test_ipv4_zone_intra_policy_requires_correct_family(config):
    """An IPv6 chain does not satisfy an IPv4 intra-zone reference."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall ipv6 name WEB default-action accept')
    config.set('set firewall zone USERS intra-zone ipv4-policy WEB')
    assert_firewall_commit_rejected(config, 'ipv4 policy')


def test_ipv6_zone_intra_policy_requires_correct_family(config):
    """An IPv4 chain does not satisfy an IPv6 intra-zone reference."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall ipv4 name WEB default-action accept')
    config.set('set firewall zone USERS intra-zone ipv6-policy WEB')
    assert_firewall_commit_rejected(config, 'ipv6 policy')


def test_ipv4_zone_nested_policy_enforces_input_restrictions(config):
    """INPUT restrictions must propagate through every jump in a zone policy."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv4 name TOP rule 10 action jump jump-target BOTTOM')
    config.set('set firewall ipv4 name BOTTOM rule 10 outbound-link-group 100 action accept')
    config.set('set firewall zone-policy from-zone USERS to-zone LOCAL ipv4-policy TOP')
    assert_firewall_commit_rejected(config, 'unavailable in input')


def test_ipv6_zone_nested_policy_enforces_output_restrictions(config):
    """OUTPUT restrictions must propagate through nested IPv6 zone policies."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv6 name TOP rule 10 action jump jump-target BOTTOM')
    config.set('set firewall ipv6 name BOTTOM rule 10 inbound-link-group 100 action accept')
    config.set('set firewall zone-policy from-zone LOCAL to-zone USERS ipv6-policy TOP')
    assert_firewall_commit_rejected(config, 'unavailable in output')


def test_ipv4_zone_dispatch_follows_rules_and_precedes_default(config):
    """Ordinary rules override zone policy; a map miss reaches the hook default."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall ipv4 forward filter rule 10 action accept')
    config.set('set firewall ipv4 forward filter default-action drop')
    config.commit()

    chain = assert_firewall_object('chain', 'ipv4_forward', 'drop comment "default')
    assert_less(chain.index('comment "10|'), chain.index('vmap @ipv4_zone_forward'))
    assert_less(chain.index('vmap @ipv4_zone_forward'), chain.index('comment "default|'))


def test_ipv6_zone_dispatch_follows_rules_and_precedes_default(config):
    """IPv6 preserves the same explicit-rule, zone-map, default-verdict ordering."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall ipv6 forward filter rule 10 action accept')
    config.set('set firewall ipv6 forward filter default-action drop')
    config.commit()

    chain = assert_firewall_object('chain', 'ipv6_forward', 'drop comment "default')
    assert_less(chain.index('comment "10|'), chain.index('vmap @ipv6_zone_forward'))
    assert_less(chain.index('vmap @ipv6_zone_forward'), chain.index('comment "default|'))


def test_ipv4_zone_output_vrf_bypass_order(config):
    """Permit the VRF-device pass after user rules, before member-interface zone policy."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv4 output filter rule 10 action drop')
    config.set('set firewall ipv4 output filter default-action drop')
    config.commit()

    chain = assert_firewall_object('chain', 'ipv4_output',
                                   'oifkind "vrf" counter accept comment "vrf-bypass"')
    assert_less(chain.index('comment "10|'), chain.index('comment "vrf-bypass"'))
    assert_less(chain.index('comment "vrf-bypass"'), chain.index('vmap @ipv4_zone_output'))
    assert_less(chain.index('vmap @ipv4_zone_output'), chain.index('comment "default|'))
    assert_firewall_object('chain', 'ipv4_input', absent=('vrf-bypass',))
    assert_firewall_object('chain', 'ipv4_forward', absent=('vrf-bypass',))


def test_ipv6_zone_output_vrf_bypass_order(config):
    """IPv6 keeps explicit output rules ahead of the VRF bypass and zone lookup."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv6 output filter rule 10 action drop')
    config.set('set firewall ipv6 output filter default-action drop')
    config.commit()

    chain = assert_firewall_object('chain', 'ipv6_output',
                                   'oifkind "vrf" counter accept comment "vrf-bypass"')
    assert_less(chain.index('comment "10|'), chain.index('comment "vrf-bypass"'))
    assert_less(chain.index('comment "vrf-bypass"'), chain.index('vmap @ipv6_zone_output'))
    assert_less(chain.index('vmap @ipv6_zone_output'), chain.index('comment "default|'))
    assert_firewall_object('chain', 'ipv6_input', absent=('vrf-bypass',))
    assert_firewall_object('chain', 'ipv6_forward', absent=('vrf-bypass',))


def test_zone_member_removal_and_full_cleanup(config):
    """Membership changes remove stale keys, and final zone removal releases all maps."""
    config.set('set firewall zone USERS interface dum998 interface dum999')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv4 output filter default-action accept')
    config.commit()

    config.delete('delete firewall zone USERS interface dum999')
    config.commit()
    assert_firewall_object('map', 'ipv4_zone_forward', 'dum998', absent=('dum999',))
    assert_firewall_object('map', 'ipv6_zone_forward', 'dum998', absent=('dum999',))
    assert_firewall_object('map', 'ipv4_zone_input', 'dum998', absent=('dum999',))
    assert_firewall_object('map', 'ipv6_zone_output', 'dum998', absent=('dum999',))

    config.delete('delete firewall zone')
    config.commit()
    assert_firewall_object('table', 'nvyr_filter', 'chain ipv4_output', absent=('_zone_', 'zone-dispatch'))


def test_ipv4_zone_nested_policy_change_rebuilds_callers(config):
    """A deep target change must release the calling map and preserve unrelated output."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum999')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv4 name TOP rule 10 action jump jump-target BOTTOM')
    config.set('set firewall ipv4 name BOTTOM default-action accept')
    config.set('set firewall zone-policy from-zone USERS to-zone WAN ipv4-policy TOP')
    config.commit()
    forward = firewall_object_handle('map', 'ipv4_zone_forward')
    output = firewall_object_handle('map', 'ipv4_zone_output')

    config.set('set firewall ipv4 name BOTTOM default-action drop')
    config.commit()
    assert_firewall_object('chain', 'ipv4_name_BOTTOM', 'drop comment "default')
    assert_not_equal(firewall_object_handle('map', 'ipv4_zone_forward'), forward)
    assert_equal(firewall_object_handle('map', 'ipv4_zone_output'), output)


def test_ipv6_zone_nested_policy_change_rebuilds_callers(config):
    """IPv6 nested-target updates rebuild only the maps that reference that policy."""
    config.set('set firewall zone USERS interface dum998')
    config.set('set firewall zone WAN interface dum999')
    config.set('set firewall zone LOCAL local-zone')
    config.set('set firewall ipv6 name TOP rule 10 action jump jump-target BOTTOM')
    config.set('set firewall ipv6 name BOTTOM default-action accept')
    config.set('set firewall zone-policy from-zone USERS to-zone WAN ipv6-policy TOP')
    config.commit()
    forward = firewall_object_handle('map', 'ipv6_zone_forward')
    output = firewall_object_handle('map', 'ipv6_zone_output')

    config.set('set firewall ipv6 name BOTTOM default-action drop')
    config.commit()
    assert_firewall_object('chain', 'ipv6_name_BOTTOM', 'drop comment "default')
    assert_not_equal(firewall_object_handle('map', 'ipv6_zone_forward'), forward)
    assert_equal(firewall_object_handle('map', 'ipv6_zone_output'), output)
