"""Global enrollment and its verification checks through the live configuration API."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from nvyr.helpers.process import cmd
from smoketests.assertions import (
    assert_equal, assert_in, assert_not_in, assert_raises, assert_true,
    assert_firewall_commit_rejected, assert_firewall_object, firewall_object_handle,
)
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_global_flowtable_precedes_state_accept(config):
    """The global target enrolls forwarding traffic before state acceptance, never local traffic."""
    config.set('set firewall flowtable FAST interface dum998 interface dum999 offload software')
    config.set('set firewall global-options state-policy established action accept')
    config.set('set firewall global-options flowtable FAST')
    config.set('set firewall ipv4 input filter default-action accept')
    config.set('set firewall ipv4 output filter default-action accept')
    config.commit()

    forward = cmd(['nft', '-s', 'list', 'chain', 'inet', 'nvyr_filter', 'forward'])
    assert_true(forward.index('flow add @flowtable_FAST') < forward.index('ct state vmap'))
    assert_not_in('flow add', cmd(['nft', '-s', 'list', 'chain', 'inet', 'nvyr_filter', 'input']))
    assert_not_in('flow add', cmd(['nft', '-s', 'list', 'chain', 'inet', 'nvyr_filter', 'output']))

    # References prevent removing the target before its consumer.
    with assert_raises(RouterError, match='referenc'):
        config.delete('delete firewall flowtable FAST')

    # Updating native devices must release and rebuild the global enrollment rule.
    config.delete('delete firewall flowtable FAST interface dum999')
    config.commit()
    assert_in('flow add @flowtable_FAST', cmd(['nft', '-s', 'list', 'chain', 'inet', 'nvyr_filter', 'forward']))


def test_global_flowtable_requires_accept_policy(config):
    """Never enroll a connection that the configured global policy would drop."""
    config.set('set firewall flowtable FAST interface dum998')
    config.set('set firewall global-options flowtable FAST')
    config.set('set firewall global-options state-policy established action drop')
    assert_firewall_commit_rejected(config, 'requires state-policy established action accept')


def test_global_flowtable_requires_existing_target(config):
    """A missing flowtable target fails verification before nftables is changed."""
    config.set('set firewall global-options state-policy established action accept')
    config.set('set firewall global-options flowtable MISSING')
    assert_firewall_commit_rejected(config, 'not a configured flowtable')


def test_global_flowtable_requires_established_policy(config):
    """An omitted established policy must not silently enable global enrollment."""
    config.set('set firewall flowtable FAST interface dum998')
    config.set('set firewall global-options flowtable FAST')
    assert_firewall_commit_rejected(config, 'requires state-policy established action accept')


def test_global_flowtable_rejects_established_reject(config):
    """Rejecting established traffic is incompatible with offloading it."""
    config.set('set firewall flowtable FAST interface dum998')
    config.set('set firewall global-options state-policy established action reject')
    config.set('set firewall global-options flowtable FAST')
    assert_firewall_commit_rejected(config, 'requires state-policy established action accept')


def test_global_flowtable_switch_and_removal(config):
    """Changing targets releases the old reference, while removal retains local hooks."""
    config.set('set firewall flowtable FAST interface dum998')
    config.set('set firewall flowtable NEXT interface dum999')
    config.set('set firewall global-options state-policy established action accept')
    config.set('set firewall global-options flowtable FAST')
    config.set('set firewall ipv4 input filter default-action accept')
    config.commit()
    input_handle = firewall_object_handle('chain', 'ipv4_input')

    config.set('set firewall global-options flowtable NEXT')
    config.delete('delete firewall flowtable FAST')
    config.commit()
    assert_firewall_object('chain', 'forward', 'flow add @flowtable_NEXT', absent=('flowtable_FAST',))
    assert_equal(firewall_object_handle('chain', 'ipv4_input'), input_handle)

    config.delete('delete firewall global-options flowtable')
    config.delete('delete firewall flowtable NEXT')
    config.commit()
    assert_firewall_object('table', 'nvyr_filter', 'chain ipv4_input', absent=('flow add', 'flowtable_NEXT'))
    assert_equal(firewall_object_handle('chain', 'ipv4_input'), input_handle)


def test_ipv4_global_flowtable_creates_forward_dispatch(config):
    """Global enrollment supplies IPv4 forwarding even without explicit forward rules."""
    config.set('set firewall flowtable FAST interface dum998')
    config.set('set firewall global-options state-policy established action accept')
    config.set('set firewall global-options flowtable FAST')
    config.commit()

    assert_firewall_object('chain', 'forward', 'ct state established', r'meta l4proto \{ tcp, udp \}',
                           'flow add @flowtable_FAST', 'ipv4 : jump ipv4_forward')
    assert_firewall_object('chain', 'ipv4_forward', 'accept comment "default')


def test_ipv6_global_flowtable_creates_forward_dispatch(config):
    """The same global enrollment supplies IPv6 forwarding without explicit rules."""
    config.set('set firewall flowtable FAST interface dum998')
    config.set('set firewall global-options state-policy established action accept')
    config.set('set firewall global-options flowtable FAST')
    config.commit()

    assert_firewall_object('chain', 'forward', 'ct state established', r'meta l4proto \{ tcp, udp \}',
                           'flow add @flowtable_FAST', 'ipv6 : jump ipv6_forward')
    assert_firewall_object('chain', 'ipv6_forward', 'accept comment "default')
