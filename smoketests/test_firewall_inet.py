"""Direct inet policies, neutral groups and flowtable accounting on a live router."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_less, assert_raises, assert_firewall_rule, assert_firewall_object,
    assert_firewall_commit_rejected,
)
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_inet_icmpx_response(config):
    """The portable response is an ICMPX statement in the shared base chain."""
    config.set('set firewall inet input filter rule 10 protocol udp destination-port 53098 action reject reject-response admin-prohibited')
    config.commit()

    assert_firewall_rule('input', 10, 'reject with icmpx.*admin-prohibited')


def test_inet_tcp_reset_requires_protocol(config):
    """Reject a TCP reset response without a positive TCP-only predicate."""
    config.set('set firewall inet input filter rule 10 action reject reject-response tcp-reset')
    assert_firewall_commit_rejected(config, 'requires protocol tcp')


def test_inet_map_conflicting_explicit_parameter(config):
    """A mapped field cannot also be supplied by the consuming rule."""
    config.set('set firewall group map inet SERVICES match protocol')
    config.set('set firewall group map inet SERVICES result-type verdict')
    config.set('set firewall inet input filter rule 10 map SERVICES protocol tcp')
    assert_firewall_commit_rejected(config, 'map cannot be combined with protocol')


def test_inet_ingress_indirect_connection_match_rejected(config):
    """An inet map cannot bypass ingress's connection-tracking restrictions."""
    config.set('set firewall group map inet TRACKED match connection mark')
    config.set('set firewall group map inet TRACKED result-type verdict')
    config.set('set firewall inet ingress filter interface dum998')
    config.set('set firewall inet ingress filter rule 10 map TRACKED')
    assert_firewall_commit_rejected(config, 'unavailable in ingress')


def test_inet_addresses_are_not_schema_options(config):
    """Family-specific addresses must remain under IPv4 or IPv6."""
    with assert_raises(RouterError):
        config.set('set firewall inet input filter rule 10 source-address 192.0.2.1')


def test_inet_no_hook_default_action(config):
    """Inet hook rules must fall through rather than gain an implicit default verdict."""
    with assert_raises(RouterError):
        config.set('set firewall inet input filter default-action drop')


def test_flowtable_counter_option(config):
    """Flow accounting can be enabled and removed using the normal lifecycle."""
    config.set('set firewall flowtable ACCOUNT interface dum998 counter')
    config.commit()
    assert_firewall_object('flowtable', 'flowtable_ACCOUNT', 'counter')

    config.delete('delete firewall flowtable ACCOUNT counter')
    config.commit()
    assert_firewall_object('flowtable', 'flowtable_ACCOUNT', 'dum998')


def test_inet_rule_precedes_ipv4_dispatch(config):
    """Native inet rules precede the IPV4 dispatch in the same base chain."""
    config.set('set firewall inet input filter rule 10 action accept protocol udp destination-port 53098 counter')
    config.set('set firewall ipv4 input filter default-action drop')
    config.commit()

    assert_firewall_rule('input', 10, 'udp dport 53098', 'counter', 'accept')
    chain = assert_firewall_object('chain', 'input', 'meta nfproto vmap')
    assert_less(chain.index('udp dport 53098'), chain.index('meta nfproto vmap'))


def test_inet_rule_precedes_ipv6_dispatch(config):
    """Native inet rules precede the IPV6 dispatch in the same base chain."""
    config.set('set firewall inet input filter rule 10 action accept protocol udp destination-port 53098 counter')
    config.set('set firewall ipv6 input filter default-action drop')
    config.commit()

    assert_firewall_rule('input', 10, 'udp dport 53098', 'counter', 'accept')
    chain = assert_firewall_object('chain', 'input', 'meta nfproto vmap')
    assert_less(chain.index('udp dport 53098'), chain.index('meta nfproto vmap'))
