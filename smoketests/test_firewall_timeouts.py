"""Installed connection timeout objects, family selection and verification."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_firewall_commit_rejected, assert_firewall_timeout, assert_firewall_rule,
    firewall_timeout_object,
    assert_equal, assert_not_equal, assert_raises, firewall_object_handle,
)
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_udp_timeout_group_ipv4(config):
    """An IPv4 rule assigns a UDP policy with both response-state lifetimes."""
    config.set('set firewall group timeout-group ipv4 DNS protocol udp timeout unreplied 10s replied 30s')
    config.set('set firewall ipv4 output filter rule 10 protocol udp destination-port 5300 connection timeout-group DNS action accept')
    config.commit()

    assert_firewall_timeout('ipv4_timeout_group_DNS', 'udp', 'ip', unreplied=10, replied=30)
    assert_firewall_rule('ipv4_output', 10, 'ct timeout set "ipv4_timeout_group_DNS"')


def test_udp_timeout_group_ipv6(config):
    """IPv6 policy objects explicitly use the IPv6 conntrack backend."""
    config.set('set firewall group timeout-group ipv6 DNS protocol udp timeout unreplied 10s replied 30s')
    config.set('set firewall ipv6 output filter rule 10 protocol udp destination-port 5300 connection timeout-group DNS action accept')
    config.commit()

    assert_firewall_timeout('ipv6_timeout_group_DNS', 'udp', 'ip6', unreplied=10, replied=30)
    assert_firewall_rule('ipv6_output', 10, 'ct timeout set "ipv6_timeout_group_DNS"')


def test_udp_timeout_group_inet(config):
    """One neutral rule selects both native policy objects with an anonymous map."""
    config.set('set firewall group timeout-group inet DNS protocol udp timeout unreplied 10s replied 30s')
    config.set('set firewall inet output filter rule 10 protocol udp destination-port 5300 connection timeout-group DNS action accept')
    config.commit()

    assert_firewall_timeout('inet_timeout_group_DNS_ip', 'udp', 'ip', unreplied=10)
    assert_firewall_timeout('inet_timeout_group_DNS_ip6', 'udp', 'ip6', unreplied=10)
    assert_firewall_rule('output', 10, 'ct timeout set meta nfproto map', 'inet_timeout_group_DNS_ip', 'inet_timeout_group_DNS_ip6')


def test_tcp_timeout_group_ipv4(config):
    """TCP policies render every native state with inherited or explicit lifetimes."""
    config.set('set firewall group timeout-group ipv4 APP protocol tcp timeout established 1d close 20s')
    config.set('set firewall ipv4 name APP rule 10 protocol tcp connection timeout-group APP action continue')
    config.set('set firewall ipv4 forward filter rule 10 action jump jump-target APP')
    config.commit()

    assert_firewall_timeout('ipv4_timeout_group_APP', 'tcp', 'ip', established=86400, close=20)
    assert_firewall_rule('ipv4_name_APP', 10, 'ct timeout set "ipv4_timeout_group_APP"', 'continue')


def test_tcp_timeout_group_ipv6(config):
    """IPv6 TCP consumers can assign the policy before returning to their caller."""
    config.set('set firewall group timeout-group ipv6 APP protocol tcp timeout established 1d')
    config.set('set firewall ipv6 name APP rule 10 protocol tcp connection timeout-group APP action return')
    config.set('set firewall ipv6 forward filter rule 10 action jump jump-target APP')
    config.commit()

    assert_firewall_timeout('ipv6_timeout_group_APP', 'tcp', 'ip6', established=86400)
    assert_firewall_rule('ipv6_name_APP', 10, 'ct timeout set "ipv6_timeout_group_APP"', 'return')


def test_timeout_policy_replacement_and_global_inheritance(config):
    """Inherited changes replace policies and consumers, preserving unrelated objects."""
    config.set('set firewall group timeout-group inet DNS protocol udp timeout unreplied 10s')
    config.set('set firewall inet output filter rule 10 protocol udp connection timeout-group DNS action accept')
    config.set('set firewall inet name UNRELATED default-action drop')
    config.commit()
    original = firewall_timeout_object('inet_timeout_group_DNS_ip')['handle']
    unrelated = firewall_object_handle('chain', 'inet_name_UNRELATED')

    config.set('set firewall global-options connection-tracking timeout udp stream 3m')
    config.commit()

    assert_firewall_timeout('inet_timeout_group_DNS_ip', 'udp', 'ip', replied=180)
    assert_firewall_timeout('inet_timeout_group_DNS_ip6', 'udp', 'ip6', replied=180)
    assert_not_equal(firewall_timeout_object('inet_timeout_group_DNS_ip')['handle'], original)
    assert_equal(firewall_object_handle('chain', 'inet_name_UNRELATED'), unrelated)


def test_timeout_group_requires_protocol(config):
    """A partially defined unused group fails verification without replacing rules."""
    config.set('set firewall group timeout-group ipv4 BAD timeout unreplied 10s')
    assert_firewall_commit_rejected(config, 'protocol tcp or udp is required')


def test_timeout_group_requires_state(config):
    """A protocol alone is not a meaningful timeout policy."""
    config.set('set firewall group timeout-group ipv4 BAD protocol udp')
    assert_firewall_commit_rejected(config, 'at least one timeout')


def test_timeout_group_rejects_wrong_state(config):
    """TCP states are not accepted in UDP policies."""
    config.set('set firewall group timeout-group ipv4 BAD protocol udp timeout established 10s')
    assert_firewall_commit_rejected(config, 'unavailable for udp')


def test_timeout_group_rejects_wrong_rule_protocol(config):
    """A rule cannot select a different transport from its timeout group."""
    config.set('set firewall group timeout-group ipv4 DNS protocol udp timeout unreplied 10s')
    config.set('set firewall ipv4 output filter rule 10 protocol tcp connection timeout-group DNS action accept')
    assert_firewall_commit_rejected(config, 'requires protocol udp')


def test_timeout_group_nested_raw_caller_rejected(config):
    """Nested named-chain jumps cannot move timeout assignment before conntrack."""
    config.set('set firewall group timeout-group ipv4 DNS protocol udp timeout unreplied 10s')
    config.set('set firewall ipv4 name BOTTOM rule 10 protocol udp connection timeout-group DNS action accept')
    config.set('set firewall ipv4 name TOP rule 10 action jump jump-target BOTTOM')
    config.set('set firewall ipv4 prerouting raw rule 10 action jump jump-target TOP')
    assert_firewall_commit_rejected(config, 'timeout-group is unavailable before connection tracking')


def test_timeout_group_referenced_deletion_rejected(config):
    """Registrar protection prevents deleting a policy still used by a rule."""
    config.set('set firewall group timeout-group inet DNS protocol udp timeout unreplied 10s')
    config.set('set firewall inet output filter rule 10 protocol udp connection timeout-group DNS action accept')
    config.commit()

    with assert_raises(RouterError, match='referenced'):
        config.delete('delete firewall group timeout-group inet DNS')
