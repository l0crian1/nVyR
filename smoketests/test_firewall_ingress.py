"""Ingress feature tests on disposable CLI-created links, away from management."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from nvyr.tree import lookup
from smoketests.assertions import (
    assert_firewall_chain, assert_config_names_unused, assert_link_absent, assert_raises,
    assert_firewall_commit_rejected, assert_firewall_rule, assert_firewall_object,
)
from smoketests.firewall_support import firewall_environment, firewall_suite, clear_firewall


@pytest.fixture(scope='module')
def ingress_links(config, firewall_suite):
    """Retain both ingress endpoints across cases; release their rules before final deletion."""
    assert_config_names_unused(config.get_config(), 'veth994', 'veth995')
    assert_link_absent('veth994')
    assert_link_absent('veth995')
    config.set('set interfaces virtual-ethernet veth994 peer-name veth995')
    config.set('set interfaces virtual-ethernet veth995 peer-name veth994')
    try:
        config.commit()
        yield
    finally:
        clear_firewall(config)
        running = config.get_config()
        if lookup(running, ('interfaces', 'virtual-ethernet', 'veth994'), None) is not None:
            config.delete('delete interfaces virtual-ethernet veth994')
        if lookup(running, ('interfaces', 'virtual-ethernet', 'veth995'), None) is not None:
            config.delete('delete interfaces virtual-ethernet veth995')
        config.commit()


def test_ingress_future_interfaces_and_wildcards(config):
    """Attachments may be installed before exact or prefix-matched devices exist."""
    config.set('set firewall ipv4 ingress filter interface nvfuture0')
    config.set('set firewall ipv6 ingress filter interface nvfuture*')
    config.commit()
    assert_firewall_object('chain', 'ingress', 'nvfuture')


def test_ingress_requires_interface(config):
    """A chain without a device selector must fail before native application."""
    config.set('set firewall ipv4 ingress filter rule 10 action accept')
    assert_firewall_commit_rejected(config, 'at least one interface')


def test_ingress_rejects_empty_vlan(config):
    """An empty VLAN node cannot silently become an unconditional rule."""
    config.set('set firewall ipv4 ingress filter interface dum998 rule 10 action accept vlan')
    assert_firewall_commit_rejected(config, 'vlan requires id or priority')


def test_ingress_schema_rejects_connection(config):
    """Connection matching is absent from the ingress command tree."""
    with assert_raises(RouterError):
        config.set('set firewall ipv4 ingress filter rule 10 connection state established')


def test_ingress_schema_rejects_fib(config):
    """The unsupported inet ingress FIB expression is unavailable at parse time."""
    with assert_raises(RouterError):
        config.set('set firewall ipv6 ingress filter rule 10 fib lookup source-address')


def test_ingress_schema_rejects_outbound_interface(config):
    """No output device has been selected at this hook."""
    with assert_raises(RouterError):
        config.set('set firewall ipv4 ingress filter rule 10 outbound-interface dum998')


def test_ingress_schema_rejects_offload(config):
    """Flow enrollment remains a forward-only action."""
    with assert_raises(RouterError):
        config.set('set firewall ipv4 ingress filter rule 10 action offload')


def test_ingress_schema_rejects_connection_limit_key(config):
    """Joinable keys have the same reduced choices as direct rule leaves."""
    with assert_raises(RouterError):
        config.set('set firewall ipv4 ingress filter rule 10 limit per source-address and connection-mark')


def test_ingress_rejects_connection_map(config):
    """A shared verdict map cannot supply a hidden connection predicate."""
    config.set('set firewall group map ipv4 TRACKED match connection mark')
    config.set('set firewall group map ipv4 TRACKED result-type verdict')
    config.set('set firewall ipv4 ingress filter interface dum998 rule 10 map TRACKED')
    assert_firewall_commit_rejected(config, 'unavailable in ingress')


def test_ingress_rejects_outbound_match_group(config):
    """Shared match groups are validated at the caller's hook."""
    config.set('set firewall group match-group ipv6 OUTPUT match outbound-link-group')
    config.set('set firewall ipv6 ingress filter interface dum998 rule 10 match-group OUTPUT action accept')
    assert_firewall_commit_rejected(config, 'unavailable in ingress')


def test_ingress_rejects_nested_connection_limit(config):
    """Nested named chains cannot bypass ingress connection restrictions."""
    config.set('set firewall ipv4 name LAST rule 10 action drop connection limit over 5')
    config.set('set firewall ipv4 name FIRST rule 10 action jump jump-target LAST')
    config.set('set firewall ipv4 ingress filter interface dum998 rule 10 action jump jump-target FIRST')
    assert_firewall_commit_rejected(config, 'unavailable in ingress')


def test_ingress_rejects_nested_fib(config):
    """A named chain cannot import inet's unsupported ingress FIB lookup."""
    config.set('set firewall ipv6 name LAST rule 10 action drop fib lookup source-address')
    config.set('set firewall ipv6 name LAST rule 10 fib result outbound-interface missing')
    config.set('set firewall ipv6 name FIRST rule 10 action jump jump-target LAST')
    config.set('set firewall ipv6 ingress filter interface dum998 rule 10 action jump jump-target FIRST')
    assert_firewall_commit_rejected(config, 'not supported from the ingress hook')


def test_ingress_rejects_named_limit_connection_key(config):
    """Named limits cannot introduce keys omitted from the inline choices."""
    config.set('set firewall group limit-group ipv4 RATE rate packets 10/s per connection-mark')
    config.set('set firewall ipv4 ingress filter interface dum998 rule 10 action accept limit group RATE')
    assert_firewall_commit_rejected(config, 'unavailable in ingress')


def test_ingress_shared_limit_and_quota(config):
    """Shared packet allowances and quotas install without connection tracking."""
    config.set('set firewall group limit-group ipv4 RATE rate packets 10/s')
    config.set('set firewall group limit-group ipv4 RATE per source-address')
    config.set('set firewall group quota-group CAP bytes 1m until')
    config.set('set firewall ipv4 ingress filter interface dum998 rule 10 action accept counter')
    config.set('set firewall ipv4 ingress filter rule 10 limit group RATE')
    config.set('set firewall ipv4 ingress filter rule 10 quota group CAP')
    config.commit()
    assert_firewall_rule('ipv4_ingress', 10, 'limit rate', 'quota name')


def test_ingress_notrack_and_log(config):
    """Untracking and logging retain the ingress-specific hook prefix."""
    config.set('set firewall ipv6 ingress filter interface dum998 rule 10 notrack log action continue')
    config.commit()
    assert_firewall_rule('ipv6_ingress', 10, 'notrack', 'ipv6-ING-filter-10-C')


def test_ipv4_ingress_native_configuration(config, ingress_links):
    """Install the IPV4 transport rule and fixed ingress hook priority."""
    config.set('set firewall ipv4 ingress filter interface veth995 default-action drop')
    config.set('set firewall ipv4 ingress filter rule 10 protocol udp destination-port 53098 counter action drop')
    config.commit()

    assert_firewall_chain('ingress', hook='ingress', prio=-10)
    assert_firewall_rule('ipv4_ingress', 10, 'udp dport 53098', 'counter', 'drop')


def test_ipv6_ingress_native_configuration(config, ingress_links):
    """Install the IPV6 transport rule and fixed ingress hook priority."""
    config.set('set firewall ipv6 ingress filter interface veth995 default-action drop')
    config.set('set firewall ipv6 ingress filter rule 10 protocol udp destination-port 53098 counter action drop')
    config.commit()

    assert_firewall_chain('ingress', hook='ingress', prio=-10)
    assert_firewall_rule('ipv6_ingress', 10, 'udp dport 53098', 'counter', 'drop')
