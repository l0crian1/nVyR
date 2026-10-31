"""Installed global helper objects, assignment ordering and validation."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from smoketests.assertions import (
    assert_equal, assert_not_equal, assert_less, assert_raises,
    assert_firewall_object, assert_firewall_rule, assert_firewall_commit_rejected,
    firewall_object_handle,
)
from smoketests.firewall_support import firewall_environment, firewall_suite


def test_ftp_helper(config):
    """FTP creates one shared dual-family TCP helper on its standard port."""
    config.set('set firewall global-options connection-tracking helper ftp')
    config.commit()

    assert_firewall_object('table', 'nvyr_filter',
                          r'ct helper conntrack_helper_ftp_tcp', r'type "ftp" protocol tcp', r'l3proto inet')
    assert_firewall_object('map', 'conntrack_helpers', r'tcp . 21 : "conntrack_helper_ftp_tcp"',
                          absent=(r'udp . 69', r'5060'))


def test_tftp_helper(config):
    """TFTP creates a UDP/69 entry without enabling FTP or SIP."""
    config.set('set firewall global-options connection-tracking helper tftp')
    config.commit()

    assert_firewall_object('map', 'conntrack_helpers', r'udp . 69 : "conntrack_helper_tftp_udp"',
                          absent=(r'tcp . 21', r'5060'))


def test_sip_helper(config):
    """SIP enables both TCP and UDP port 5060 through separate native objects."""
    config.set('set firewall global-options connection-tracking helper sip')
    config.commit()

    assert_firewall_object('map', 'conntrack_helpers', r'tcp . 5060 : "conntrack_helper_sip_tcp"',
                          r'udp . 5060 : "conntrack_helper_sip_udp"')


def test_helper_entrypoint_order_ipv4(config):
    """The helper runs after state policy and before inet rules and IPv4 dispatch."""
    config.set('set firewall global-options connection-tracking helper ftp tftp sip')
    config.set('set firewall global-options state-policy established action accept')
    config.set('set firewall inet forward filter rule 10 action continue')
    config.set('set firewall ipv4 forward filter rule 10 action continue')
    config.commit()

    chain = assert_firewall_object('chain', 'forward', r'ct state vmap', r'ct helper set', r'jump ipv4_forward')
    assert_less(chain.index('ct state vmap'), chain.index('ct helper set'))
    assert_less(chain.index('ct helper set'), chain.index('comment "10|"'))
    assert_less(chain.index('comment "10|"'), chain.index('meta nfproto vmap'))


def test_helper_entrypoint_order_ipv6(config):
    """The same shared assignment precedes IPv6 dispatch without accepting traffic."""
    config.set('set firewall global-options connection-tracking helper ftp')
    config.set('set firewall ipv6 forward filter rule 10 action continue')
    config.commit()

    chain = assert_firewall_object('chain', 'forward', r'ct helper set', r'jump ipv6_forward')
    assert_less(chain.index('ct helper set'), chain.index('meta nfproto vmap'))
    assert_firewall_rule('forward', 'global-helpers', r'ct state new', r'ct direction original',
                         absent=(r' accept', r' return'))


def test_helper_input_and_output(config):
    """Local-service and locally originated traffic use the shared helper map too."""
    config.set('set firewall global-options connection-tracking helper tftp')
    config.commit()

    assert_firewall_rule('input', 'global-helpers', r'ct helper set .* map @conntrack_helpers')
    assert_firewall_rule('output', 'global-helpers', r'ct helper set .* map @conntrack_helpers')


def test_helper_change_preserves_unrelated_chain(config):
    """Changing selection replaces its consumers without resetting other rule chains."""
    config.set('set firewall global-options connection-tracking helper ftp sip')
    config.set('set firewall ipv4 name UNRELATED default-action drop')
    config.commit()
    original = firewall_object_handle('map', 'conntrack_helpers')
    unrelated = firewall_object_handle('chain', 'ipv4_name_UNRELATED')

    config.delete('delete firewall global-options connection-tracking helper sip')
    config.commit()

    assert_not_equal(firewall_object_handle('map', 'conntrack_helpers'), original)
    assert_equal(firewall_object_handle('chain', 'ipv4_name_UNRELATED'), unrelated)
    assert_firewall_object('map', 'conntrack_helpers', r'tcp . 21', absent=(r'5060',))


def test_empty_helper_rejected(config):
    """An empty helper node is an incomplete selection, not an implicit enable-all."""
    config.set('set firewall global-options connection-tracking helper')
    assert_firewall_commit_rejected(config, 'select at least one helper')


def test_unknown_helper_rejected(config):
    """The CLI accepts only the known application leaves."""
    with assert_raises(RouterError):
        config.set('set firewall global-options connection-tracking helper ftpp')
