"""Interface IP options through configuration commits and native observations."""

from pathlib import Path

import pytest

if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from smoketests.assertions import (
    assert_equal, assert_configured_link_addresses, assert_config_commit_rejected,
)
from smoketests.interface_support import interface_case, interface_suite


@pytest.fixture(scope='module')
def ip_suite(config, request):
    with interface_suite(config, request, {'dummy': ['dum986'], 'virtual-ethernet': ['veth985', 'veth986'],
                                          'bridge': ['br986']}, [
        'set interfaces dummy dum986',
        'set interfaces virtual-ethernet veth985 peer-name veth986',
        'set interfaces virtual-ethernet veth986 peer-name veth985',
        'set interfaces bridge br986',
    ]) as reset:
        yield reset


@pytest.fixture(autouse=True)
def environment(request, ip_suite):
    with interface_case(request, ip_suite):
        yield


def setting(family, interface, name, area='conf'):
    return (Path('/proc/sys/net') / family / area / interface / name).read_text().strip()


def test_ipv4_arp_ignore_and_inheritance(config):
    config.set('set interfaces dummy dum986 ip arp-ignore 2')
    config.commit()
    assert_equal(setting('ipv4', 'dum986', 'arp_ignore'), '2')

    config.delete('delete interfaces dummy dum986 ip arp-ignore')
    config.commit()
    assert_equal(setting('ipv4', 'dum986', 'arp_ignore'), setting('ipv4', 'default', 'arp_ignore'))


def test_ipv4_arp_parameters(config):
    config.set('set interfaces dummy dum986 ip arp-announce best-local arp-accept same-subnet arp-filter enable')
    config.set('set interfaces dummy dum986 ip arp-notify enable arp-proxy enable arp-proxy-pvlan enable')
    config.set('set interfaces dummy dum986 ip arp-cache-timeout 2m arp-retransmit-interval 500ms arp-stale-time 3m')
    config.commit()
    assert_equal(setting('ipv4', 'dum986', 'arp_announce'), '2')
    assert_equal(setting('ipv4', 'dum986', 'arp_accept'), '2')
    assert_equal(setting('ipv4', 'dum986', 'arp_filter'), '1')
    assert_equal(setting('ipv4', 'dum986', 'arp_notify'), '1')
    assert_equal(setting('ipv4', 'dum986', 'proxy_arp'), '1')
    assert_equal(setting('ipv4', 'dum986', 'proxy_arp_pvlan'), '1')
    assert_equal(setting('ipv4', 'dum986', 'base_reachable_time_ms', 'neigh'), '120000')
    assert_equal(setting('ipv4', 'dum986', 'retrans_time_ms', 'neigh'), '500')
    assert_equal(setting('ipv4', 'dum986', 'gc_stale_time', 'neigh'), '180')


def test_ipv4_forwarding_and_local_addresses(config):
    config.set('set interfaces dummy dum986 ip disable-forwarding accept-local route-localnet promote-secondaries')
    config.commit()
    assert_equal(setting('ipv4', 'dum986', 'forwarding'), '0')
    assert_equal(setting('ipv4', 'dum986', 'accept_local'), '1')
    assert_equal(setting('ipv4', 'dum986', 'route_localnet'), '1')
    assert_equal(setting('ipv4', 'dum986', 'promote_secondaries'), '1')


def test_ipv4_global_setting_overrides(config):
    config.set('set interfaces dummy dum986 ip receive-redirects enable send-redirects enable source-route enable')
    config.set('set interfaces dummy dum986 ip directed-broadcast enable log-martians enable')
    config.commit()
    assert_equal(setting('ipv4', 'dum986', 'accept_redirects'), '1')
    assert_equal(setting('ipv4', 'dum986', 'send_redirects'), '1')
    assert_equal(setting('ipv4', 'dum986', 'accept_source_route'), '1')
    assert_equal(setting('ipv4', 'dum986', 'bc_forwarding'), '1')
    assert_equal(setting('ipv4', 'dum986', 'log_martians'), '1')


def test_ipv4_veth_vif_and_bridge_options(config):
    config.set('set interfaces virtual-ethernet veth985 ip arp-ignore 1')
    config.set('set interfaces virtual-ethernet veth985 vif 986 ip arp-ignore 2')
    config.set('set interfaces bridge br986 ip arp-ignore 8')
    config.set('set interfaces bridge br986 vif 987 ip arp-ignore 3')
    config.commit()
    assert_equal(setting('ipv4', 'veth985', 'arp_ignore'), '1')
    assert_equal(setting('ipv4', 'veth985.986', 'arp_ignore'), '2')
    assert_equal(setting('ipv4', 'br986', 'arp_ignore'), '8')
    assert_equal(setting('ipv4', 'br986.987', 'arp_ignore'), '3')


def test_ipv6_eui64_and_explicit_link_local(config):
    config.set('set interfaces dummy dum986 mac 02:00:00:12:34:56')
    config.set('set interfaces dummy dum986 ipv6 eui64 2001:db8:986::/64 link-local-address fe80::1234')
    config.commit()
    assert_configured_link_addresses('dum986', '2001:db8:986::ff:fe12:3456/64', 'fe80::1234/64')


def test_ipv6_ra_and_token(config):
    config.set('set interfaces virtual-ethernet veth985 ipv6 autoconf interface-identifier ::1234 no-default-route no-ra-mtu')
    config.commit()
    assert_equal(setting('ipv6', 'veth985', 'accept_ra'), '2')
    assert_equal(setting('ipv6', 'veth985', 'autoconf'), '1')
    assert_equal(setting('ipv6', 'veth985', 'accept_ra_defrtr'), '0')
    assert_equal(setting('ipv6', 'veth985', 'accept_ra_mtu'), '0')

    config.delete('delete interfaces virtual-ethernet veth985 ipv6')
    config.commit()
    assert_equal(setting('ipv6', 'veth985', 'accept_ra'), '0')


def test_ipv6_stable_privacy(config):
    config.set('set interfaces dummy dum986 ipv6 address-generation stable-privacy')
    config.commit()
    assert_equal(setting('ipv6', 'dum986', 'addr_gen_mode'), '2')


def test_ipv6_temporary_addresses(config):
    config.set('set interfaces virtual-ethernet veth985 ipv6 autoconf temporary-addresses prefer-temporary maximum-autoconf-addresses 32')
    config.commit()
    assert_equal(setting('ipv6', 'veth985', 'use_tempaddr'), '2')
    assert_equal(setting('ipv6', 'veth985', 'max_addresses'), '32')


def test_ipv6_disable_and_link_local_suppression(config):
    config.set('set interfaces dummy dum986 ipv6 disable')
    config.commit()
    assert_equal(setting('ipv6', 'dum986', 'disable_ipv6'), '1')

    config.delete('delete interfaces dummy dum986 ipv6 disable')
    config.set('set interfaces dummy dum986 ipv6 no-default-link-local')
    config.commit()
    assert_equal(setting('ipv6', 'dum986', 'disable_ipv6'), '0')
    assert_equal(setting('ipv6', 'dum986', 'addr_gen_mode'), '1')


def test_ipv6_neighbor_and_dad_options(config):
    config.set('set interfaces dummy dum986 ipv6 duplicate-address-detection probes 2')
    config.set('set interfaces dummy dum986 ipv6 neighbor-reachable-time 2m neighbor-retransmit-interval 500ms neighbor-stale-time 3m')
    config.set('set interfaces dummy dum986 ipv6 hop-limit 42 proxy-ndp')
    config.commit()
    assert_equal(setting('ipv6', 'dum986', 'dad_transmits'), '2')
    assert_equal(setting('ipv6', 'dum986', 'base_reachable_time_ms', 'neigh'), '120000')
    assert_equal(setting('ipv6', 'dum986', 'retrans_time_ms', 'neigh'), '500')
    assert_equal(setting('ipv6', 'dum986', 'gc_stale_time', 'neigh'), '180')
    assert_equal(setting('ipv6', 'dum986', 'hop_limit'), '42')
    assert_equal(setting('ipv6', 'dum986', 'proxy_ndp'), '1')


def test_ipv6_global_setting_overrides(config):
    config.set('set interfaces dummy dum986 ipv6 receive-redirects enable source-route disable')
    config.commit()
    assert_equal(setting('ipv6', 'dum986', 'accept_redirects'), '1')
    assert_equal(setting('ipv6', 'dum986', 'accept_source_route'), '-1')


def test_ipv6_disabled_address_rejected(config):
    config.set('set interfaces dummy dum986 address 2001:db8:986::1/64 ipv6 disable')
    assert_config_commit_rejected(config, 'conflicts')


def test_ipv6_token_without_autoconf_rejected(config):
    config.set('set interfaces virtual-ethernet veth985 ipv6 interface-identifier ::1234')
    assert_config_commit_rejected(config, 'require')


def test_ipv6_stable_privacy_token_conflict_rejected(config):
    config.set('set interfaces virtual-ethernet veth985 ipv6 autoconf interface-identifier ::1234 address-generation stable-privacy')
    assert_config_commit_rejected(config, 'conflicts')


def test_ipv6_dad_disable_probes_conflict_rejected(config):
    config.set('set interfaces dummy dum986 ipv6 duplicate-address-detection disable probes 2')
    assert_config_commit_rejected(config, 'conflicts')
