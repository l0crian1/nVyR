"""Native recovery checks for interface policy and the latest firewall features."""

import json
from pathlib import Path

from nvyr.config_session import ConfigurationSession
from nvyr.helpers import interfaces, interface_ip, kernel_settings
from nvyr.helpers.kernel_settings_map import SETTINGS, assignments, native_value
from nvyr.helpers.process import cmd
from smoketests.assertions import (
    assert_equal, assert_in, assert_link_addresses, assert_sysctl, assert_vrf_conntrack_zone,
    assert_firewall_object, assert_firewall_rule, assert_firewall_timeout,
    assert_ntp_configuration, assert_ntp_client_access, assert_ntp_vrf, assert_operational_output,
)


def check_kernel_settings(options):
    """Read every managed global default/gate plus explicit lab overrides."""
    with ConfigurationSession() as config:
        configuration = config.get_config()
    for name, value in kernel_settings.firewall_values(configuration).items():
        spec = SETTINGS[name]
        expected = native_value(spec, value)
        if expected is None:
            # Auto capacities depend on memory, but must be positive native values.
            assert int(Path('/proc/sys').joinpath(*spec['path']).read_text()) > 0
            continue
        for path, setting in assignments(spec, expected):
            if '*' not in path:
                assert_sysctl(path, setting)

    assert_sysctl('net/ipv4/neigh/dum995/base_reachable_time_ms', 40000)
    assert_sysctl('net/ipv4/conf/dum995/arp_ignore', 1)


def check_interface_ip_options(options):
    """Read every explicit override across physical, virtual, bridge and VLAN links."""
    with ConfigurationSession() as config:
        configuration = config.get_config()
    for interface, settings in interfaces.configured(configuration):
        for name, value in interface_ip.overrides(settings).items():
            spec = SETTINGS[name]
            expected = native_value(spec, value)
            if name == 'interface ipv6 address-generation' and (
                    'link-local-address' in settings.get('ipv6', {})
                    or 'no-default-link-local' in settings.get('ipv6', {})):
                expected = '1'
            path = '/'.join(part.replace('{interface}', interface) for part in spec['path'])
            assert_sysctl(path, expected)

    assert_link_addresses('dum996', '2001:db8:210::ff:fe19:9601/64', 'fe80::1996/64')
    addresses = json.loads(cmd(['ip', '-j', '-6', 'address', 'show', 'dev', 'dum997']))[0]['addr_info']
    assert not any(address['scope'] == 'link' for address in addresses)
    assert_in('::195', cmd(['ip', 'token', 'list', 'dev', 'veth995']))
    secret = json.loads(Path('/config/ipv6-stable-secret.json').read_text())
    assert_equal(len(secret['secret']), 64)


def check_vrf_conntrack(options):
    """VRF maps include VLAN/container links and keep routing domains distinct."""
    left = assert_vrf_conntrack_zone('BOOTLEFT', 'veth995', 'veth995.195', 'dum996', 'br995.195', absent=('eth0',))
    right = assert_vrf_conntrack_zone('BOOTRIGHT', 'veth997', 'veth997.195', 'pd-BOOTVRF', options['ethernet'], absent=('eth0',))
    assert left != right
    assert_in('unreachable', cmd(['ip', '-4', 'rule', 'show']))
    assert_in('unreachable', cmd(['ip', '-6', 'rule', 'show']))


def check_ntp(options):
    """VRF-bound Chrony restores listeners, sources and native client access rules."""
    assert_ntp_configuration('server 198.18.196.123 iburst prefer',
                             'server time.boot.example.invalid iburst nts',
                             'pool pool.boot.example.invalid iburst nts',
                             'bindaddress 198.18.196.1', 'bindaddress 2001:db8:196::1')
    assert_ntp_vrf('BOOTLEFT')
    assert_ntp_client_access('198.18.196.10', allowed=True)
    assert_ntp_client_access('2001:db8:196::10', allowed=True)
    assert_ntp_client_access('198.18.197.10', allowed=False)
    assert_operational_output('show ntp sources no-resolve', '198.18.196.123')


def check_firewall_inet(options):
    """Neutral rules precede family dispatch and retain their own providers."""
    assert_firewall_rule('inet_name_BOOTNEUTRAL', 10, 'vmap @inet_map_BOOTNEUTRAL', '@inet_match_group_BOOTNEUTRAL')
    assert_firewall_rule('inet_name_BOOTNEUTRAL', 20, 'meta mark set', 'ct mark set', 'tcp option maxseg size set 1360')
    assert_firewall_rule('inet_name_BOOTNEUTRAL', 40, 'reject with icmpx admin-prohibited')
    chain = assert_firewall_object('chain', 'forward', 'jump inet_name_BOOTNEUTRAL', 'meta nfproto vmap')
    assert chain.index('jump inet_name_BOOTNEUTRAL') < chain.index('meta nfproto vmap')
    assert_firewall_rule('prerouting', 41970, 'notrack')
    assert_firewall_rule('output_raw', 41970, 'notrack')
    assert_firewall_rule('ingress', 41970, 'udp', '41991')


def check_firewall_ingress_ipv4(options):
    """Recreated VLAN parents attach to ingress with a concatenated VLAN lookup."""
    assert_firewall_rule('ipv4_ingress', 10, 'vlan id . vlan pcp @ipv4_match_group_BOOTVLAN')
    assert_firewall_rule('ipv4_ingress', 20, 'notrack')
    assert_firewall_object('chain', 'ingress', 'hook ingress', 'bootfuture', 'jump ipv4_ingress')
    assert_in('ingress', cmd(['nft', 'list', 'hooks', 'netdev', 'device', 'veth995']))


def check_firewall_ingress_ipv6(options):
    """IPv6 ingress has its own VLAN map and future-device subscription."""
    assert_firewall_rule('ipv6_ingress', 10, 'vlan id . vlan pcp vmap @ipv6_map_BOOTVLAN')
    assert_firewall_rule('ipv6_ingress', 20, 'notrack')
    assert_firewall_object('chain', 'ingress', 'hook ingress', 'bootfuture', 'jump ipv6_ingress')
    assert_in('ingress', cmd(['nft', 'list', 'hooks', 'netdev', 'device', 'veth997']))


def check_firewall_source_validation_ipv4(options):
    """Strict and loose overrides apply only to the requested IPv4 interfaces."""
    assert_firewall_rule('ipv4_prerouting', 'source-validation-strict', 'fib saddr . iif oif 0', 'drop')
    assert_firewall_rule('ipv4_prerouting', 'source-validation-loose', 'fib saddr oif 0', 'drop')
    assert_firewall_object('set', 'source_validation_ipv4_strict', 'dum995', absent=('eth0',))
    assert_firewall_object('set', 'source_validation_ipv4_loose', 'dum996', absent=('eth0',))


def check_firewall_source_validation_ipv6(options):
    """IPv6 validation is independent of IPv4 and leaves management untouched."""
    assert_firewall_rule('ipv6_prerouting', 'source-validation-strict', 'fib saddr . iif oif 0', 'drop')
    assert_firewall_rule('ipv6_prerouting', 'source-validation-loose', 'fib saddr oif 0', 'drop')
    assert_firewall_object('set', 'source_validation_ipv6_strict', 'dum995', absent=('eth0',))
    assert_firewall_object('set', 'source_validation_ipv6_loose', 'dum996', absent=('eth0',))


def check_firewall_timeout_policies(options):
    """TCP and dual-family UDP objects retain their lifetimes and consumers."""
    assert_firewall_timeout('ipv4_timeout_group_BOOTTCP', 'tcp', 'ip', established=86400, close=20)
    assert_firewall_timeout('ipv6_timeout_group_BOOTTCP', 'tcp', 'ip6', established=86400, close=20)
    assert_firewall_timeout('inet_timeout_group_BOOTUDP_ip', 'udp', 'ip', unreplied=10, replied=40)
    assert_firewall_timeout('inet_timeout_group_BOOTUDP_ip6', 'udp', 'ip6', unreplied=10, replied=40)
    assert_firewall_rule('ipv4_name_BOOTFILTER', 305, 'ct timeout set "ipv4_timeout_group_BOOTTCP"')
    assert_firewall_rule('ipv6_name_BOOTFILTER', 305, 'ct timeout set "ipv6_timeout_group_BOOTTCP"')
    assert_firewall_rule('output', 41971, 'ct timeout set meta nfproto map')


def check_firewall_helpers(options):
    """Helper assignments follow state policy and precede inet rules/dispatch."""
    assert_firewall_object('map', 'conntrack_helpers', 'conntrack_helper_ftp_tcp',
                           'conntrack_helper_tftp_udp', 'conntrack_helper_sip_tcp', 'conntrack_helper_sip_udp')
    for hook in ('input', 'forward', 'output'):
        chain = assert_firewall_object('chain', hook, 'ct helper set', 'ct state vmap')
        assert chain.index('ct state vmap') < chain.index('ct helper set') < chain.index('meta nfproto vmap')


def check_firewall_modifications_ipv4(options):
    """IPv4 tracing, packet/connection setters and route-based MSS are installed."""
    assert_firewall_rule('ipv4_forward', 41989, 'meta nftrace set 1', 'meta mark set', 'ct mark set',
                         'ip dscp set ef', 'ip ttl set 63', 'tcp option maxseg size set 1360')
    assert_firewall_rule('ipv4_output_raw', 41989, 'tcp option maxseg size set rt mtu')


def check_firewall_modifications_ipv6(options):
    """IPv6 uses hop-limit and traffic-class setters with the same trace/MSS contract."""
    assert_firewall_rule('ipv6_forward', 41989, 'meta nftrace set 1', 'meta mark set', 'ct mark set',
                         'ip6 dscp set ef', 'ip6 hoplimit set 63', 'tcp option maxseg size set 1360')
    assert_firewall_rule('ipv6_output_raw', 41989, 'tcp option maxseg size set rt mtu')


def check_firewall_map_defaults(options):
    """Catch-all elements retain verdict and translated address/port results."""
    assert_firewall_object('map', 'ipv4_map_BOOTMAP', r'\*.*: continue')
    assert_firewall_object('map', 'ipv6_map_BOOTMAP', r'\*.*: continue')
    assert_firewall_object('map', 'inet_map_BOOTNEUTRAL', r'\*.*: continue')
    assert_firewall_object('map', 'ipv4_map_BOOTNAT', r'\*.*: 198.18.195.11 . 8081')
