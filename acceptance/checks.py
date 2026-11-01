"""Independent native observations for the combined boot configuration."""

import json
from pathlib import Path
import socket
import uuid

from nvyr.config_session import ConfigurationSession
from nvyr.helpers import cpu_settings, dhcp_hosts, kea, logging_runtime
from nvyr.helpers.process import cmd
from nvyr.tree import lookup
from smoketests.assertions import (
    assert_equal, assert_in, assert_not_in, assert_link, assert_link_addresses,
    assert_vlan, assert_bridge, assert_bridge_port, assert_bridge_vlans, assert_bridge_mac,
    assert_kernel_route, assert_kernel_route_absent, assert_kernel_multipath_weights,
    assert_frr_routes, assert_bgp_neighbor, assert_bgp_path, assert_frr_policy_commands,
    assert_firewall_object, assert_firewall_rule, assert_firewall_rule_absent,
    assert_container_running, assert_dhcp_client_options, assert_dhcp_lease,
    assert_dhcp_default_route, assert_log_output, assert_operational_output,
)
from smoketests.firewall_support import send_firewall_udp
from smoketests.support import wait_for
from acceptance.feature_checks import (
    check_kernel_settings, check_interface_ip_options, check_vrf_conntrack, check_ntp,
    check_firewall_inet, check_firewall_ingress_ipv4, check_firewall_ingress_ipv6,
    check_firewall_source_validation_ipv4, check_firewall_source_validation_ipv6,
    check_firewall_timeout_policies, check_firewall_helpers,
    check_firewall_modifications_ipv4, check_firewall_modifications_ipv6, check_firewall_map_defaults,
)


class CheckSkipped(Exception):
    """A check cannot run because an optional lab prerequisite is unavailable."""


def require_carrier(port):
    """Only missing physical carrier may skip IPv6 readiness, not a broken link."""
    def linked():
        link = json.loads(cmd(['ip', '-j', 'link', 'show', 'dev', port]))[0]
        if 'UP' not in link['flags']:
            raise RuntimeError(f'{port} is administratively down; the baseline requires it enabled')
        return 'LOWER_UP' in link['flags']

    try:
        wait_for(linked, bool, description=f'{port} physical carrier', timeout=2)
    except AssertionError:
        raise CheckSkipped(f'{port} has no carrier; connect a cable or loopback adapter '
                           'for physical IPv6/VLAN address checks') from None


def check_kernel_release(options):
    """The running kernel must match the image's pinned package, not an older boot entry."""
    lock = json.loads(Path('/usr/share/nvyr/kernel-sources.lock').read_text())
    release = lock['version'] + lock['local_version']
    assert_equal(cmd(['uname', '-r']).strip(), release)
    package = 'linux-image-' + release
    assert_equal(cmd(['dpkg-query', '-W', '-f=${Version}', package]).strip(), lock['package_version'])
    assert_operational_output('show system packages ' + package, package, lock['package_version'])


def check_operational_inventory(options):
    """Installed operational dispatch can read build attribution, license and script metadata."""
    assert_operational_output('show version', 'Version', 'L0crian', 'https://github.com/')
    assert_operational_output('show license | no-more', 'MIT License', 'Permission is hereby granted')
    assert_operational_output('show system config script-priority | no-more',
                              'firewall_failsafe', 'firewall', 'name-server')


def check_system_hostname(options):
    """Check the OS hostname against the effective setting, separately from FRR policy."""
    with ConfigurationSession() as config:
        configuration = config.get_config()
    assert_equal(socket.gethostname(), lookup(configuration, ('system', 'host-name'), 'nvyr'))


def check_system_timezone(options):
    """Both host timezone files select the saved local-time policy after reboot."""
    with ConfigurationSession() as config:
        zone = lookup(config.get_config(), ('system', 'time-zone'), 'UTC')
    assert_equal(Path('/etc/timezone').read_text().strip(), zone)
    assert_equal(Path('/etc/localtime').resolve(), (Path('/usr/share/zoneinfo') / zone).resolve())
    assert_operational_output('show date', cmd(['date', '+%Z']).strip())


def check_cpu_policy(options):
    """Saved CPU overrides, or the hardware-supported boot policy, survive reboot."""
    with ConfigurationSession() as config:
        settings = lookup(config.get_config(), ('system', 'cpu'), {})
    records = cpu_settings.inventory()
    if not records:
        raise CheckSkipped('CPU frequency controls are not exposed by this host')
    for record in records:
        expected = settings.get('governor')
        if expected is None and 'performance' in record['governors']:
            expected = 'performance'
        if expected is not None:
            assert_equal(record['governor'], expected)
        if 'energy-performance' in settings:
            assert_equal(record['energy-performance'], settings['energy-performance'].replace('-', '_'))


def check_vrfs(options):
    """Both routing domains must be recreated with their own tables."""
    assert_link('BOOTLEFT', kind='vrf', table=41995, up=True)
    assert_link('BOOTRIGHT', kind='vrf', table=41996, up=True)


def check_ethernet(options):
    """The selected physical port retains its VRF, MTU, alias, and Linux group."""
    assert_link(options['ethernet'], mtu=1400, master='BOOTRIGHT', group=195,
                description='Boot acceptance spare port', up=True)


def check_ethernet_ipv4(options):
    """Validate IPv4 on the physical port and its VLAN child."""
    assert_link_addresses(options['ethernet'], '198.18.205.1/24')
    assert_link_addresses(options['ethernet'] + '.195', '198.18.206.1/24')


def check_ethernet_ipv6(options):
    """Validate IPv6 on the physical port and its VLAN child."""
    require_carrier(options['ethernet'])
    assert_link_addresses(options['ethernet'], '2001:db8:205::1/64')
    assert_link_addresses(options['ethernet'] + '.195', '2001:db8:206::1/64')


def check_vlans(options):
    """Each supported parent type must recreate its VLAN and its VRF membership."""
    assert_vlan(options['ethernet'] + '.195', options['ethernet'], 195, master='BOOTRIGHT')
    assert_vlan('veth995.195', 'veth995', 195, master='BOOTLEFT')
    assert_vlan('veth997.195', 'veth997', 195, master='BOOTRIGHT')
    assert_vlan('br995.195', 'br995', 195, master='BOOTLEFT')


def check_vlan_ipv4_traffic(options):
    """A tagged packet crosses the veth pair between the two routing domains."""
    cmd(['ip', 'vrf', 'exec', 'BOOTLEFT', 'ping', '-4', '-c', '1', '-W', '3', '198.18.209.2'])


def check_vlan_ipv6_traffic(options):
    """Verify IPv6 neighbor discovery and forwarding over the recreated VLAN pair."""
    cmd(['ip', 'vrf', 'exec', 'BOOTLEFT', 'ping', '-6', '-c', '1', '-W', '3', '2001:db8:209::2'])


def check_loopback_ipv4(options):
    """The configured identity coexists with the protected system loopback address."""
    assert_link_addresses('lo', '127.0.0.1/8', '198.18.207.1/32')


def check_loopback_ipv6(options):
    """The IPv6 identity coexists with ::1 after startup reconciliation."""
    assert_link_addresses('lo', '::1/128', '2001:db8:207::1/128')


def check_dummy_and_disabled(options):
    """Active and deliberately disabled links must recover different admin states."""
    assert_link('dum995', kind='dummy', description='Boot acceptance default VRF', up=True)
    assert_link('dum996', kind='dummy', master='BOOTLEFT', up=True)
    assert_link('dum992', kind='dummy', description='Disabled at boot', up=False)


def check_veth_pair(options):
    """Peer relationships and VRF attachments must be valid in both directions."""
    assert_link('veth995', kind='veth', peer='veth997', mtu=1400, master='BOOTLEFT', up=True)
    assert_link('veth997', kind='veth', peer='veth995', mtu=1400, master='BOOTRIGHT', up=True)


def check_bridge(options):
    """Inspect bridge properties, not just a link with the right name."""
    assert_link('br995', kind='bridge', master='BOOTLEFT', group=197, mtu=1400)
    assert_bridge('br995', vlan_filtering=1, vlan_default_pvid=0, stp_state=1,
                  priority=4096, hello_time=200, forward_delay=1000, max_age=1200,
                  ageing_time=60000, fdb_max_learned=100, no_linklocal_learn=1)


def check_bridge_ports(options):
    """Access/trunk membership, port policy and the static FDB survive reboot."""
    assert_bridge_vlans('dum998', {195: (True, True)})
    assert_bridge_vlans('dum999', {195: (False, False)})
    assert_bridge_vlans('br995', {195: (False, False)})
    assert_bridge_port('dum998', cost=500, priority=16, guard=True, root_block=True,
                      learning=False, hairpin=True, isolated=True)
    assert_bridge_port('dum999', flood=False)
    assert_bridge_mac('br995', '02:00:00:19:95:10', port='dum999', vlan=195)


def check_bridge_multicast(options):
    """Multicast querier/version settings are restored into the kernel bridge."""
    assert_bridge('br995', mcast_querier=1, mcast_igmp_version=3,
                  mcast_mld_version=2, mcast_stats_enabled=1, mcast_router=2)


def check_static_ipv4(options):
    """FRR and the kernel agree on discard, preferred gateway and interface routes."""
    assert_frr_routes('ip route 198.18.197.0/24 blackhole')
    assert_kernel_route('198.18.197.0/24', 'blackhole')
    assert_kernel_route('198.18.198.0/24', 'via 198.18.195.2', 'dev dum995')
    assert_kernel_route('198.18.201.0/24', 'dev dum995')
    assert_kernel_route_absent('198.18.200.0/24')


def check_static_ipv6(options):
    """IPv6 includes source-specific forwarding and an explicitly disabled prefix."""
    assert_frr_routes('ipv6 route 2001:db8:197::/64 reject')
    assert_kernel_route('2001:db8:197::/64', 'unreachable')
    assert_kernel_route('2001:db8:198::/64', 'via 2001:db8:195::2', 'dev dum995')
    assert_kernel_route('2001:db8:201::/64', 'dev dum995', source='2001:db8:195::/64')
    assert_kernel_route_absent('2001:db8:200::/64')


def check_multipath_ipv4(options):
    """Both weighted IPv4 next hops must appear, not just the first usable path."""
    assert_kernel_multipath_weights('198.18.199.0/24', {('198.18.195.2', 'dum995'): 2,
                                                      ('198.18.195.3', 'dum995'): 3})


def check_multipath_ipv6(options):
    """Both weighted IPv6 next hops must appear after the daemon reload."""
    assert_kernel_multipath_weights('2001:db8:199::/64', {('2001:db8:195::2', 'dum995'): 2,
                                                         ('2001:db8:195::3', 'dum995'): 3})


def check_vrf_static_ipv4(options):
    """Check both ordinary VRF routing and resolution through the default VRF."""
    assert_kernel_route('198.18.202.0/24', 'via 198.18.196.2', 'dev dum996', vrf='BOOTLEFT')
    assert_kernel_route('198.18.210.0/24', 'via 198.18.195.2', 'dev dum995', vrf='BOOTRIGHT')


def check_vrf_static_ipv6(options):
    """IPv6 cross-VRF next-hop resolution must be reconstructed as well."""
    assert_kernel_route('2001:db8:202::/64', 'via 2001:db8:196::2', 'dev dum996', vrf='BOOTLEFT')
    assert_kernel_route('2001:db8:210::/64', 'via 2001:db8:195::2', 'dev dum995', vrf='BOOTRIGHT')


def check_routing_policies(options):
    """ACLs, prefix filters and named community/AS-path providers reach FRR."""
    assert_frr_policy_commands('access-list BOOTACL seq 10 permit 198.18.0.0 0.0.255.255',
                               'ipv6 access-list BOOTACL seq 10 permit 2001:db8::/32',
                               'ip prefix-list BOOTPREFIX seq 10 permit 198.18.0.0/15 ge 24 le 32',
                               'ipv6 prefix-list BOOTPREFIX seq 10 permit 2001:db8::/32 ge 48 le 128',
                               'route-map BOOTIN permit 10', 'match as-path BOOTAS',
                               'set local-preference 250', 'call BOOTCALL')


def check_bgp_ipv4_session(options):
    """Both ends must establish a new IPv4 session, not merely retain a configured peer."""
    assert_bgp_neighbor('BOOTLEFT', '198.18.192.2')
    assert_bgp_neighbor('BOOTRIGHT', '198.18.192.1')


def check_bgp_ipv6_session(options):
    """IPv6 activation and peer-group inheritance must produce established peers."""
    assert_bgp_neighbor('BOOTLEFT', '2001:db8:192::2')
    assert_bgp_neighbor('BOOTRIGHT', '2001:db8:192::1')


def check_bgp_ipv4_policy_result(options):
    """Route-map export, list matches and import setters affect an actual received prefix."""
    assert_bgp_path('BOOTRIGHT', 'ipv4', '198.18.208.0/24', attributes={
        'locPrf': 250, 'community.string': '65095:100', 'largeCommunity.string': '65095:100:200'})
    assert_kernel_route('198.18.208.0/24', 'via 198.18.192.1', vrf='BOOTRIGHT')


def check_bgp_ipv6_policy_result(options):
    """IPv6 policy and route installation must recover independently of IPv4."""
    assert_bgp_path('BOOTRIGHT', 'ipv6', '2001:db8:208::/64', attributes={
        'locPrf': 250, 'community.string': '65095:100', 'largeCommunity.string': '65095:100:200'})
    assert_kernel_route('2001:db8:208::/64', 'dev veth997', vrf='BOOTRIGHT')


def check_bgp_unicast_options(options):
    """New peer options recover as negotiated behavior and exact native configuration."""
    from smoketests.assertions import assert_bgp_commands

    peer = assert_bgp_neighbor('BOOTLEFT', '198.18.192.2')
    assert peer['localRole'] == 'provider'
    assert peer['remoteRole'] == 'customer'
    assert peer['bgpTcpMssConfigured'] == 1200
    assert_bgp_commands('neighbor 198.18.192.1 maximum-prefix 1000 90 warning-only force',
                        'neighbor 198.18.192.1 filter-list BOOTAS in', vrf='BOOTRIGHT', family='ipv4')
    assert_bgp_commands('neighbor 2001:db8:192::1 maximum-prefix 1000 90 warning-only force',
                        'neighbor 2001:db8:192::1 filter-list BOOTAS in', vrf='BOOTRIGHT', family='ipv6')
    assert_bgp_commands('neighbor 198.18.207.2 local-as 65197 no-prepend replace-as dual-as',
                        'neighbor dum995 interface v6only remote-as external',
                        'neighbor fe80::995 interface dum995', vrf='default')


def server_configuration(family, vrf):
    """Read the live Kea control socket; a config file alone is insufficient."""
    path = kea.RUNTIME / (kea.instance_name(family, vrf) + '.sock')
    return kea.control(path, 'config-get')['arguments'][f'Dhcp{family}']


def check_dhcp4_server(options):
    """The default instance retains inherited options, disjoint pools and reservation."""
    server = server_configuration(4, 'default')
    assert_equal(server['valid-lifetime'], 43200)
    assert_equal(server['interfaces-config']['dhcp-socket-type'], 'udp')
    subnet = server['shared-networks'][0]['subnet4'][0]
    assert_equal(len(subnet['pools']), 4)
    assert_equal([pool['client-classes'] for pool in subnet['pools']],
                 [['HA_BOOT1'], ['HA_BOOT2'], ['HA_BOOT1'], ['HA_BOOT2']])
    assert_equal(subnet['reservations'][0]['ip-address'], '198.18.195.50')
    assert_equal(subnet['valid-lifetime'], 21600)


def check_dhcp_hostfile_hook(options):
    """The default Kea daemon reloads its hostfile hook and the expiry timer is active."""
    server = server_configuration(4, 'default')
    assert_equal(dhcp_hosts.enabled({'Dhcp4': server}), True)
    assert_equal(Path(dhcp_hosts.HOOK_SCRIPT).is_file(), True)
    assert_equal(cmd(['systemctl', 'is-active', 'nvyr-dhcp-hosts.timer']).strip(), 'active')


def check_dhcp6_server(options):
    """The default DHCPv6 server has the correct lifetime and interface selector."""
    server = server_configuration(6, 'default')
    assert_equal(server['preferred-lifetime'], 21600)
    assert_equal(server['valid-lifetime'], 43200)
    assert_equal(server['shared-networks'][0]['interface'], 'dum995')
    subnet = server['shared-networks'][0]['subnet6'][0]
    assert_in('2001:db8:195::50', subnet['reservations'][0]['ip-addresses'])


def check_vrf_dhcp4_server(options):
    """A second IPv4 instance binds the recreated VRF member and its own lease scope."""
    server = server_configuration(4, 'BOOTLEFT')
    assert_equal(server['interfaces-config']['dhcp-socket-type'], 'raw')
    assert_equal(server['shared-networks'][0]['subnet4'][0]['subnet'], '198.18.193.0/24')


def check_vrf_dhcp6_server(options):
    """Derived interface selection remains deterministic after links are recreated."""
    server = server_configuration(6, 'BOOTLEFT')
    assert_equal(server['shared-networks'][0]['interface'], 'veth993')


def check_dhcp_ha(options):
    """HA roles, listener ports and pool ownership survive boot without a live peer."""
    server4 = server_configuration(4, 'default')
    ha4 = server4['hooks-libraries'][1]['parameters']['high-availability'][0]
    assert_equal(ha4['mode'], 'load-balancing')
    assert_equal(ha4['this-server-name'], 'BOOT1')
    assert_equal(ha4['peers'][0]['url'], 'http://198.18.195.1:8005/')

    server6 = server_configuration(6, 'default')
    ha6 = server6['hooks-libraries'][1]['parameters']['high-availability'][0]
    assert_equal(ha6['mode'], 'hot-standby')
    assert_equal(ha6['peers'][0]['url'], 'http://[2001:db8:195::1]:9006/')
    assert_equal(ha6['peers'][1]['url'], 'http://[2001:db8:195::2]:9007/')
    assert_equal(len(server6['shared-networks'][0]['subnet6'][0]['pools']), 1)

    vrf = server_configuration(6, 'BOOTLEFT')
    ha_vrf = vrf['hooks-libraries'][1]['parameters']['high-availability'][0]
    assert_equal(ha_vrf['this-server-name'], 'BOOT2')
    peers = {peer['name']: peer for peer in ha_vrf['peers']}
    assert_equal(peers['BOOTCOPY']['auto-failover'], False)
    assert_equal(vrf['shared-networks'][0]['subnet6'][0]['pools'][0]['client-classes'], ['HA_BOOT1'])


def check_dhcp_client_lease(options):
    """A configured client must obtain its reservation from the configured server."""
    lease = assert_dhcp_lease('br994')
    assert_equal(lease['address'], '198.18.193.50/24')
    assert_dhcp_default_route('br994', distance=210)
    assert_dhcp_client_options('br994', **{'host-name': 'boot-client', 'vendor-class-id': 'nvyr-acceptance'})


def check_container_workload(options):
    """Check running state, entrypoint, hostname and resource limits in Podman."""
    container = assert_container_running('BOOTBOX')
    assert_equal(container['Config']['Entrypoint'], ['sleep'])
    assert_equal(container['HostConfig']['Memory'], 128 * 1024 * 1024)
    assert_equal(container['HostConfig']['PidsLimit'], 64)
    assert_equal(container['HostConfig']['Dns'], ['1.1.1.1'])
    assert_equal(cmd(['podman', 'exec', 'BOOTBOX', 'hostname']).strip(), 'boot-box')
    assert_in('CAP_NET_ADMIN', container['EffectiveCaps'])
    assert_in('no-new-privileges', container['HostConfig']['SecurityOpt'])


def check_container_network_ipv4(options):
    """Check both Netavark attachments, their static addresses, naming and VRF bridge."""
    container = assert_container_running('BOOTBOX')
    networks = container['NetworkSettings']['Networks']
    assert_equal(networks['BOOTNET']['IPAddress'], '198.18.203.10')
    assert_equal(networks['BOOTVRF']['IPAddress'], '198.18.204.10')
    assert_link('pd-BOOTBOX-0', kind='veth', master='pd-BOOTNET')
    assert_link('pd-BOOTBOX-1', kind='veth', master='pd-BOOTVRF')
    assert_link('pd-BOOTVRF', kind='bridge', master='BOOTRIGHT', mtu=1400)


def check_container_network_ipv6(options):
    """The dual-stack attachment must restore its IPv6 address too."""
    container = assert_container_running('BOOTBOX')
    assert_equal(container['NetworkSettings']['Networks']['BOOTNET']['GlobalIPv6Address'], '2001:db8:203::10')


def check_container_persistence(options):
    """Read the preboot sentinel through the mount; verification never creates it."""
    assert_equal(cmd(['podman', 'exec', 'BOOTBOX', 'cat', '/data/sentinel']).strip(), options['assets'])
    assert_equal(cmd(['podman', 'exec', 'BOOTBOX', 'stat', '-c', '%u:%g:%a', '/data']).strip(), '0:0:750')
    assert_equal(cmd(['podman', 'exec', 'BOOTBOX', 'cat', '/host-name']), Path('/etc/hostname').read_text())
    environment = cmd(['podman', 'exec', 'BOOTBOX', 'env']).splitlines()
    assert_in('BOOT_FILE=from-file', environment)
    assert_in('BOOT_OVERRIDE=explicit', environment)
    assert_in(' /scratch tmpfs ', cmd(['podman', 'exec', 'BOOTBOX', 'cat', '/proc/mounts']))
    cmd(['podman', 'exec', 'BOOTBOX', 'test', '-c', '/dev/boot-null'])


def check_container_pod(options):
    """Pod membership and its shared dual-stack namespace survive reboot."""
    first = assert_container_running('BOOTAPP')
    second = assert_container_running('BOOTCACHE')
    pod = json.loads(cmd(['podman', 'pod', 'inspect', 'BOOTPOD']))[0]
    assert_equal(first['Pod'], pod['Id'])
    assert_equal(second['Pod'], pod['Id'])
    assert_equal(cmd(['podman', 'exec', 'BOOTAPP', 'hostname']).strip(), 'boot-pod')
    infra = json.loads(cmd(['podman', 'inspect', pod['InfraContainerID']]))[0]
    network = infra['NetworkSettings']['Networks']['BOOTNET']
    assert_equal(network['IPAddress'], '198.18.203.20')
    assert_equal(network['GlobalIPv6Address'], '2001:db8:203::20')
    assert_link('pd-BOOTPOD-0', kind='veth', master='pd-BOOTNET')


def check_firewall_failsafe_handover(options):
    """The main firewall has removed the temporary boot table after startup."""
    document = json.loads(cmd(['nft', '-j', 'list', 'tables']))
    names = [item['table']['name'] for item in document['nftables'] if 'table' in item]
    assert_in('nvyr_filter', names)
    assert_not_in('nvyr_filter_failsafe', names)


def check_firewall_ipv4_rules(options):
    """Check representative matches, stateful objects and the nested jump graph."""
    assert_firewall_rule('ipv4_name_BOOTFILTER', 40, 'tcp flags')
    assert_firewall_rule('ipv4_name_BOOTFILTER', 140, 'ct original', 'proto-dst')
    assert_firewall_rule('ipv4_name_BOOTFILTER', 190, 'update @', '&')
    assert_firewall_rule('ipv4_name_BOOTFILTER', 220, 'ct count over 20')
    assert_firewall_rule('ipv4_name_BOOTFILTER', 300, 'jump ipv4_name_BOOTOUTER')
    assert_firewall_rule('ipv4_name_BOOTOUTER', 10, 'jump ipv4_name_BOOTINNER')
    assert_firewall_rule('ipv4_name_BOOTINNER', 10, 'vmap @ipv4_map_BOOTMAP', '@ipv4_match_group_BOOTMATCH')
    assert_firewall_rule_absent('ipv4_name_BOOTFILTER', 310)


def check_firewall_ipv6_rules(options):
    """IPv6 expressions must survive alongside independent IPv4 state."""
    assert_firewall_rule('ipv6_name_BOOTFILTER', 40, 'tcp flags')
    assert_firewall_rule('ipv6_name_BOOTFILTER', 140, 'ct original', 'proto-dst')
    assert_firewall_rule('ipv6_name_BOOTFILTER', 190, 'update @', '&')
    assert_firewall_rule('ipv6_name_BOOTFILTER', 220, 'ct count over 20')
    assert_firewall_rule('ipv6_name_BOOTFILTER', 300, 'jump ipv6_name_BOOTOUTER')
    assert_firewall_rule('ipv6_name_BOOTOUTER', 10, 'jump ipv6_name_BOOTINNER')
    assert_firewall_rule('ipv6_name_BOOTINNER', 10, 'vmap @ipv6_map_BOOTMAP', '@ipv6_match_group_BOOTMATCH')
    assert_firewall_rule_absent('ipv6_name_BOOTFILTER', 310)


def check_firewall_ipv4_dynamic(options):
    """Dynamic set definitions and packet-path update consumers are rebuilt."""
    assert_firewall_object('set', 'ipv4_address_group_BOOTLEARN', 'dynamic', 'timeout 10m', 'size 1024')
    assert_firewall_rule('ipv4_name_BOOTFILTER', 260, 'update @ipv4_address_group_BOOTLEARN', 'timeout 5m')
    assert_firewall_rule('ipv4_name_BOOTFILTER', 270, 'update @ipv4_match_group_BOOTDYNAMIC')


def check_firewall_ipv6_dynamic(options):
    """Dynamic IPv6 tuple learners retain the declared fields and lifetime."""
    assert_firewall_object('set', 'ipv6_address_group_BOOTLEARN', 'dynamic', 'timeout 10m', 'size 1024')
    assert_firewall_rule('ipv6_name_BOOTFILTER', 260, 'update @ipv6_address_group_BOOTLEARN', 'timeout 5m')
    assert_firewall_rule('ipv6_name_BOOTFILTER', 270, 'update @ipv6_match_group_BOOTDYNAMIC')


def check_firewall_zones_ipv4(options):
    """Zone dispatch retains comments, policies and both INPUT interface identities."""
    assert_firewall_object('map', 'ipv4_zone_forward', 'BOOTUSERS to BOOTWAN', 'jump ipv4_name_BOOTPASS', 'counter')
    assert_firewall_object('chain', 'ipv4_input', 'sdifname vmap', 'iifname vmap')
    assert_firewall_object('chain', 'ipv4_output', 'oifkind "vrf"', 'vmap @ipv4_zone_output')
    assert_firewall_rule('ipv4_name_BOOTINPUT', 10, 'sdifname')


def check_firewall_zones_ipv6(options):
    """IPv6 zone dispatch and the preliminary VRF output pass remain separate."""
    assert_firewall_object('map', 'ipv6_zone_forward', 'BOOTUSERS to BOOTWAN', 'jump ipv6_name_BOOTPASS', 'counter')
    assert_firewall_object('chain', 'ipv6_input', 'sdifname vmap', 'iifname vmap')
    assert_firewall_object('chain', 'ipv6_output', 'oifkind "vrf"', 'vmap @ipv6_zone_output')


def check_firewall_raw(options):
    """All four raw hooks have native notrack statements after reboot."""
    assert_firewall_rule('ipv4_prerouting', 41990, 'notrack')
    assert_firewall_rule('ipv6_prerouting', 41990, 'notrack')
    assert_firewall_rule('ipv4_output_raw', 41990, 'notrack')
    assert_firewall_rule('ipv6_output_raw', 41990, 'notrack')


def check_firewall_named_state(options):
    """Shared counters, quotas and limits must exist as named native objects."""
    assert_firewall_object('counter', 'counter_group_BOOTTOTAL')
    assert_firewall_object('quota', 'quota_group_BOOTQUOTA', '1 mbytes', absent=('over',))
    assert_firewall_object('limit', 'ipv4_limit_group_BOOTLIMIT', '10/second')
    assert_firewall_object('limit', 'ipv6_limit_group_BOOTLIMIT', '10/second')
    assert_equal(Path('/proc/sys/net/netfilter/nf_conntrack_acct').read_text().strip(), '1')


def check_firewall_flowtable(options):
    """Global enrollment remains ahead of state-policy acceptance and has its counter."""
    assert_firewall_object('flowtable', 'flowtable_BOOTFAST', r'veth995\*', r'veth997\*', 'counter')
    text = assert_firewall_object('chain', 'forward', 'flow add @flowtable_BOOTFAST counter')
    assert text.index('flow add') < text.index('ct state vmap')

    # Prefix hooks must attach to recreated devices, not merely survive in the definition.
    first = cmd(['nft', 'list', 'hooks', 'netdev', 'device', 'veth995'])
    second = cmd(['nft', 'list', 'hooks', 'netdev', 'device', 'veth997'])
    assert_equal(first.count('flowtable inet nvyr_filter flowtable_BOOTFAST'), 1)
    assert_equal(second.count('flowtable inet nvyr_filter flowtable_BOOTFAST'), 1)


def check_firewall_ipv4_inclusions(options):
    """Nested address inclusions recover IPv4 members from every level."""
    # Auto-merge joins these adjacent /24s into one inclusive interval.
    assert_firewall_object('set', 'ipv4_address_group_BOOTADDR', '198.18.195.0-198.18.196.255')


def check_firewall_ipv6_inclusions(options):
    """Nested address inclusions recover IPv6 members independently."""
    assert_firewall_object('set', 'ipv6_address_group_BOOTADDR', '2001:db8:195::/64', '2001:db8:196::/64')


def check_firewall_singleton_inclusions(options):
    """Interface prefixes, ports and MAC addresses are flattened into consumer sets."""
    assert_firewall_object('set', 'interface_group_BOOTIF', r'dum995\*', r'dum997\*')
    assert_firewall_object('set', 'port_group_BOOTPORT', '8443')
    assert_firewall_object('set', 'mac_group_BOOTMAC', '02:00:00:19:95:02')


def check_firewall_ipv4_prefixes(options):
    """Rule and zone prefixes stay native selectors rather than boot-time expansions."""
    assert_firewall_rule('ipv4_forward', 41990, r'iifname "dum995\*"')
    assert_firewall_object('map', 'ipv4_zone_forward', r'veth995\*', r'veth997\*')


def check_firewall_ipv6_prefixes(options):
    """IPv6 dispatch restores the same prefix semantics with independent policies."""
    assert_firewall_rule('ipv6_forward', 41990, r'iifname "dum995\*"')
    assert_firewall_object('map', 'ipv6_zone_forward', r'veth995\*', r'veth997\*')


def check_logging_service(options):
    """Generate a fresh service record so an old log cannot conceal a dead collector."""
    marker = 'nvyr-acceptance-' + str(uuid.uuid4())
    cmd(['logger', '-t', 'bgpd', '-p', 'daemon.debug', marker])
    assert_log_output('bgp', expected=(marker,))
    rotation = Path('/run/nvyr-logging/logrotate.conf').read_text()
    assert_in('size 64M', rotation)
    assert_in('rotate 3', rotation)


def check_logging_container(options):
    """Container stdout reaches its file-backed operational log after each boot."""
    marker = 'nvyr-container-acceptance-' + str(uuid.uuid4())
    cmd(['podman', 'exec', 'BOOTBOX', 'sh', '-c', 'echo "$1" > /proc/1/fd/1', 'sh', marker])
    assert_log_output('container', '--name', 'BOOTBOX', expected=(marker,))


def check_logging_ipv4_packets(options):
    """A new IPv4 packet must reach its NFLOG file and scoped operational view."""
    path = logging_runtime.group_path('normal:BOOTLOG4')
    offset = path.stat().st_size if path.exists() else 0
    assert_equal(send_firewall_udp(1), 1)
    prefix = '[ipv4-OUT-filter-41980-A]'
    wait_for(lambda: path.read_bytes()[offset:] if path.exists() else b'',
             lambda data: prefix.encode() in data, description='fresh IPv4 NFLOG record')
    assert_log_output('firewall', '--family', 'ipv4', '--hook', 'output', '--stage', 'filter',
                      '--rule', '41980', expected=(prefix,), absent=('[ipv6-',))


def check_logging_ipv6_packets(options):
    """A new IPv6 packet must reach its separate NFLOG file after the reboot too."""
    path = logging_runtime.group_path('normal:BOOTLOG6')
    offset = path.stat().st_size if path.exists() else 0
    assert_equal(send_firewall_udp(1, family='ipv6'), 1)
    prefix = '[ipv6-OUT-filter-41980-A]'
    wait_for(lambda: path.read_bytes()[offset:] if path.exists() else b'',
             lambda data: prefix.encode() in data, description='fresh IPv6 NFLOG record')
    assert_log_output('firewall', '--family', 'ipv6', '--hook', 'output', '--stage', 'filter',
                      '--rule', '41980', expected=(prefix,), absent=('[ipv4-',))


def check_nat(options):
    """NAT rules and their map provider must be present in the same recovered table."""
    assert_firewall_object('map', 'ipv4_map_BOOTNAT', '198.18.195.10', '8080')
    assert_firewall_rule('ipv4_nat_prerouting', 41990, 'dnat ip to', '@ipv4_map_BOOTNAT')
    assert_firewall_rule('ipv4_nat_postrouting', 41990, 'masquerade')


def check_firewall_ipv4_learning_packets(options):
    """Exercise a real packet-path update and inspect the learned IPv4 member."""
    assert_equal(send_firewall_udp(1), 1)
    assert_firewall_object('set', 'ipv4_address_group_BOOTLEARN', '127.0.0.2')


def check_firewall_ipv6_learning_packets(options):
    """IPv6 learning and delivery must work independently after a cold start."""
    assert_equal(send_firewall_udp(1, family='ipv6'), 1)
    assert_firewall_object('set', 'ipv6_address_group_BOOTLEARN', '::1')


def check_complete_rule_inventory(options):
    """Require every configured active rule and every provider, not only sampled assertions."""
    document = json.loads(cmd(['nft', '-j', 'list', 'table', 'inet', 'nvyr_filter']))
    rules = {}
    objects = set()
    for entry in document['nftables']:
        for kind, value in entry.items():
            if kind == 'rule':
                rules.setdefault(value['chain'], []).append(value.get('comment', '').split('|', 1)[0])
            elif kind not in ('metainfo', 'table'):
                objects.add((kind, value['name']))

    with ConfigurationSession() as config:
        firewall = config.get_config()['firewall']
    for family in ('inet', 'ipv4', 'ipv6'):
        for name, chain in firewall.get(family, {}).get('name', {}).items():
            expected = [str(number) for number, rule in chain.get('rule', {}).items() if 'disable' not in rule]
            installed = [number for number in rules.get(f'{family}_name_{name}', []) if number != 'default']
            assert_equal(installed, sorted(expected, key=int), msg=f'{family} {name}: rule order/inventory')
        for kind in ('address-group', 'match-group', 'icmp-group', 'map'):
            for name in firewall['group'].get(kind, {}).get(family, {}):
                native_name = f'{family}_{kind.replace("-", "_")}_{name}'
                assert_in(('map' if kind == 'map' else 'set', native_name), objects)
    for kind in ('interface-group', 'mac-group', 'port-group'):
        for name in firewall['group'].get(kind, {}):
            assert_in(('set', f'{kind.replace("-", "_")}_{name}'), objects)


CHECKS = (
    check_kernel_release, check_operational_inventory,
    check_system_hostname, check_system_timezone, check_cpu_policy, check_vrfs,
    check_ethernet, check_ethernet_ipv4, check_ethernet_ipv6, check_vlans,
    check_vlan_ipv4_traffic, check_vlan_ipv6_traffic,
    check_loopback_ipv4, check_loopback_ipv6, check_dummy_and_disabled, check_veth_pair,
    check_bridge, check_bridge_ports, check_bridge_multicast,
    check_static_ipv4, check_static_ipv6, check_multipath_ipv4, check_multipath_ipv6,
    check_vrf_static_ipv4, check_vrf_static_ipv6, check_routing_policies,
    check_bgp_ipv4_session, check_bgp_ipv6_session, check_bgp_ipv4_policy_result, check_bgp_ipv6_policy_result,
    check_bgp_unicast_options,
    check_dhcp4_server, check_dhcp6_server, check_vrf_dhcp4_server, check_vrf_dhcp6_server,
    check_dhcp_hostfile_hook, check_dhcp_ha, check_dhcp_client_lease, check_container_workload, check_container_network_ipv4,
    check_container_network_ipv6, check_container_persistence, check_container_pod,
    check_firewall_failsafe_handover,
    check_firewall_ipv4_rules, check_firewall_ipv6_rules, check_firewall_ipv4_dynamic,
    check_firewall_ipv6_dynamic, check_firewall_zones_ipv4, check_firewall_zones_ipv6,
    check_firewall_raw, check_firewall_named_state, check_firewall_flowtable, check_nat,
    check_firewall_ipv4_learning_packets, check_firewall_ipv6_learning_packets,
    check_firewall_ipv4_inclusions, check_firewall_ipv6_inclusions, check_firewall_singleton_inclusions,
    check_firewall_ipv4_prefixes, check_firewall_ipv6_prefixes,
    check_logging_service, check_logging_container, check_logging_ipv4_packets, check_logging_ipv6_packets,
    check_complete_rule_inventory,
    check_kernel_settings, check_interface_ip_options, check_vrf_conntrack, check_ntp,
    check_firewall_inet, check_firewall_ingress_ipv4, check_firewall_ingress_ipv6,
    check_firewall_source_validation_ipv4, check_firewall_source_validation_ipv6,
    check_firewall_timeout_policies, check_firewall_helpers,
    check_firewall_modifications_ipv4, check_firewall_modifications_ipv6, check_firewall_map_defaults,
)
