"""MP-BGP forwarding over every implemented IGP family with LDP.

Reuse the routed scenario's links, loopbacks, LDP/BGP sessions and customer VRFs.
Only the transport IGP changes: no static route may stand in for either family's
loopback reachability. OSPFv2/v3, dual-stack IS-IS and RIP/RIPng run separately so
one protocol cannot conceal another's failure.
"""

import json

import pytest

from functionaltests.mpls_peer import OSPF_CONFIGURATION
from functionaltests.mpls_transit import igp_configuration
from functionaltests.network.test_mpls_forwarding import capture_ping
from nvyr.helpers.process import cmd
from smoketests.support import wait_for


ISIS = '''
set protocols isis net 49.0071.0000.0000.0001.00 options level level-2
set protocols isis topology ipv6-unicast
set protocols isis level level-2 timers lsp-generation 1 spf-interval 1
set protocols isis ldp-sync hold-down 30
set protocols isis interface veth42079 address-family ipv4-unicast address-family ipv6-unicast network point-to-point
set protocols isis interface veth42079 topology ipv6-unicast
set protocols isis interface veth42079 level level-2 timers hello-interval 1 hello-multiplier 3
set protocols isis interface dum42081 address-family ipv4-unicast address-family ipv6-unicast passive
set protocols isis interface dum42081 topology ipv6-unicast
'''

ISIS_PEER = '''
router isis nvyr
 net 49.0071.0000.0000.0002.00
 is-type level-2-only
 metric-style wide
 topology ipv6-unicast
 lsp-gen-interval level-2 1
 spf-interval level-2 1
exit
interface veth42082
 ip router isis nvyr
 ipv6 router isis nvyr
 isis network point-to-point
 isis topology ipv6-unicast
 isis hello-interval level-2 1
 isis hello-multiplier level-2 3
exit
interface lo
 ip router isis nvyr
 ipv6 router isis nvyr
 isis passive
 isis topology ipv6-unicast
exit
'''

RIP = '''
set protocols rip version 2
set protocols rip timers update 2 timeout 12 garbage-collection 8
set protocols rip interface veth42079 passive disable
set protocols rip interface dum42081 passive
set protocols ripng timers update 2 timeout 12 garbage-collection 8
set protocols ripng interface veth42079 passive disable
set protocols ripng interface dum42081 passive
'''

RIP_PEER = '''
ipv6 prefix-list MPLSTRANSPORT seq 10 permit 2001:db8:77::2/128
route-map MPLSTRANSPORT permit 10
 match ipv6 address prefix-list MPLSTRANSPORT
exit
router rip
 version 2
 timers basic 2 12 8
 network veth42082
 network lo
 passive-interface lo
exit
router ripng
 timers basic 2 12 8
 network veth42082
 redistribute connected route-map MPLSTRANSPORT
exit
'''


def configure_peer(directory, configuration):
    path = directory / 'underlay.conf'
    path.write_text(configuration)
    cmd(['vtysh', '--vty_socket', str(directory), '-f', str(path)])


def require_igp_route(prefix, protocol, peer=None):
    family = 'ipv6' if ':' in prefix else 'ip'
    arguments = ['vtysh']
    if peer is not None:
        arguments.extend(['--vty_socket', str(peer)])
    arguments.extend(['-c', f'show {family} route {prefix} json'])
    wait_for(lambda: json.loads(cmd(arguments)),
             lambda routes: any(route.get('protocol') == protocol and route.get('selected')
                                for route in routes.get(prefix, [])),
             timeout=45, description=f'{protocol} selected transport route {prefix}')


def require_labeled_route(version, destination, interface, *, namespace=None, vrf=None):
    arguments = ['ip']
    if namespace:
        arguments.extend(['-n', namespace])
    arguments.extend([version, '-j', 'route', 'show'])
    if vrf:
        arguments.extend(['vrf', vrf])
    arguments.append(destination)
    wait_for(lambda: json.loads(cmd(arguments)),
             lambda rows: any(row.get('protocol') == 'bgp' and row.get('dev') == interface
                              and row.get('encap', {}).get('encap_type') == 'mpls' for row in rows),
             timeout=45, description=f'labeled BGP route to {destination} through {interface}')


@pytest.mark.parametrize('underlay,protocol4,protocol6', [
    ('ospf', 'ospf', 'ospf6'), ('isis', 'isis', 'isis'), ('rip', 'rip', 'ripng'),
])
@pytest.mark.parametrize('transport', ['ipv4', 'ipv6'])
def test_mp_bgp_over_igp(config, routed_peer, underlay, protocol4, protocol6, transport):
    core = routed_peer.parent / 'core'
    try:
        if transport == 'ipv6':
            config.set('set protocols bgp neighbor 198.19.77.2 shutdown')
            config.delete('delete protocols bgp neighbor 2001:db8:77::2 shutdown')
        if underlay != 'ospf':
            config.delete('delete protocols ospf')
            config.delete('delete protocols ospfv3')
            commands = ISIS if underlay == 'isis' else RIP
            for line in commands.strip().splitlines():
                config.set(line)
        else:
            config.delete('delete protocols ospf interface veth42071')
            config.delete('delete protocols ospfv3 interface veth42071')
            config.set('set protocols ospf interface veth42079 area 0 network point-to-point hello-interval 1 dead-interval 4')
            config.set('set protocols ospfv3 interface veth42079 area 0 network point-to-point hello-interval 1 dead-interval 4')

        # Loopback LDP transports remain reachable over the selected IGP, while
        # both P-facing links carry the actual transport/service label stack.
        config.set('set protocols ldp address-family ipv4 transport-address 198.19.81.1 interface veth42079')
        config.set('set protocols ldp address-family ipv6 transport-address 2001:db8:81::1 interface veth42079')
        config.delete('delete protocols ldp address-family ipv4 interface veth42071')
        config.delete('delete protocols ldp address-family ipv6 interface veth42071')
        config.set(f'set protocols ldp options dual-stack transport-preference {transport}')
        config.commit()
        # IPv6 is FRR's native default; only the IPv4 preference has a command.
        negate = 'no ' if transport == 'ipv6' else ''
        preference = f'mpls ldp\n {negate}dual-stack transport-connection prefer ipv4\nexit\n'
        configure_peer(core, igp_configuration(underlay) + preference)
        if underlay == 'ospf':
            native = OSPF_CONFIGURATION.replace('veth42072', 'veth42082')
        else:
            native = ISIS_PEER if underlay == 'isis' else RIP_PEER
        configure_peer(routed_peer, 'no router ospf\nno router ospf6\n' + native + preference + '''
mpls ldp
 address-family ipv4
  no interface veth42072
  discovery transport-address 198.19.77.2
  interface veth42082
  exit
 exit-address-family
 address-family ipv6
  no interface veth42072
  discovery transport-address 2001:db8:77::2
  interface veth42082
  exit
 exit-address-family
exit
''')

        for prefix, protocol in [('198.19.77.2/32', protocol4), ('2001:db8:77::2/128', protocol6)]:
            require_igp_route(prefix, protocol)
            require_igp_route(prefix, protocol, core)
        for prefix, protocol in [('198.19.81.1/32', protocol4), ('2001:db8:81::1/128', protocol6)]:
            require_igp_route(prefix, protocol, routed_peer)
            require_igp_route(prefix, protocol, core)

        def ldp_transports():
            data = json.loads(cmd(['vtysh', '--vty_socket', str(core), '-c', 'show mpls ldp neighbor json']))
            return {row['neighborId'] for row in data.get('neighbors', [])
                    if row['addressFamily'] == transport and row['state'].lower() == 'operational'}

        # Sequential transport changes can trigger FRR's 120-second retry backoff.
        wait_for(ldp_transports, lambda peers: {'198.18.71.1', '198.18.71.2'} <= peers,
                 timeout=150, description=transport + ' LDP sessions on both core links')

        neighbor = '198.19.77.2' if transport == 'ipv4' else '2001:db8:77::2'
        wait_for(lambda: json.loads(cmd(['vtysh', '-c', f'show bgp neighbors {neighbor} json'])),
                 lambda data: data.get(neighbor, {}).get('bgpState') == 'Established',
                 timeout=45, description=transport + ' MP-BGP session over ' + underlay)

        if underlay in {'ospf', 'isis'}:
            command = ('show ip ospf mpls ldp-sync interface veth42079' if underlay == 'ospf'
                       else 'show isis mpls ldp-sync')
            wait_for(lambda: cmd(['vtysh', '-c', command]), lambda output: 'Sync achieved' in output,
                     timeout=45, description=underlay + ' LDP synchronization')

        if underlay == 'ospf':
            # OSPFv3 advertises interface /128s. LDP must terminate those local
            # host FECs, not advertise a transit label with no usable LFIB entry.
            require_igp_route('2001:db8:84::1/128', 'ospf6', routed_peer)
            wait_for(lambda: cmd(['vtysh', '-c', 'show mpls ldp ipv6 binding 2001:db8:84::1/128 detail']),
                     lambda output: 'Local binding: label: imp-null' in output, timeout=15,
                     description='local interface host-route egress label')
            cmd(['ip', 'netns', 'exec', 'nvyr-routed-right', 'ping', '-6', '-n',
                 '-I', '2001:db8:77::2', '-c', '3', '-W', '2', '2001:db8:84::1'])
            address = '2001:db8:85::99/64'
            prefix = '2001:db8:85::99/128'
            address_command = ['ip', '-n', 'nvyr-routed-right', '-6', 'address']
            binding_command = ['vtysh', '--vty_socket', str(core), '-c',
                               f'show mpls ldp ipv6 binding {prefix} detail json']

            def remote_binding():
                return json.loads(cmd(binding_command)).get(prefix, {}).get('remoteLabels', [])

            # This address belongs to the external PE, whose interfaces are
            # managed natively rather than by the nVyR configuration fixture.
            cmd([*address_command, 'add', address, 'dev', 'veth42082', 'nodad'])
            try:
                require_igp_route(prefix, 'ospf6')
                wait_for(remote_binding,
                         lambda rows: any(row['neighborId'] == '198.18.71.2' and row['label'] == 'imp-null' for row in rows),
                         timeout=15, description='peer received interface host binding')
            finally:
                cmd([*address_command, 'del', address, 'dev', 'veth42082'])
            wait_for(remote_binding, lambda rows: not any(row['neighborId'] == '198.18.71.2' for row in rows),
                     timeout=15, description='peer withdrew removed interface host binding')

        for family, version, local, remote, transport_prefix, lu in (
            ('ipv4', '-4', '198.19.80.1', '198.19.80.2', '198.19.77.2/32', '198.19.76.2'),
            ('ipv6', '-6', '2001:db8:80::1', '2001:db8:80::2', '2001:db8:77::2/128', '2001:db8:76::2'),
        ):
            wait_for(lambda: cmd(['vtysh', '-c', f'show mpls ldp {family} binding {transport_prefix} detail']),
                     lambda output: '198.18.84.2' in output, timeout=30,
                     description=underlay + ' ' + family + ' remote transport label')
            local_lu = '198.19.76.1' if family == 'ipv4' else '2001:db8:76::1'
            require_labeled_route(version, remote, 'veth42079', vrf='RNVPNBLUE')
            require_labeled_route(version, lu, 'veth42079')
            require_labeled_route(version, local, 'veth42082', namespace='nvyr-routed-right', vrf='VPNPEER')
            require_labeled_route(version, local_lu, 'veth42082', namespace='nvyr-routed-right')

            probe = ['ping', version, '-n', '-c', '2', '-W', '2']
            payload = 'ip' if family == 'ipv4' else 'ip6'
            output = capture_ping(['ip', 'vrf', 'exec', 'RNVPNBLUE', *probe, '-I', local, remote],
                                  interface='veth42079', packet_filter=f'mpls and mpls and {payload} dst {remote}')
            assert remote in output and output.count('(label ') == 2, output
            peer_command = ['ip', 'netns', 'exec', 'nvyr-routed-right']
            output = capture_ping([*peer_command, 'ip', 'vrf', 'exec', 'VPNPEER', *probe, '-I', remote, local],
                                  interface='veth42082', namespace='nvyr-routed-right',
                                  packet_filter=f'mpls and mpls and {payload} dst {local}')
            assert local in output and output.count('(label ') == 2, output
            output = capture_ping([*probe, '-I', local_lu, lu], interface='veth42079',
                                  packet_filter=f'mpls and mpls and {payload} dst {lu}')
            assert lu in output and output.count('(label ') == 2, output
            output = capture_ping([*peer_command, *probe, '-I', lu, local_lu], interface='veth42082',
                                  namespace='nvyr-routed-right', packet_filter=f'mpls and mpls and {payload} dst {local_lu}')
            assert local_lu in output and output.count('(label ') == 2, output
    finally:
        # The shared configuration fixture restores nVyR; restore only the native
        # peer here. Daemons, links, LDP and BGP remain alive for the next case.
        removal = {'ospf': 'no router ospf\nno router ospf6\n', 'isis': 'no router isis nvyr\n',
                   'rip': 'no router rip\nno router ripng\n'}[underlay]
        preference = 'mpls ldp\n dual-stack transport-connection prefer ipv4\nexit\n'
        configure_peer(core, removal + preference)
        if underlay == 'rip':
            removal += 'no route-map MPLSTRANSPORT\nno ipv6 prefix-list MPLSTRANSPORT\n'
        configure_peer(routed_peer, removal + OSPF_CONFIGURATION + preference + '''
mpls ldp
 address-family ipv4
  no interface veth42082
  discovery transport-address 198.18.71.2
  interface veth42072
  exit
 exit-address-family
 address-family ipv6
  no interface veth42082
  discovery transport-address 2001:db8:71::2
  interface veth42072
  exit
 exit-address-family
exit
''')
