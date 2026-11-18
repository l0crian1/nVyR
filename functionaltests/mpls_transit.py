"""One native P router, reused by the MP-BGP/IGP matrix in the routed scenario."""

from contextlib import contextmanager

from functionaltests.mpls_peer import processes
from nvyr.helpers.process import cmd


LDP = '''
mpls ldp
 router-id 198.18.84.2
 dual-stack transport-connection prefer ipv4
 discovery hello interval 1
 discovery hello holdtime 6
 address-family ipv4
  discovery transport-address 198.18.84.2
  interface veth42080
  exit
  interface veth42081
  exit
 exit-address-family
 address-family ipv6
  discovery transport-address 2001:db8:84::2
  interface veth42080
  exit
  interface veth42081
  exit
 exit-address-family
exit
'''


def igp_configuration(protocol):
    """Enable the selected IGP on both core links; there are no static routes."""
    if protocol == 'ospf':
        result = '''
router ospf
 ospf router-id 198.18.84.2
exit
router ospf6
 ospf6 router-id 198.18.84.2
exit
'''
        for interface in ('veth42080', 'veth42081'):
            result += f'''
interface {interface}
 ip ospf area 0
 ip ospf network point-to-point
 ip ospf hello-interval 1
 ip ospf dead-interval 4
 ipv6 ospf6 area 0
 ipv6 ospf6 network point-to-point
 ipv6 ospf6 hello-interval 1
 ipv6 ospf6 dead-interval 4
exit
'''
        return result
    if protocol == 'isis':
        result = '''
router isis nvyr
 net 49.0071.0000.0000.0003.00
 is-type level-2-only
 metric-style wide
 topology ipv6-unicast
 lsp-gen-interval level-2 1
 spf-interval level-2 1
exit
'''
        for interface in ('veth42080', 'veth42081'):
            result += f'''
interface {interface}
 ip router isis nvyr
 ipv6 router isis nvyr
 isis network point-to-point
 isis topology ipv6-unicast
 isis hello-interval level-2 1
 isis hello-multiplier level-2 3
exit
'''
        return result
    return '''
router rip
 version 2
 timers basic 2 12 8
 network veth42080
 network veth42081
exit
router ripng
 timers basic 2 12 8
 network veth42080
 network veth42081
exit
'''


@contextmanager
def daemon(directory):
    namespace = 'nvyr-routed-core'
    cmd(['ip', '-n', namespace, 'link', 'set', 'lo', 'up'])
    cmd(['ip', '-n', namespace, 'link', 'add', 'veth42081', 'type', 'veth',
         'peer', 'name', 'veth42082', 'netns', 'nvyr-routed-right'])
    for node, interface, ipv4, ipv6 in (
        (namespace, 'veth42080', '198.18.84.2/30', '2001:db8:84::2/64'),
        (namespace, 'veth42081', '198.18.84.5/30', '2001:db8:84:1::1/64'),
        ('nvyr-routed-right', 'veth42082', '198.18.84.6/30', '2001:db8:84:1::2/64'),
    ):
        cmd(['ip', '-n', node, 'link', 'set', interface, 'mtu', '1600', 'up'])
        cmd(['ip', '-n', node, 'address', 'add', ipv4, 'dev', interface])
        cmd(['ip', '-n', node, '-6', 'address', 'add', ipv6, 'dev', interface, 'nodad'])
        cmd(['ip', 'netns', 'exec', node, 'sysctl', '-qw', 'net.mpls.platform_labels=1048575',
             f'net.mpls.conf.{interface}.input=1'])
    cmd(['ip', 'netns', 'exec', namespace, 'sysctl', '-qw',
         'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1'])
    with processes(directory, namespace, LDP, bgp=False):
        yield directory
