"""Native LDP/OSPF/BGP-LU peer in the routed suite's right-side host namespace."""

from contextlib import contextmanager, ExitStack
import subprocess
import time

from nvyr.helpers.process import cmd


CONFIGURATION = '''
access-list EXPLICIT4 permit host 198.19.62.2
ipv6 access-list EXPLICIT6 permit 2001:db8:64::2/128
route-map RECURSIVE-IN deny 10
exit
route-map RECURSIVE6 permit 10
 set ipv6 next-hop global 2001:db8:77::2
exit
router bgp 65072
 bgp router-id 198.18.71.2
 no bgp default ipv4-unicast
 no bgp ebgp-requires-policy
 no bgp network import-check
 bgp labeled-unicast explicit-null
 neighbor 198.18.71.1 remote-as 65071
 neighbor 198.18.71.1 capability dynamic
 neighbor 198.18.73.1 remote-as 65071
 neighbor 198.18.73.1 ebgp-multihop 2
 neighbor 198.18.73.1 update-source 198.19.77.2
 address-family ipv4 unicast
  network 198.19.72.2/32
  network 198.19.72.3/32
  network 198.19.76.2/32
 exit-address-family
 address-family ipv6 unicast
  network 2001:db8:72::2/128
  network 2001:db8:72::3/128
  network 2001:db8:76::2/128
 exit-address-family
 address-family ipv4 vpn
  neighbor 198.18.73.1 activate
  neighbor 198.18.73.1 attribute-unchanged next-hop
 exit-address-family
 address-family ipv6 vpn
  neighbor 198.18.73.1 activate
  neighbor 198.18.73.1 attribute-unchanged next-hop
 exit-address-family
 address-family ipv4 labeled-unicast
  neighbor 198.18.71.1 activate
  neighbor 198.18.73.1 activate
  neighbor 198.18.73.1 route-map RECURSIVE-IN in
 exit-address-family
 address-family ipv6 labeled-unicast
  neighbor 198.18.71.1 activate
  neighbor 198.18.73.1 activate
  neighbor 198.18.73.1 route-map RECURSIVE-IN in
  neighbor 198.18.73.1 route-map RECURSIVE6 out
 exit-address-family
exit
router bgp 65072 vrf VPNPEER
 bgp router-id 198.19.80.2
 no bgp default ipv4-unicast
 address-family ipv4 unicast
  nexthop vpn export 198.19.77.2
  network 198.19.80.2/32
  network 198.19.80.3/32
  rd vpn export 65072:80
  label vpn export auto
  rt vpn both 65071:80
  import vpn
  export vpn
 exit-address-family
 address-family ipv6 unicast
  nexthop vpn export 2001:db8:77::2
  network 2001:db8:80::2/128
  network 2001:db8:80::3/128
  rd vpn export 65072:80
  label vpn export auto
  rt vpn both 65071:80
  import vpn
  export vpn
 exit-address-family
exit
interface veth42072
 ip ospf area 0
 ip ospf network point-to-point
 ip ospf hello-interval 1
 ip ospf dead-interval 4
exit
interface lo
 ip ospf area 0
 ip ospf passive
exit
router ospf
 ospf router-id 198.18.71.2
exit
mpls ldp
 router-id 198.18.71.2
 dual-stack transport-connection prefer ipv4
 discovery hello interval 1
 discovery hello holdtime 6
 address-family ipv4
  discovery transport-address 198.18.71.2
  label local advertise explicit-null for EXPLICIT4
  interface veth42072
  exit
 exit-address-family
 address-family ipv6
  discovery transport-address 2001:db8:71::2
  label local advertise explicit-null for EXPLICIT6
  interface veth42072
  exit
 exit-address-family
exit
'''


def static_forwarding(namespace):
    """Use the existing left/right namespaces for a real two-label transit path."""
    left = ['ip', '-n', 'nvyr-routed-left']
    right = ['ip', '-n', namespace]
    cmd(left + ['link', 'set', 'veth42074', 'up'])
    cmd(left + ['address', 'add', '198.18.73.2/30', 'dev', 'veth42074'])
    cmd(left + ['-6', 'address', 'add', '2001:db8:73::2/64', 'dev', 'veth42074', 'nodad'])
    for version, destination, gateway, stack, inner in (
        ('-4', '198.19.73.2/32', '198.18.73.1', '17000/18000', '18000'),
        ('-4', '198.19.74.2/32', '198.18.73.1', '17001', None),
        ('-6', '2001:db8:74::2/128', '2001:db8:73::1', '17002/18002', '18002'),
        ('-6', '2001:db8:75::2/128', '2001:db8:73::1', '17003', None),
    ):
        cmd(right + [version, 'address', 'add', destination, 'dev', 'lu0', *(['nodad'] if version == '-6' else [])])
        cmd(left + [version, 'route', 'add', destination, 'encap', 'mpls', stack, 'via', gateway, 'dev', 'veth42074'])
        if inner:
            cmd(right + ['-f', 'mpls', 'route', 'add', inner, 'dev', 'lo'])
    cmd(right + ['route', 'add', '198.18.73.0/30', 'via', '198.18.71.1'])
    cmd(right + ['-6', 'route', 'add', '2001:db8:73::/64', 'via', '2001:db8:71::1'])


@contextmanager
def daemon(directory, namespace):
    directory.mkdir(mode=0o755)
    cmd(['chown', 'frr:frr', str(directory)])
    cmd(['ip', '-n', namespace, 'link', 'set', 'veth42072', 'up'])
    cmd(['ip', '-n', namespace, 'address', 'add', '198.18.71.2/30', 'dev', 'veth42072'])
    cmd(['ip', '-n', namespace, '-6', 'address', 'add', '2001:db8:71::2/64', 'dev', 'veth42072', 'nodad'])
    cmd(['ip', 'netns', 'exec', namespace, 'sysctl', '-qw', 'net.mpls.platform_labels=1048575',
         'net.mpls.conf.veth42072.input=1'])
    cmd(['ip', '-n', namespace, 'link', 'add', 'lu0', 'type', 'dummy'])
    cmd(['ip', '-n', namespace, 'link', 'set', 'lu0', 'up'])
    cmd(['ip', '-n', namespace, 'address', 'add', '198.19.77.2/32', 'dev', 'lo'])
    cmd(['ip', '-n', namespace, '-6', 'address', 'add', '2001:db8:77::2/128', 'dev', 'lo', 'nodad'])
    cmd(['ip', '-n', namespace, 'address', 'add', '198.19.72.2/32', 'dev', 'lu0'])
    cmd(['ip', '-n', namespace, '-6', 'address', 'add', '2001:db8:72::2/128', 'dev', 'lu0', 'nodad'])
    cmd(['ip', '-n', namespace, 'address', 'add', '198.19.76.2/32', 'dev', 'lu0'])
    cmd(['ip', '-n', namespace, '-6', 'address', 'add', '2001:db8:76::2/128', 'dev', 'lu0', 'nodad'])
    cmd(['ip', '-n', namespace, 'link', 'add', 'VPNPEER', 'type', 'vrf', 'table', '42080'])
    cmd(['ip', '-n', namespace, 'link', 'set', 'VPNPEER', 'up'])
    cmd(['ip', '-n', namespace, 'link', 'add', 'vpn0', 'type', 'dummy'])
    cmd(['ip', '-n', namespace, 'link', 'set', 'vpn0', 'master', 'VPNPEER'])
    cmd(['ip', '-n', namespace, 'link', 'set', 'vpn0', 'up'])
    for address in ('198.19.80.2/32', '198.19.80.3/32', '2001:db8:80::2/128', '2001:db8:80::3/128'):
        cmd(['ip', '-n', namespace, 'address', 'add', address, 'dev', 'vpn0', *(['nodad'] if ':' in address else [])])
    cmd(['ip', '-n', namespace, '-6', 'route', 'add', '2001:db8:81::1/128', 'via', '2001:db8:71::1'])
    static_forwarding(namespace)
    config = directory / 'frr.conf'
    config.write_text(CONFIGURATION)
    config.chmod(0o644)
    empty = directory / 'empty.conf'
    empty.write_text('')
    empty.chmod(0o644)
    with ExitStack() as cleanup:
        for name in ('mgmtd', 'zebra', 'ldpd', 'ospfd', 'bgpd'):
            args = ['ip', 'netns', 'exec', namespace, '/usr/lib/frr/' + name,
                    '-N', 'nvyr-routed-mpls', '-z', str(directory / 'zserv.api'),
                    '--vty_socket', str(directory), '-i', str(directory / (name + '.pid')), '-P', '0']
            if name != 'mgmtd':
                args.extend(['-f', str(empty)])
            log = cleanup.enter_context((directory / (name + '.log')).open('w+'))
            process = subprocess.Popen(args, stdout=log, stderr=log)
            cleanup.callback(process.wait, timeout=10)
            cleanup.callback(process.terminate)
            deadline = time.monotonic() + 10
            while not (directory / (name + '.vty')).exists():
                if process.poll() is not None or time.monotonic() >= deadline:
                    log.seek(0)
                    raise AssertionError(f'{name} peer did not start: ' + log.read())
                time.sleep(.05)
        # Integrated configuration is parsed by vtysh after all daemon sockets exist.
        cmd(['vtysh', '--vty_socket', str(directory), '-f', str(config)])
        yield directory
