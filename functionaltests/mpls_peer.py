"""Native LDP/OSPF/BGP-LU peer in the routed suite's right-side host namespace."""

from contextlib import contextmanager, ExitStack
import subprocess
import time

from nvyr.helpers.process import cmd


CONFIGURATION = '''
router bgp 65072
 bgp router-id 198.18.71.2
 no bgp default ipv4-unicast
 no bgp ebgp-requires-policy
 no bgp network import-check
 bgp labeled-unicast explicit-null
 neighbor 198.18.71.1 remote-as 65071
 neighbor 198.18.71.1 capability dynamic
 address-family ipv4 unicast
  network 198.19.72.2/32
  network 198.19.72.3/32
 exit-address-family
 address-family ipv6 unicast
  network 2001:db8:72::2/128
  network 2001:db8:72::3/128
 exit-address-family
 address-family ipv4 labeled-unicast
  neighbor 198.18.71.1 activate
 exit-address-family
 address-family ipv6 labeled-unicast
  neighbor 198.18.71.1 activate
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
  label local advertise explicit-null
  interface veth42072
  exit
 exit-address-family
 address-family ipv6
  discovery transport-address 2001:db8:71::2
  label local advertise explicit-null
  interface veth42072
  exit
 exit-address-family
exit
'''


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
    cmd(['ip', '-n', namespace, 'address', 'add', '198.19.72.2/32', 'dev', 'lu0'])
    cmd(['ip', '-n', namespace, '-6', 'address', 'add', '2001:db8:72::2/128', 'dev', 'lu0', 'nodad'])
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
