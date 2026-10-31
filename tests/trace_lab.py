"""Reproducible native packet journeys in an isolated router network namespace.

Run with ``unshare -n python3 -m tests.trace_lab /tmp/trace-evidence``. Two
disposable process-owned namespaces act as LAN and WAN hosts. The real router's
links, ruleset, configuration and conntrack table are never modified.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

from nvyr.helpers import firewall_trace, firewall_trace_analysis
from nvyr.helpers.firewall_trace_output import render


SERVER = '''
import socket,threading,time
def tcp():
 s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 s.bind(('::',9000)); s.listen()
 while True:
  c,a=s.accept()
  with c:
   data=c.recv(1024); c.sendall(data)
def udp():
 s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM); s.bind(('::',9000))
 while True:
  data,a=s.recvfrom(1024); s.sendto(data,a)
threading.Thread(target=tcp,daemon=True).start()
threading.Thread(target=udp,daemon=True).start()
print('ready',flush=True)
time.sleep(300)
'''
CLIENT = '''
import socket,sys
address,protocol,port=sys.argv[1:]
family=socket.AF_INET6 if ':' in address else socket.AF_INET
kind=socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM
with socket.socket(family,kind) as s:
 s.settimeout(.6); s.connect((address,int(port))); s.sendall(b'nvyr-trace'); assert s.recv(128)==b'nvyr-trace'
'''


def run(*arguments, **kwargs):
    """Fail with the complete native error when topology or rule programming fails."""
    result = subprocess.run(arguments, capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise AssertionError((arguments, result.stdout, result.stderr))
    return result.stdout


def enter(process, *arguments):
    """Use process-owned namespaces, avoiding persistent namespace registrations."""
    return ['nsenter', '-t', str(process.pid), '-n', *arguments]


def endpoint(name, address, ipv6, children):
    """Create one disposable peer and a default route through the isolated router."""
    process = subprocess.Popen(['unshare', '-n', 'sleep', '300'])
    children.append(process)
    current = os.readlink('/proc/self/ns/net')
    deadline = time.monotonic() + 3
    while os.readlink(f'/proc/{process.pid}/ns/net') == current:
        if time.monotonic() > deadline:
            raise AssertionError('Endpoint namespace did not start')
        time.sleep(.01)
    run('ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', 'peer-' + name)
    run('ip', 'link', 'set', 'peer-' + name, 'netns', str(process.pid))
    run('ip', 'addr', 'add', address + '.1/24', 'dev', name)
    run('ip', '-6', 'addr', 'add', ipv6 + '1/64', 'dev', name, 'nodad')
    run('ip', 'link', 'set', name, 'up')
    run(*enter(process, 'ip', 'link', 'set', 'lo', 'up'))
    run(*enter(process, 'ip', 'addr', 'add', address + '.2/24', 'dev', 'peer-' + name))
    run(*enter(process, 'ip', '-6', 'addr', 'add', ipv6 + '2/64', 'dev', 'peer-' + name, 'nodad'))
    run(*enter(process, 'ip', 'link', 'set', 'peer-' + name, 'up'))
    run(*enter(process, 'ip', 'route', 'add', 'default', 'via', address + '.1'))
    run(*enter(process, 'ip', '-6', 'route', 'add', 'default', 'via', ipv6 + '1'))
    return process


def rules(extra='', forward='accept comment "10|permit"'):
    """Use actual nVyR chain/comment conventions with native trace-capable statements."""
    return '''table inet nvyr_filter {
 chain prerouting { type filter hook prerouting priority raw; meta nftrace set 1; }
 chain input { type filter hook input priority filter; accept comment "10|local"; }
 chain output { type filter hook output priority filter; meta nftrace set 1; accept comment "10|local"; }
 chain ipv4_forward {
 FORWARD
 }
 chain ipv6_forward {
 FORWARD
 }
 chain forward { type filter hook forward priority filter; meta nfproto vmap { ipv4 : jump ipv4_forward, ipv6 : jump ipv6_forward }; }
 EXTRA
}
'''.replace('FORWARD', forward).replace('EXTRA', extra)


def exercise(directory, name, ruleset, traffic, *, success=True, check=None):
    """Record current native output, enforce traffic outcome, then inspect the saved story."""
    run('nft', 'flush', 'ruleset')
    run('nft', '-f', '-', input=ruleset)
    target = directory / (name + '.jsonl')
    # The capture directory is intentionally injected only in this isolated test process.
    code = ('from pathlib import Path; from nvyr.helpers import firewall_trace as t; '
            f't.DIRECTORY=Path({str(directory)!r}); '
            f't.monitor(duration=1.8,save={str(target)!r})')
    monitor = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert monitor.stdout.readline().startswith('Monitoring firewall traces.'), monitor.stderr.read()
        # An initial packet tests subscription readiness; a second guarantees captured traffic.
        time.sleep(.1)
        result = subprocess.run(traffic, text=True, capture_output=True, timeout=5)
        assert (result.returncode == 0) == success, (name, result.stdout, result.stderr)
        output, error = monitor.communicate(timeout=5)
        assert monitor.returncode == 0, (output, error)
    finally:
        if monitor.poll() is None:
            monitor.kill()
            monitor.wait()
        monitor.stdout.close()
        monitor.stderr.close()
    with target.open() as stream:
        report = firewall_trace_analysis.analyze(stream, detail=True)
    assert report['traces'], name
    assert not report['unparsed'], (name, report['unparsed'])
    assert not report['warnings'], (name, report['warnings'])
    if check:
        check(report)
    (directory / (name + '.txt')).write_text(render(report, detail=True))
    print(f'{name}: {len(report["traces"])} traces, {report["events"]} events', flush=True)
    return report


def require_verdict(verdict):
    """Require an actual observed terminal verdict in at least one packet journey."""
    def check(report):
        assert any(trace['last-verdict'] == verdict for trace in report['traces']), report
    return check


def require_change(field):
    """Require packet evidence of translation, not merely a NAT rule expression."""
    def check(report):
        assert any(field in change['fields'] for trace in report['traces'] for change in trace['changes']), report
    return check


def main(directory):
    """Exercise IPv4/IPv6 forwarding, filtering, nested control flow, maps, NAT and VRFs."""
    if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
        raise SystemExit('Run this lab inside unshare -n; never in the host network namespace.')
    directory.mkdir(parents=True, exist_ok=True)
    children = []
    try:
        run('ip', 'link', 'set', 'lo', 'up')
        run('sysctl', '-qw', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
        lan = endpoint('tr-in', '192.0.2', '2001:db8:1::', children)
        wan = endpoint('tr-out', '198.51.100', '2001:db8:2::', children)
        server = subprocess.Popen(enter(wan, sys.executable, '-u', '-c', SERVER), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        children.append(server)
        assert server.stdout.readline().strip() == 'ready'
        def client(address, protocol='tcp', port=9000):
            return enter(lan, sys.executable, '-c', CLIENT, address, protocol, str(port))

        exercise(directory, 'ipv4-tcp', rules(), client('198.51.100.2'), check=require_verdict('accept'))
        exercise(directory, 'ipv6-tcp', rules(), client('2001:db8:2::2'), check=require_verdict('accept'))
        exercise(directory, 'ipv4-udp', rules(), client('198.51.100.2', 'udp'))
        exercise(directory, 'ipv6-udp', rules(), client('2001:db8:2::2', 'udp'))
        exercise(directory, 'ipv4-icmp', rules(), enter(lan, 'ping', '-c', '1', '-W', '1', '198.51.100.2'))
        exercise(directory, 'ipv6-icmp', rules(), enter(lan, 'ping', '-c', '1', '-W', '1', '2001:db8:2::2'))
        exercise(directory, 'silent-drop', rules(forward='drop comment "20|deny"'), client('198.51.100.2'), success=False, check=require_verdict('drop'))
        exercise(directory, 'tcp-reject', rules(forward='reject with tcp reset comment "30|reset"'), client('198.51.100.2'), success=False, check=require_verdict('drop'))
        nested = '''chain ipv4_name_A { jump ipv4_name_B comment "10|nested"; return comment "20|caller"; }
 chain ipv4_name_B { return comment "10|leaf"; }'''
        exercise(directory, 'nested-return', rules(nested, 'jump ipv4_name_A comment "10|jump"\n accept comment "20|after return"'), client('198.51.100.2'))
        exercise(directory, 'goto', rules('chain ipv4_name_A { return comment "10|return"; }', 'goto ipv4_name_A comment "10|goto"'), client('198.51.100.2'))
        empty_chains = '''chain ipv4_name_EMPTY { }
 chain ipv4_name_MISS { ip daddr 198.51.100.99 drop comment "10|not matched"; }'''
        empty_caller = '''jump ipv4_name_EMPTY comment "10|empty chain"
 jump ipv4_name_MISS comment "20|unmatched chain"
 accept comment "30|after returns"'''
        exercise(directory, 'empty-and-unmatched', rules(empty_chains, empty_caller),
                 client('198.51.100.2'), check=require_verdict('accept'))
        zone = '''map ipv4_zone_forward { type ifname . ifname : verdict; counter; elements = { "tr-in" . "tr-out" comment "LAN to WAN" : jump ipv4_name_WEB, "tr-out" . "tr-in" comment "WAN to LAN" : accept }; }
 chain ipv4_name_WEB { accept comment "10|web policy"; }'''
        exercise(directory, 'zone-vmap', rules(zone, 'iifname . oifname vmap @ipv4_zone_forward comment "zone-dispatch|forward"\n drop comment "default|default-action drop"'), client('198.51.100.2'))
        objects = '''set ipv4_match_group_ALLOWED { type ipv4_addr . inet_service; elements = { 192.0.2.2 . 9000 }; }
 map ipv4_map_SERVICES { type inet_service : verdict; elements = { 9000 : accept }; }'''
        exercise(directory, 'match-group-map', rules(objects, 'ip saddr . tcp dport @ipv4_match_group_ALLOWED tcp dport vmap @ipv4_map_SERVICES comment "10|service lookup"\n accept comment "default|default-action accept"'), client('198.51.100.2'))
        dnat = 'chain ipv4_nat_prerouting { type nat hook prerouting priority dstnat; ip daddr 203.0.113.9 tcp dport 8000 dnat ip to 198.51.100.2:9000 comment "10|published service"; }'
        exercise(directory, 'dnat-address-port', rules(dnat), client('203.0.113.9', port=8000), check=require_change('destination-address'))
        portnat = 'chain ipv4_nat_prerouting { type nat hook prerouting priority dstnat; ip daddr 198.51.100.2 tcp dport 8001 dnat to :9000 comment "20|port translation"; }'
        exercise(directory, 'dnat-port-only', rules(portnat), client('198.51.100.2', port=8001), check=require_change('destination-port'))
        snat = '''chain ipv4_nat_postrouting { type nat hook postrouting priority srcnat; ip saddr 192.0.2.2 snat ip to 198.51.100.1 comment "30|source NAT"; }
 chain after_nat { type filter hook postrouting priority 110; counter; }'''
        exercise(directory, 'snat', rules(snat), client('198.51.100.2'), check=require_change('source-address'))
        exercise(directory, 'masquerade', rules(snat.replace('snat ip to 198.51.100.1', 'masquerade')), client('198.51.100.2'), check=require_change('source-address'))
        exercise(directory, 'notrack', rules().replace('meta nftrace set 1;', 'meta nftrace set 1 notrack;'), client('198.51.100.2', 'udp'))
        ingress = 'chain ingress { type filter hook ingress device "tr-in" priority -500; meta nftrace set 1; }'
        exercise(directory, 'ingress', rules(ingress), client('198.51.100.2'))
        exercise(directory, 'packet-mark', rules(forward='meta mark set 0x42 comment "10|mark"\n accept comment "20|marked"'), client('198.51.100.2', 'udp'))
        exercise(directory, 'ipv6-reject', rules(forward='reject with icmpx type admin-prohibited comment "10|reject"'), client('2001:db8:2::2', 'udp'), success=False, check=require_verdict('drop'))
        policy = rules().replace('priority filter; meta nfproto vmap', 'priority filter; policy drop; meta nfproto vmap')
        exercise(directory, 'base-policy-drop', policy.replace('accept comment "10|permit"', 'return comment "10|return to policy"'), client('198.51.100.2', 'udp'), success=False, check=require_verdict('drop'))
        state = rules().replace('meta nfproto vmap', 'ct state vmap { established : accept, related : accept }; meta nfproto vmap')
        exercise(directory, 'global-state-policy', state, client('198.51.100.2'))
        exercise(directory, 'failsafe', rules().replace('nvyr_filter', 'nvyr_filter_failsafe'), client('198.51.100.2', 'udp'))
        tracked = '''counter counter_group_TRAFFIC { }
 quota quota_group_BUDGET { until 10 mbytes; }
 limit ipv4_limit_group_FAST { rate 100/second; }'''
        exercise(directory, 'named-stateful-objects', rules(tracked, 'counter name counter_group_TRAFFIC quota name quota_group_BUDGET limit name ipv4_limit_group_FAST accept comment "10|accounted"'), client('198.51.100.2', 'udp'))

        # VRF output deliberately takes both the master and the member pass.
        run('ip', 'link', 'add', 'TRACEVRF', 'type', 'vrf', 'table', '101')
        run('ip', 'link', 'set', 'TRACEVRF', 'up')
        run('ip', 'link', 'set', 'tr-out', 'master', 'TRACEVRF')
        vrf_rules = rules().replace('accept comment "10|local";', 'meta oifkind "vrf" accept comment "vrf-bypass"; accept comment "10|member pass";')
        exercise(directory, 'vrf-output', vrf_rules, ['ip', 'vrf', 'exec', 'TRACEVRF', 'ping', '-c', '1', '-W', '1', '198.51.100.2'])
        print('All native trace scenarios passed.', flush=True)
    finally:
        for child in reversed(children):
            child.terminate()
            child.wait(timeout=3)
            if child.stdout:
                child.stdout.close()
            if child.stderr:
                child.stderr.close()


if __name__ == '__main__':
    main(Path(sys.argv[1]))
