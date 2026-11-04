"""Exercise an ISP granting two prefixes and an address, LAN SLAAC, release and renew.

The shared interface topology owns the veth pairs. A tagged ISP and a LAN
station live in private namespaces. Other DHCPv6 servers on this link would
make the offers nondeterministic.
"""

from contextlib import ExitStack
import ipaddress
import json
import os
import subprocess

from nvyr.helpers.interfaces import manager
from nvyr.helpers.process import cmd
from smoketests.support import wait_for


def test_delegations(tmp_path):
    wan = 'veth43440.20'
    isp, lan = (f'nvyr-pd-{role}-{os.getpid()}' for role in ('isp', 'lan'))

    def status():
        return manager.request('dhcp6-status')[wan]

    with ExitStack() as cleanup:
        for namespace in (isp, lan):
            cmd(['ip', 'netns', 'add', namespace])
            cleanup.callback(cmd, ['ip', 'netns', 'del', namespace])
            cmd(['ip', '-n', namespace, 'link', 'set', 'lo', 'up'])
        cmd(['ip', 'link', 'add', 'link', 'veth43441', 'name', 'isp0', 'netns', isp, 'type', 'vlan', 'id', '20'])
        cmd(['ip', 'link', 'add', 'link', 'veth43443', 'name', 'lan0', 'netns', lan, 'type', 'macvlan', 'mode', 'bridge'])
        cmd(['ip', 'netns', 'exec', lan, 'sysctl', '-qw', 'net.ipv6.conf.lan0.accept_ra=2',
             'net.ipv6.conf.lan0.autoconf=1'])
        for namespace, port in ((isp, 'isp0'), (lan, 'lan0')):
            cmd(['ip', '-n', namespace, 'link', 'set', port, 'up'])
        cmd(['ip', '-n', isp, '-6', 'addr', 'add', '2001:db8:442::1/64', 'dev', 'isp0', 'nodad'])
        wait_for(lambda: cmd(['ip', '-n', isp, '-6', 'addr', 'show', 'dev', 'isp0', 'scope', 'link']),
                 lambda text: 'fe80:' in text and 'tentative' not in text, description='ISP link-local address')
        native = {'interfaces-config': {'interfaces': ['isp0']}, 'lease-database': {'type': 'memfile', 'persist': False},
                  'subnet6': [{'id': 1, 'subnet': '2001:db8:442::/64', 'interface': 'isp0',
                               'pools': [{'pool': '2001:db8:442::10-2001:db8:442::20'}],
                               'pd-pools': [{'prefix': '2001:db8:443::', 'prefix-len': 48, 'delegated-len': 56}]}],
                  'option-data': [{'name': 'domain-search', 'data': 'pd.example'},
                                  {'name': 'dns-servers', 'data': '2001:db8:442::1'}]}
        config_file = tmp_path / 'isp.json'
        config_file.write_text(json.dumps({'Dhcp6': native}))
        env = os.environ | {key: str(tmp_path) for key in ('KEA_PIDFILE_DIR', 'KEA_DHCP_DATA_DIR', 'KEA_CONTROL_SOCKET_DIR')}
        server = subprocess.Popen(['ip', 'netns', 'exec', isp, 'kea-dhcp6', '-c', str(config_file)], env=env)
        cleanup.callback(server.wait, timeout=10)
        cleanup.callback(server.terminate)

        # Restart discovery now that the ISP exists rather than waiting out a previous Solicit backoff.
        manager.request('dhcp6-release', interface=wan)
        manager.request('dhcp6-renew', interface=wan)
        lease = wait_for(status, lambda s: len(s.get('entries', ())) == 3 and s.get('lans'),
                         description='two distinct PD associations and one address', timeout=40)
        prefixes = {e['id']: ipaddress.IPv6Network(e['prefix']) for e in lease['entries'] if e['type'] == 'IA_PD'}
        assert prefixes.keys() == {'0', '1'} and not prefixes['0'].overlaps(prefixes['1'])
        assert lease['search'] == ['pd.example'] and lease['dns'] == ['2001:db8:442::1']
        dns = wait_for(lambda: manager.request('dns-status'),
                       lambda s: any(r['interface'] == wan for r in s.get('search', ())),
                       description='publication of learned search domain')
        assert {'domain': 'pd.example', 'interface': wan, 'source': 'DHCPv6'} in dns['search']
        assert {'server': '2001:db8:442::1', 'interface': wan, 'source': 'DHCPv6'} in dns['servers']
        address = ipaddress.IPv6Address(int(prefixes['1'].network_address) + (1 << 64) + 254)
        assert lease['lans'][0]['address'] == f'{address}/64'
        wait_for(lambda: cmd(['ip', '-n', lan, '-6', 'route', 'show', 'default']), lambda s: 'proto ra' in s,
                 description='downstream default router', timeout=30)
        network = ipaddress.IPv6Interface(f'{address}/64').network
        wait_for(lambda: json.loads(cmd(['ip', '-n', lan, '-j', '-6', 'addr', 'show', 'dev', 'lan0'])),
                 lambda links: any(ipaddress.IPv6Address(a['local']) in network and not a.get('tentative')
                                   for a in links[0]['addr_info']),
                 description='downstream SLAAC address', timeout=30)

        manager.request('dhcp6-release', interface=wan)
        wait_for(lambda: cmd(['ip', '-6', 'addr', 'show', 'dev', 'veth43442']),
                 lambda s: str(address) + '/' not in s, description='withdrawal of delegated router address')
        assert status()['released']
        manager.request('dhcp6-renew', interface=wan)
        renewed = wait_for(status, lambda s: len(s.get('entries', ())) == 3,
                           description='reacquisition after release', timeout=40)
        assert renewed['duid'] == lease['duid']
