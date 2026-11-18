"""VPNv4/VPNv6 labels, RT isolation, import/export maps and customer delivery.

Uses the shared routed topology and its existing MPLS peer. No extra daemon or
per-test topology is created. Mutations of global BGP must restore that fixture.
"""

import json

import pytest

from nvyr.helpers.process import cmd
from smoketests.support import wait_for


@pytest.mark.parametrize('family,version,local,remote,rejected', [
    ('ipv4', '-4', '198.19.80.1', '198.19.80.2', '198.19.80.3'),
    ('ipv6', '-6', '2001:db8:80::1', '2001:db8:80::2', '2001:db8:80::3'),
])
def test_vpn_import_policy_isolation_and_delivery(routed_peer, family, version, local, remote, rejected):
    def routes(vrf, destination):
        return json.loads(cmd(['ip', version, '-j', 'route', 'show', 'vrf', vrf, destination]))

    installed = wait_for(lambda: routes('RNVPNBLUE', remote),
                         lambda values: any(route.get('protocol') == 'bgp' for route in values),
                         timeout=45, description=family + ' imported VPN route')
    assert any(route.get('encap', {}).get('encap_type') == 'mpls' for route in installed), installed
    # The denied prefix exists in VPN RIB, proving the import map rejected it.
    vpn = cmd(['bgp.nvyr.op', 'show', f'show bgp {family} vpn rd 65072:80'])
    assert rejected in vpn
    assert routes('RNVPNBLUE', rejected) == []
    assert routes('RNVPNRED', remote) == []

    cmd(['ip', 'vrf', 'exec', 'RNVPNBLUE', 'ping', version, '-n', '-I', local, '-c', '2', '-W', '2', remote])
    cmd(['ip', 'netns', 'exec', 'nvyr-routed-right', 'ip', 'vrf', 'exec', 'VPNPEER',
         'ping', version, '-n', '-I', remote, '-c', '2', '-W', '2', local])
    # Our export map supplies the RT, without a static export RT configuration.
    received = cmd(['vtysh', '--vty_socket', str(routed_peer), '-c', f'show bgp {family} vpn rd 65071:80'])
    assert local in received


def test_vpn_operational_views():
    for family in ('ipv4', 'ipv6'):
        for suffix in ('summary', 'rd all', 'rd 65072:80', 'neighbors 198.19.77.2 routes'):
            output = cmd(['bgp.nvyr.op', 'show', f'show bgp {family} vpn {suffix}'])
            assert '% Unknown command' not in output
        cmd(['bgp.nvyr.op', 'clear', f'clear bgp {family} vpn 198.19.77.2 soft out'])
    for command in ('show bgp extcommunity-list RNVPNRT detail', 'show bgp mplsvpn-nh-label-bind detail'):
        assert '% Unknown command' not in cmd(['bgp.nvyr.op', 'show', command])


@pytest.mark.parametrize('family,version,local,remote,map_prefix', [
    ('ipv4', '-4', '198.19.80.1', '198.19.80.2', 'RNVPN4'),
    ('ipv6', '-6', '2001:db8:80::1', '2001:db8:80::2', 'RNVPN6'),
])
def test_vpn_policy_changes_withdraw_and_restore(config, routed_peer, family, version, local, remote, map_prefix):
    """Editing import/export policy must update live VPN routes without a reset."""
    local_route = ['ip', version, '-j', 'route', 'show', 'vrf', 'RNVPNBLUE', remote]
    peer_route = ['ip', '-n', 'nvyr-routed-right', version, '-j', 'route', 'show', 'vrf', 'VPNPEER', local]
    neighbor_command = ['vtysh', '-c', 'show bgp neighbors 198.19.77.2 json']

    for route, policy, rule in ((local_route, map_prefix + 'IN', 20), (peer_route, map_prefix + 'OUT', 10)):
        wait_for(lambda: json.loads(cmd(route)), bool, timeout=45, description='VPN route before policy edit')
        before = json.loads(cmd(neighbor_command))['198.19.77.2']
        config.set(f'set policy route-map {policy} rule {rule} action deny')
        config.commit()
        wait_for(lambda: json.loads(cmd(route)), lambda routes: not routes,
                 timeout=30, description=policy + ' withdraws customer route')
        if policy.endswith('IN'):
            # Import filtering removes the VRF route, not its received VPN NLRI.
            assert remote in cmd(['vtysh', '-c', f'show bgp {family} vpn rd 65072:80'])

        config.set(f'set policy route-map {policy} rule {rule} action permit')
        config.commit()
        wait_for(lambda: json.loads(cmd(route)),
                 lambda rows: any(row.get('protocol') == 'bgp' and row.get('encap') for row in rows),
                 timeout=30, description=policy + ' restores labeled customer route')
        after = json.loads(cmd(neighbor_command))['198.19.77.2']
        assert after['bgpState'] == 'Established'
        assert after['connectionsEstablished'] == before['connectionsEstablished']
        assert after['connectionsDropped'] == before['connectionsDropped']

    cmd(['ip', 'vrf', 'exec', 'RNVPNBLUE', 'ping', version, '-n', '-I', local, '-c', '2', '-W', '2', remote])
    cmd(['ip', 'netns', 'exec', 'nvyr-routed-right', 'ip', 'vrf', 'exec', 'VPNPEER',
         'ping', version, '-n', '-I', remote, '-c', '2', '-W', '2', local])
