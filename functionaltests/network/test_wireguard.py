"""IPv4/IPv6 tunnels over both endpoint families, using the shared routed setup.

The IPv6 transport tunnel carries its inner traffic in NVYRLEFT; the IPv4
transport tunnel uses the default VRF. The second tunnel also verifies PSKs.
Overlapping /8 and /24 peers (and IPv6 /48 and /64) share the second tunnel.
No setup per case; the default-prefix case edits only its broad peer's prefixes.
Incompatible with removing the shared peers or VRFs.
"""
import pytest
import json

from nvyr.helpers.process import cmd, rc_cmd
from nvyr.helpers import wireguard

OVERLAPPING_PEERS = (
    (4, '10.1.0.2', 'nvyr-routed-right', 'zo060cy2M+x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk='),
    (4, '10.0.0.2', 'nvyr-routed-left', 'Xf7dO2vUf2+ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI='),
    (6, 'fd42:100:0:2::2', 'nvyr-routed-right', 'zo060cy2M+x7cMF4FKXHbs0CloUFDTRHRboFhw5YfVk='),
    (6, 'fd42:100:0:1::2', 'nvyr-routed-left', 'Xf7dO2vUf2+ijuFdlp1bsOpTd01Ii9r53xxuASSz7yI='),
)


def overlapping_traffic(family, address, namespace, key):
    before = wireguard.state('wg42076')['peers'][key]
    args = ['ping', f'-{family}', '-n', '-c', '3', '-W', '2', '-i', '0.2']
    assert '0% packet loss' in cmd([*args, '-I', 'NVYRLEFT', address])
    host = '198.18.77.1' if family == 4 else '2001:db8:77::1'
    assert '0% packet loss' in cmd(['ip', 'netns', 'exec', namespace, *args, '-I', address, host])
    after = wireguard.state('wg42076')['peers'][key]
    assert after['sent'] > before['sent'] and after['received'] > before['received']


@pytest.mark.parametrize('family,address,namespace,key', OVERLAPPING_PEERS)
def test_overlapping_prefixes_select_peer_bidirectionally(family, address, namespace, key):
    overlapping_traffic(family, address, namespace, key)


@pytest.mark.parametrize('family,source,namespace', [
    (4, '10.0.0.99', 'nvyr-routed-right'), (4, '10.1.0.99', 'nvyr-routed-left'),
    (6, 'fd42:100:0:1::99', 'nvyr-routed-right'), (6, 'fd42:100:0:2::99', 'nvyr-routed-left'),
])
def test_overlapping_prefixes_reject_wrong_source_peer(family, source, namespace):
    def receive_errors():
        link = json.loads(cmd(['ip', '-s', '-j', 'link', 'show', 'dev', 'wg42076']))[0]
        return link['stats64']['rx']['errors']

    host = '198.18.77.1' if family == 4 else '2001:db8:77::1'
    before = receive_errors()
    status, output = rc_cmd(['ip', 'netns', 'exec', namespace, 'ping', f'-{family}', '-n',
                            '-c', '2', '-W', '1', '-i', '0.2', '-I', source, host])
    assert status == 1 and '100% packet loss' in output
    # A missing reply alone could be asymmetric routing: confirm WireGuard rejected ingress.
    assert receive_errors() >= before + 2


def test_default_prefix_with_more_specific_peer(config):
    config.delete('delete interfaces wireguard wg42076 peer routed allowed-ips 10.0.0.0/8')
    config.delete('delete interfaces wireguard wg42076 peer routed allowed-ips fd42:100::/48')
    config.set('set interfaces wireguard wg42076 peer routed allowed-ips 0.0.0.0/0 allowed-ips ::/0')
    config.commit()
    for values in OVERLAPPING_PEERS:
        overlapping_traffic(*values)


@pytest.mark.parametrize('suffix,subnet,vrf', [(75, 78, None), (76, 77, 'NVYRLEFT')])
@pytest.mark.parametrize('family', [4, 6])
def test_tunnel_traffic(suffix, subnet, vrf, family):
    target = f'198.18.{subnet}.2' if family == 4 else f'2001:db8:{subnet}::2'
    args = ['ping', f'-{family}', '-n', '-c', '3', '-W', '2', '-i', '0.2']
    if vrf:
        args += ['-I', vrf]
    assert '0% packet loss' in cmd([*args, target])
    reverse = f'198.18.{subnet}.1' if family == 4 else f'2001:db8:{subnet}::1'
    assert '0% packet loss' in cmd(['ip', 'netns', 'exec', 'nvyr-routed-right',
        'ping', f'-{family}', '-n', '-c', '3', '-W', '2', '-i', '0.2', reverse])
    peer = next(iter(wireguard.state(f'wg420{suffix}')['peers'].values()))
    assert peer['handshake'] > 0 and peer['sent'] > 0 and peer['received'] > 0


@pytest.mark.parametrize('family,source,target', [
    (4, '198.18.78.99', '198.18.78.1'), (6, '2001:db8:78::99', '2001:db8:78::1')])
def test_peer_source_prefix_enforced(family, source, target):
    command = ['ip', 'netns', 'exec', 'nvyr-routed-right', 'ping', f'-{family}', '-n', '-c', '1', '-W', '1']
    # The established peer works, but authenticated packets outside AllowedIPs do not.
    cmd([*command, target])
    status, output = rc_cmd([*command, '-I', source, target])
    assert status == 1 and '100% packet loss' in output
