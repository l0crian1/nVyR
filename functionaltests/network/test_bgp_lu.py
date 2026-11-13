"""LU negotiation, import policy, labels and bidirectional delivery.

Shares the routed suite's MPLS link, right namespace and native FRR processes.
Dedicated destinations have no static/IGP fallback. Tests replacing global BGP
or its policies must restore the common configuration before these observations.
"""

import json
import subprocess

import pytest

from nvyr.helpers.process import cmd
from smoketests.support import wait_for


@pytest.mark.parametrize('family,accepted,rejected,label', [
    ('ipv4', '198.19.72.2/32', '198.19.72.3/32', 0),
    ('ipv6', '2001:db8:72::2/128', '2001:db8:72::3/128', 2),
])
def test_lu_import_policy_and_label(family, accepted, rejected, label):
    base = f'show bgp {family} labeled-unicast'
    routes = wait_for(lambda: json.loads(cmd(['vtysh', '-c', base + ' json'])),
                      lambda data: accepted in data.get('routes', {}),
                      timeout=45, description=family + ' labeled BGP route')
    # Observing the rejected route in Adj-RIB-In proves the peer advertised it.
    received = wait_for(lambda: cmd(['vtysh', '-c', base + ' neighbors 198.18.71.2 received-routes']),
                        lambda text: rejected in text,
                        timeout=30, description=family + ' rejected LU advertisement')
    assert rejected in received
    assert rejected not in routes['routes']
    destination = accepted.split('/')[0]
    version = '-4' if family == 'ipv4' else '-6'
    kernel = wait_for(lambda: json.loads(cmd(['ip', version, '-j', 'route', 'show', destination])),
                      lambda values: any(route.get('encap', {}).get('encap_type') == 'mpls' for route in values),
                      timeout=30, description=family + ' BGP labeled kernel route')
    assert any(route.get('protocol') == 'bgp' and route.get('dev') == 'veth42071' for route in kernel)
    capture = subprocess.Popen(['tcpdump', '-l', '-nn', '-v', '-i', 'veth42071', '-c', '1', 'mpls'],
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert 'listening on' in capture.stderr.readline()
        cmd(['ping', version, '-n', '-c', '2', '-W', '2', destination])
        output, errors = capture.communicate(timeout=5)
        assert capture.returncode == 0, errors
        assert f'label {label}' in output, output
    finally:
        if capture.poll() is None:
            capture.terminate()
            capture.wait(timeout=5)


@pytest.mark.parametrize('version,destination', [('-4', '198.19.72.1'), ('-6', '2001:db8:72::1')])
def test_peer_receives_and_uses_our_label(version, destination):
    prefix = ['ip', 'netns', 'exec', 'nvyr-routed-right']
    wait_for(lambda: json.loads(cmd(prefix + ['ip', version, '-j', 'route', 'show', destination])),
             lambda routes: any(route.get('protocol') == 'bgp' and route.get('encap', {}).get('encap_type') == 'mpls'
                                for route in routes), timeout=45, description='remote LU forwarding route')
    cmd(prefix + ['ping', version, '-n', '-c', '2', '-W', '2', destination])


def test_lu_operational_views():
    for command in ('show bgp ipv4 labeled-unicast summary', 'show bgp ipv6 labeled-unicast summary',
                    'show bgp labelpool summary', 'show bgp labelpool inuse', 'show bgp labelpool ledger',
                    'show bgp labelpool requests', 'show bgp labelpool chunks'):
        output = cmd(['bgp.nvyr.op', 'show', command])
        assert '% Unknown command' not in output

    for family in ('ipv4', 'ipv6'):
        cmd(['bgp.nvyr.op', 'clear', f'clear bgp {family} labeled-unicast 198.18.71.2 soft out'])


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_group_receive_limit_capability_updates(config, routed_peer, family):
    """A live peer observes inherited limits, overrides and their withdrawal."""
    command = ['vtysh', '--vty_socket', str(routed_peer), '-c', 'show bgp neighbors 198.18.71.1 json']

    def received_limit():
        peer = json.loads(cmd(command))['198.18.71.1']
        limits = peer.get('neighborCapabilities', {}).get('pathsLimit', {})
        return limits.get(family + 'LabeledUnicast', {}).get('receivedPathsLimit')

    def expect(value):
        wait_for(received_limit, lambda received: received == value,
                 timeout=10, description=f'{family} remote receive limit {value}')

    expect(4)
    connections = json.loads(cmd(command))['198.18.71.1']['connectionsEstablished']
    group = f'protocols bgp peer-group RNLU address-family {family}-labeled-unicast addpath receive-limit'
    neighbor = f'protocols bgp neighbor 198.18.71.2 address-family {family}-labeled-unicast addpath receive-limit'
    config.set('set ' + group + ' 7')
    config.commit()
    expect(7)

    config.set('set ' + neighbor + ' 9')
    config.commit()
    expect(9)

    config.delete('delete ' + neighbor)
    config.commit()
    expect(7)

    config.delete('delete ' + group)
    config.commit()
    expect(0)
    peer = json.loads(cmd(command))['198.18.71.1']
    assert peer['bgpState'] == 'Established'
    assert peer['connectionsEstablished'] == connections
