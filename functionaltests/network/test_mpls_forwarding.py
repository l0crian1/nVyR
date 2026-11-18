"""Static push/swap/pop, two-label forwarding, TTL and MPLS MTU boundaries.

Shares the routed scenario's two host namespaces and MPLS transport links.
Only TTL cases mutate configuration; the common fixture restores them.
Tests replacing these links or labels must restore the suite's base first.
"""

import json
import subprocess

import pytest

from nvyr.helpers.process import cmd, rc_cmd
from smoketests.support import wait_for


def capture_ping(arguments, interface='veth42071', *, namespace=None, packet_filter='mpls'):
    prefix = ['ip', 'netns', 'exec', namespace] if namespace else []
    capture = subprocess.Popen([*prefix, 'tcpdump', '-l', '-nn', '-v', '-i', interface, '-c', '1', packet_filter],
                               text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        assert 'listening on' in capture.stderr.readline()
        cmd(arguments)
        output, errors = capture.communicate(timeout=5)
        assert capture.returncode == 0, errors
        return output
    finally:
        if capture.poll() is None:
            capture.terminate()
            capture.wait(timeout=5)


@pytest.mark.parametrize('family,version,destination', [
    ('ipv4', '-4', '198.19.76.2'), ('ipv6', '-6', '2001:db8:76::2'),
])
def test_recursive_lu_forwarding(family, version, destination):
    wait_for(lambda: json.loads(cmd(['vtysh', '-c', 'show bgp neighbors 198.19.77.2 json'])),
             lambda data: data.get('198.19.77.2', {}).get('bgpState') == 'Established',
             timeout=45, description='loopback-addressed LU session')
    routes = wait_for(lambda: json.loads(cmd(['ip', version, '-j', 'route', 'show', destination])),
                      lambda values: any(route.get('protocol') == 'bgp' and route.get('encap') for route in values),
                      timeout=45, description=family + ' recursively resolved labeled route')
    assert any(route.get('dev') == 'veth42071' for route in routes)
    prefix = destination + ('/32' if family == 'ipv4' else '/128')
    data = json.loads(cmd(['vtysh', '-c', f'show bgp {family} labeled-unicast {prefix} json']))
    next_hop = '198.19.77.2' if family == 'ipv4' else '2001:db8:77::2'
    assert any(hop['ip'] == next_hop for path in data['paths'] for hop in path['nexthops'])
    output = capture_ping(['ping', version, '-n', '-c', '2', '-W', '2', destination])
    assert 'MPLS' in output


@pytest.mark.parametrize('version,destination,label', [
    ('-4', '198.19.73.2', 18000), ('-6', '2001:db8:74::2', 18002),
])
def test_static_push_and_uniform_ttl(version, destination, label):
    output = capture_ping(['ping', version, '-n', '-c', '2', '-W', '2', '-t', '40', destination])
    assert f'label {label}' in output
    assert 'ttl 40' in output


@pytest.mark.parametrize('version,destination', [('-4', '198.19.73.2'), ('-6', '2001:db8:74::2')])
def test_pipe_ttl(config, version, destination):
    config.set('set protocols mpls disable-ttl-propagation default-ttl 64')
    config.commit()
    output = capture_ping(['ping', version, '-n', '-c', '2', '-W', '2', '-t', '40', destination])
    assert 'ttl 64' in output


@pytest.mark.parametrize('destination,label', [('198.19.74.2', 18000), ('2001:db8:75::2', 18002)])
def test_static_swap(destination, label):
    output = capture_ping(['ip', 'netns', 'exec', 'nvyr-routed-left', 'ping', '-n', '-c', '2', '-W', '2', destination])
    assert f'label {label}' in output


@pytest.mark.parametrize('version,destination,outer,inner,size', [
    ('-4', '198.19.73.2', 17000, 18000, 1472),
    ('-6', '2001:db8:74::2', 17002, 18002, 1452),
])
def test_two_label_full_size_delivery(version, destination, outer, inner, size):
    arguments = ['ip', 'netns', 'exec', 'nvyr-routed-left', 'ping', version, '-n', '-M', 'do',
                 '-c', '2', '-W', '2', '-s', str(size), destination]
    output = capture_ping(arguments, 'veth42073')
    assert f'label {outer}' in output and f'label {inner}' in output


@pytest.mark.parametrize('version,destination,size', [('-4', '198.19.73.2', 1472), ('-6', '2001:db8:74::2', 1452)])
def test_transit_mtu_boundary(version, destination, size):
    assert json.loads(cmd(['ip', '-j', 'link', 'show', 'veth42071']))[0]['mtu'] == 1504
    arguments = ['ip', 'netns', 'exec', 'nvyr-routed-left', 'ping', version, '-n', '-M', 'do', '-c', '1', '-W', '1']
    # Transit removes the outer label: a 1500-byte IP packet plus one label fits.
    cmd([*arguments, '-s', str(size), destination])
    # The source's 1600-byte link permits this packet; the MPLS transit MTU does not.
    result = rc_cmd([*arguments, '-s', str(size + 1), destination])
    assert result[0] != 0
    cmd([*arguments, '-s', str(size), destination])
