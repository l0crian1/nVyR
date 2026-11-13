"""LDP dual-stack bindings, labeled delivery and OSPF synchronization.

Uses the shared routed-network configuration and its right-side native peer.
Explicit-null labels make both IPv4 and IPv6 data-plane use observable on wire.
Incompatible: tests replacing global OSPF, LDP or the veth42071 transit must
restore the shared configuration before these observations.
"""

import json
from pathlib import Path
import subprocess

import pytest

from nvyr.helpers.process import cmd
from smoketests.support import wait_for


def test_ldp_neighbor_and_both_binding_families():
    wait_for(lambda: cmd(['vtysh', '-c', 'show mpls ldp neighbor']),
             lambda output: '198.18.71.2' in output and 'OPERATIONAL' in output.upper(),
             timeout=45, description='shared LDP session')
    for family, prefix in (('ipv4', '198.19.62.2/32'), ('ipv6', '2001:db8:64::2/128')):
        wait_for(lambda: cmd(['vtysh', '-c', f'show mpls ldp {family} binding {prefix} detail']),
                 lambda output: '198.18.71.2' in output,
                 timeout=30, description=f'{family} remote label binding')


@pytest.mark.parametrize('family,destination,label', [('ipv4', '198.19.62.2', 0), ('ipv6', '2001:db8:64::2', 2)])
def test_labeled_packet_delivery(family, destination, label):
    version = '-4' if family == 'ipv4' else '-6'
    routes = wait_for(lambda: json.loads(cmd(['ip', version, '-j', 'route', 'show', destination])),
                      lambda values: any(route.get('encap', {}).get('encap_type') == 'mpls' for route in values),
                      timeout=45, description=f'{family} labeled kernel route')
    assert any(route.get('dev') == 'veth42071' for route in routes)

    # Wait for tcpdump's readiness message, not an arbitrary sleep before probing.
    arguments = ['tcpdump', '-l', '-nn', '-v', '-i', 'veth42071', '-c', '1', 'mpls']
    capture = subprocess.Popen(arguments, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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


def test_ospf_ldp_synchronization_completes():
    wait_for(lambda: cmd(['vtysh', '-c', 'show ip ospf mpls ldp-sync interface veth42071']),
             lambda output: 'Sync achieved' in output,
             timeout=45, description='OSPF restores its metric after LDP synchronization')


def test_recreated_interface_regains_mpls_input():
    before = Path('/sys/class/net/dum42071/ifindex').read_text()
    cmd(['ip', 'link', 'delete', 'dum42071'])
    wait_for(lambda: json.loads(cmd(['ip', '-j', 'link', 'show'])),
             lambda links: any(link['ifname'] == 'dum42071' and str(link['ifindex']) != before.strip()
                               for link in links),
             description='netlinkd recreates the MPLS dummy interface')
    wait_for(lambda: Path('/proc/sys/net/mpls/conf/dum42071/input').read_text().strip(),
             lambda value: value == '1', description='MPLS input restored on the recreated interface')
