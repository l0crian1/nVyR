"""Native parsing and real discovery on one shared isolated two-port topology.

Run NVYR_LLDP_NATIVE=1 in a privileged disposable Linux container. Changes to
mode, TTL and advertisements deliberately mutate the daemon, never recreate links.
"""

from contextlib import ExitStack
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

import pytest

from functionaltests.lldp_lab import control, daemon
from smoketests.support import wait_for

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_LLDP_NATIVE') != '1',
                                reason='requires disposable native LLDP lab')


@pytest.fixture(scope='module')
def lab():
    root = Path(tempfile.mkdtemp(prefix='nvyr-lldp-'))
    root.chmod(0o755)
    names = ['lldp-' + uuid.uuid4().hex[:8] for _ in range(2)]
    created = []
    try:
        for name in names:
            subprocess.run(['ip', 'netns', 'add', name], check=True)
            created.append(name)
        subprocess.run(['ip', '-n', names[0], 'link', 'add', 'eth0', 'type', 'veth',
                        'peer', 'name', 'eth0', 'netns', names[1]], check=True)
        for name in names:
            subprocess.run(['ip', '-n', name, 'link', 'add', 'BLUE', 'type', 'vrf', 'table', '100'], check=True)
            subprocess.run(['ip', '-n', name, 'link', 'set', 'BLUE', 'up'], check=True)
            subprocess.run(['ip', '-n', name, 'link', 'set', 'eth0', 'master', 'BLUE'], check=True)
            subprocess.run(['ip', '-n', name, 'link', 'set', 'eth0', 'up'], check=True)
            subprocess.run(['ip', '-n', name, '-6', 'address', 'add', '2001:db8::1/64',
                            'dev', 'eth0', 'nodad'], check=True)
        with ExitStack() as stack:
            ports = []
            for index, name in enumerate(names):
                configuration = {
                    'system-name': f'peer-{index}', 'system-description': 'Core "A" \\ lab',
                    'chassis-id': f'chassis-{index}', 'interface': {'eth*': {}, 'eth0': {
                        'port-id': f'uplink-{index}', 'port-description': 'Uplink "A" \\ lab'}},
                    'exclude-interface': ['eth9'], 'management-address': ['192.0.2.1', '2001:db8::1'],
                    'transmit-interval': '1', 'hold-multiplier': '3', 'capability': ['router'],
                    'max-neighbors': '16', 'port-id': 'interface-name',
                    'port-description': 'Default', 'bond-member-source-mac': 'real',
                    'agent-type': 'nearest-bridge',
                }
                ports.append(stack.enter_context(daemon(root / str(index), name, configuration)))
            yield ports
    finally:
        for name in reversed(created):
            subprocess.run(['ip', 'netns', 'delete', name], check=True)
        shutil.rmtree(root)


def neighbors(directory):
    return control(directory, 'show', 'neighbors', 'details', raw=True)['lldp'][0].get('interface', [])


def test_real_neighbor_exchange_and_quoting(lab):
    for index, directory in enumerate(lab):
        peers = wait_for(lambda: neighbors(directory), bool, description='LLDP neighbor', timeout=10)
        peer = peers[0]
        assert peer['chassis'][0]['name'][0]['value'] == f'peer-{1-index}'
        assert peer['chassis'][0]['descr'][0]['value'] == 'Core "A" \\ lab'
        assert peer['port'][0]['id'][0]['value'] == f'uplink-{1-index}'
        assert peer['port'][0]['descr'][0]['value'] == 'Uplink "A" \\ lab'


def test_native_modes_vlan_and_lifetime(lab):
    directory = lab[0]
    fields = control(directory, 'show', 'configuration', raw=True)['configuration'][0]['config'][0]
    assert fields['max-neighbors'][0]['value'] == '16'
    assert fields['perm-iface-pattern'][0]['value'] == 'eth0'
    assert fields['iface-pattern'][0]['value'] == 'eth*,eth0,!eth9'
    for mode, expected in [('rx-only', 'RX only'), ('tx-only', 'TX only'), ('disabled', 'disabled'), ('rx-and-tx', 'RX and TX')]:
        control(directory, 'configure', 'ports', 'eth0', 'lldp', 'status', mode)
        port = control(directory, 'show', 'interfaces', 'details', raw=True)['lldp'][0]['interface'][0]
        assert port['status'][0]['value'].lower() == expected.lower()
    control(directory, 'configure', 'ports', 'eth0', 'lldp', 'vlan-tx', '123', 'prio', '5', 'dei', '1')
    port = control(directory, 'show', 'interfaces', 'details', raw=True)['lldp'][0]['interface'][0]
    assert port['port'][0]['vlanTX'][0] == {'id': '123', 'prio': '5', 'dei': '1'}
    control(directory, 'unconfigure', 'ports', 'eth0', 'lldp', 'vlan-tx')


def test_receive_only_stops_transmissions_and_peer_expires(lab):
    wait_for(lambda: neighbors(lab[1]), bool, description='neighbor before expiry', timeout=10)
    control(lab[0], 'configure', 'lldp', 'status', 'rx-only')
    try:
        wait_for(lambda: neighbors(lab[1]), lambda rows: not rows, description='LLDP neighbor expiry', timeout=12)
        counters = control(lab[0], 'show', 'statistics', raw=True)['lldp'][0]['interface'][0]
        sent = counters['tx'][0]['tx']
        time.sleep(1.2)
        assert control(lab[0], 'show', 'statistics', raw=True)['lldp'][0]['interface'][0]['tx'][0]['tx'] == sent
    finally:
        control(lab[0], 'configure', 'lldp', 'status', 'rx-and-tx')


def test_advertisement_flags_remove_optional_tlvs(lab):
    directory = lab[0]
    control(directory, 'unconfigure', 'lldp', 'capabilities-advertisements')
    control(directory, 'unconfigure', 'lldp', 'management-addresses-advertisements')
    try:
        def read():
            ports = neighbors(lab[1])
            return ports[0]['chassis'][0] if ports else None

        wait_for(read, lambda chassis: chassis is not None and 'capability' not in chassis and 'mgmt-ip' not in chassis,
                 description='optional LLDP TLVs withdrawn', timeout=10)
    finally:
        control(directory, 'configure', 'lldp', 'capabilities-advertisements')
        control(directory, 'configure', 'lldp', 'management-addresses-advertisements')
