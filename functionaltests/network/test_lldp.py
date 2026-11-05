"""Discovery and counters on the shared routed LANs, including VRF interfaces.

The package fixture owns two native peers for all compatible tests. Replacing
these LANs or changing their LLDP selectors is incompatible with discovery checks.
"""

import json

from nvyr.helpers import lldp
from nvyr.helpers.process import cmd
from smoketests.support import wait_for


def test_neighbors_on_both_routed_lans():
    def read():
        document = lldp.control('show', 'neighbors', 'details', raw=True)
        return {port['name']: port for port in document['lldp'][0].get('interface', [])}

    ports = wait_for(read, lambda ports: {'veth42063', 'veth42065'} <= ports.keys(),
                     description='LLDP discovery on both routed LANs', timeout=10)
    for interface, side in (('veth42063', 'left'), ('veth42065', 'right')):
        assert ports[interface]['chassis'][0]['name'][0]['value'] == 'routed-' + side
        assert ports[interface]['port'][0]['id'][0]['value'] == side + '-uplink'
    text = cmd(['lldp.nvyr.op', 'show', 'neighbors'])
    assert 'routed-left' in text and 'routed-right' in text


def test_operational_statistics():
    document = json.loads(cmd(['lldp.nvyr.op', 'show', 'statistics', '--raw']))
    ports = {port['name']: port for port in document['lldp'][0]['interface']}
    for name in ('veth42063', 'veth42065'):
        assert int(ports[name]['tx'][0]['tx']) > 0
