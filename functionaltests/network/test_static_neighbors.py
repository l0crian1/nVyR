"""Permanent ARP/NDP forwarding on the shared routed-network LANs.

Uses the existing dual-stack hosts, VRFs and firewall allowance; no extra setup.
Deleting these entries or changing host MACs is incompatible with these checks.
"""

import json

import pytest

from nvyr.helpers.process import cmd
from functionaltests.routed_network import assert_traffic


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_permanent_neighbors_forward(family):
    assert_traffic(family, 52100)
    for interface, mac, address in (
        ('veth42063', '02:00:00:42:06:04', '198.18.61.2' if family == 'ipv4' else '2001:db8:61::2'),
        ('veth42065', '02:00:00:42:06:06', '198.18.62.2' if family == 'ipv4' else '2001:db8:62::2'),
    ):
        records = json.loads(cmd(['ip', '-j', 'neighbor', 'show', 'dev', interface]))
        entry = next(item for item in records if item['dst'] == address)
        assert entry['lladdr'] == mac and 'PERMANENT' in entry['state']
