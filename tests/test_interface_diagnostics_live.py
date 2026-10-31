"""Opt-in native tests in an isolated Linux network namespace/container."""

import json
import os

import pytest

from nvyr.helpers import ethtool
from nvyr.helpers.process import cmd
from nvyr.op_scripts import interfaces


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_INTERFACE_OP_TEST') != '1',
                                reason='Requires isolated Linux environment with NET_ADMIN')


@pytest.fixture(scope='module')
def pair():
    """Create disposable kernel devices, never use an existing management port."""
    from pyroute2 import IPRoute

    cmd(['ip', 'link', 'add', 'nvyrdiag0', 'type', 'veth', 'peer', 'name', 'nvyrdiag1'])
    try:
        cmd(['ip', 'link', 'add', 'link', 'nvyrdiag0', 'name', 'nvyrdiag0.100', 'type', 'vlan', 'id', '100'])
        with IPRoute() as iproute:
            index = iproute.link_lookup(ifname='nvyrdiag0')[0]
            iproute.link('set', index=index, group=4294967295)
        cmd(['ip', 'link', 'set', 'nvyrdiag0', 'up'])
        cmd(['ip', 'link', 'set', 'nvyrdiag1', 'up'])
        cmd(['ip', 'link', 'set', 'nvyrdiag0.100', 'up'])
        yield 'nvyrdiag0'
    finally:
        cmd(['ip', 'link', 'delete', 'nvyrdiag0'])


def test_native_peer_and_group(pair, capsys):
    interfaces.show(intf_name=pair, detail=True)
    output = capsys.readouterr().out
    assert 'Peer' in output and 'nvyrdiag1' in output
    assert '4294967295' in output


def test_native_vlan_parent(pair, capsys):
    interfaces.show(intf_name='nvyrdiag0.100', detail=True)
    output = capsys.readouterr().out
    assert 'Parent' in output and 'nvyrdiag0' in output
    assert 'VLAN ID' in output and '100' in output and '802.1Q' in output


def test_native_link_settings(pair):
    record = ethtool.json_data(pair, 'link')
    assert record['ifname'] == pair
    assert record['duplex'] == 'Full'
    assert ethtool.driver_info(pair)['Driver'] == 'veth'


def test_native_offloads(pair, capsys):
    interfaces.hardware('offload', intf_name=pair)
    output = capsys.readouterr().out
    assert 'Feature' in output and 'rx-checksumming' in output
    records = json.loads(interfaces.hardware('offload', intf_name=pair, raw=True))
    assert isinstance(records[pair]['rx-checksumming']['active'], bool)


def test_native_channels_and_unsupported_rings(pair, capsys):
    interfaces.hardware('queues', intf_name=pair)
    output = capsys.readouterr().out
    assert 'Channels' in output and 'Maximum' in output
    assert 'Ring information is not supported.' in output


def test_native_driver_statistics(pair):
    records = dict(ethtool.hardware_statistics(pair))
    link = json.loads(cmd(['ip', '-j', 'link', 'show', 'nvyrdiag1']))[0]
    assert records['peer_ifindex'] == link['ifindex']


def test_native_unsupported_optics(pair, capsys):
    interfaces.hardware('transceiver', intf_name=pair)
    assert 'Not supported or no data available.' in capsys.readouterr().out
