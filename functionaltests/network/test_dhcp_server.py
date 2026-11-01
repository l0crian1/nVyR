"""DHCPv4/v6 pool, listener, lease views and IPv4 server disable behavior.

Both listeners coexist on dum980 in the persistent NVYRDHCPSMOKE VRF. Only the
disable case changes service state; no case recreates the interface or VRF.
"""

import json
import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.helpers import kea
from nvyr.helpers.process import cmd
from nvyr.op_scripts import dhcp_server
from smoketests.assertions import assert_equal, assert_false, assert_in, assert_operational_output


def test_ipv4_operational_views(config):
    """The installed IPv4 views expose actual ranges and sockets with the Pool header."""
    # Installed once by configs/network-services.conf.

    assert_operational_output('show dhcp-server vrf NVYRDHCPSMOKE shared-network LAN pools',
                              'Pool', '198.18.210.0/24', absent=('2001:db8:210::',))

    result = json.loads(cmd(['dhcp_server.nvyr.op', 'show', '4', 'pools', '--vrf', 'NVYRDHCPSMOKE', '--raw']))
    assert_equal(result['records'][0]['pool'], 'LAN')
    assert_equal(result['records'][0]['total'], 11)
    assert_in('Pool', dhcp_server.show(4, 'pools', vrf='NVYRDHCPSMOKE'))
    listeners = json.loads(dhcp_server.show(4, 'listeners', vrf='NVYRDHCPSMOKE', raw=True))['records']
    assert_equal(listeners[0]['interface'], 'dum980')
    assert_equal(listeners[0]['state'], 'Listening')
    assert_equal(listeners[0]['address'], '198.18.210.1')
    assert_equal(listeners[0]['socket_type'], 'raw')
    result = json.loads(dhcp_server.show(4, 'leases', vrf='NVYRDHCPSMOKE', shared_network='LAN', raw=True))
    assert_equal(result['disabled_servers'], [])


def test_ipv6_operational_views(config):
    """IPv6 views use the applied subnet and its actual link-local listener."""
    # Installed once by configs/network-services.conf.

    assert_operational_output('show dhcpv6-server vrf NVYRDHCPSMOKE shared-network LAN pools',
                              'Pool', '2001:db8:210::/64', absent=('198.18.210.0',))

    result = json.loads(cmd(['dhcp_server.nvyr.op', 'show', '6', 'pools', '--vrf', 'NVYRDHCPSMOKE', '--raw']))
    assert_equal(result['records'][0]['pool'], 'LAN')
    assert_equal(result['records'][0]['total'], 17)
    assert_in('Pool', dhcp_server.show(6, 'pools', vrf='NVYRDHCPSMOKE'))
    listeners = json.loads(dhcp_server.show(6, 'listeners', vrf='NVYRDHCPSMOKE', raw=True))['records']
    assert_equal(listeners[0]['interface'], 'dum980')
    assert_equal(listeners[0]['state'], 'Listening')
    assert_in('fe80:', listeners[0]['address'])
    assert_equal(listeners[0]['socket_type'], 'udp')
    result = json.loads(dhcp_server.show(6, 'leases', vrf='NVYRDHCPSMOKE', shared_network='LAN', raw=True))
    assert_equal(result['disabled_servers'], [])


def test_ipv4_disable_stops_instance(config):
    """Disabling an instance closes its sockets without discarding configuration."""
    # Installed once by configs/network-services.conf.

    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server disable')
    config.commit()

    path = kea.RUNTIME / (kea.instance_name(4, 'NVYRDHCPSMOKE') + '.sock')
    assert_false(path.exists())
