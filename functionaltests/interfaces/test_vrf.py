"""VRF-scoped probes, connected IPv6 routes and explicit VRF creation/deletion.

All address families, bridges, cables and both shared VRFs are configured once.
Each test uses dedicated links/subnets so disabling, moving or changing VLANs
cannot disturb another case. The explicit VRF creation/deletion case alone owns
disposable routing domains. No other case recreates a VRF.
"""

from contextlib import closing

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from smoketests.assertions import (
    assert_operational_output, assert_link_addresses, assert_link, assert_kernel_route, assert_link_absent,
    assert_equal, assert_in, assert_true,
)
from nvyr.protocol import Client


def assert_cli_probe(command, address):
    """Exercise configd's actual service restrictions as well as the probe wrapper."""
    with closing(Client('/run/nvyr/configd.sock')) as client:
        result = client.request('execute', text=command)

    output = result['text']
    assert_equal(result['returncode'], 0, output)
    assert_in(address, output)
    if command.startswith('traceroute '):
        assert_true(any(line.lstrip().startswith('1 ') and address in line
                        for line in output.splitlines()), msg=output)


def test_ipv4_ping_and_traceroute(config):
    """Both installed probe commands reach an IPv4 address inside the selected VRF."""
    # Installed once by configs/interfaces.conf.

    assert_cli_probe('ping 198.18.58.1 vrf NVYRIFSMOKE count 1 deadline 3 numeric', '198.18.58.1')
    assert_cli_probe('traceroute 198.18.58.1 vrf NVYRIFSMOKE no-resolve icmp probes 1 max-ttl 1 wait 1', '198.18.58.1')


def test_ipv6_ping_and_traceroute(config):
    """IPv6 probing uses the requested VRF rather than the default routing table."""
    # Installed once by configs/interfaces.conf.

    assert_link_addresses('dum43300', '2001:db8:3c::1/64')
    assert_cli_probe('ping 2001:db8:3c::1 ipv6 vrf NVYRIFSMOKE count 1 deadline 3 numeric', '2001:db8:3c::1')
    assert_cli_probe('traceroute 2001:db8:3c::1 ipv6 vrf NVYRIFSMOKE no-resolve icmp probes 1 max-ttl 1 wait 1', '2001:db8:3c::1')


def test_create_multiple_and_delete(config):
    """Each configured name creates an independent up VRF with its requested table."""
    config.set('set vrf name IFDELETE1 table 41990')
    config.set('set vrf name IFDELETE2 table 41991')
    config.commit()

    assert_link('IFDELETE1', kind='vrf', up=True, table=41990)
    assert_link('IFDELETE2', kind='vrf', up=True, table=41991)

    assert_operational_output('show vrf IFDELETE1', 'IFDELETE1', absent=('IFDELETE2',))
    assert_operational_output('show vrf IFDELETE2', 'IFDELETE2')

    config.delete('delete vrf name IFDELETE1')
    config.commit()

    assert_link_absent('IFDELETE1')
    assert_link('IFDELETE2', table=41991)


def test_ipv6_connected_route(config):
    """A member's connected IPv6 route belongs to the selected VRF table."""
    # Installed once by configs/interfaces.conf.

    assert_link_addresses('dum43320', '2001:db8:40::1/64')
    assert_kernel_route('2001:db8:40::/64', 'dev dum43320', vrf='NVYRIFSMOKE')
