"""Ethernet address readiness, VRF moves, VIFs and DHCP client/lease behavior.

The explicit spare port and two VRFs persist for the module. Each case resets
port settings because static-address, DHCP and membership changes conflict.
Lease tests require a test server; IPv6 readiness requires physical carrier.
Deleting the shared VRFs or using the management port is incompatible.
"""

import json
import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from nvyr.helpers.process import cmd
from nvyr.op_scripts import dhcp as dhcp_op
from smoketests.assertions import (
    assert_dhcp_client, assert_dhcp_lease, assert_link, assert_link_addresses, assert_equal,
    assert_dhcp_client_options, assert_dhcp_default_route, assert_in, assert_true, assert_vlan,
)

from smoketests.support import wait_for

from smoketests.interface_support import interface_case, interface_suite, spare_ethernet


@pytest.fixture(scope='module')
def ethernet_suite(config, request, interface_topology):
    """Use the explicitly selected physical port and the package's existing VRFs."""
    port = spare_ethernet(request)
    with interface_suite(config, request, {'ethernet': [port]},
                         [f'set interfaces ethernet {port}'], ethernet=port,
                         vrfs=('NVYRIFSMOKE', 'NVYRIFSMOKE2'), shared_vrfs=True) as reset:
        yield port, reset


@pytest.fixture(autouse=True)
def ethernet_environment(request, ethernet_suite):
    """Reset incompatible physical-port options without deleting shared VRFs."""
    port, reset = ethernet_suite
    with interface_case(request, reset):
        yield port


def require_carrier(port):
    """IPv6 address readiness needs a physical link; absence is a test prerequisite."""
    def linked():
        link = json.loads(cmd(['ip', '-j', 'link', 'show', 'dev', port]))[0]
        return 'LOWER_UP' in link['flags']

    try:
        wait_for(linked, bool, description=f'{port} physical carrier', timeout=2)
    except AssertionError:
        pytest.skip(f'{port} has no carrier; connect a cable or loopback adapter for IPv6 readiness tests')


def test_dhcp_client_start_and_stop(config, ethernet_environment):
    """DHCP enables the real client; isolation keeps offered routes out of main."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp')
    config.commit()

    assert_dhcp_client(port, active=True)

    config.delete(f'delete interfaces ethernet {port} address dhcp')
    config.commit()

    assert_dhcp_client(port, active=False)


def test_dhcp_lease_and_renewal(config, ethernet_environment, request):
    """Opt-in server-backed case verifies lease installation and explicit renewal."""
    if not request.config.getoption('--ethernet-dhcp'):
        pytest.skip('Use --ethernet-dhcp with a DHCP server on the spare-port network')
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp')
    config.commit()

    lease = assert_dhcp_lease(port)
    dhcp_op.renew(port)
    assert_dhcp_lease(port, after=lease['expires'])


def test_dhcp_client_operational_detail(config, ethernet_environment, request):
    """Show the real negotiated lease without confusing received data with installed policy."""
    if not request.config.getoption('--ethernet-dhcp'):
        pytest.skip('Use --ethernet-dhcp with a DHCP server on the spare-port network')

    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp')
    config.commit()
    lease = assert_dhcp_lease(port)

    record, = json.loads(cmd(['dhcp.nvyr.op', 'show', '--interface', port, '--raw']))
    assert_equal(record['state'], 'Bound')
    assert_equal(record['address'], lease['address'])
    assert_equal(record['vrf'], 'NVYRIFSMOKE')
    assert_true(record['address_installed'])
    assert_true(record['expires_in'] > 0)
    assert_in('Received name servers', dhcp_op.show(interface=port, detail=True))


def test_dhcp_release_and_reacquire(config, ethernet_environment, request):
    """Operational release removes the leased address; renew reacquires without a commit."""
    if not request.config.getoption('--ethernet-dhcp'):
        pytest.skip('Use --ethernet-dhcp with a DHCP server on the spare-port network')
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp')
    config.commit()
    lease = assert_dhcp_lease(port)

    dhcp_op.release(port)
    assert_link_addresses(port, absent=(lease['address'],))
    assert_dhcp_client(port, active=True)

    dhcp_op.renew(port)
    assert_dhcp_lease(port)


def test_dhcp_default_route_distance(config, ethernet_environment, request):
    """A real lease defaults to AD 210 and changes to AD 10 without a new client."""
    if not request.config.getoption('--ethernet-dhcp'):
        pytest.skip('Use --ethernet-dhcp with a DHCP server advertising a default route')
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp')
    config.commit()
    assert_dhcp_lease(port)
    original = assert_dhcp_client_options(port)
    assert_dhcp_default_route(port, distance=210)

    config.set(f'set interfaces ethernet {port} dhcp-options default-route-distance 10')
    config.commit()
    assert_dhcp_default_route(port, distance=10)
    assert_equal(assert_dhcp_client_options(port)['token'], original['token'])

    config.delete(f'delete interfaces ethernet {port} dhcp-options default-route-distance')
    config.commit()
    assert_dhcp_default_route(port, distance=210)


def test_dhcp_no_default_route(config, ethernet_environment, request):
    """Suppressing the default keeps the lease and restores the route on removal."""
    if not request.config.getoption('--ethernet-dhcp'):
        pytest.skip('Use --ethernet-dhcp with a DHCP server advertising a default route')
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp')
    config.commit()
    lease = assert_dhcp_lease(port)
    assert_dhcp_default_route(port, distance=210)
    config.set(f'set interfaces ethernet {port} dhcp-options no-default-route')
    config.commit()
    assert_dhcp_default_route(port, absent=True)
    assert_link_addresses(port, lease['address'])
    config.delete(f'delete interfaces ethernet {port} dhcp-options no-default-route')
    config.commit()
    assert_dhcp_default_route(port, distance=210)


def test_dhcp_mtu_override_and_restore(config, ethernet_environment, request):
    """Use an offered MTU if present, then restore the explicit interface setting."""
    if not request.config.getoption('--ethernet-dhcp'):
        pytest.skip('Use --ethernet-dhcp with a DHCP server on the spare-port network')
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp mtu 1500 dhcp-options mtu')
    config.commit()
    lease = assert_dhcp_lease(port)
    assert_link(port, mtu=lease.get('mtu', 1500))
    config.delete(f'delete interfaces ethernet {port} dhcp-options mtu')
    config.commit()
    assert_link(port, mtu=1500)


def test_vif_dhcp_client_start_stop(config, ethernet_environment):
    """DHCP is attached to the VLAN identity and stopped when the child is removed."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vif 10 address dhcp')
    config.commit()
    assert_dhcp_client(f'{port}.10', active=True)

    config.delete(f'delete interfaces ethernet {port} vif 10')
    config.commit()
    assert_dhcp_client(f'{port}.10', active=False)


def test_dhcp_client_id_text(config, ethernet_environment):
    """A text identifier reaches the active client with no server prerequisite."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp dhcp-options client-id text "smoketest client"')
    config.commit()
    assert_dhcp_client_options(port, **{'client-id': {'text': 'smoketest client'}})


def test_dhcp_client_id_hex(config, ethernet_environment):
    """A complete hexadecimal identifier is retained without a second type byte."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp dhcp-options client-id hex 00:73:6d:6f:6b:65')
    config.commit()
    assert_dhcp_client_options(port, **{'client-id': {'hex': '00:73:6d:6f:6b:65'}})


def test_dhcp_hostname_override_and_default(config, ethernet_environment):
    """Removing a hostname override restarts with the system hostname."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp dhcp-options host-name nvyr-smoke')
    config.commit()
    assert_dhcp_client_options(port, **{'host-name': 'nvyr-smoke'})
    config.delete(f'delete interfaces ethernet {port} dhcp-options host-name')
    config.commit()
    assert_dhcp_client_options(port, **{'host-name': cmd(['hostname']).strip()})


def test_dhcp_vendor_class(config, ethernet_environment):
    """An ISP vendor class is carried into the managed client's options."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp dhcp-options vendor-class-id "nVyR smoke"')
    config.commit()
    assert_dhcp_client_options(port, **{'vendor-class-id': 'nVyR smoke'})


def test_dhcp_user_class(config, ethernet_environment):
    """A user class reaches the client for RFC 3004 encoding."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp dhcp-options user-class customer')
    config.commit()
    assert_dhcp_client_options(port, **{'user-class': 'customer'})


def test_ipv4_addresses(config, ethernet_environment):
    """Adding two IPv4 prefixes and removing one preserves the remaining address."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} address 198.18.110.1/24')
    config.set(f'set interfaces ethernet {port} address 198.18.111.1/24')
    config.commit()

    assert_link_addresses(port, '198.18.110.1/24', '198.18.111.1/24')

    config.delete(f'delete interfaces ethernet {port} address 198.18.110.1/24')
    config.commit()

    assert_link_addresses(port, '198.18.111.1/24', absent=('198.18.110.1/24',))


def test_ipv6_addresses(config, ethernet_environment):
    """IPv6 configuration reaches the physical port and supports individual deletion."""
    port = ethernet_environment
    require_carrier(port)
    config.set(f'set interfaces ethernet {port} address 2001:db8:110::1/64')
    config.set(f'set interfaces ethernet {port} address 2001:db8:111::1/64')
    config.commit()

    assert_link_addresses(port, '2001:db8:110::1/64', '2001:db8:111::1/64')

    config.delete(f'delete interfaces ethernet {port} address 2001:db8:110::1/64')
    config.commit()

    assert_link_addresses(port, '2001:db8:111::1/64', absent=('2001:db8:110::1/64',))


def test_vrf_attach_move_and_detach(config, ethernet_environment):
    """A physical member can move between VRFs and return to the default domain."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address 198.18.110.1/24')
    config.commit()

    assert_link(port, master='NVYRIFSMOKE')

    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE2')
    config.commit()

    assert_link(port, master='NVYRIFSMOKE2')
    assert_link_addresses(port, '198.18.110.1/24')

    config.delete(f'delete interfaces ethernet {port} vrf')
    config.commit()

    assert_link(port, master='')


def test_vif_ipv4_address(config, ethernet_environment):
    """A spare physical port hosts an addressed 802.1Q child."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vif 10 address 198.18.110.1/24')
    config.commit()
    assert_vlan(f'{port}.10', port, 10)
    assert_link_addresses(f'{port}.10', '198.18.110.1/24')


def test_vif_ipv6_address(config, ethernet_environment):
    """An IPv6 address is installed on the child rather than its physical parent."""
    port = ethernet_environment
    require_carrier(port)
    config.set(f'set interfaces ethernet {port} vif 10 address 2001:db8:110::1/64')
    config.commit()
    assert_link_addresses(f'{port}.10', '2001:db8:110::1/64')
    assert_link_addresses(port, absent=('2001:db8:110::1/64',))
