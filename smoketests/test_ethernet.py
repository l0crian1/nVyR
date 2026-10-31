"""Ethernet profiles, addresses, attributes, DHCP options, VRF moves and VIFs.

An explicit unused physical port and two test VRFs persist for the module.
Cases reset port settings without recreating those routing domains. Profile
and VIF deletion cases deliberately remove their own objects; deleting shared
VRFs or using the management port is incompatible with the remaining cases.
"""


import pytest

if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from nvyr.helpers.process import cmd
from smoketests.assertions import (
    assert_config_commit_rejected, assert_link, assert_configured_link_addresses, assert_raises,
    assert_vlan, assert_equal, assert_link_absent, assert_dhcp_client_configuration,
    assert_config_names_unused,
)
from smoketests.interface_support import interface_case, interface_suite, spare_ethernet


@pytest.fixture(scope='module')
def ethernet_suite(config, request):
    """Keep the spare port and both routing domains instantiated for this script."""
    port = spare_ethernet(request)
    with interface_suite(config, request, {'ethernet': [port]},
                         [f'set interfaces ethernet {port}'], ethernet=port,
                         vrfs=('NVYRIFSMOKE', 'NVYRIFSMOKE2')) as reset:
        yield port, reset


@pytest.fixture(autouse=True)
def ethernet_environment(request, ethernet_suite):
    """Reset settings between functions while retaining the managed port."""
    port, reset = ethernet_suite
    with interface_case(request, reset):
        yield port


def test_create_and_release_profile(config, ethernet_environment):
    """An Ethernet profile enables an existing device; removing it keeps the device."""
    port = ethernet_environment
    assert_link(port, mtu=1500, up=True)

    config.delete(f'delete interfaces ethernet {port}')
    config.commit()

    assert_link(port, up=False)


def test_ipv4_addresses(config, ethernet_environment):
    """Adding two IPv4 prefixes and removing one preserves the remaining address."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} address 198.18.110.1/24')
    config.set(f'set interfaces ethernet {port} address 198.18.111.1/24')
    config.commit()

    assert_configured_link_addresses(port, '198.18.110.1/24', '198.18.111.1/24')

    config.delete(f'delete interfaces ethernet {port} address 198.18.110.1/24')
    config.commit()

    assert_configured_link_addresses(port, '198.18.111.1/24', absent=('198.18.110.1/24',))


def test_ipv6_addresses(config, ethernet_environment):
    """IPv6 configuration reaches the physical port and supports individual deletion."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} address 2001:db8:110::1/64')
    config.set(f'set interfaces ethernet {port} address 2001:db8:111::1/64')
    config.commit()

    assert_configured_link_addresses(port, '2001:db8:110::1/64', '2001:db8:111::1/64')

    config.delete(f'delete interfaces ethernet {port} address 2001:db8:110::1/64')
    config.commit()

    assert_configured_link_addresses(port, '2001:db8:111::1/64', absent=('2001:db8:110::1/64',))


def test_mtu_and_default(config, ethernet_environment):
    """A portable supported MTU change is removed back to the direct 1500 default."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} mtu 1400')
    config.commit()

    assert_link(port, mtu=1400)

    config.delete(f'delete interfaces ethernet {port} mtu')
    config.commit()

    assert_link(port, mtu=1500)


def test_mac_and_baseline(config, ethernet_environment):
    """A unicast MAC override is reversible without replacing the physical device."""
    port = ethernet_environment
    original = assert_link(port)['address']

    config.set(f'set interfaces ethernet {port} mac 02:00:00:00:11:03')
    config.commit()

    assert_link(port, mac='02:00:00:00:11:03')

    config.delete(f'delete interfaces ethernet {port} mac')
    config.commit()

    assert_link(port, mac=original)


def test_description(config, ethernet_environment):
    """Description maps to the kernel alias and removing it restores the baseline."""
    port = ethernet_environment
    original = assert_link(port).get('ifalias', '')

    config.set(f'set interfaces ethernet {port} description "Ethernet smoketest"')
    config.commit()

    assert_link(port, description='Ethernet smoketest')

    config.delete(f'delete interfaces ethernet {port} description')
    config.commit()

    assert_link(port, description=original)


def test_disable_and_reenable(config, ethernet_environment):
    """Disabling and enabling the spare port changes its administrative state."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} disable')
    config.commit()

    assert_link(port, up=False)

    config.delete(f'delete interfaces ethernet {port} disable')
    config.commit()

    assert_link(port, up=True)


def test_link_group(config, ethernet_environment):
    """Linux link-group values can be configured and reset independently of VRFs."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} link-group 110')
    config.commit()

    assert_link(port, group=110)

    config.delete(f'delete interfaces ethernet {port} link-group')
    config.commit()

    assert_link(port, group=0)


def test_vrf_attach_move_and_detach(config, ethernet_environment):
    """A physical member can move between VRFs and return to the default domain."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address 198.18.110.1/24')
    config.commit()

    assert_link(port, master='NVYRIFSMOKE')

    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE2')
    config.commit()

    assert_link(port, master='NVYRIFSMOKE2')
    assert_configured_link_addresses(port, '198.18.110.1/24')

    config.delete(f'delete interfaces ethernet {port} vrf')
    config.commit()

    assert_link(port, master='')


def test_dhcp_client_id_text(config, ethernet_environment):
    """A text identifier reaches the active client with no server prerequisite."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp dhcp-options client-id text "smoketest client"')
    config.commit()
    assert_dhcp_client_configuration(port, **{'client-id': {'text': 'smoketest client'}})


def test_dhcp_client_id_hex(config, ethernet_environment):
    """A complete hexadecimal identifier is retained without a second type byte."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp dhcp-options client-id hex 00:73:6d:6f:6b:65')
    config.commit()
    assert_dhcp_client_configuration(port, **{'client-id': {'hex': '00:73:6d:6f:6b:65'}})


def test_dhcp_hostname_override_and_default(config, ethernet_environment):
    """Removing a hostname override restarts with the system hostname."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp dhcp-options host-name nvyr-smoke')
    config.commit()
    assert_dhcp_client_configuration(port, **{'host-name': 'nvyr-smoke'})
    config.delete(f'delete interfaces ethernet {port} dhcp-options host-name')
    config.commit()
    assert_dhcp_client_configuration(port, **{'host-name': cmd(['hostname']).strip()})


def test_dhcp_vendor_class(config, ethernet_environment):
    """An ISP vendor class is carried into the managed client's options."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp dhcp-options vendor-class-id "nVyR smoke"')
    config.commit()
    assert_dhcp_client_configuration(port, **{'vendor-class-id': 'nVyR smoke'})


def test_dhcp_user_class(config, ethernet_environment):
    """A user class reaches the client for RFC 3004 encoding."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vrf NVYRIFSMOKE address dhcp dhcp-options user-class customer')
    config.commit()
    assert_dhcp_client_configuration(port, **{'user-class': 'customer'})


def test_dhcp_client_id_encodings_conflict(config, ethernet_environment):
    """Both identifier encodings must fail verification before changing the client."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} address dhcp dhcp-options client-id text smoke')
    config.set(f'set interfaces ethernet {port} dhcp-options client-id hex 00:01')
    assert_config_commit_rejected(config, 'exactly one of text or hex')


def test_missing_vrf_rejected(config, ethernet_environment):
    """Membership in an unconfigured VRF fails verification before changing the port."""
    port = ethernet_environment
    assert_config_names_unused(config.get_config(), 'NVYRIFMISSING')
    config.set(f'set interfaces ethernet {port} vrf NVYRIFMISSING')

    assert_config_commit_rejected(config, 'not configured')
    assert_link(port, master='')


def test_invalid_address_rejected(config, ethernet_environment):
    """The address validator rejects malformed prefixes during command entry."""
    port = ethernet_environment
    with assert_raises(RouterError, match='Invalid value'):
        config.set(f'set interfaces ethernet {port} address 192.0.2.256/24')


def test_invalid_mac_rejected(config, ethernet_environment):
    """Multicast MAC addresses cannot be assigned to a physical interface."""
    port = ethernet_environment
    with assert_raises(RouterError, match='Invalid value'):
        config.set(f'set interfaces ethernet {port} mac 01:00:5e:00:00:01')


def test_invalid_link_group_rejected(config, ethernet_environment):
    """Linux link-group IDs cannot exceed their unsigned 32-bit representation."""
    port = ethernet_environment
    with assert_raises(RouterError, match='Invalid value'):
        config.set(f'set interfaces ethernet {port} link-group 4294967296')


def test_vif_ipv4_address(config, ethernet_environment):
    """A spare physical port hosts an addressed 802.1Q child."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vif 10 address 198.18.110.1/24')
    config.commit()
    assert_vlan(f'{port}.10', port, 10)
    assert_configured_link_addresses(f'{port}.10', '198.18.110.1/24')


def test_vif_ipv6_address(config, ethernet_environment):
    """An IPv6 address is installed on the child rather than its physical parent."""
    port = ethernet_environment
    config.set(f'set interfaces ethernet {port} vif 10 address 2001:db8:110::1/64')
    config.commit()
    assert_configured_link_addresses(f'{port}.10', '2001:db8:110::1/64')
    assert_configured_link_addresses(port, absent=('2001:db8:110::1/64',))


def test_vif_delete_retains_physical_port(config, ethernet_environment):
    """Creating and removing a child never replaces or disables its parent."""
    port = ethernet_environment
    original = assert_link(port)['ifindex']
    config.set(f'set interfaces ethernet {port} vif 10 description "Spare VLAN" link-group 10')
    config.commit()
    assert_vlan(f'{port}.10', port, 10, description='Spare VLAN', group=10)

    config.delete(f'delete interfaces ethernet {port} vif 10')
    config.commit()
    assert_link_absent(f'{port}.10')
    assert_equal(assert_link(port, up=True)['ifindex'], original)
