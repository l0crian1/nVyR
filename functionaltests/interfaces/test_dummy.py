"""Dummy IPv4/IPv6 address readiness, admin state and VRF attach/move/detach.

All address families, bridges, cables and both shared VRFs are configured once.
Each test uses dedicated links/subnets so disabling, moving or changing VLANs
cannot disturb another case. The explicit VRF creation/deletion case alone owns
disposable routing domains. No other case recreates a VRF.
"""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from smoketests.assertions import assert_link, assert_link_addresses


def test_ipv4_addresses(config):
    """Multiple IPv4 prefixes coexist; deleting one retains the other."""
    # Installed once by configs/interfaces.conf.

    assert_link_addresses('dum43010', '198.18.2.1/24', '198.18.3.1/24')

    config.delete('delete interfaces dummy dum43010 address 198.18.2.1/24')
    config.commit()

    assert_link_addresses('dum43010', '198.18.3.1/24', absent=('198.18.2.1/24',))


def test_ipv6_addresses(config):
    """Multiple IPv6 prefixes coexist and individual deletion reaches the kernel."""
    # Installed once by configs/interfaces.conf.

    assert_link_addresses('dum43020', '2001:db8:4::1/64', '2001:db8:5::1/64')

    config.delete('delete interfaces dummy dum43020 address 2001:db8:4::1/64')
    config.commit()

    assert_link_addresses('dum43020', '2001:db8:5::1/64', absent=('2001:db8:4::1/64',))


def test_disable_and_reenable(config):
    """Disabling withdraws addresses; enabling reinstalls the retained configuration."""
    # Installed once by configs/interfaces.conf.

    assert_link('dum43030', up=False)
    assert_link_addresses('dum43030', absent=('198.18.6.1/24',))

    config.delete('delete interfaces dummy dum43030 disable')
    config.commit()

    assert_link('dum43030', up=True)
    assert_link_addresses('dum43030', '198.18.6.1/24')


def test_vrf_attach_move_and_detach(config):
    """Moving an interface preserves addresses while changing its routing domain."""
    # Installed once by configs/interfaces.conf.

    assert_link('dum43040', master='NVYRIFSMOKE')

    config.set('set interfaces dummy dum43040 vrf NVYRIFSMOKE2')
    config.commit()

    assert_link('dum43040', master='NVYRIFSMOKE2')
    assert_link_addresses('dum43040', '198.18.8.1/24')

    config.delete('delete interfaces dummy dum43040 vrf')
    config.commit()

    assert_link('dum43040', master='')
    assert_link_addresses('dum43040', '198.18.8.1/24')
