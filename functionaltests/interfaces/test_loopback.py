"""Loopback address readiness, alias removal and preservation of system prefixes.

Each case owns separate addresses or the alias, all installed in the interface
baseline. Only its own values are removed, so cases work in any selection/order.
Deleting the complete loopback subtree would conflict with this shared scenario.
"""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from smoketests.assertions import assert_link, assert_link_addresses


def test_system_addresses():
    """The configured loopback retains both localhost addresses and stays up."""
    assert_link('lo', up=True)
    assert_link_addresses('lo', '127.0.0.1/8', '::1/128')


def test_ipv4_addresses(config):
    """IPv4 host addresses coexist and individual deletion preserves localhost."""
    # Installed once by configs/interfaces.conf.
    assert_link_addresses('lo', '127.0.0.1/8', '198.18.250.1/32', '198.18.250.2/32')

    config.delete('delete interfaces loopback lo address 198.18.250.1/32')
    config.commit()
    assert_link_addresses('lo', '127.0.0.1/8', '198.18.250.2/32', absent=('198.18.250.1/32',))


def test_ipv6_addresses(config):
    """IPv6 host addresses coexist and deleting one leaves ::1 untouched."""
    # Installed once by configs/interfaces.conf.
    assert_link_addresses('lo', '::1/128', '2001:db8:250::1/128', '2001:db8:250::2/128')

    config.delete('delete interfaces loopback lo address 2001:db8:250::1/128')
    config.commit()
    assert_link_addresses('lo', '::1/128', '2001:db8:250::2/128', absent=('2001:db8:250::1/128',))


def test_description(config):
    """The anchored alias can be set beside an address and removed independently."""
    # Installed once by configs/interfaces.conf.
    assert_link('lo', description='Router identity', up=True)

    config.delete('delete interfaces loopback lo description')
    config.commit()
    assert_link('lo', description='', up=True)
    assert_link_addresses('lo', '198.18.250.3/32', '127.0.0.1/8', '::1/128')


def test_system_addresses_survive_configured_removal(config):
    """Deleting explicitly configured system prefixes leaves their kernel addresses intact."""
    # Installed once by configs/interfaces.conf.
    config.delete('delete interfaces loopback lo address 127.0.0.1/8')
    config.delete('delete interfaces loopback lo address ::1/128')
    config.commit()
    assert_link_addresses('lo', '127.0.0.1/8', '::1/128')
