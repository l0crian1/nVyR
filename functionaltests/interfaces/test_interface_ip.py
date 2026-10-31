"""Interface address readiness and runtime behavior on the live router."""

import pytest


if __name__ == "__main__":
    import sys

    raise SystemExit(pytest.main([__file__, "-v", "-s", *sys.argv[1:]]))

from smoketests.assertions import assert_link_addresses


def test_ipv6_eui64_and_explicit_link_local(config):
    """Derived global and explicit link-local addresses reach the kernel."""
    # Installed once by configs/interfaces.conf.
    assert_link_addresses('dum986', '2001:db8:986::ff:fe12:3456/64', 'fe80::1234/64')
