"""Boot firewall startup, handover, failed apply, nested replacement and deletion.

Each case needs a fresh boot lifecycle in a disposable network namespace; an
already-active fail-safe table would invalidate that precondition. Host configd,
interfaces and routing domains are never recreated or modified.
"""

import pytest


if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from smoketests.assertions import assert_failsafe_lifecycle


def test_ipv4_startup_and_handover():
    """Load before interfaces, filter packets, then hand over without later reactivation."""
    assert_failsafe_lifecycle('ipv4', 'handover')


def test_ipv6_startup_and_handover():
    """IPv6 boot protection yields to the main table in the same native transaction."""
    assert_failsafe_lifecycle('ipv6', 'handover')


def test_ipv4_failed_main_load():
    """A rejected main transaction leaves the active IPv4 protection unchanged."""
    assert_failsafe_lifecycle('ipv4', 'failure')


def test_ipv6_failed_main_load():
    """A rejected main transaction leaves the active IPv6 protection unchanged."""
    assert_failsafe_lifecycle('ipv6', 'failure')


def test_ipv4_replace_nested_jumps():
    """An active replacement rebuilds all IPv4 chains, including nested jump targets."""
    assert_failsafe_lifecycle('ipv4', 'replace')


def test_ipv6_replace_nested_jumps():
    """An active replacement rebuilds all IPv6 chains, including nested jump targets."""
    assert_failsafe_lifecycle('ipv6', 'replace')


def test_ipv4_delete_active_table():
    """Deleting active boot protection removes its IPv4 packet restrictions."""
    assert_failsafe_lifecycle('ipv4', 'delete')


def test_ipv6_delete_active_table():
    """Deleting active boot protection removes its IPv6 packet restrictions."""
    assert_failsafe_lifecycle('ipv6', 'delete')
