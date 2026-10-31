"""No-carrier labs skip physical IPv6 readiness without hiding configuration errors."""

import json

import pytest

from acceptance import checks
from smoketests import support


@pytest.fixture
def carrier_clock(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(support.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(support.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    return clock


def test_no_carrier_skips_before_waiting_for_ipv6_addresses(monkeypatch, carrier_clock):
    monkeypatch.setattr(checks, 'cmd', lambda argv: json.dumps([{'flags': ['UP', 'NO-CARRIER']}]))
    monkeypatch.setattr(checks, 'assert_link_addresses',
                        lambda *args: pytest.fail('IPv6 address wait ran without carrier'))

    with pytest.raises(checks.CheckSkipped, match='eth1 has no carrier'):
        checks.check_ethernet_ipv6({'ethernet': 'eth1'})

    assert carrier_clock[0] == pytest.approx(2)


def test_carrier_arrival_runs_parent_and_vlan_ipv6_checks(monkeypatch, carrier_clock):
    replies = iter([['UP'], ['UP', 'LOWER_UP']])
    addresses = []
    monkeypatch.setattr(checks, 'cmd', lambda argv: json.dumps([{'flags': next(replies)}]))
    monkeypatch.setattr(checks, 'assert_link_addresses', lambda *args: addresses.append(args))

    checks.check_ethernet_ipv6({'ethernet': 'eth1'})

    assert addresses == [('eth1', '2001:db8:205::1/64'), ('eth1.195', '2001:db8:206::1/64')]
    assert carrier_clock[0] > 0


def test_carrier_is_rechecked_between_boot_phases(monkeypatch, carrier_clock):
    flags = ['UP']
    addresses = []
    monkeypatch.setattr(checks, 'cmd', lambda argv: json.dumps([{'flags': flags}]))
    monkeypatch.setattr(checks, 'assert_link_addresses', lambda *args: addresses.append(args))

    with pytest.raises(checks.CheckSkipped):
        checks.check_ethernet_ipv6({'ethernet': 'eth1'})
    flags.append('LOWER_UP')
    checks.check_ethernet_ipv6({'ethernet': 'eth1'})
    assert len(addresses) == 2


def test_enabled_link_with_missing_ipv6_still_fails(monkeypatch):
    monkeypatch.setattr(checks, 'cmd', lambda argv: json.dumps([{'flags': ['UP', 'LOWER_UP']}]))

    def missing(*args):
        raise AssertionError('IPv6 address missing')

    monkeypatch.setattr(checks, 'assert_link_addresses', missing)
    with pytest.raises(AssertionError, match='IPv6 address missing'):
        checks.check_ethernet_ipv6({'ethernet': 'eth1'})


def test_administratively_down_link_is_a_failure(monkeypatch):
    monkeypatch.setattr(checks, 'cmd', lambda argv: json.dumps([{'flags': []}]))
    with pytest.raises(RuntimeError, match='administratively down'):
        checks.check_ethernet_ipv6({'ethernet': 'eth1'})


def test_failed_link_query_is_not_a_skip(monkeypatch):
    def missing(argv):
        raise RuntimeError('Device does not exist')

    monkeypatch.setattr(checks, 'cmd', missing)
    with pytest.raises(RuntimeError, match='Device does not exist'):
        checks.check_ethernet_ipv6({'ethernet': 'eth1'})
