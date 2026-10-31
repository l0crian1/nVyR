"""System loopback addresses and alias, preserving the built-in host addresses."""

from copy import deepcopy

import pytest

if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from nvyr.helpers.dependencies import Dependencies
from nvyr.schema import Schema
from nvyr.tree import lookup
from smoketests.assertions import assert_link, assert_configured_link_addresses, assert_raises
from smoketests.support import configuration_case, prepared_test


@pytest.fixture(scope='module')
def loopback_suite(config, request):
    """Keep lo configured across cases, restoring its original settings at module exit."""
    original = config.get_config()
    if lookup(original, ('interfaces', 'loopback', 'lo'), None) is None:
        references = Dependencies(Schema.bundled()).from_tree(original, 'depends')
        if any(kind == 'interface' and name == 'lo' for kind, name, path in references):
            pytest.skip('Configure interfaces loopback lo first: existing references would prevent restoring its absence')

    baseline = deepcopy(original)
    baseline.setdefault('interfaces', {}).setdefault('loopback', {})['lo'] = {}

    def standup(session):
        """Retain lo's provider identity so existing references remain valid."""
        session.load(baseline, replace=True)
        session.commit()

    def cleanup(session):
        """Restore original addresses and description even after a rejected test command."""
        session.discard()
        session.load(original, replace=True)
        session.commit()

    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, standup, cleanup, stop=stop):
        yield config.get_config()


@pytest.fixture(autouse=True)
def loopback_environment(config, request, loopback_suite):
    """Restore case settings in one commit while retaining unchanged suite objects."""
    with configuration_case(config, request, loopback_suite):
        yield


def test_system_addresses():
    """An empty loopback instance retains both localhost addresses and stays up."""
    assert_link('lo', up=True)
    assert_configured_link_addresses('lo', '127.0.0.1/8', '::1/128')


def test_ipv4_addresses(config):
    """IPv4 host addresses coexist and individual deletion preserves localhost."""
    config.set('set interfaces loopback lo address 198.18.250.1/32')
    config.set('set interfaces loopback lo address 198.18.250.2/32')
    config.commit()
    assert_configured_link_addresses('lo', '127.0.0.1/8', '198.18.250.1/32', '198.18.250.2/32')

    config.delete('delete interfaces loopback lo address 198.18.250.1/32')
    config.commit()
    assert_configured_link_addresses('lo', '127.0.0.1/8', '198.18.250.2/32', absent=('198.18.250.1/32',))


def test_ipv6_addresses(config):
    """IPv6 host addresses coexist and deleting one leaves ::1 untouched."""
    config.set('set interfaces loopback lo address 2001:db8:250::1/128')
    config.set('set interfaces loopback lo address 2001:db8:250::2/128')
    config.commit()
    assert_configured_link_addresses('lo', '::1/128', '2001:db8:250::1/128', '2001:db8:250::2/128')

    config.delete('delete interfaces loopback lo address 2001:db8:250::1/128')
    config.commit()
    assert_configured_link_addresses('lo', '::1/128', '2001:db8:250::2/128', absent=('2001:db8:250::1/128',))


def test_description(config):
    """The anchored alias can be set beside an address and removed independently."""
    config.set('set interfaces loopback lo description "Router identity" address 198.18.250.1/32')
    config.commit()
    assert_link('lo', description='Router identity', up=True)

    config.delete('delete interfaces loopback lo description')
    config.commit()
    assert_link('lo', description='', up=True)
    assert_configured_link_addresses('lo', '198.18.250.1/32', '127.0.0.1/8', '::1/128')


def test_system_addresses_survive_configured_removal(config):
    """Deleting explicitly configured system prefixes leaves their kernel addresses intact."""
    config.set('set interfaces loopback lo address 127.0.0.1/8')
    config.set('set interfaces loopback lo address ::1/128')
    config.commit()
    config.delete('delete interfaces loopback lo address')
    config.commit()
    assert_configured_link_addresses('lo', '127.0.0.1/8', '::1/128')


def test_dhcp_rejected(config):
    """Loopback accepts static prefixes only."""
    with assert_raises(RouterError):
        config.set('set interfaces loopback lo address dhcp')


def test_disable_rejected(config):
    """There is no administrative shutdown setting for the system loopback."""
    with assert_raises(RouterError):
        config.set('set interfaces loopback lo disable')


def test_other_loopback_name_rejected(config):
    """Additional logical interfaces belong under dummy, not invented loopback devices."""
    with assert_raises(RouterError):
        config.set('set interfaces loopback lo1 address 198.18.250.1/32')


def test_system_prefix_change_rejected(config):
    """Verification protects the system IPv4 loopback prefix length."""
    config.set('set interfaces loopback lo address 127.0.0.1/32')
    with assert_raises(RouterError, match='System loopback addresses'):
        config.commit()
