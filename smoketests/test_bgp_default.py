"""Default-VRF-only BGP controls; never replace existing default-VRF peers."""

import pytest

if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.config_session import CommitError
from nvyr.helpers.frr_bgp import adapter
from nvyr.helpers.process import cmd
from nvyr.tree import lookup
from smoketests.assertions import assert_bgp_commands, assert_frr_policy_commands, assert_raises
from smoketests.support import configuration_case, prepared_test


def standup(config, resources):
    """Reserve the default instance only when both configuration and FRR are empty."""
    native = cmd(['vtysh', '-c', 'show running-config no-header'])
    existing = adapter.select(native, ['default', '@global'])
    if lookup(config.get_config(), ('protocols', 'bgp'), None) is not None or any(existing.values()):
        pytest.skip('Default-VRF BGP or daemon-wide parameters are in use; default-only tests require unused settings.')

    resources['prepared'] = True
    config.set('set protocols bgp local-as 65000 parameters router-id 192.0.2.1')
    config.commit()


def cleanup(config, resources):
    """Remove only the instance reserved by this test, including after failed verification."""
    if resources['prepared']:
        config.discard()
        if lookup(config.get_config(), ('protocols', 'bgp'), None) is not None:
            config.delete('delete protocols bgp')
            config.commit()


@pytest.fixture(scope='module')
def default_bgp_suite(config, request):
    """Reserve the default instance once; never wait for a peer to establish."""
    resources = {'prepared': False}

    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, lambda session: standup(session, resources),
                       lambda session: cleanup(session, resources), stop=stop):
        yield config.get_config()


@pytest.fixture(autouse=True)
def default_bgp_environment(config, request, default_bgp_suite):
    """Restore only case-specific settings while retaining the default instance."""
    with configuration_case(config, request, default_bgp_suite):
        yield


def test_dampening_defaults(config):
    """Enable native default dampening and remove it without retaining the command."""
    config.set('set protocols bgp parameters dampening state enable')
    config.commit()
    assert_bgp_commands('bgp dampening', vrf='default')

    config.delete('delete protocols bgp parameters dampening')
    config.commit()
    assert_bgp_commands(vrf='default', absent=('bgp dampening',))


def test_dampening_custom_thresholds(config):
    """Custom IPv4 decay and suppression thresholds survive native readback."""
    config.set('set protocols bgp parameters dampening state enable half-life 10 reuse 500 suppress 1500 max-suppress-time 40')
    config.commit()
    assert_bgp_commands('bgp dampening 10 500 1500 40', vrf='default')


def test_dampening_invalid_thresholds(config):
    """Reuse cannot equal or exceed the suppression threshold."""
    config.set('set protocols bgp parameters dampening state enable reuse 2000 suppress 2000')
    with assert_raises(CommitError, match='reuse must be less than suppress'):
        config.commit()


def test_dampening_invalid_duration(config):
    """Maximum suppression must cover the configured half-life."""
    config.set('set protocols bgp parameters dampening state enable half-life 15 max-suppress-time 10')
    with assert_raises(CommitError, match='at least half-life'):
        config.commit()


def test_route_map_delay_timer(config):
    """The daemon-wide policy rescan timer can be installed, changed and removed."""
    config.set('set protocols bgp parameters route-map delay-timer 10')
    config.commit()
    assert_frr_policy_commands('bgp route-map delay-timer 10')

    config.set('set protocols bgp parameters route-map delay-timer 20')
    config.commit()
    assert_frr_policy_commands('bgp route-map delay-timer 20', absent=('bgp route-map delay-timer 10',))

    config.delete('delete protocols bgp parameters route-map')
    config.commit()
    assert_frr_policy_commands(absent=('bgp route-map delay-timer 20',))
