"""One package lifetime for routing, BGP, policy and compatible firewall checks."""

import pytest

from functionaltests.routed_network import scenario
from smoketests.support import configuration_case


@pytest.fixture(scope='package', autouse=True)
def routed_network(config, request):
    """Prepare all compatible features before any test, independent of selection."""
    def stop(message):
        request.session.shouldstop = message

    with scenario(config, stop):
        yield config.get_config()


@pytest.fixture(autouse=True)
def network_case(config, request, policy_baseline):
    """Restore deliberate mutations; observations require no commit or link reset."""
    with configuration_case(config, request, policy_baseline):
        if request.node.get_closest_marker('exclusive_firewall'):
            # These tests change global/default policy, not ordinary per-service
            # rules. Stage removal without an extra empty-firewall commit.
            config.delete('delete firewall')
        if request.node.get_closest_marker('exclusive_static'):
            config.delete('delete protocols static')
            config.delete('delete vrf name NVYRSMOKE protocols static')
        yield


@pytest.fixture(scope='module')
def policy_baseline(config, request, routed_network):
    """Restore large common sets once after a module of incompatible policies."""
    if not request.node.get_closest_marker('exclusive_firewall'):
        yield routed_network
        return

    with configuration_case(config, request, routed_network):
        config.delete('delete firewall')
        config.commit()
        yield config.get_config()
