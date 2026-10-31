"""Run the installed BGP policy examples through the engine, optionally with real daemons."""

from copy import deepcopy
import os

import pytest

from nvyr.config_session import CommitError
from nvyr.helpers import frr_reload, interfaces
from functionaltests.network import test_bgp_policy as smoke


@pytest.fixture
def policy_session(controller, engine, session, monkeypatch):
    if os.environ.get('NVYR_BGP_POLICY_TEST') == '1':
        monkeypatch.setattr(frr_reload, 'manager', frr_reload.Manager())
        monkeypatch.setattr(interfaces, 'manager', interfaces.NetlinkManager())
    else:
        monkeypatch.setattr(smoke, 'assert_bgp_path', lambda *args, **kwargs: None)
        monkeypatch.setattr(interfaces, 'local_addresses', lambda vrf=None: set())

    class LocalSession:
        def set(self, command):
            return controller.execute(command, session)

        def delete(self, command):
            return controller.execute(command, session)

        def commit(self):
            result = engine.commit(session)
            if any(not unit['success'] for unit in result['results'].values()):
                raise CommitError(result)
            return result

        def get_config(self):
            return deepcopy(engine.running)

        def discard(self):
            engine.discard(session)

    return LocalSession()


@pytest.mark.parametrize('function', [pytest.param(function, id=name)
                                     for name, function in vars(smoke).items() if name.startswith('test_')])
def test_bgp_policy_commands_and_results(policy_session, function):
    from functionaltests import routed_network

    # The policy cases now use dedicated prefixes on the common network peers.
    for filename in ('routed-network.conf', 'network-policies.conf'):
        for command in routed_network.CONFIGURATION.with_name(filename).read_text().splitlines():
            if command and not command.startswith('#'):
                policy_session.set(command)
    policy_session.commit()
    function(policy_session)
