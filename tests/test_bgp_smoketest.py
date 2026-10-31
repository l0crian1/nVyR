"""Exercise the live BGP examples through the real configuration engine.

With NVYR_BGP_TEST=1, use the disposable FRR daemons and native assertions too.
Ordinary builds only check CLI, verification, and cleanup behavior.
"""

from copy import deepcopy
import json
import os
from types import SimpleNamespace

import pytest

from nvyr.config_session import CommitError
from nvyr.helpers import frr_reload
from smoketests import test_bgp as smoke
from smoketests.support import configuration_case


@pytest.fixture
def local_bgp_session(controller, engine, session, monkeypatch):
    if os.environ.get('NVYR_BGP_TEST') == '1':
        monkeypatch.setattr(frr_reload, 'manager', frr_reload.Manager())
    else:
        monkeypatch.setattr(smoke, 'assert_bgp_commands', lambda *args, **kwargs: None)
        monkeypatch.setattr(smoke, 'assert_bgp_resources_unused', lambda *args, **kwargs: None)

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

        def load(self, configuration, *, replace=True):
            controller.load(session, json.dumps(configuration), replace=replace)

    return LocalSession()


def test_case_reset_keeps_vrf_and_base_policy(local_bgp_session, monkeypatch):
    """Reset accepted and rejected edits without deleting the stable routing domain."""
    from nvyr.helpers import interfaces

    resources = {'prepared': False}
    smoke.standup(local_bgp_session, resources)
    baseline = local_bgp_session.get_config()
    request = SimpleNamespace(session=SimpleNamespace(shouldstop=False))
    applied = []
    monkeypatch.setattr(interfaces.manager, 'replace', lambda *args, **kwargs: applied.append(args))
    try:
        with configuration_case(local_bgp_session, request, baseline):
            smoke.test_ipv4_external_policies(local_bgp_session)
        assert local_bgp_session.get_config() == baseline
        assert applied == []

        with configuration_case(local_bgp_session, request, baseline):
            local_bgp_session.delete('delete vrf name NVYRBGP protocols bgp local-as')
            with pytest.raises(CommitError):
                local_bgp_session.commit()
        assert local_bgp_session.get_config() == baseline
        assert applied == []
        assert not request.session.shouldstop
    finally:
        smoke.cleanup(local_bgp_session, resources)


@pytest.mark.parametrize('function', [pytest.param(function, id=name)
                                     for name, function in vars(smoke).items() if name.startswith('test_')])
def test_bgp_live_case_commands_and_cleanup(local_bgp_session, function):
    resources = {'prepared': False}
    smoke.standup(local_bgp_session, resources)
    try:
        function(local_bgp_session)
    finally:
        smoke.cleanup(local_bgp_session, resources)


def test_reserved_vrf_collision_preserves_existing_configuration(local_bgp_session):
    local_bgp_session.set('set vrf name NVYRBGP table 41040')
    local_bgp_session.commit()
    before = local_bgp_session.get_config()
    resources = {'prepared': False}
    try:
        with pytest.raises(AssertionError, match='already configured or referenced'):
            smoke.standup(local_bgp_session, resources)
        smoke.cleanup(local_bgp_session, resources)
        assert local_bgp_session.get_config() == before
    finally:
        local_bgp_session.delete('delete vrf name NVYRBGP')
        local_bgp_session.commit()
