"""Exercise the live policy examples through the real configuration engine.

With NVYR_POLICY_TEST=1, use the disposable FRR daemons and native assertions too.
Ordinary builds only check CLI, verification, and cleanup behavior.
"""

from copy import deepcopy
import os

import pytest

from nvyr.config_session import CommitError
from nvyr.helpers import frr_reload
from smoketests import test_policy as smoke


@pytest.fixture
def local_policy_session(controller, engine, session, monkeypatch):
    if os.environ.get('NVYR_POLICY_TEST') == '1':
        monkeypatch.setattr(frr_reload, 'manager', frr_reload.Manager())
    else:
        monkeypatch.setattr(smoke, 'assert_frr_policy_commands', lambda *args, **kwargs: None)

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
def test_policy_live_case_commands_and_cleanup(local_policy_session, function):
    resources = {'prepared': False}
    smoke.standup(local_policy_session, resources)
    try:
        function(local_policy_session)
    finally:
        smoke.cleanup(local_policy_session, resources)
    smoke.standup(local_policy_session, resources)


def test_preflight_collision_does_not_remove_existing_policy(local_policy_session):
    local_policy_session.set('set policy prefix-list ipv4 NVYRPOLICYSMOKE rule 10 action permit prefix 10.0.0.0/8')
    local_policy_session.commit()
    before = local_policy_session.get_config()
    resources = {'prepared': False}
    try:
        with pytest.raises(AssertionError, match='already configured or referenced'):
            smoke.standup(local_policy_session, resources)
        smoke.cleanup(local_policy_session, resources)
        assert local_policy_session.get_config() == before
    finally:
        local_policy_session.delete('delete policy prefix-list ipv4 NVYRPOLICYSMOKE')
        local_policy_session.commit()
