"""Check ownership of reserved routing-policy smoketest names."""

import pytest

from smoketests import test_policy as smoke


def test_cleanup_releases_name_for_next_run(local_session):
    resources = {'prepared': False}
    smoke.standup(local_session, resources)
    local_session.set('set policy route-map NVYRPOLICYSMOKE rule 10 action permit')
    local_session.commit()

    smoke.cleanup(local_session, resources)
    smoke.standup(local_session, {'prepared': False})


def test_preflight_collision_does_not_remove_existing_policy(local_session):
    local_session.set('set policy prefix-list ipv4 NVYRPOLICYSMOKE rule 10 action permit prefix 10.0.0.0/8')
    local_session.commit()
    before = local_session.get_config()
    resources = {'prepared': False}
    try:
        with pytest.raises(AssertionError, match='already configured or referenced'):
            smoke.standup(local_session, resources)
        smoke.cleanup(local_session, resources)
        assert local_session.get_config() == before
    finally:
        local_session.delete('delete policy prefix-list ipv4 NVYRPOLICYSMOKE')
        local_session.commit()
