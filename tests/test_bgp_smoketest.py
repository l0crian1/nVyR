"""Check that BGP smoketest setup and teardown respect existing configuration."""

from types import SimpleNamespace

import pytest

from nvyr.config_session import CommitError
from smoketests import test_bgp as smoke
from smoketests.support import configuration_case


def test_case_reset_keeps_vrf_and_base_policy(local_session, monkeypatch):
    """Reset accepted and rejected edits without deleting the stable routing domain."""
    from nvyr.helpers import interfaces

    monkeypatch.setattr(smoke, 'assert_bgp_resources_unused', lambda running: None)
    resources = {'prepared': False}
    smoke.standup(local_session, resources)
    baseline = local_session.get_config()
    request = SimpleNamespace(session=SimpleNamespace(shouldstop=False))
    applied = []
    monkeypatch.setattr(interfaces.manager, 'replace', lambda *args, **kwargs: applied.append(args))
    try:
        with configuration_case(local_session, request, baseline):
            local_session.set('set vrf name NVYRBGP protocols bgp neighbor 192.0.2.2 remote-as external')
            local_session.commit()
        assert local_session.get_config() == baseline
        assert applied == []

        with configuration_case(local_session, request, baseline):
            local_session.delete('delete vrf name NVYRBGP protocols bgp local-as')
            with pytest.raises(CommitError):
                local_session.commit()
        assert local_session.get_config() == baseline
        assert applied == []
        assert not request.session.shouldstop
    finally:
        smoke.cleanup(local_session, resources)


def test_reserved_vrf_collision_preserves_existing_configuration(local_session):
    local_session.set('set vrf name NVYRBGP table 41040')
    local_session.commit()
    before = local_session.get_config()
    resources = {'prepared': False}
    try:
        with pytest.raises(AssertionError, match='already configured or referenced'):
            smoke.standup(local_session, resources)
        smoke.cleanup(local_session, resources)
        assert local_session.get_config() == before
    finally:
        local_session.delete('delete vrf name NVYRBGP')
        local_session.commit()
