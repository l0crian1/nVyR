"""Verify static smoketest resource ownership, reset and failure cleanup."""

import json

import pytest

from nvyr.helpers import interfaces
from nvyr.tree import lookup
from smoketests import test_static as smoke


@pytest.fixture
def fake_observations(monkeypatch):
    def empty_inventory(argv):
        assert argv[0] == 'ip' and 'show' in argv
        return '[]'

    monkeypatch.setattr(smoke, 'cmd', empty_inventory)
    monkeypatch.setattr(smoke, 'assert_no_static_routes', lambda *args: None)
    monkeypatch.setattr(smoke, 'assert_kernel_route_absent', lambda *args, **kwargs: None)


def test_existing_dummy_is_not_claimed_or_deleted(local_session, fake_observations, monkeypatch):
    """A preflight collision must stop before clearing routes or claiming resources."""
    local_session.set('set interfaces dummy dum997')
    local_session.commit()
    original = local_session.get_config()
    monkeypatch.setattr(smoke, 'cmd', lambda *args, **kwargs: json.dumps([{'ifname': 'dum997'}]))
    resources = {'prepared': False, 'dummy': False, 'vrf': False}

    with pytest.raises(AssertionError, match='already configured or referenced'):
        smoke.standup(local_session, resources)
    smoke.cleanup(local_session, resources)

    assert local_session.get_config() == original
    assert resources == {'prepared': False, 'dummy': False, 'vrf': False}


def test_route_reset_retains_dummy_and_vrf(local_session, fake_observations, monkeypatch):
    """Independent cases withdraw routes without recreating their next-hop topology."""
    resources = {'prepared': False, 'dummy': False, 'vrf': False}
    smoke.standup(local_session, resources)
    smoke.create_test_vrf(local_session, resources)
    local_session.set('set protocols static route 192.0.2.0/24 blackhole')
    local_session.set('set vrf name NVYRSMOKE protocols static route6 2001:db8:100::/64 reject')
    local_session.commit()
    applied = []
    try:
        with monkeypatch.context() as patch:
            patch.setattr(interfaces.manager, 'replace', lambda *args, **kwargs: applied.append(args))
            smoke.clear_static(local_session, resources)
            smoke.create_test_vrf(local_session, resources)

        running = local_session.get_config()
        assert applied == []
        assert lookup(running, ('interfaces', 'dummy', 'dum997'))['address']
        assert lookup(running, ('vrf', 'name', 'NVYRSMOKE', 'table')) == '41001'
        assert lookup(running, ('protocols', 'static'), None) is None
        assert lookup(running, ('vrf', 'name', 'NVYRSMOKE', 'protocols', 'static'), None) is None
    finally:
        smoke.cleanup(local_session, resources)

    assert lookup(local_session.get_config(), ('interfaces', 'dummy', 'dum997'), None) is None
    assert lookup(local_session.get_config(), ('vrf', 'name', 'NVYRSMOKE'), None) is None


def test_partial_setup_commit_is_cleaned(local_session, fake_observations, monkeypatch):
    """If setup loses its response after applying, teardown still removes our dummy."""
    commit = local_session.commit

    def applied_then_failed():
        """Simulate a setup response failure after the engine has applied the dummy."""
        commit()
        raise RuntimeError('setup response lost')

    monkeypatch.setattr(local_session, 'commit', applied_then_failed)
    resources = {'prepared': False, 'dummy': False, 'vrf': False}
    with pytest.raises(RuntimeError, match='response lost'):
        smoke.standup(local_session, resources)

    monkeypatch.setattr(local_session, 'commit', commit)
    smoke.cleanup(local_session, resources)

    assert lookup(local_session.get_config(), ('interfaces', 'dummy', 'dum997'), None) is None


def test_cleanup_continues_after_observation_failure(local_session, fake_observations, monkeypatch):
    """A failed withdrawal assertion must not prevent owned-device cleanup."""
    resources = {'prepared': False, 'dummy': False, 'vrf': False}
    smoke.standup(local_session, resources)

    def failed_observation(*args):
        """Represent a stale kernel route after configd accepted its deletion."""
        raise AssertionError('route remained')

    monkeypatch.setattr(smoke, 'assert_no_static_routes', failed_observation)
    with pytest.raises(RuntimeError, match='route remained'):
        smoke.cleanup(local_session, resources)

    assert lookup(local_session.get_config(), ('interfaces', 'dummy', 'dum997'), None) is None
