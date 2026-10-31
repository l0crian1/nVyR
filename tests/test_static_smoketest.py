"""Check live-suite commands and cleanup with the real engine and fake host I/O.

These tests do not establish FRR/kernel correctness; that is the live suite's job.
They ensure its CLI commands, expected validation failures, and resource cleanup
remain compatible with the configuration engine without contacting a router.
"""

from copy import deepcopy
import inspect
import ipaddress
import json

import pytest

from nvyr.config_session import CommitError
from nvyr.helpers import interfaces
from nvyr.tree import lookup
from smoketests import test_static as smoke


@pytest.fixture
def local_session(controller, engine, session, monkeypatch):
    """Use real parsing, candidate mutations, defaults, verification, and commits."""
    local = {ipaddress.ip_address(address) for address in ('198.18.97.1', '2001:db8:97::1', 'fe80::97:1')}
    monkeypatch.setattr(interfaces, 'local_addresses', lambda vrf=None: local if vrf in (None, 'default') else set())

    class LocalSession:
        def set(self, command):
            """Stage a full CLI command through the real controller."""
            return controller.execute(command, session)

        def delete(self, command):
            """Exercise dependency checks when removing configuration."""
            return controller.execute(command, session)

        def commit(self):
            """Match ConfigurationSession's result-to-exception contract."""
            result = engine.commit(session)
            if any(not unit['success'] for unit in result['results'].values()):
                raise CommitError(result)
            return result

        def get_config(self, source='running'):
            """Return an independent explicit configuration snapshot."""
            configuration = engine.view(session) if source == 'candidate' else engine.running
            return deepcopy(configuration)

        def discard(self):
            """Drop failed candidate operations before local teardown."""
            return engine.discard(session)

    return LocalSession()


@pytest.fixture
def fake_observations(monkeypatch, engine, controller):
    """Isolate host queries; forbid raw commands that could create/delete devices."""
    def show(words, *, raw=False):
        """Observe the fake committed state; never query unrelated real FRR daemons."""
        vrf = words[words.index('vrf') + 1] if 'vrf' in words else 'default'
        root = engine.running
        if vrf != 'default':
            root = lookup(root, ('vrf', 'name', vrf), {})
        configuration = lookup(root, ('protocols', 'static'), {})

        if words[:3] == ('show', 'static', 'routes'):
            prefixes = [*configuration.get('route', {}), *configuration.get('route6', {})]
            result = {vrf: {'routes': [{'prefix': prefix} for prefix in prefixes]}}
        else:
            kind = 'route6' if words[1] == 'ipv6' else 'route'
            result = {prefix: [{'vrfName': vrf}] for prefix in configuration.get(kind, {})}

        return json.dumps(result) if raw else str(result)

    def command(argv, **options):
        """Allow only preflight inventory and the suite's read-only route wrapper."""
        if argv[:2] == ['static.nvyr.op', 'show']:
            return smoke.static.show(argv[2], raw='--raw' in argv)
        assert argv[0] == 'ip'
        assert 'show' in argv
        return '[]'

    def operational_output(text, *expected, absent=()):
        """Keep operational parsing and output checks without a live configd socket."""
        output = controller.execute(text)['text']
        for value in expected:
            assert value in output
        for value in absent:
            assert value not in output

    monkeypatch.setattr(smoke.static.vtysh, 'show', show)
    monkeypatch.setattr(smoke, 'cmd', command)
    monkeypatch.setattr('nvyr.controller.cmd', command)
    monkeypatch.setattr(smoke, 'assert_operational_output', operational_output)
    for name in (
        'assert_static_route_configured', 'assert_static_route_unconfigured', 'assert_no_static_configuration', 'assert_no_static_routes',
        'assert_frr_routes', 'assert_frr_route_absent', 'assert_kernel_route',
        'assert_kernel_route_absent', 'assert_static_instance_empty',
        'assert_kernel_multipath_weights',
    ):
        monkeypatch.setattr(smoke, name, lambda *args, **kwargs: None)


@pytest.mark.parametrize('function', [
    pytest.param(function, id=name)
    for name, function in vars(smoke).items()
    if name.startswith('test_')
])
def test_live_case_commands_and_cleanup(local_session, fake_observations, function):
    """Run each live case's config commands and exception assertions in isolation."""
    resources = {'prepared': False, 'dummy': False, 'vrf': False}
    original = local_session.get_config()

    try:
        smoke.standup(local_session, resources)
        parameters = {}
        if 'static_environment' in inspect.signature(function).parameters:
            parameters = parameters | {'static_environment': resources}
        function(local_session, **parameters)
    finally:
        smoke.cleanup(local_session, resources)

    # Empty ancestor nodes are deliberately preserved by the configuration engine.
    running = local_session.get_config()
    assert lookup(running, ('interfaces', 'dummy', 'dum997'), None) is None
    assert lookup(running, ('vrf', 'name', 'NVYRSMOKE'), None) is None
    assert lookup(running, ('protocols', 'static'), None) is None
    assert original == {}


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
