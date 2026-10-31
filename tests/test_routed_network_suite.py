"""Check the shared scenario's configuration, lifetime and failure restoration."""

import ast
from copy import deepcopy
import ipaddress
from pathlib import Path
from types import SimpleNamespace

import pytest

from functionaltests import routed_network
from nvyr.helpers import interfaces
from tests.test_bgp_policy_smoketest import policy_session


pytest_plugins = ['pytester']


def test_combined_configuration(policy_session, monkeypatch):
    """Real parsing and verification accept all features in one transaction."""
    addresses = {
        'default': {'127.0.0.1', '::1'},
        'NVYRLEFT': {'198.18.60.1', '198.18.61.1', '2001:db8:60::1', '2001:db8:61::1'},
        'NVYRRIGHT': {'198.18.60.2', '198.18.62.1', '2001:db8:60::2', '2001:db8:62::1'},
    }
    monkeypatch.setattr(interfaces, 'local_addresses',
                        lambda vrf=None: {ipaddress.ip_address(value) for value in addresses.get(vrf, ())})
    from nvyr.helpers import domain_groups, geoip, kea

    monkeypatch.setattr(kea, 'inventory', lambda: {
        'dum980': {'vrf': 'NVYRDHCPSMOKE', 'up': True, 'running': True,
                   'addresses': ['198.18.210.1', '2001:db8:210::1', 'fe80::980']},
    })
    monkeypatch.setattr(geoip, 'manager', SimpleNamespace(apply=lambda *args, **kwargs: None))
    monkeypatch.setattr(domain_groups, 'manager', SimpleNamespace(prepare=lambda *args: ('', None)))
    routed_network.configure(policy_session)
    running = policy_session.get_config()

    assert set(running['vrf']['name']) == {'NVYRLEFT', 'NVYRRIGHT', 'NVYRFWSMOKE', 'NVYRSMOKE', 'NTPTEST', 'NVYRDHCPSMOKE'}
    assert 'bgp' in running['vrf']['name']['NVYRLEFT']['protocols']
    assert 'static' in running['vrf']['name']['NVYRLEFT']['protocols']
    assert 'RNMAP' in running['firewall']['group']['map']['inet']
    assert 'RNMATCH' in running['firewall']['group']['match-group']['ipv6']


def test_initial_route_exchange_must_finish(monkeypatch):
    """Established alone is insufficient evidence for a negative route assertion."""
    import json

    neighbor = '198.18.60.2'
    observed = []
    responses = iter([
        {neighbor: {'bgpState': 'Established', 'gracefulRestartInfo': {'endOfRibRecv': {}}}},
        {neighbor: {'bgpState': 'Established',
                    'gracefulRestartInfo': {'endOfRibRecv': {'ipv4Unicast': True}}}},
    ])

    def command(argv):
        value = next(responses)
        observed.append(value)
        return json.dumps(value)

    monkeypatch.setattr(routed_network, 'cmd', command)
    routed_network.end_of_rib(neighbor, 'ipv4Unicast')
    assert len(observed) == 2


def test_literal_scenario_is_packaged():
    """The installed test must receive its configuration alongside its Python files."""
    root = Path(__file__).resolve().parents[1]
    script = (root / 'scripts/build-deb.sh').read_text()
    assert "-name '*.conf'" in script
    assert routed_network.CONFIGURATION.is_file()


def test_readonly_cases_and_shared_scope():
    """A future feature must not silently reintroduce commits between observations."""
    path = Path(routed_network.__file__).with_name('network') / 'test_routed_network.py'
    tree = ast.parse(path.read_text())
    fixture_tree = ast.parse(path.with_name('conftest.py').read_text())
    fixture = next(node for node in fixture_tree.body if isinstance(node, ast.FunctionDef)
                   and node.name == 'routed_network')
    assert any('scope=\'package\'' in ast.unparse(decorator) for decorator in fixture.decorator_list)

    for function in tree.body:
        if not isinstance(function, ast.FunctionDef) or not function.name.startswith('test_'):
            continue
        assert not function.args.args, function.name
        for node in ast.walk(function):
            if isinstance(node, ast.Call):
                assert not ast.unparse(node.func).endswith(('.commit', '.set', '.delete', '.load'))


def test_scenario_restores_after_setup_failure(monkeypatch):
    """A failed commit still restores the baseline and never claims unrelated namespaces."""
    original = {'interfaces': {'ethernet': {'eth0': {'address': ['10.0.101.47/24']}}}}
    calls = []
    monkeypatch.setattr(routed_network, 'preflight', lambda config: deepcopy(original))

    def fail(config):
        raise RuntimeError('injected setup failure')

    monkeypatch.setattr(routed_network, 'configure', fail)
    monkeypatch.setattr(routed_network, 'restore',
                        lambda config, baseline, moved, namespaces: calls.append((baseline, moved, namespaces)))
    with pytest.raises(RuntimeError, match='injected setup failure'):
        with routed_network.scenario(object(), lambda message: calls.append(message)):
            pytest.fail('Failed setup must not yield to tests')

    assert calls == [(original, [], [])]


def test_restore_attempts_configuration_after_peer_failure(monkeypatch):
    """A broken endpoint must not prevent restoration of firewall and routing state."""
    calls = []
    original = {'service': {'ssh': {}}}

    class Session:
        def discard(self):
            calls.append('discard')

        def load(self, configuration, *, replace):
            assert replace
            assert configuration == original
            calls.append('load')

        def commit(self):
            calls.append('commit')

        def get_config(self):
            return original

    def command(argv):
        calls.append(argv)
        if 'flush' in argv:
            raise RuntimeError('peer inaccessible')

    monkeypatch.setattr(routed_network, 'cmd', command)
    with pytest.raises(ExceptionGroup, match='restoration failed'):
        routed_network.restore(Session(), original, [('owned', 'veth42064')], ['owned'])
    assert 'commit' in calls
    assert calls[-1] == ['ip', 'netns', 'delete', 'owned']


def test_one_scenario_for_selected_cases_in_any_order(pytester):
    """Two files share one topology and still tear it down after a failed observation."""
    package = pytester.mkdir('scenario_cases')
    (package / '__init__.py').write_text('')
    (package / 'conftest.py').write_text('''
from contextlib import contextmanager
import pytest
from functionaltests.network import conftest as suite
from functionaltests.network.conftest import routed_network

events = []

@contextmanager
def fake_scenario(config, stop):
    events.append('setup')
    yield
    events.append('teardown')

suite.scenario = fake_scenario

@pytest.fixture(scope='session')
def config():
    yield type('Session', (), {'get_config': lambda self: {}})()
    assert events == ['setup', 'third', 'failure', 'first', 'teardown']
''')
    (package / 'test_first.py').write_text('''
from scenario_cases.conftest import events

def test_first():
    events.append('first')
''')
    (package / 'test_other.py').write_text('''
from scenario_cases.conftest import events

def test_failure():
    events.append('failure')
    assert False, 'test observation failed'

def test_third():
    events.append('third')
''')
    result = pytester.runpytest('scenario_cases/test_other.py::test_third',
                               'scenario_cases/test_other.py::test_failure',
                               'scenario_cases/test_first.py::test_first', '-q')
    result.assert_outcomes(passed=2, failed=1)
