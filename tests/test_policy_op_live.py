"""Opt-in execution of policy operational smoketests against isolated FRR daemons."""

import json
import os
from pathlib import Path

import pytest

from nvyr.helpers.process import cmd
from nvyr.op_scripts import policy
from functionaltests.network import test_policy_operations as smoke
from tests.test_policy_smoketest import local_policy_session


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_POLICY_TEST') != '1',
                                reason='requires isolated FRR policy daemons')


@pytest.mark.parametrize('function', [pytest.param(function, id=name)
                                     for name, function in vars(smoke).items() if name.startswith('test_')])
def test_native_policy_operation(local_policy_session, function):
    """Run shipped smoke functions through the real engine, formatter, reload and vtysh."""
    assert Path('/.dockerenv').exists(), 'native tests must not run on a shared router'
    configuration = Path(__file__).resolve().parents[1] / 'functionaltests/configs/network-features.conf'
    try:
        for command in configuration.read_text().splitlines():
            if command.startswith('set policy '):
                local_policy_session.set(command)
        local_policy_session.commit()
        function(local_policy_session)
    finally:
        local_policy_session.discard()
        local_policy_session.delete('delete policy')
        local_policy_session.commit()


def test_native_clear_used_route_map():
    """Clear a nonzero BGP invocation counter while retaining the route and policy setter."""
    assert Path('/.dockerenv').exists(), 'native tests must not run on a shared router'
    cmd(['vtysh', '-c', 'configure terminal', '-c', 'route-map OP_COUNTER permit 10',
         '-c', 'set metric 51', '-c', 'exit', '-c', 'router bgp 65123',
         '-c', 'no bgp network import-check', '-c', 'address-family ipv4 unicast',
         '-c', 'network 198.51.100.0/24 route-map OP_COUNTER'])
    try:
        before = json.loads(policy.show('show route-map OP_COUNTER', raw=True))
        assert before['bgpd']['OP_COUNTER']['invoked'] > 0

        policy.clear('clear route-map counter OP_COUNTER')

        after = json.loads(policy.show('show route-map OP_COUNTER', raw=True))
        assert after['bgpd']['OP_COUNTER']['invoked'] == 0
        assert 'metric 51' in after['bgpd']['OP_COUNTER']['rules'][0]['setClauses']
        assert '198.51.100.0/24' in cmd(['vtysh', '-c', 'show bgp ipv4 unicast'])
    finally:
        cmd(['vtysh', '-c', 'configure terminal', '-c', 'no router bgp 65123',
             '-c', 'no route-map OP_COUNTER'])
