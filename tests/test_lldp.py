"""LLDP selector/override contracts, CLI routing and native output presentation."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import service_lldp as service
from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import lldp
from nvyr.helpers.lldp import install
from nvyr.helpers.template import lldp_interface_pattern
from nvyr.lexer import lex
from nvyr.op_scripts import lldp as operational
from nvyr.schema import Schema


@pytest.mark.parametrize('section,message', [
    ({'interface': {'eth*': {'mode': 'receive-only'}}}, 'exact interface'),
    ({'interface': {'all': {'disable': None}}}, 'exact interface'),
    ({'interface': {'eth1': {'mode': 'receive-only'}}, 'exclude-interface': ['eth*']}, 'excluded'),
    ({'interface': {'eth1': {'mode': 'receive-only', 'disable': None}}}, 'mutually exclusive'),
    ({'interface': {'eth1': {'transmit-vlan': {'1': {}, '2': {}}}}}, 'one transmit-vlan'),
    ({'chassis-id': 'router', 'chassis-interface': ['eth0']}, 'mutually exclusive'),
])
def test_relationships(section, message):
    with pytest.raises(ValidationError, match=message):
        service.verify(section, None)


def test_shared_selector_node_and_no_implicit_children(controller, engine, session, monkeypatch):
    installed = []
    monkeypatch.setattr(lldp, 'install', installed.append)
    for line in ('interface all', 'interface eth*', 'interface eth1 port-description "Inside uplink"',
                 'exclude-interface eth9', 'system-name example', 'transmit-interval 5'):
        controller.execute('set service lldp ' + line, session)

    result = engine.commit(session)
    assert result['results']['lldp']['success'], result
    assert engine.running['service']['lldp']['interface']['all'] == {}
    assert installed[-1]['overrides'] == ['eth1']
    assert 'configure system interface pattern *,eth*,eth1,!eth9' in installed[-1]['configuration']
    assert 'configure ports eth1 lldp portdescription "Inside uplink"' in installed[-1]['configuration']

    controller.execute('set service lldp interface eth* port-description invalid', session)
    result = engine.commit(session)
    assert not result['results']['lldp']['success']


def test_native_default_and_disable():
    assert service.generate(None, None) is None
    assert service.generate({'disable': None}, None) is None
    text = service.generate({}, None)['configuration']
    assert 'configure ' not in text
    assert lldp_interface_pattern({'exclude-interface': ['eth0']}) == '!eth0'


@pytest.mark.parametrize('line', [
    'show lldp neighbors', 'show lldp neighbors detail',
    'show lldp neighbors interface eth1', 'show lldp neighbors interface eth1 detail',
    'show lldp interfaces', 'show lldp interfaces detail', 'show lldp interfaces eth1',
    'show lldp interfaces eth1 detail', 'show lldp local', 'show lldp statistics',
    'show lldp statistics interface eth1', 'monitor lldp', 'monitor lldp interface eth1',
    'show log lldp', 'show log lldp follow',
])
def test_operational_tree(line):
    cursor = Schema.bundled('operational').operational(lex(line))
    assert cursor.node.get('command')


def test_output_preserves_multiple_neighbors_on_one_port(monkeypatch):
    document = {'lldp': [{'interface': [
        {'name': 'eth1', 'chassis': [{'name': [{'value': name}], 'id': [{'value': name + '-id'}]}],
         'port': [{'id': [{'value': 'uplink'}], 'descr': [{'value': 'Core'}]}]}
        for name in ('switch-a', 'switch-b')]}]}
    monkeypatch.setattr(lldp, 'control', lambda *args, **kwargs: deepcopy(document))

    text = operational.show('neighbors')
    assert 'switch-a' in text and 'switch-b' in text
    assert text.count('eth1') == 2
    assert json.loads(operational.show('neighbors', raw=True)) == document


def test_details_and_empty_output(monkeypatch):
    calls = []
    def control(*arguments, raw=False):
        calls.append((arguments, raw))
        return {'lldp': [{}]} if raw else 'Native detailed information\n'
    monkeypatch.setattr(lldp, 'control', control)

    assert operational.show('neighbors') == 'No LLDP neighbors to display.\n'
    assert operational.show('interfaces', 'eth1', detail=True) == 'Native detailed information\n'
    assert calls[-1] == (('show', 'interfaces', 'ports', 'eth1', 'details'), False)


def test_install_change_noop_and_removal(tmp_path, monkeypatch):
    calls = []
    queries = []
    monkeypatch.setattr(lldp, 'ROOT', tmp_path)
    monkeypatch.setattr(lldp, 'cmd', lambda argv, **kwargs: calls.append(argv))
    monkeypatch.setattr(lldp, 'run', lambda argv: 0)
    def control(*args, **kwargs):
        queries.append((args, kwargs))
        return {'lldp': [{'interface': [{'name': 'eth1'}]}]}
    monkeypatch.setattr(lldp, 'control', control)
    plan = service.generate({'interface': {'eth1': {'port-id': 'uplink'}}}, None)

    install(plan)
    assert calls == [['systemctl', 'restart', lldp.UNIT]]
    assert queries[-1] == (('show', 'interfaces', 'details'), {'raw': True})
    assert (tmp_path / 'lldpd.conf').stat().st_mode & 0o777 == 0o644
    install(plan)
    assert len(calls) == 1

    install(service.generate({'interface': {'eth1': {}}}, None))
    assert len(calls) == 2
    install(None)
    assert calls[-1] == ['systemctl', 'stop', lldp.UNIT]
    assert not (tmp_path / 'lldpd.conf').exists()


def test_missing_override_is_not_reported_as_applied(tmp_path, monkeypatch):
    monkeypatch.setattr(lldp, 'ROOT', tmp_path)
    monkeypatch.setattr(lldp, 'cmd', lambda *args, **kwargs: '')
    monkeypatch.setattr(lldp, 'control', lambda *args, **kwargs: {'lldp': [{}]})
    with pytest.raises(RouterError, match='eth1'):
        install(service.generate({'interface': {'eth1': {'port-id': 'uplink'}}}, None))


def test_smoke_fixture_uses_valid_cli_and_readonly_generation(local_session):
    from smoketests.test_lldp import lldp_suite

    request = SimpleNamespace(session=SimpleNamespace(shouldstop=None))
    fixture = lldp_suite.__wrapped__(local_session, request)
    try:
        configuration = next(fixture)
        assert configuration['service']['lldp']['interface']['veth421*'] == {}
    finally:
        fixture.close()
    assert request.session.shouldstop is None
