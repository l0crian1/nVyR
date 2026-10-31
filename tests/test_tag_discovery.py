import json

import pytest

from nvyr.errors import RouterError
from nvyr.helpers import interfaces
from nvyr.helpers.validators import REGISTRY
from nvyr.schema import Schema


@pytest.mark.parametrize('verb', ['set', 'delete', 'edit', 'show'])
def test_invalid_tags_do_not_block_discovery(controller, session, verb):
    command = f'{verb} interfaces dummy dm0 '

    assert 'address' in dict(controller.completion(command.rstrip(), session, explicit=True)['candidates'])

    for options in ({}, {'tab': True}, {'explicit': True}, {'space': True}):
        result = controller.completion(command, session, **options)

        assert {'address', 'description', 'disable', 'mac', 'mtu'} <= dict(result['candidates']).keys()
        assert '<Enter>' not in dict(result['candidates'])

        result = controller.completion(command + 'des', session, **options)

        assert result['replacement'] == 'description' and result['extension'] == 'cription'

    with pytest.raises(RouterError):
        controller.execute(command + 'description invalid', session)

    assert not session.mutations


def test_invalid_tag_anchor_and_relative_discovery(controller, session):
    controller.execute('edit interfaces', session)
    command = 'set dummy dm0 description "LAN port" '
    result = controller.completion(command, session, explicit=True)

    assert 'address' in dict(result['candidates']) and '<Enter>' not in dict(result['candidates'])
    assert controller.completion(command + 'mt', session, tab=True)['replacement'] == 'mtu'
    assert controller.completion('set dummy dm0 address ', session)['hints']

    with pytest.raises(RouterError):
        controller.execute(command + 'mtu 9000', session)

    with pytest.raises(RouterError):
        controller.load(session, json.dumps({'interfaces': {'dummy': {'dm0': {}}}}))

    assert not session.mutations


@pytest.mark.parametrize('kind,hint', [('ethernet', 'ethN'), ('dummy', 'dumN')])
def test_tag_hints_are_display_only(controller, session, kind, hint):
    command = f'set interfaces {kind} '

    for options in ({}, {'tab': True}, {'explicit': True}, {'space': True}):
        result = controller.completion(command, session, **options)

        assert dict(result['hints']) == {hint: kind.capitalize() + ' interface name'}
        assert hint not in dict(result['candidates'])
        assert not result['extension'] and result['replacement'] is None and not result['unique']

    assert controller.completion(command.rstrip(), session, explicit=True)['hints']


@pytest.mark.parametrize('kind,name', [('ethernet', 'eth0'), ('dummy', 'dum0')])
def test_mtu_direct_default_is_effective_only(controller, engine, session, monkeypatch, kind, name):
    monkeypatch.setattr(interfaces, 'exists', lambda value: kind == 'ethernet')
    plans = []
    monkeypatch.setattr(interfaces.manager, 'replace', lambda owner, plan, **kwargs: plans.append(plan[name]['attributes']['mtu']))

    assert engine.schema.defaults({}) == {}

    controller.execute(f'set interfaces {kind} {name}', session)

    assert engine.view(session) == {'interfaces': {kind: {name: {}}}}
    assert engine.commit(session)['results'][kind]['success']
    assert plans[-1] == 1500

    engine.save(session)

    assert engine.running == engine.store.read('boot.json') == {'interfaces': {kind: {name: {}}}}

    controller.execute(f'set interfaces {kind} {name} mtu 9000', session)

    assert engine.commit(session)['results'][kind]['success']
    assert plans[-1] == 9000

    controller.execute(f'delete interfaces {kind} {name} mtu', session)
    controller.execute(f'set interfaces {kind} {name}', session)

    assert engine.commit(session)['results'][kind]['success']
    assert plans[-1] == 1500
    assert engine.running == {'interfaces': {kind: {name: {}}}}


def test_interface_validator_removed_and_naming_remains_regex_based():
    assert 'interface' not in REGISTRY

    schema = Schema.bundled()

    for kind, prefix in [('ethernet', 'eth'), ('dummy', 'dum')]:
        for name in [prefix + '0', prefix + '10', prefix + '1' * 20]:
            assert schema.resolve(['interfaces', kind, name]).value == name

        with pytest.raises(RouterError):
            schema.resolve(['interfaces', kind, prefix + 'N'])


def test_show_interface_shorthand_runs_operational_script(controller, session, monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append(argv)
        return 'All interfaces (placeholder)\n'

    monkeypatch.setattr('nvyr.controller.cmd', run)

    assert controller.execute('show interface')['text'] == 'All interfaces (placeholder)\n'
    assert controller.execute('run show interface', session)['text'] == 'All interfaces (placeholder)\n'
    assert calls == [['interfaces.nvyr.op', 'show']] * 2
