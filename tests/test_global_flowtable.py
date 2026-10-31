"""Global flow enrollment precedes state acceptance and follows object lifecycle."""

from copy import deepcopy

import pytest

from nvyr.errors import ValidationError
from tests.test_firewall_maps import rendered


def configuration():
    return {'firewall': {
        'flowtable': {'FAST': {'interface': ['eth0', 'eth1']}},
        'global-options': {'flowtable': 'FAST', 'state-policy': {'established': {'action': 'accept'}}},
        'ipv4': {'input': {'filter': {}}, 'output': {'filter': {}}},
    }}


@pytest.fixture(autouse=True)
def interfaces_exist(monkeypatch):
    monkeypatch.setattr('nvyr.helpers.interfaces.exists', lambda name: True)


def test_global_enrollment_only_precedes_forward_state_accept():
    text = rendered(configuration())
    forward = text.split('chain forward {')[1].split('\n    }')[0]
    assert forward.index('ct state established meta l4proto { tcp, udp } flow add @flowtable_FAST counter') < forward.index('ct state vmap')
    assert text.count('flow add @flowtable_FAST') == 1
    assert 'chain ipv4_forward {' in text and 'chain ipv6_forward {' in text
    assert 'global-offload|Established forwarding flows' in forward


@pytest.mark.parametrize('action', [None, 'drop', 'reject'])
def test_global_enrollment_requires_established_accept(action):
    config = configuration()
    config['firewall']['global-options']['state-policy'] = {}
    if action is not None:
        config['firewall']['global-options']['state-policy']['established'] = {'action': action}
    with pytest.raises(ValidationError, match='requires state-policy established action accept'):
        rendered(config)


def test_global_enrollment_rejects_missing_flowtable():
    config = configuration()
    config['firewall']['global-options']['flowtable'] = 'MISSING'
    with pytest.raises(ValidationError, match='not a configured flowtable'):
        rendered(config)


def test_global_flowtable_changes_release_forward_references():
    before = configuration()
    after = deepcopy(before)
    after['firewall']['flowtable']['FAST']['interface'] = ['eth2']
    text = rendered(after, before)
    assert text.index('flush chain inet nvyr_filter forward') < text.index('destroy flowtable inet nvyr_filter flowtable_FAST')
    assert 'chain forward {' in text
    assert 'destroy chain inet nvyr_filter input' not in text

    del after['firewall']['global-options']['flowtable']
    del after['firewall']['flowtable']
    text = rendered(after, before)
    assert 'destroy flowtable inet nvyr_filter flowtable_FAST' in text
    assert 'flow add' not in text


def test_global_target_change_rebuilds_forward(controller, engine, session):
    controller.execute('set firewall flowtable FAST interface eth0', session)
    controller.execute('set firewall flowtable NEXT interface eth1', session)
    controller.execute('set firewall global-options state-policy established action accept', session)
    controller.execute('set firewall global-options flowtable FAST', session)
    assert engine.commit(session)['results']['firewall']['success']
    with pytest.raises(ValidationError, match='referenc'):
        controller.execute('delete firewall flowtable FAST', session)

    before = engine.running
    controller.execute('set firewall global-options flowtable NEXT', session)
    text = rendered(engine.view(session), before)
    assert 'destroy chain inet nvyr_filter forward' in text
    assert 'flow add @flowtable_NEXT' in text

    suggestions = controller.completion('set firewall global-options flowtable ', session)
    assert {'FAST', 'NEXT'} <= dict(suggestions['candidates']).keys()
