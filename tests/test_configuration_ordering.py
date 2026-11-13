"""Natural ordering across configuration views, without changing stored values."""

from copy import deepcopy
import json
import re
from types import MappingProxyType

import pytest

from nvyr.render import json_text, marked_json


def json_side(text, marker):
    return json.loads('\n'.join(line[2:] for line in text.splitlines()
                                if line.startswith(('  ', marker + ' '))))


def test_json_orders_nested_names_and_preserves_list_order():
    original = {
        'eth10': {'description': 'ten', 'address': ['10.0.0.10/24', '10.0.0.2/24']},
        'eth02': {}, 'eth2': {},
        'eth1.100': {}, 'eth1.20': {},
    }
    before = deepcopy(original)
    rendered = json.loads(json_text(MappingProxyType(original)))

    assert list(rendered) == ['eth1.20', 'eth1.100', 'eth2', 'eth02', 'eth10']
    assert list(rendered['eth10']) == ['address', 'description']
    assert rendered['eth10']['address'] == before['eth10']['address']
    assert original == before
    assert list(original) == list(before)


@pytest.mark.parametrize('before,after', [
    ({'5': {}, '10': {}, '25': {}}, {'5': {}, '10': {}}),
    ({'5': {}, '10': {}}, {'5': {}, '10': {}, '25': {}}),
    ({'5': {'value': 'old'}, '10': {}}, {'5': {'value': 'new'}, '10': {}}),
])
def test_natural_diff_order_keeps_both_json_sides_valid(before, after):
    rendered = marked_json(before, after)
    old = json_side(rendered, '-')
    new = json_side(rendered, '+')

    assert old == before
    assert new == after
    assert list(old) == sorted(before, key=int)
    assert list(new) == sorted(after, key=int)


@pytest.mark.parametrize('scoped', [False, True])
def test_every_configuration_view_orders_rules(controller, engine, session, scoped):
    numbers = ['1000', '5', '10010', '25', '10', '10005', '30']
    for number in numbers:
        controller.execute(f'set firewall ipv4 input filter rule {number} action drop', session)
    engine.commit(session)
    engine.save(session)

    for number in numbers:
        if number == '25':
            controller.execute('delete firewall ipv4 input filter rule 25', session)
        else:
            controller.execute(f'set firewall ipv4 input filter rule {number} action accept', session)
    for number in ('10011', '2'):
        controller.execute(f'set firewall ipv4 input filter rule {number} action accept', session)

    if scoped:
        controller.execute('edit firewall ipv4 input', session)

    running = deepcopy(engine.running)
    candidate = deepcopy(engine.view(session))
    expected_running = ['5', '10', '25', '30', '1000', '10005', '10010']
    expected_changes = ['2', '5', '10', '25', '30', '1000', '10005', '10010', '10011']
    views = ['show', 'show running-configuration', 'show candidate-configuration', 'compare',
             'show all', 'show running-configuration all', 'show candidate-configuration all']

    for view in views:
        expected = expected_running if view.startswith('show running-configuration') else expected_changes
        if view in ('show all', 'show candidate-configuration all'):
            expected = [number for number in expected_changes if number != '25']
        for commands in (False, True):
            command = view + (' | commands' if commands else '')
            text = controller.execute(command, session)['text']
            if commands:
                matches = re.findall(r'\brule ([0-9]+)(?:\s|$)', text)
            elif view == 'compare':
                matches = re.findall(r'(?:^| / )rule / ([0-9]+)(?: /|:)', text, re.MULTILINE)
            else:
                matches = re.findall(r'"([0-9]+)":', text)
            assert list(dict.fromkeys(matches)) == expected, command

    assert engine.running == running
    assert engine.view(session) == candidate

    engine.commit(session)
    for comparison in ('compare saved', 'compare 1'):
        text = controller.execute(comparison, session)['text']
        matches = re.findall(r'(?:^| / )rule / ([0-9]+)(?: /|:)', text, re.MULTILINE)
        assert list(dict.fromkeys(matches)) == expected_changes, comparison
        commands = controller.execute(comparison + ' | commands', session)['text']
        matches = re.findall(r'\brule ([0-9]+)(?:\s|$)', commands)
        assert list(dict.fromkeys(matches)) == expected_changes, comparison
