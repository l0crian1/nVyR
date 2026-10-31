"""Temporary upstream map restrictions must not block working sets or map keys."""

from copy import deepcopy

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import ValidationError
from tests.test_firewall_maps import rendered


AFFECTED_PATHS = [
    ('zone',),
    ('original', 'zone'),
    ('reply', 'zone'),
    ('original', 'packets'),
    ('reply', 'packets'),
    ('total', 'packets'),
    ('original', 'bytes'),
    ('reply', 'bytes'),
    ('total', 'bytes'),
    ('original', 'average-packet-size'),
    ('reply', 'average-packet-size'),
    ('total', 'average-packet-size'),
]


def map_definition(path, count, populated=True):
    """Build a valid map with the requested conntrack field and harmless extra keys."""
    selectors = {}
    values = {}
    selector_node = selectors
    value_node = values
    for name in path[:-1]:
        selector_node[name] = {}
        value_node[name] = {}
        selector_node = selector_node[name]
        value_node = value_node[name]
    selector_node[path[-1]] = True
    value_node[path[-1]] = '3'

    mapping = {
        'match': {'connection': selectors},
        'result-type': 'verdict',
    }
    entry = {'connection': values, 'result': {'action': 'accept'}}
    additional_fields = [
        ('packet-mark', '42'),
        ('dscp', '8'),
        ('protocol', 'udp'),
        ('source-port', '53099'),
    ]
    for name, value in additional_fields[:count - 1]:
        mapping['match'][name] = True
        entry[name] = value
    if populated:
        mapping['entry'] = {'ONE': entry}
    return mapping


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('path', AFFECTED_PATHS)
@pytest.mark.parametrize('populated', [False, True])
def test_single_field_conntrack_maps_are_rejected(family, path, populated):
    mapping = map_definition(path, 1, populated)

    with pytest.raises(ValidationError, match='incorrect byte order') as error:
        firewall.verify_map(family, 'BROKEN', mapping, {})

    assert f'firewall group map {family} BROKEN' in str(error.value)
    assert 'connection ' + ' '.join(path) in str(error.value)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('path', AFFECTED_PATHS)
@pytest.mark.parametrize('populated', [False, True])
def test_five_field_conntrack_maps_are_rejected(family, path, populated):
    mapping = map_definition(path, 5, populated)

    with pytest.raises(ValidationError, match='five-field maps.*lists their keys incorrectly'):
        firewall.verify_map(family, 'BROKEN', mapping, {})


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('path', AFFECTED_PATHS)
@pytest.mark.parametrize('count', [2, 3, 4])
def test_working_conntrack_concatenations_remain_available(family, path, count):
    mapping = map_definition(path, count)
    original = deepcopy(mapping)

    firewall.verify_map(family, 'WORKING', mapping, {})

    assert mapping == original


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('path', AFFECTED_PATHS)
@pytest.mark.parametrize('count', [1, 5])
def test_equivalent_match_groups_are_not_restricted(family, path, count):
    group = map_definition(path, count)
    del group['result-type']
    del group['entry']['ONE']['result']

    firewall.verify_match_group(family, 'WORKING', group)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
@pytest.mark.parametrize('path', [('id',), ('mark',), ('expiration',)])
def test_other_single_field_conntrack_maps_remain_available(family, path):
    mapping = map_definition(path, 1)
    if path == ('expiration',):
        mapping['entry']['ONE']['connection']['expiration'] = '3s'

    firewall.verify_map(family, 'WORKING', mapping, {})


def test_five_field_packet_maps_remain_available():
    mapping = {
        'match': {
            'source-address': True, 'destination-address': True,
            'protocol': True, 'source-port': True, 'destination-port': True,
        },
        'result-type': 'verdict',
    }

    firewall.verify_map('ipv4', 'WORKING', mapping, {})
    firewall.verify_map('ipv6', 'WORKING', mapping, {})


def test_normal_firewall_verification_checks_unused_maps():
    tree = {'firewall': {'group': {'map': {'ipv4': {
        'BROKEN': map_definition(('zone',), 1),
    }}}}}

    with pytest.raises(ValidationError, match='incorrect byte order'):
        rendered(tree)


def test_two_affected_fields_can_share_a_map():
    mapping = {
        'match': {'connection': {'zone': True, 'original': {'bytes': True}}},
        'result-type': 'verdict',
        'entry': {'ONE': {
            'connection': {'zone': '3', 'original': {'bytes': '1k'}},
            'result': {'action': 'accept'},
        }},
    }

    firewall.verify_map('ipv4', 'WORKING', mapping, {})
    firewall.verify_map('ipv6', 'WORKING', mapping, {})


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_cli_candidate_can_correct_a_rejected_map(controller, engine, session, family):
    prefix = f'set firewall group map {family} CT'
    controller.execute(f'{prefix} match connection zone', session)
    controller.execute(f'{prefix} result-type verdict', session)
    controller.execute(f'{prefix} entry first connection zone 3 result action accept', session)

    with pytest.raises(ValidationError, match='incorrect byte order'):
        rendered(engine.view(session))

    controller.execute('set firewall global-options connection-accounting', session)
    controller.execute(f'{prefix} match connection original bytes', session)
    controller.execute(f'{prefix} entry first connection original bytes 1k', session)

    assert 'typeof ct zone . ct original bytes : verdict' in rendered(engine.view(session))


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_cli_five_field_map_is_rejected_during_verification(controller, engine, session, family):
    prefix = f'set firewall group map {family} CT'
    controller.execute(f'{prefix} match packet-mark protocol source-port destination-port connection zone', session)
    controller.execute(f'{prefix} result-type verdict', session)
    controller.execute(
        f'{prefix} entry first packet-mark 42 protocol udp source-port 53099 '
        'destination-port 53098 connection zone 3 result action accept', session)

    with pytest.raises(ValidationError, match='five-field maps'):
        rendered(engine.view(session))
