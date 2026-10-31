import json
import re
import pytest

from nvyr.errors import RouterError
from nvyr.schema import Schema
from nvyr.helpers.suggestors import Context, interfaces, registry
from nvyr.helpers.validators import port


@pytest.mark.parametrize('allow_range', [False, True])
@pytest.mark.parametrize('value', ['1', '80', '65535'])
def test_port_validator_accepts_single_ports(value, allow_range):
    assert port(value, allow_range=allow_range)


@pytest.mark.parametrize('value', ['1-65535', '80-81', '80-80', '65535-65535'])
def test_port_validator_ranges_require_opt_in(value):
    assert port(value, allow_range=True)
    assert not port(value)


@pytest.mark.parametrize('allow_range', [False, True])
@pytest.mark.parametrize('value', [
    '', '0', '65536', '999999', '080', '0080', '00080', '01-80', '80-090',
    '0-80', '80-65536', '90-80', '80-', '-80', '-', '--', '1-2-3', '1--2',
    'tcp', '1.5', '+80', ' 80', '80 ', '80\n', '80:90', '80 -90',
    '８０', '٨٠', '²', '1-９',
])
def test_port_validator_rejects_invalid_endpoints(value, allow_range):
    assert not port(value, allow_range=allow_range)


def value_schema(references, mode="AND", **options):
    return Schema({"kind": "node", "children": {"value": {
        "kind": "leaf_node", "validators": {"mode": mode, "checks": references},
    }}}, **options)


def test_interface_suggestor_arguments_participate_in_all_completion_modes(controller, session, monkeypatch):
    calls = []
    def links(command):
        calls.append(command)
        assert command == ['ip', '-j', '-d', 'link', 'show']
        return json.dumps([
            {'ifname': 'lo'},
            {'ifname': 'eth0', 'ifalias': 'WAN uplink'},
            {'ifname': 'dum2', 'ifalias': 'Routing test interface'},
            {'ifname': 'dum10', 'ifalias': ''},
        ])

    monkeypatch.setattr('nvyr.helpers.suggestors.cmd', links)
    command = 'set interfaces dummy '

    for options in [{}, {'tab': True}, {'space': True}]:
        controller.completion(command, session, **options)

    assert len(calls) == 3

    candidates = dict(controller.completion(command, session, explicit=True)['candidates'])

    assert list(candidates) == ['dum10', 'dum2', '<Enter>']
    assert candidates['dum2'] == 'Routing test interface'
    assert candidates['dum10'] == ''
    assert len(calls) == 4
    assert [item.value for item in interfaces(Context())] == ['dum10', 'dum2', 'eth0', 'lo']
    assert [item.value for item in registry()['interfaces'](prefix='eth')] == ['eth0']
    assert registry()['interfaces'](prefix='eth')[0].description == 'WAN uplink'

    controller.execute('set interfaces dummy dum99', session)  # Discovery does not restrict names.

    assert dict(controller.completion(command, session)['candidates'])['dum99'] == ''


def test_interface_suggestor_filters_device_kinds_and_keeps_candidate_names(monkeypatch):
    """Link metadata filters renamed infrastructure devices without excluding VRF members."""
    devices = [
        {'ifname': 'BLUE', 'linkinfo': {'info_kind': 'vrf'}},
        {'ifname': 'register4', 'link_type': 'pimreg'},
        {'ifname': 'pim6reg', 'link_type': 'pimreg'},
        {'ifname': 'fallback-ip', 'link_type': 'ipip'},
        {'ifname': 'fallback-gre', 'link_type': 'gre'},
        {'ifname': 'mirror', 'link_type': 'ether', 'linkinfo': {'info_kind': 'erspan'}},
        {'ifname': 'eth0', 'linkinfo': {'info_slave_kind': 'vrf'}},
        {'ifname': 'pimreg-user', 'linkinfo': {'info_kind': 'dummy'}},
        {'ifname': 'lo'},
    ]
    monkeypatch.setattr('nvyr.helpers.suggestors.cmd', lambda command: json.dumps(devices))
    configuration = {'interfaces': {'dummy': {'dum99': {}, 'register4': {}}}}

    suggestions = interfaces(Context(configuration=configuration))

    assert [item.value for item in suggestions] == ['dum99', 'eth0', 'lo', 'pimreg-user']
    assert [item.value for item in interfaces(Context(), prefix='pim')] == ['pimreg-user']


def test_regex_arguments_fullmatch_and_native_validation(monkeypatch):
    refs = [{'name': 'text'}, {'name': 'regex', 'args': {'pattern': r'dum[0-9]+'}}]
    schema = value_schema(dict(zip(['single-line', 'interface-format'], refs)))

    # Compilation is complete at schema load; repeated validation reuses it.
    original_compile = re.compile

    def compile_other(pattern, *args, **kwargs):
        assert pattern != r'dum[0-9]+', 'Validator pattern was recompiled'

        return original_compile(pattern, *args, **kwargs)

    monkeypatch.setattr('nvyr.helpers.validators.re.compile', compile_other)

    assert schema.resolve(['value', 'dum10']).value == 'dum10'

    schema.validate_configuration({'value': 'dum2'})

    for value in ['eth0', 'dum', 'xdum2', 'dum2x']:
        with pytest.raises(RouterError, match='regular expression'):
            schema.resolve(['value', value])

        with pytest.raises(RouterError):
            schema.validate_configuration({'value': value})


@pytest.mark.parametrize('mode,accepted,rejected', [
    ('AND', ['dum2'], ['dum22', 'eth2']),
    ('OR', ['dum22', 'eth2'], ['eth22']),
])
def test_argument_validators_preserve_boolean_combinations(mode, accepted, rejected):
    refs = [
        {'name': 'regex', 'args': {'pattern': r'dum[0-9]+'}},
        {'name': 'regex', 'args': {'pattern': r'[a-z]+[0-9]'}},
    ]
    schema = value_schema(dict(zip(['dummy-prefix', 'single-digit'], refs)), mode)

    for value in accepted:
        schema.resolve(['value', value])

    for value in rejected:
        with pytest.raises(RouterError):
            schema.resolve(['value', value])


@pytest.mark.parametrize('reference', [
    {'name': 'regex'}, {'name': 'regex', 'args': {'pattern': '['}},
    {'name': 'regex', 'args': {'pattern': 123}},
    {'name': 'regex', 'args': {'pattern': '.*', 'typo': True}},
    {'name': 'text', 'args': []}, {'name': 'text', 'arguments': {}},
    {'name': 'missing'}, 42, 'text',
])
def test_invalid_validator_arguments_fail_at_schema_load(reference):
    with pytest.raises(ValueError):
        value_schema({'format': reference})


@pytest.mark.parametrize('validation', [
    [], None, {'checks': []}, {'checks': {'': 'text'}}, {'checks': {1: 'text'}},
    {'checks': {}, 'names': []}, {'names': ['text']}, {'names': {'text': {}}},
    {'checks': {}, 'typo': {}}, {'checks': {}, 'mode': 'INVALID'},
])
def test_invalid_check_definitions_fail_at_schema_load(validation):
    with pytest.raises(ValueError):
        Schema({'kind': 'leaf_node', 'validators': validation})


def test_custom_callbacks_receive_named_arguments_and_context():
    calls = []
    schema = value_schema({'length': {'name': 'length', 'args': {'minimum': 3}}},
                          validators={'length': lambda value, minimum: len(value) >= minimum})
    schema.resolve(['value', 'abc'])

    with pytest.raises(RouterError):
        schema.resolve(['value', 'ab'])

    schema = Schema({'kind': 'node', 'children': {'tag': {
        'kind': 'tag_node', 'suggestors': [{'name': 'custom', 'args': {'prefix': 'x', 'limit': 2}}],
    }}}, suggestors={'custom': lambda prefix, limit: calls.append((prefix, limit)) or ['x1', 'x2']})

    assert not calls
    assert schema.candidates(schema.resolve(['tag']), '', {}, explicit=True) == [('x1', 'Suggested value'), ('x2', 'Suggested value')]
    assert calls == [('x', 2)]


def test_invalid_suggestor_arguments_fail_without_running_discovery():
    with pytest.raises(ValueError, match='Invalid arguments'):
        Schema({'kind': 'node', 'children': {'tag': {
            'kind': 'tag_node', 'suggestors': [{'name': 'interfaces', 'args': {'typo': 'dum'}}],
        }}})


def test_string_suggestor_reference_is_rejected():
    with pytest.raises(ValueError, match='Callback must be an object'):
        Schema({'kind': 'tag_node', 'suggestors': ['interfaces']})
