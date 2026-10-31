import pytest

from nvyr.errors import RouterError
from nvyr.schema import Schema


def test_hints_are_separate_from_every_completion_operation(controller, session):
    command = 'set interfaces ethernet eth0 address '

    assert controller.completion(command.rstrip(), session, explicit=True)['hints']

    for options in ({}, {'tab': True}, {'explicit': True}, {'space': True}):
        result = controller.completion(command, session, **options)

        assert dict(result['candidates']) == {'dhcp': 'Acquire an IPv4 address using DHCP'}
        assert result['replacement'] == 'dhcp' and result['extension'] == 'dhcp'
        assert dict(result['hints']) == {'x.x.x.x/x': 'IPv4 address with mask',
                                        'x:x:x:x:x:x/x': 'IPv6 address with mask'}

        result = controller.completion(command + 'x', session, **options)

        assert not result['extension'] and result['replacement'] is None

    controller.execute('edit interfaces ethernet eth0', session)

    assert controller.completion('set address ', session)['hints']
    assert not controller.completion('set address dhcp ', session)['hints']


def test_list_validation_is_independent_of_choices_and_validates_defaults():
    leaf = {'kind': 'leaf_node', 'choices': {'common': 'Common suggestion'},
            'validators': {'checks': {'list': {'name': 'list', 'args': {'values': 'common uncommon'}}}}}
    schema = Schema({'kind': 'node', 'children': {'value': leaf}})

    assert schema.resolve(['value', 'uncommon']).value == 'uncommon'

    with pytest.raises(RouterError):
        schema.validate_configuration({'value': 'bad'})

    leaf['default'] = {'mode': 'always', 'value': 'bad'}

    with pytest.raises(RouterError):
        Schema({'kind': 'node', 'children': {'value': leaf}})


@pytest.mark.parametrize('hints', [['literal'], 'format', {'format': 42}, {'': 'empty'}])
def test_bad_hints_are_schema_errors(hints):
    with pytest.raises(ValueError, match='Hints'):
        Schema({'kind': 'node', 'children': {'value': {'kind': 'leaf_node', 'hints': hints}}})


@pytest.mark.parametrize('kind,name', [('ethernet', 'eth'), ('ethernet', 'ens0'), ('ethernet', 'eth0x'),
                                      ('dummy', 'dum'), ('dummy', 'dummy0'), ('dummy', 'dum-1')])
def test_interface_name_restrictions(controller, session, kind, name):
    with pytest.raises(RouterError):
        controller.execute(f'set interfaces {kind} {name}', session)


@pytest.mark.parametrize('setting', ['mac ff:ff:ff:ff:ff:ff', 'mac 00:00:00:00:00:00',
                                     'mac 00:11:22:33:44:zz', 'mtu 1279', 'mtu 65536', 'mtu 1.5'])
def test_invalid_link_attributes(controller, session, setting):
    with pytest.raises(RouterError):
        controller.execute(f'set interfaces ethernet eth0 {setting}', session)


def test_dummy_has_no_dhcp_but_accepts_shared_attributes(controller, session):
    with pytest.raises(RouterError):
        controller.execute('set interfaces dummy dum0 address dhcp', session)

    controller.execute('set interfaces dummy dum0 address 192.0.2.1/24 address 2001:db8::1/64 '
                       'mac 02:11:22:33:44:55 mtu 9000 description "Core loopback" disable', session)

    assert controller.engine.view(session)['interfaces']['dummy']['dum0']['description'] == 'Core loopback'
