"""VRF schema, commit lifecycle and shared Netlink ownership/recovery."""

from copy import deepcopy
import socket

import pytest

from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import interfaces
from nvyr.helpers.link_manager import Manager
from nvyr.helpers.netlink import read_attributes, TYPES
from nvyr.helpers.validators import integer_ranges, prepare_integer_ranges
from tests.test_netlink import Kernel, Leases, Message


def test_lifecycle_uses_gathered_relationships_and_applies_prepared_links(monkeypatch):
    from types import SimpleNamespace
    from nvyr.config_scripts import vrf
    from nvyr.tree import ReadOnlyTree

    tree = ReadOnlyTree({'vrf': {'name': {'BLUE': {'table': '101'}}}})
    configuration = vrf.get_config(SimpleNamespace(effective=tree, previous=tree))
    before = deepcopy(configuration)
    later = SimpleNamespace(recovery=False)
    requests, applied = [], []
    monkeypatch.setattr(interfaces.manager, 'request', lambda *args, **kwargs: requests.append((args, kwargs)))
    monkeypatch.setattr(interfaces.manager, 'replace', lambda *args, **kwargs: applied.append((args, kwargs)))

    vrf.verify(configuration, later)
    links = vrf.generate(configuration, later)
    monkeypatch.setattr(vrf, 'link_definitions', lambda *args: pytest.fail('apply formatted links'))
    vrf.apply(links, later)

    assert links == {'BLUE': {'kind': 'vrf', 'attributes': {'table': 101}}}
    assert requests == [(('validate',), {'owner': 'vrf', 'links': links, 'recovery': False})]
    assert applied == [(('vrf', links), {'recovery': False})]
    assert configuration == before


def test_gathered_zone_membership_prevents_vrf_master_creation():
    from types import SimpleNamespace
    from nvyr.config_scripts import vrf

    tree = {'vrf': {'name': {'BLUE': {'table': '101'}}},
            'firewall': {'zone': {'LAN': {'interface': ['BLUE']}}}}
    configuration = vrf.get_config(SimpleNamespace(effective=tree, previous={}))
    with pytest.raises(ValidationError, match='VRF masters cannot belong to firewall zone LAN'):
        vrf.verify(configuration, SimpleNamespace(recovery=False))


@pytest.mark.parametrize('value,accepted', [
    ('99', False), ('100', True), ('251', True), ('252', False),
    ('253', False), ('254', False), ('255', False), ('256', True),
    ('4294967295', True), ('4294967296', False), ('-1', False),
    ('1.5', False), ('100-101', False), ('foo', False),
])
def test_table_ranges_validate_at_command_entry(controller, session, value, accepted):
    command = f'set vrf name BLUE table {value}'
    if accepted:
        controller.execute(command, session)
        assert controller.engine.view(session)['vrf']['name']['BLUE']['table'] == value
    else:
        with pytest.raises(ValidationError):
            controller.execute(command, session)


def test_discontiguous_validator_is_generic():
    ranges = [[-10, -5], [0, 0], [10, 20]]
    compiled = prepare_integer_ranges(ranges)
    for value in ('-10', '-7', '-5', '0', '10', '20'):
        assert compiled(value) and integer_ranges(value, ranges)

    for value in ('-11', '-4', '1', '21', '', '1.2'):
        assert not compiled(value) and not integer_ranges(value, ranges)


@pytest.mark.parametrize('ranges', [None, [], '1-5', [1], [[1]], [[2, 1]], [[True, 5]], [[1, '5']]])
def test_malformed_discontiguous_ranges_rejected(ranges):
    with pytest.raises(ValueError):
        prepare_integer_ranges(ranges)


@pytest.mark.parametrize('name', ['default', '123', 'a' * 16, 'bad:name'])
def test_vrf_name_validation(controller, session, name):
    with pytest.raises(ValidationError):
        controller.execute(f'set vrf name {name} table 100', session)


def test_vrf_commit_check_apply_delete_and_table_change(controller, session, monkeypatch):
    requests, applied = [], []
    monkeypatch.setattr(interfaces.manager, 'request', lambda operation, **kw: requests.append((operation, kw)))
    monkeypatch.setattr(interfaces.manager, 'replace', lambda owner, links, **kw: applied.append((owner, links)))
    controller.execute('set vrf name BLUE table 100', session)
    controller.execute('set vrf name RED table 256', session)

    assert controller.engine.check(session)['results']['vrf']['success']
    assert not applied
    assert requests[-1][0] == 'validate'

    result = controller.engine.commit(session)
    expected = {'BLUE': {'kind': 'vrf', 'attributes': {'table': 100}},
                'RED': {'kind': 'vrf', 'attributes': {'table': 256}}}
    assert result['results'] == {'vrf_conntrack': {'success': True}, 'vrf': {'success': True}}
    assert applied == [('vrf', expected)]

    controller.execute('set vrf name BLUE table 101', session)
    failed = controller.engine.commit(session)['results']['vrf']
    assert not failed['success'] and 'delete and commit' in failed['error']
    assert len(applied) == 1
    assert controller.engine.running['vrf']['name']['BLUE']['table'] == '100'

    controller.execute('delete vrf', session)
    assert controller.engine.commit(session)['results']['vrf']['success']
    assert applied[-1] == ('vrf', {})

    controller.execute('set vrf name BLUE table 101', session)
    assert controller.engine.commit(session)['results']['vrf']['success']
    assert applied[-1][1]['BLUE']['attributes']['table'] == 101


def test_vrf_requires_table_and_rejects_duplicate_tables(controller, session):
    controller.execute('set vrf name BLUE', session)
    result = controller.engine.commit(session)['results']['vrf_conntrack']
    assert not result['success'] and 'BLUE' in result['error'] and 'required' in result['error']

    controller.execute('set vrf name BLUE table 100', session)
    controller.execute('set vrf name RED table 100', session)
    result = controller.engine.commit(session)['results']['vrf']
    assert not result['success'] and 'already configured' in result['error']


def test_vrf_completion_and_reference_inspection(controller, session):
    controller.execute('set vrf name BLUE table 100', session)
    assert controller.completion('set vrf name B', session, tab=True)['replacement'] == 'BLUE'
    assert 'table' in dict(controller.completion('set vrf name BLUE ', session, explicit=True)['candidates'])
    assert controller.execute('show references vrf name BLUE', session)['text'] == 'No references found.\n'


def test_interface_membership_schema_references_and_defaults(controller, session):
    controller.execute('set vrf name BLUE table 100', session)
    controller.execute('set interfaces dummy dum0 vrf BLUE link-group 4294967295', session)

    assert controller.completion('set interfaces dummy dum1 vrf B', session, tab=True)['replacement'] == 'BLUE'
    assert controller.engine.check(session)['results']['dummy']['success']
    assert controller.engine.commit(session)['results']['dummy']['success']

    with pytest.raises(ValidationError, match='referenc'):
        controller.execute('delete vrf name BLUE', session)

    controller.execute('delete interfaces dummy dum0 vrf', session)
    controller.execute('delete interfaces dummy dum0 link-group', session)
    configuration = controller.engine.view(session)['interfaces']['dummy']
    links = interfaces.NetlinkManager.definitions('dummy', interfaces.settings(configuration))

    assert links['dum0']['attributes']['vrf'] == ''
    assert links['dum0']['attributes']['link-group'] == 0
    controller.execute('delete vrf name BLUE', session)


def test_interface_membership_requires_configured_vrf(controller, session):
    controller.execute('set interfaces dummy dum0 vrf MISSING', session)
    result = controller.engine.check(session)['results']['dummy']

    assert not result['success']
    assert 'not configured' in result['error']


@pytest.mark.parametrize('value', ['-1', '4294967296', 'blue', '1.5'])
def test_link_group_invalid_values(controller, session, value):
    with pytest.raises(ValidationError):
        controller.execute(f'set interfaces dummy dum0 link-group {value}', session)


class VRFKernel(Kernel):
    def link(self, operation, **args):
        super().link(operation, **args)
        if operation == 'add' and args['kind'] == 'vrf':
            self.devices[args['ifname']]['attributes']['table'] = args['vrf_table']

    def device(self, name):
        device = super().device(name)
        if device and device['kind'] == 'vrf':
            device['message']['IFLA_LINKINFO'] = Message(
                IFLA_INFO_KIND='vrf', IFLA_INFO_DATA=Message(IFLA_VRF_TABLE=device['attributes']['table']))

        return device


@pytest.fixture
def backend(tmp_path):
    return Manager(VRFKernel(), Leases(), tmp_path, boot='first')


def definition(table):
    return {'kind': 'vrf', 'attributes': {'table': table}}


def test_vrf_netlink_lifecycle_drift_restart_and_removal(backend):
    backend.replace('vrf', {'BLUE': definition(100)})
    device = backend.kernel.device('BLUE')
    assert device['up'] and read_attributes(device['message'], TYPES['vrf'].keymap) == {'table': 100}

    backend.kernel.state('BLUE', False)
    backend.reconcile({'BLUE'})
    assert backend.kernel.device('BLUE')['up']

    del backend.kernel.devices['BLUE']
    restarted = Manager(backend.kernel, backend.dhcp, backend.path.parent, boot='first')
    restarted.reconcile()
    device = restarted.kernel.device('BLUE')
    assert device['up'] and device['attributes']['table'] == 100

    restarted.replace('vrf', {})
    assert restarted.kernel.device('BLUE') is None
    assert not restarted.state['records'] and not restarted.state['pending']


def test_vrf_reconciliation_repairs_shared_routing_rules(backend):
    """A full daemon audit repairs the policy even if the VRF device is unchanged."""
    backend.replace('vrf', {'BLUE': definition(100)})
    rules = backend.kernel.rule_socket
    rules.rule('del', family=socket.AF_INET6, priority=2000, l3mdev=1, action=7)
    rules.rule('add', family=socket.AF_INET, priority=0, table=255)

    restarted = Manager(backend.kernel, backend.dhcp, backend.path.parent, boot='first')
    restarted.reconcile()

    assert not restarted.failures
    assert sorted(rule.get_attr('FRA_PRIORITY') for rule in rules.get_rules(family=socket.AF_INET)) == [1000, 2000, 32765, 32766]
    assert sorted(rule.get_attr('FRA_PRIORITY') for rule in rules.get_rules(family=socket.AF_INET6)) == [1000, 2000, 32765, 32766]


def test_member_only_reconciliation_restores_provider_across_owner_order(backend):
    # An interface may have been configured before any VRF existed.
    backend.kernel.add('eth1')
    backend.replace('ethernet', {'eth1': {'kind': 'ethernet'}})
    backend.replace('vrf', {'BLUE': definition(100)})
    backend.replace('ethernet', {'eth1': {'kind': 'ethernet', 'attributes': {'vrf': 'BLUE'}}})
    old_index = backend.kernel.device('BLUE')['index']
    del backend.kernel.devices['BLUE']

    # A targeted member repair must include and recreate its managed dependency.
    backend.reconcile({'eth1'})

    new_index = backend.kernel.device('BLUE')['index']
    assert new_index != old_index
    assert backend.kernel.device('eth1')['attributes']['vrf'] == new_index
    assert not backend.failures


def test_vrf_netlink_table_change_compensates_and_preserves_state(backend):
    backend.replace('vrf', {'BLUE': definition(100)})
    before = deepcopy(backend.state['owners'])
    with pytest.raises(RouterError, match='table cannot be changed'):
        backend.replace('vrf', {'BLUE': definition(101)})

    assert backend.state['owners'] == before
    assert not backend.state['pending']
    assert backend.kernel.device('BLUE')['attributes']['table'] == 100


def test_failed_vrf_creation_rolls_back_other_devices(backend, monkeypatch):
    original = backend.kernel.link

    def fail(operation, **args):
        if operation == 'add' and args['ifname'] == 'RED':
            raise OSError('injected kernel failure')

        return original(operation, **args)

    monkeypatch.setattr(backend.kernel.ipr, 'link', fail)
    with pytest.raises(RouterError, match='previous configuration restored'):
        backend.replace('vrf', {'BLUE': definition(100), 'RED': definition(101)})

    assert not backend.kernel.devices
    assert not backend.state['records'] and not backend.state['pending']


def test_vrf_rejects_foreign_devices_and_other_owners(backend):
    backend.kernel.link('add', ifname='BLUE', kind='vrf', vrf_table=100)
    with pytest.raises(ValidationError, match='not owned'):
        backend.replace('vrf', {'BLUE': definition(100)})

    backend.replace('dummy', {'dum0': {'kind': 'dummy'}})
    with pytest.raises(ValidationError, match='another configuration owner'):
        backend.replace('vrf', {'dum0': definition(100)})


def test_failed_vrf_deletion_restores_devices_and_tables(backend, monkeypatch):
    links = {'BLUE': definition(100), 'RED': definition(256)}
    backend.replace('vrf', links)
    original = backend.kernel.link
    deleted = []

    def fail(operation, **args):
        if operation == 'del':
            if deleted:
                raise OSError('injected deletion failure')

            deleted.append(args['index'])

        return original(operation, **args)

    monkeypatch.setattr(backend.kernel.ipr, 'link', fail)
    with pytest.raises(RouterError, match='previous configuration restored'):
        backend.replace('vrf', {})

    for name, spec in links.items():
        device = backend.kernel.device(name)
        assert device['up'] and device['attributes']['table'] == spec['attributes']['table']

    assert not backend.state['pending']
