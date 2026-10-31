"""Safety and observation contracts for the live interface suites."""

from types import SimpleNamespace
import json

import pytest

from nvyr.helpers import interfaces
from nvyr.tree import lookup
from smoketests import assertions, interface_support
from tests.test_static_smoketest import local_session


@pytest.fixture
def request_state():
    return SimpleNamespace(session=SimpleNamespace(shouldstop=False))


@pytest.fixture
def empty_host(monkeypatch):
    monkeypatch.setattr(interface_support, 'cmd', lambda argv: '[]')


def test_existing_name_does_not_delete_user_configuration(local_session, request_state, empty_host):
    """A reservation collision fails without claiming or cleaning the user's device."""
    local_session.set('set interfaces dummy dum990 description original')
    local_session.commit()
    original = local_session.get_config()

    with pytest.raises(AssertionError, match='already configured or referenced'):
        with interface_support.interface_test(local_session, request_state, {'dummy': ['dum990']}):
            pytest.fail('Preflight should reject the collision')

    assert local_session.get_config() == original
    assert not request_state.session.shouldstop


def test_empty_selected_ethernet_is_restored(local_session, request_state, monkeypatch):
    """An empty enabled spare profile and its automatic IPv6 link-local are reusable."""
    monkeypatch.setattr(interfaces, 'exists', lambda name: name == 'eth5')
    local_session.set('set interfaces ethernet eth5')
    local_session.commit()
    original = local_session.get_config()
    device = {'ifname': 'eth5', 'flags': ['UP'],
              'addr_info': [{'family': 'inet6', 'local': 'fe80::5', 'scope': 'link'}]}

    def command(arguments):
        if 'address' in arguments:
            return json.dumps([device])
        return json.dumps([{'dev': 'eth5', 'dst': 'fe80::/64', 'table': 'main'}]) if '-6' in arguments else '[]'

    monkeypatch.setattr(interface_support, 'cmd', command)
    original_exists = interface_support.Path.exists
    monkeypatch.setattr(interface_support.Path, 'exists',
                        lambda path: str(path) == '/sys/class/net/eth5/device' or original_exists(path))
    with interface_support.interface_test(local_session, request_state, {'ethernet': ['eth5']}, ethernet='eth5'):
        local_session.set('set interfaces ethernet eth5 description temporary')
        local_session.commit()
    assert local_session.get_config() == original


def test_empty_ethernet_does_not_hide_references(local_session, request_state, empty_host, monkeypatch):
    """Allowing the empty profile must not allow borrowing a port used by firewall policy."""
    monkeypatch.setattr(interfaces, 'exists', lambda name: name == 'eth5')
    local_session.set('set interfaces ethernet eth5')
    local_session.set('set firewall zone LAN interface eth5')
    local_session.commit()
    original = local_session.get_config()
    with pytest.raises(AssertionError, match='configured or referenced'):
        with interface_support.interface_test(local_session, request_state, {'ethernet': ['eth5']}, ethernet='eth5'):
            pytest.fail('Referenced spare must not be claimed')
    assert local_session.get_config() == original


def test_cleanup_removes_both_peers_before_vrf(local_session, request_state, empty_host):
    """A failed body still deletes the pair together before releasing its VRF."""
    with pytest.raises(RuntimeError, match='test failed'):
        with interface_support.interface_test(local_session, request_state,
                                              {'virtual-ethernet': ['veth990', 'veth991']}):
            local_session.set('set vrf name NVYRIFSMOKE table 41010')
            local_session.set('set interfaces virtual-ethernet veth990 peer-name veth991 vrf NVYRIFSMOKE')
            local_session.set('set interfaces virtual-ethernet veth991 peer-name veth990')
            local_session.commit()
            raise RuntimeError('test failed')

    running = local_session.get_config()
    assert running['interfaces']['virtual-ethernet'] == {}
    assert running['vrf']['name'] == {}
    assert not request_state.session.shouldstop


def test_cleanup_failure_stops_remaining_tests(local_session, request_state, empty_host, monkeypatch):
    """Local cleanup failures must trigger the shared full-configuration restore."""
    def fail_discard():
        raise RuntimeError('connection lost')

    with pytest.raises(RuntimeError, match='connection lost'):
        with interface_support.interface_test(local_session, request_state, {'dummy': ['dum990']}):
            monkeypatch.setattr(local_session, 'discard', fail_discard)

    assert 'cleanup failed' in request_state.session.shouldstop


def test_suite_reset_preserves_device_definition_and_removes_vrf(local_session, request_state,
                                                                 empty_host, monkeypatch):
    """Reset sends the baseline directly to netlinkd, without an empty owner update."""
    applied = []
    monkeypatch.setattr(interfaces.manager, 'replace', lambda owner, links, **kwargs: applied.append((owner, links)))
    with interface_support.interface_suite(local_session, request_state, {'dummy': ['dum990']},
                                           ['set interfaces dummy dum990']) as reset:
        local_session.set('set vrf name NVYRIFSMOKE table 41010')
        local_session.set('set interfaces dummy dum990 vrf NVYRIFSMOKE address 198.18.110.1/24')
        local_session.set('set interfaces dummy dum990 mtu 9000 description changed disable')
        local_session.commit()
        applied.clear()

        reset()

        assert [owner for owner, links in applied] == ['dummy', 'vrf']
        assert applied[1][1] == {}
        assert applied[0][0] == 'dummy'
        assert 'dum990' in applied[0][1]
        assert lookup(local_session.get_config(), ('interfaces', 'dummy', 'dum990')) == {}
        assert lookup(local_session.get_config(), ('vrf', 'name', 'NVYRIFSMOKE'), None) is None

        # A second reset with no intervening changes must not invoke the backend.
        applied.clear()
        reset()
        assert applied == []

    assert lookup(local_session.get_config(), ('interfaces', 'dummy', 'dum990'), None) is None


def test_suite_reset_retains_shared_vrfs(local_session, request_state, empty_host, monkeypatch):
    """Membership resets preserve both routing domains until the entire suite exits."""
    deleted = []
    delete = local_session.delete

    def record_delete(command):
        deleted.append(command)
        return delete(command)

    monkeypatch.setattr(local_session, 'delete', record_delete)
    with interface_support.interface_suite(
        local_session, request_state, {'dummy': ['dum990']},
        ['set interfaces dummy dum990'], vrfs=('NVYRIFSMOKE', 'NVYRIFSMOKE2'),
    ) as reset:
        baseline = local_session.get_config()['vrf']
        local_session.set('set interfaces dummy dum990 vrf NVYRIFSMOKE address 198.18.110.1/24')
        local_session.commit()
        reset()

        local_session.set('set interfaces dummy dum990 vrf NVYRIFSMOKE2')
        local_session.commit()
        reset()

        assert local_session.get_config()['vrf'] == baseline
        assert lookup(local_session.get_config(), ('interfaces', 'dummy', 'dum990')) == {}
        assert not any(command.startswith('delete vrf') for command in deleted)

    assert lookup(local_session.get_config(), ('vrf', 'name')) == {}
    assert 'delete vrf name NVYRIFSMOKE' in deleted
    assert 'delete vrf name NVYRIFSMOKE2' in deleted


def test_pair_reset_discards_rejected_edits_and_restores_both_peers(local_session, request_state, empty_host):
    """A failed function leaves a clean reciprocal pair available for the next one."""
    commands = ['set interfaces virtual-ethernet veth990 peer-name veth991',
                'set interfaces virtual-ethernet veth991 peer-name veth990']
    with interface_support.interface_suite(local_session, request_state,
                                           {'virtual-ethernet': ['veth990', 'veth991', 'veth992']}, commands) as reset:
        with pytest.raises(RuntimeError, match='test failed'):
            with interface_support.interface_case(request_state, reset):
                local_session.set('set interfaces virtual-ethernet veth990 mtu 9000')
                local_session.commit()
                local_session.set('set interfaces virtual-ethernet veth992 peer-name veth992')
                raise RuntimeError('test failed')

        links = lookup(local_session.get_config(), ('interfaces', 'virtual-ethernet'))
        assert links == {'veth990': {'peer-name': 'veth991'}, 'veth991': {'peer-name': 'veth990'}}
        assert local_session.get_config(source='candidate') == local_session.get_config()
        assert not request_state.session.shouldstop

    assert lookup(local_session.get_config(), ('interfaces', 'virtual-ethernet')) == {}


def test_reset_failure_stops_following_tests(request_state):
    """A reset failure is visible and must not allow another test to use dirty state."""
    def failed_reset():
        raise RuntimeError('reset failed')

    with pytest.raises(RuntimeError, match='reset failed'):
        with interface_support.interface_case(request_state, failed_reset):
            pass

    assert 'Interface reset failed' in request_state.session.shouldstop


def test_ethernet_requires_explicit_selection():
    """No Ethernet port is selected from inventory or a default name."""
    request = SimpleNamespace(config=SimpleNamespace(getoption=lambda option: None))
    with pytest.raises(pytest.skip.Exception, match='--ethernet-interface'):
        interface_support.spare_ethernet(request)


def test_selected_ethernet_is_not_replaced_by_another_port():
    """An explicit selection is passed unchanged to the preflight checks."""
    request = SimpleNamespace(config=SimpleNamespace(getoption=lambda option: 'eth2'))
    assert interface_support.spare_ethernet(request) == 'eth2'


@pytest.mark.parametrize('device, message', [
    ({'flags': ['UP']}, 'initially be down'),
    ({'flags': [], 'addr_info': [{'local': '192.0.2.1'}]}, 'already has addresses'),
    ({'flags': [], 'master': 'BLUE'}, 'already has a master'),
])
def test_in_use_ethernet_is_not_modified(device, message, local_session, request_state, monkeypatch):
    """Explicit selection cannot bypass the spare-port preflight restrictions."""
    def inventory(arguments):
        if 'address' in arguments:
            return json.dumps([{'ifname': 'eth1', **device}])
        return '[]'

    monkeypatch.setattr(interface_support, 'cmd', inventory)
    monkeypatch.setattr(interface_support.Path, 'exists', lambda path: True)
    with pytest.raises(AssertionError, match=message):
        with interface_support.interface_test(local_session, request_state,
                                              {'ethernet': ['eth1']}, ethernet='eth1'):
            pytest.fail('Preflight must fail')

    assert local_session.get_config() == {}
    assert not request_state.session.shouldstop


def test_native_link_group_and_named_peer(monkeypatch):
    """iproute2 emits signed group strings and same-namespace peers by name."""
    devices = [
        {'ifname': 'veth990', 'ifindex': 10, 'link': 'veth991', 'group': '-1',
         'flags': ['UP'], 'linkinfo': {'info_kind': 'veth'}},
        {'ifname': 'veth991', 'ifindex': 11, 'link': 'veth990', 'group': '0', 'flags': ['UP']},
    ]
    monkeypatch.setattr(assertions, 'cmd', lambda argv: json.dumps(devices))

    assert assertions.assert_link('veth990', kind='veth', peer='veth991', group=4294967295, up=True)['ifindex'] == 10
    assertions.assert_link('veth991', peer='veth990', group=0)


def test_tentative_addresses_do_not_pass_assertion(monkeypatch):
    """An address must complete detection rather than only appear in a dump."""
    values = iter([
        {'eth1': {'addr_info': [{'local': '2001:db8::1', 'prefixlen': 64, 'tentative': True}]}},
        {'eth1': {'addr_info': [{'local': '2001:db8::1', 'prefixlen': 64}]}},
    ])
    monkeypatch.setattr(assertions, 'link_inventory', lambda: next(values))
    monkeypatch.setattr('smoketests.support.time.sleep', lambda seconds: None)
    assertions.assert_link_addresses('eth1', '2001:db8::1/64')


def test_configuration_address_check_does_not_wait_for_carrier(monkeypatch):
    """Configuration smoke checks installed prefixes; functional checks still wait for DAD."""
    monkeypatch.setattr(assertions, 'link_inventory', lambda: {
        'eth1': {'addr_info': [
            {'local': '2001:db8::1', 'prefixlen': 64, 'tentative': True},
        ]},
    })

    assertions.assert_configured_link_addresses('eth1', '2001:db8::1/64')


def test_existing_table_blocks_setup(local_session, request_state, monkeypatch):
    """An unconfigured native VRF can still own a reserved routing table."""
    monkeypatch.setattr(interface_support, 'cmd', lambda argv: json.dumps([
        {'ifname': 'existing', 'linkinfo': {'info_data': {'table': 41010}}},
    ]))
    with pytest.raises(AssertionError, match='routing table is already in use'):
        with interface_support.interface_test(local_session, request_state, {'dummy': ['dum990']}):
            pytest.fail('Preflight must fail')
    assert local_session.get_config() == {}
