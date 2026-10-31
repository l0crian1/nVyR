"""Bridge observations and cleanup keep native scopes and the operational JSON contract."""

from copy import deepcopy
import json

import pytest

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.op_scripts import bridge


@pytest.fixture
def native_bridge(monkeypatch):
    """Provide two bridges so accidentally unscoped lookups expose unrelated state."""
    devices = []
    for name in ('br1', 'br2'):
        options = {
            'stp_state': 1,
            'vlan_filtering': 1,
            'hello_time': 200,
            'max_age': 2000,
            'forward_delay': 1500,
        }
        devices.append({
            'ifname': name,
            'flags': ['UP'],
            'mtu': 1500,
            'linkinfo': {'info_kind': 'bridge', 'info_data': options},
        })

    calls = []

    def execute(argv):
        calls.append(argv)
        if argv[0] == 'ip':
            return json.dumps(devices)
        if 'flush' in argv:
            return ''
        if argv[1] == 'vlan':
            return json.dumps([{'ifname': name, 'vlans': [{'vlan': vlan}]}
                               for name, vlan in (('br1', 10), ('eth1', 10), ('br2', 20), ('eth2', 20))])
        if 'link' in argv:
            return json.dumps([{'ifname': 'eth1', 'master': 'br1', 'state': 'forwarding'}])
        return '[]'

    monkeypatch.setattr(bridge, 'cmd', execute)
    return devices, calls


@pytest.mark.parametrize('section', [None, 'member', 'vlan', 'mac', 'multicast', 'spanning-tree'])
def test_raw_works_through_script_dispatch(native_bridge, capsys, section):
    """A direct Python return must also work when invoked as bridge.nvyr.op show --raw."""
    argv = ['show', '--bridge', 'br1', '--raw']
    if section:
        argv += ['--section', section]
    opmode.run(argv, namespace=vars(bridge))
    output = capsys.readouterr()
    value = json.loads(output.out)
    assert isinstance(value, dict if section == 'spanning-tree' else list)
    assert 'br2' not in output.out and 'eth2' not in output.out
    assert not output.err


def test_empty_bridge_inventory_and_unknown_selection(monkeypatch, capsys):
    monkeypatch.setattr(bridge, 'cmd', lambda argv: '[]')
    bridge.show()
    assert capsys.readouterr().out == 'No entries.\n'
    assert json.loads(bridge.show(raw=True)) == []
    with pytest.raises(OperationalError, match='br1 does not exist'):
        bridge.show('br1')


def test_spanning_tree_conversion_does_not_mutate_native_data(native_bridge, capsys):
    original = deepcopy(native_bridge[0])
    bridge.show('br1', section='spanning-tree')
    assert 'Hello (s)' in capsys.readouterr().out
    assert native_bridge[0] == original
    assert json.loads(bridge.show('br1', section='spanning-tree', raw=True))['hello_time'] == 200


def test_clear_only_targets_dynamic_entries_on_selected_bridge(native_bridge):
    bridge.clear('br1', member='eth1', vlan=20)
    assert native_bridge[1][-1] == ['bridge', 'fdb', 'flush', 'dev', 'br1', 'self', 'dynamic',
                                  'brport', 'eth1', 'vlan', '20']


def test_clear_rejects_foreign_member_before_flush(native_bridge):
    with pytest.raises(OperationalError, match='eth2 is not a member of br1'):
        bridge.clear('br1', member='eth2')
    assert not any('flush' in argv for argv in native_bridge[1])


def test_member_view_excludes_hardware_switch_and_other_bridge_records(monkeypatch):
    """Intel X710 VEPA records do not describe membership in a Linux bridge."""
    records = [
        {'ifname': 'eth2', 'hwmode': 'VEPA'},
        {'ifname': 'eth3', 'hwmode': 'VEPA'},
        {'ifname': 'dum0', 'master': 'br1', 'state': 'forwarding'},
        {'ifname': 'dum1', 'master': 'br1', 'state': 'forwarding'},
        {'ifname': 'dum2', 'master': 'br2', 'state': 'forwarding'},
    ]
    monkeypatch.setattr(bridge, 'cmd', lambda argv: json.dumps(records))

    assert bridge.native('br1', 'member') == records[2:4]
    assert bridge.native('br1', 'member', 'dum1') == [records[3]]
    assert bridge.native('br1', 'member', 'eth2') == []


def test_inventory_filters_empty_native_records(native_bridge):
    """A filtered native dump can contain empty objects for unrelated devices."""
    devices, _ = native_bridge
    devices.insert(0, {})

    assert [device['ifname'] for device in bridge.inventory()] == ['br1', 'br2']
    assert bridge.inventory('br1')[0]['ifname'] == 'br1'
