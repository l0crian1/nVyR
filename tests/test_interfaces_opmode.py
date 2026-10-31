"""Display VRF membership from kernel link metadata, including scoped queries."""

import json

import pytest

from nvyr import opmode
from nvyr.op_scripts import interfaces


@pytest.mark.parametrize('detail,statistics', [(False, False), (True, False), (False, True)])
def test_device_kind_filter_keeps_vrf_members_and_similarly_named_interfaces(detail, statistics):
    """All formatted views filter link types/kinds without relying on name prefixes."""
    common = {'flags': ['UP'], 'operstate': 'UP', 'addr_info': [],
              'stats64': {'rx': {}, 'tx': {}}}
    links = [
        dict(common, ifname='BLUE', linkinfo={'info_kind': 'vrf'}),
        dict(common, ifname='register4', link_type='pimreg'),
        dict(common, ifname='pim6reg', link_type='pimreg'),
        dict(common, ifname='register-vrf', link_type='pimreg', linkinfo={'info_slave_kind': 'vrf'}),
        dict(common, ifname='fallback-ip', link_type='ipip'),
        dict(common, ifname='fallback-gre', link_type='gre'),
        dict(common, ifname='fallback-v6', link_type='tunnel6'),
        dict(common, ifname='branch-ip', linkinfo={'info_kind': 'ipip'}),
        dict(common, ifname='branch-routed', linkinfo={'info_kind': 'gre'}),
        dict(common, ifname='branch-ethernet', linkinfo={'info_kind': 'gretap'}),
        dict(common, ifname='mirror', linkinfo={'info_kind': 'erspan'}),
        dict(common, ifname='eth0', master='BLUE', linkinfo={'info_slave_kind': 'vrf'}),
        dict(common, ifname='pimreg-user', linkinfo={'info_kind': 'dummy'}),
        dict(common, ifname='tunl-user', linkinfo={'info_kind': 'dummy'}),
        dict(common, ifname='gre-user', linkinfo={'info_kind': 'dummy'}),
        dict(common, ifname='erspan-user', linkinfo={'info_kind': 'dummy'}),
        dict(common, ifname='lo'),
    ]

    rows = interfaces._format_kernel_data(links, None, detail, statistics)

    assert [row[0] for row in rows] == [
        'erspan-user', 'eth0', 'gre-user', 'lo', 'pimreg-user', 'tunl-user',
    ]
    assert interfaces._format_kernel_data(links, None, detail, statistics, 'register4') == []
    assert interfaces._format_kernel_data(links, None, detail, statistics, 'branch-routed') == []


@pytest.mark.parametrize('slave_kind, master, expected', [
    ('vrf', 'BLUE', 'BLUE'), ('bridge', 'br0', 'default'), (None, None, 'default'),
])
@pytest.mark.parametrize('scoped, detail', [(False, False), (True, False), (True, True)])
def test_interface_vrf_column(monkeypatch, capsys, slave_kind, master, expected, scoped, detail):
    link = {'ifname': 'dum0', 'flags': ['UP'], 'operstate': 'UP', 'addr_info': [],
            'stats64': {'rx': {}, 'tx': {}}, 'linkinfo': {'info_kind': 'dummy'}}
    if slave_kind:
        link['linkinfo']['info_slave_kind'] = slave_kind
        link['master'] = master
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    commands = []

    def kernel_data(command):
        commands.append(command)
        return json.dumps([link])

    monkeypatch.setattr(interfaces, 'cmd', kernel_data)
    interfaces.show(intf_name='dum0' if scoped else None, detail=detail)
    output = capsys.readouterr().out

    assert 'VRF' in output and expected in output
    if expected != 'default':
        assert 'default' not in output
    assert commands == [['ip', '-j', '-d', '-s', 'address', 'show']]


def container_links(name='pd-alpine-0', kind='veth', bridge_vrf=True):
    """Build a port, bridge and VRF in one native interface snapshot."""
    common = {'flags': ['UP'], 'operstate': 'UP', 'addr_info': [], 'stats64': {'rx': {}, 'tx': {}}}
    bridge = dict(common, ifname='pd-LAN', linkinfo={'info_kind': 'bridge'})
    if bridge_vrf:
        bridge['master'] = 'BLUE'
        bridge['linkinfo']['info_slave_kind'] = 'vrf'

    return [
        dict(common, ifname=name, master='pd-LAN', linkinfo={'info_kind': kind, 'info_slave_kind': 'bridge'}),
        bridge,
        dict(common, ifname='BLUE', linkinfo={'info_kind': 'vrf'}),
    ]


@pytest.mark.parametrize('scoped,detail', [(False, False), (True, False), (True, True)])
def test_container_port_inherits_bridge_vrf(monkeypatch, capsys, scoped, detail):
    """Full and scoped displays use the same bridge VRF without extra commands."""
    commands = []

    def snapshot(command):
        commands.append(command)
        return json.dumps(container_links())

    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    monkeypatch.setattr(interfaces, 'cmd', snapshot)
    interfaces.show(intf_name='pd-alpine-0' if scoped else None, detail=detail)
    output = capsys.readouterr().out

    assert 'pd-alpine-0' in output
    assert 'BLUE' in output
    assert 'default' not in output
    if scoped:
        assert 'pd-LAN' not in output
    assert commands == [['ip', '-j', '-d', '-s', 'address', 'show']]


@pytest.mark.parametrize('name,kind,bridge_vrf', [
    ('veth0', 'veth', True), ('pd-test', 'dummy', True), ('pd-alpine-0', 'veth', False),
])
def test_bridge_inheritance_only_applies_to_container_veth(name, kind, bridge_vrf):
    """Ordinary bridge ports and non-VRF bridges retain the default display."""
    rows = interfaces._format_kernel_data(container_links(name, kind, bridge_vrf), None, False, False, name)
    assert rows[0][3] == 'default'


def test_missing_bridge_metadata_defaults_safely():
    """A port whose bridge vanished from the snapshot still renders normally."""
    rows = interfaces._format_kernel_data(container_links()[:1], None, False, False)
    assert rows[0][3] == 'default'


def test_raw_scoped_query_keeps_native_output(monkeypatch):
    """Display inheritance must not add or alter fields in raw kernel output."""
    commands = []
    port = container_links()[:1]

    def snapshot(command):
        commands.append(command)
        return json.dumps(port)

    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    monkeypatch.setattr(interfaces, 'cmd', snapshot)
    raw, formatted = interfaces._get_kernel_data(True, 'pd-alpine-0')
    assert raw == port and formatted is None
    assert commands == [['ip', '-j', '-d', '-s', 'address', 'show', 'dev', 'pd-alpine-0']]


def test_scoped_vlan_detail_resolves_parent_and_link_local(monkeypatch, capsys):
    """A scoped VIF retains the full link snapshot for parent-index resolution."""
    links = [
        {'ifname': 'eth0', 'ifindex': 2},
        {'ifname': 'eth0.100', 'ifindex': 3, 'link_index': 2, 'group': 12,
         'flags': ['UP'], 'operstate': 'UP', 'stats64': {},
         'addr_info': [{'family': 'inet6', 'scope': 'link', 'local': 'fe80::1234', 'prefixlen': 64}],
         'linkinfo': {'info_kind': 'vlan', 'info_data': {'id': 100, 'protocol': '802.1Q'}}},
    ]
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    monkeypatch.setattr(interfaces, 'cmd', lambda argv: json.dumps(links))
    interfaces.show(intf_name='eth0.100', detail=True)
    output = capsys.readouterr().out
    assert 'Parent' in output and 'eth0' in output
    assert 'VLAN ID' in output and '100' in output
    assert '802.1Q' in output and 'fe80::1234/64' in output
    assert 'Link-group' in output and '12' in output


def test_peer_index_never_resolves_in_wrong_namespace():
    """Namespace ID zero is still remote, even if its peer index exists locally."""
    local = [{'ifindex': 3, 'ifname': 'eth0'}]
    peer = {'link_index': 3, 'link_netnsid': 0}
    assert interfaces._link_reference(peer, local) == 'Index 3 (another network namespace)'
    assert interfaces._link_reference({'link_index': 3}, local) == 'eth0'


def test_veth_peer_detail(monkeypatch, capsys):
    """A scoped veth resolves its local peer without extra netlink requests."""
    links = container_links(name='veth0', bridge_vrf=False)[:1]
    links[0].update(ifindex=3, link_index=4)
    links.append({'ifindex': 4, 'ifname': 'veth1'})
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    monkeypatch.setattr(interfaces, 'cmd', lambda argv: json.dumps(links))
    interfaces.show(intf_name='veth0', detail=True)
    output = capsys.readouterr().out
    assert 'Peer' in output and 'veth1' in output


def test_only_detail_queries_ethernet_metadata(monkeypatch, capsys):
    """Summary and statistics avoid diagnostic queries; detail enriches Ethernet."""
    link = dict(container_links()[0], ifname='eth0', link_type='ether', linkinfo={})
    monkeypatch.setattr(interfaces, 'cmd', lambda argv: json.dumps([link]))
    calls = []
    monkeypatch.setattr(interfaces.ethtool, 'link_details',
                        lambda name: calls.append(name) or [('Speed', '1 Gbit/s')])
    interfaces.show()
    interfaces.show(statistics=True)
    assert not calls
    interfaces.show(detail=True)
    assert calls == ['eth0']
    assert '1 Gbit/s' in capsys.readouterr().out


def test_ethernet_detail_survives_unavailable_link_settings(monkeypatch, capsys):
    """A disabled hardware port still displays its addresses, driver and counters."""
    from nvyr.helpers.process import CommandResult

    link = dict(container_links()[0], ifname='eth1', link_type='ether', linkinfo={},
                flags=[], operstate='DOWN')
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    monkeypatch.setattr(interfaces, 'cmd', lambda argv: json.dumps([link]))
    monkeypatch.setattr(interfaces.ethtool, 'cli_cmd', lambda *args, **kwargs:
                        CommandResult('[{"ifname":"eth1"}]', 'netlink error: No such device', 0))
    monkeypatch.setattr(interfaces.ethtool, 'driver_info', lambda name: {'Driver': 'r8169'})

    interfaces.show(intf_name='eth1', detail=True)
    output = capsys.readouterr().out

    assert 'eth1' in output and 'A/D' in output
    assert 'IP Address' in output and 'MAC' in output
    assert 'RX Packets' in output and 'TX Packets' in output
    assert 'r8169' in output
    assert output.count('Currently unavailable') == 1
    assert 'No such device' not in output and 'Unknown' not in output


def test_link_local_obeys_strip_private(monkeypatch, capsys):
    link = container_links()[0]
    link['addr_info'] = [{'family': 'inet6', 'scope': 'link', 'local': 'fe80::1234', 'prefixlen': 64}]
    monkeypatch.setattr(interfaces, 'cmd', lambda argv: json.dumps([link]))
    interfaces.show(detail=True, strip_private=True)
    assert 'fe80::1234' not in capsys.readouterr().out


@pytest.mark.parametrize('view', ['offload', 'queues', 'hardware-statistics', 'transceiver'])
def test_focused_commands_require_no_privileged_role(controller, monkeypatch, view):
    """Both existing interface selectors preserve scoped command arguments."""
    from nvyr.helpers import access

    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or 'output')
    token = access.role.set('read-only')
    try:
        controller.execute(f'show interfaces eth0 {view}')
        controller.execute(f'show interfaces ethernet eth0 {view}')
        controller.execute(f'show interfaces {view}')
    finally:
        access.role.reset(token)
    assert calls == [
        ['interfaces.nvyr.op', 'hardware', view, '--intf_name', 'eth0'],
        ['interfaces.nvyr.op', 'hardware', view, '--intf_type', 'ethernet', '--intf_name', 'eth0'],
        ['interfaces.nvyr.op', 'hardware', view],
    ]


def test_diagnostic_completion(controller):
    candidates = dict(controller.completion('show interfaces eth0 ', explicit=True)['candidates'])
    assert {'detail', 'statistics', 'offload', 'queues', 'hardware-statistics', 'transceiver'} <= candidates.keys()


def test_offload_false_is_not_unknown(capsys):
    interfaces._hardware_output('eth0', 'offload', {
        'ifname': 'eth0', 'rx-checksumming': {'active': False},
        'tx-checksumming': {'active': True}, 'other': {'active': None}})
    output = capsys.readouterr().out
    assert 'No' in output and 'Yes' in output and 'Unknown' in output


def test_queues_keep_partial_support_and_zero(capsys):
    interfaces._hardware_output('eth0', 'queues', {
        'channels': None, 'rings': {'rx': 0, 'rx-max': 1024, 'tx-max': 512}})
    output = capsys.readouterr().out
    assert 'Channel information is not supported.' in output
    assert '1024' in output and 'Unknown' in output


def test_hardware_statistics_preserve_large_counters(capsys):
    interfaces._hardware_output('eth0', 'hardware-statistics', [['rx', 2 ** 63 + 7]])
    assert str(2 ** 63 + 7) in capsys.readouterr().out


def test_raw_diagnostic_and_serial_mask(monkeypatch, capsys):
    monkeypatch.setattr(interfaces, 'exists', lambda name: True)
    monkeypatch.setattr(interfaces, 'cmd', lambda argv: '[{"ifname":"eth0"}]')
    monkeypatch.setattr(interfaces, '_hardware_data', lambda *args:
                        {'vendor_sn': 'PRIVATE', 'module_temperature': 35.0})
    result = json.loads(interfaces.hardware('transceiver', intf_name='eth0', raw=True, strip_private=True))
    assert result['eth0']['vendor_sn'] != 'PRIVATE'
    assert result['eth0']['module_temperature'] == 35.0
    assert capsys.readouterr().out == ''


def test_raw_output_is_json_through_script_dispatch(monkeypatch, capsys):
    """The API form must serialize JSON rather than Python's list/dict representation."""
    devices = [{'ifname': 'eth0', 'flags': ['UP'], 'linkinfo': {'enabled': True}, 'ifalias': None}]
    monkeypatch.setattr(interfaces, 'cmd', lambda argv: json.dumps(devices))

    opmode.run(['show', '--raw'], namespace=vars(interfaces))
    assert json.loads(capsys.readouterr().out) == devices
