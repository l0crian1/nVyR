"""HA CLI defaults, relational checks and deterministic native pool ownership."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import service_dhcp
from nvyr.errors import ValidationError, Warning
from nvyr.helpers import kea
from nvyr.helpers.validators import dhcp_ha_address
from tests.dhcp_config import generated_server, verify_servers


def relationship(mode='active-active'):
    partner = 'secondary' if mode == 'active-active' else 'standby'
    return {'name': 'R1', 'source-address': '192.0.2.1', 'port': '8005', 'role': 'primary',
            'mode': mode, 'peer': {'R2': {'address': '192.0.2.2', 'port': '8005', 'role': partner}}}


def inventory():
    return {'eth1': {'vrf': 'default', 'up': True,
                     'addresses': ['192.0.2.1', '2001:db8::1', 'fe80::1']}}


def test_cli_defaults_anchors_and_removal(controller, engine, session, monkeypatch):
    monkeypatch.setattr(kea, 'inventory', inventory)
    plans = []
    monkeypatch.setattr(kea.manager, 'apply', lambda plan, *args, **kwargs: plans.append(plan))
    controller.execute('set service dhcp-server listen-interface eth1', session)
    controller.execute('set service dhcp-server shared-network LAN subnet 192.0.2.0/24 range 192.0.2.100-192.0.2.109', session)
    controller.execute('set service dhcp-server ha name R1 source-address 192.0.2.1 role primary', session)
    controller.execute('set service dhcp-server ha peer R2 address 192.0.2.2 role secondary', session)
    result = engine.commit(session)

    assert result['results']['dhcp-server']['success']
    native = json.loads(next(iter(plans[-1].desired.values())))['Dhcp4']
    ha = native['hooks-libraries'][1]['parameters']['high-availability'][0]
    assert ha['mode'] == 'load-balancing'
    assert [peer['url'] for peer in ha['peers']] == ['http://192.0.2.1:8005/', 'http://192.0.2.2:8005/']
    assert 'mode' not in engine.running['service']['dhcp-server']['ha']
    assert native['shared-networks'][0]['subnet4'][0]['pools'] == [
        {'pool': '192.0.2.100-192.0.2.104', 'client-classes': ['HA_R1']},
        {'pool': '192.0.2.105-192.0.2.109', 'client-classes': ['HA_R2']},
    ]

    controller.execute('delete service dhcp-server ha', session)
    assert engine.commit(session)['results']['dhcp-server']['success']
    native = json.loads(next(iter(plans[-1].desired.values())))['Dhcp4']
    assert native['hooks-libraries'] == []
    assert 'multi-threading' not in native
    assert native['shared-networks'][0]['subnet4'][0]['pools'] == [{'pool': '192.0.2.100-192.0.2.109'}]


def test_ipv6_vrf_family_ports_and_explicit_peer_port(controller, engine, session, monkeypatch):
    devices = inventory()
    devices['eth1']['vrf'] = 'BLUE'
    monkeypatch.setattr(kea, 'inventory', lambda: devices)
    plans = []
    monkeypatch.setattr(kea.manager, 'apply', lambda plan, *args, **kwargs: plans.append(plan))
    controller.execute('set vrf name BLUE table 40101', session)
    controller.execute('set vrf name BLUE service dhcpv6-server listen-interface eth1', session)
    controller.execute('set vrf name BLUE service dhcpv6-server shared-network LAN interface eth1', session)
    controller.execute('set vrf name BLUE service dhcpv6-server shared-network LAN subnet 2001:db8::/64 range 2001:db8::100-2001:db8::109', session)
    controller.execute('set vrf name BLUE service dhcpv6-server ha mode active-passive name R2 source-address 2001:db8::1 role standby', session)
    controller.execute('set vrf name BLUE service dhcpv6-server ha peer R1 address 2001:db8::2 role primary port 9006', session)
    assert engine.commit(session)['results']['dhcpv6-server']['success']

    native = json.loads(plans[-1].desired[kea.instance_name(6, 'BLUE')])['Dhcp6']
    ha = native['hooks-libraries'][1]['parameters']['high-availability'][0]
    assert ha['mode'] == 'hot-standby'
    assert [peer['url'] for peer in ha['peers']] == ['http://[2001:db8::1]:8006/', 'http://[2001:db8::2]:9006/']
    assert native['shared-networks'][0]['subnet6'][0]['pools'] == [{'pool': '2001:db8::100-2001:db8::109'}]


def test_pool_split_identical_from_primary_secondary_and_backup():
    primary = relationship()
    primary['peer']['COPY'] = {'address': '192.0.2.3', 'port': '8005', 'role': 'backup'}
    secondary = deepcopy(primary)
    secondary.update(name='R2', role='secondary', **{'source-address': '192.0.2.2'})
    secondary['peer'].pop('R2')
    secondary['peer']['R1'] = {'address': '192.0.2.1', 'port': '8005', 'role': 'primary'}
    backup = deepcopy(primary)
    backup.update(name='COPY', role='backup', **{'source-address': '192.0.2.3'})
    backup['peer'].pop('COPY')
    backup['peer']['R1'] = {'address': '192.0.2.1', 'port': '8005', 'role': 'primary'}
    ranges = ['192.0.2.100-192.0.2.110', '192.0.2.200-192.0.2.201']

    expected = service_dhcp.allocation_pools(ranges, primary)
    assert service_dhcp.allocation_pools(ranges, secondary) == expected
    assert service_dhcp.allocation_pools(ranges, backup) == expected
    assert expected[0]['pool'] == '192.0.2.100-192.0.2.105'
    assert expected[1]['pool'] == '192.0.2.106-192.0.2.110'
    assert service_dhcp.allocation_pools(ranges + ['192.0.2.220-192.0.2.229'], primary)[:4] == expected


def test_ipv6_huge_range_split_and_single_address():
    pools = service_dhcp.allocation_pools(['2001:db8::-2001:db8::ffff:ffff:ffff:ffff'], relationship())
    assert pools == [
        {'pool': '2001:db8::-2001:db8::7fff:ffff:ffff:ffff', 'client-classes': ['HA_R1']},
        {'pool': '2001:db8:0:0:8000::-2001:db8::ffff:ffff:ffff:ffff', 'client-classes': ['HA_R2']},
    ]
    assert service_dhcp.allocation_pools(['192.0.2.100-192.0.2.100'], relationship()) == [
        {'pool': '192.0.2.100-192.0.2.100', 'client-classes': ['HA_R1']},
    ]


@pytest.mark.parametrize('change,message', [
    ({'name': None}, 'requires name'),
    ({'source-address': None}, 'requires source-address'),
    ({'role': None}, 'requires role'),
    ({'role': 'standby'}, 'requires exactly'),
    ({'peer': {}}, 'requires exactly'),
    ({'peer': {'R1': {'address': '192.0.2.2', 'port': '8005', 'role': 'secondary'}}}, 'differ from'),
    ({'peer': {'R2': {'port': '8005', 'role': 'secondary'}}}, 'requires address'),
    ({'peer': {'R2': {'address': '192.0.2.2', 'port': '8005'}}}, 'requires role'),
    ({'peer': {'R2': {'address': '192.0.2.1', 'port': '8005', 'role': 'secondary'}}}, 'duplicate HA'),
])
def test_invalid_relationship(change, message):
    ha = relationship()
    for key, value in change.items():
        if value is None:
            del ha[key]
        else:
            ha[key] = value
    with pytest.raises(ValidationError, match=message):
        service_dhcp.verify_ha(ha, 'service dhcp-server', 'default', None)


def test_source_address_checked_in_its_own_vrf():
    service_dhcp.verify_ha(relationship(), 'service dhcp-server', 'default', inventory())
    with pytest.raises(ValidationError, match='source-address must belong'):
        service_dhcp.verify_ha(relationship(), 'service dhcp-server', 'BLUE', inventory())


def test_listener_collisions_are_per_vrf_and_address():
    first = ('default', 'dhcp-server', '2001:db8::1', '8005')
    duplicate = ('default', 'dhcpv6-server', '2001:0db8::1', '8005')
    with pytest.raises(ValidationError, match='listener conflicts'):
        service_dhcp.verify_ha_listeners([first, duplicate])
    service_dhcp.verify_ha_listeners([first, ('BLUE', *duplicate[1:])])
    service_dhcp.verify_ha_listeners([first, (*duplicate[:3], '8006')])


def test_warning_uses_warning_type_without_requiring_peer_connectivity():
    messages = []
    server = {'listen-interface': ['eth1'], 'lease-time': '1d', 'ha': relationship()}
    verify_servers({'default': server}, SimpleNamespace(check_only=True, report=messages.append), 4)
    warnings = [message for message in messages if isinstance(message, Warning)]
    assert len(warnings) == 1
    assert 'pool ranges must match on the local server and every remote peer' in warnings[0].message


def test_hostfile_hook_remains_after_ha_hooks():
    server = {'listen-interface': ['eth1'], 'lease-time': '1d', 'ha': relationship(), 'update-hostfile': {}}
    native = generated_server(server, 4, inventory())['Dhcp4']
    assert [hook['library'].split('/')[-1] for hook in native['hooks-libraries']] == [
        'libdhcp_lease_cmds.so', 'libdhcp_ha.so', 'libdhcp_run_script.so',
    ]
    assert native['control-sockets'][0]['socket-type'] == 'unix'


@pytest.mark.parametrize('value', ['0.0.0.0', '::', 'ff02::1', '224.0.0.1', 'fe80::1', 'fe80::1%eth1', '255.255.255.255'])
def test_invalid_ha_addresses(value):
    assert not dhcp_ha_address(value)


@pytest.mark.parametrize('value', ['192.0.2.1', '2001:db8::1', '127.0.0.1', '::1'])
def test_valid_ha_addresses(value):
    assert dhcp_ha_address(value)
