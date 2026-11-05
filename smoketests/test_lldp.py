"""CLI-to-lldpd configuration, validation and removal; no packet assertions.

One veth pair is retained for every case. Selector restrictions and disabled
service cases deliberately change the common configuration.
"""

from copy import deepcopy

import pytest

from nvyr.helpers import lldp
from nvyr.helpers.process import cmd
from smoketests.assertions import assert_config_commit_rejected, assert_config_names_unused
from smoketests.support import configuration_case, prepared_test


@pytest.fixture(scope='module')
def lldp_suite(config, request):
    original = config.get_config()
    assert_config_names_unused(original, 'veth42101', 'veth42102')
    baseline = deepcopy(original)
    baseline.get('service', {}).pop('lldp', None)

    def setup(session):
        session.load(baseline, replace=True)
        session.set('set interfaces virtual-ethernet veth42101 peer-name veth42102')
        session.set('set interfaces virtual-ethernet veth42102 peer-name veth42101')
        for line in ('interface veth421*', 'exclude-interface veth42102',
                     'system-name smoke-lldp', 'system-description "LLDP smoke router"',
                     'chassis-id smoke-chassis', 'management-address 192.0.2.1',
                     'management-address 2001:db8::1', 'capability router',
                     'mode receive-only', 'transmit-interval 5', 'hold-multiplier 3',
                     'max-neighbors 16', 'port-id interface-name', 'port-description "Default description"',
                     'agent-type nearest-bridge', 'bond-member-source-mac real',
                     'interface veth42101 mode transmit-only port-id smoke-uplink port-description "Inside uplink"',
                     'interface veth42101 transmit-vlan 123 priority 5 dei'):
            session.set('set service lldp ' + line)
        session.commit()

    def cleanup(session):
        session.discard()
        session.load(original, replace=True)
        session.commit()

    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, setup, cleanup, stop=stop):
        yield config.get_config()


@pytest.fixture(autouse=True)
def lldp_case(config, request, lldp_suite):
    with configuration_case(config, request, lldp_suite):
        yield


def test_native_configuration():
    settings = lldp.control('show', 'configuration', raw=True)['configuration'][0]['config'][0]
    assert settings['hostname'][0]['value'] == 'smoke-lldp'
    assert settings['tx-delay'][0]['value'] == '5'
    assert settings['tx-hold'][0]['value'] == '3'
    assert settings['max-neighbors'][0]['value'] == '16'
    assert settings['bond-slave-src-mac-type'][0]['value'] == 'real'
    ports = lldp.control('show', 'interfaces', 'details', raw=True)['lldp'][0]['interface']
    assert [port['name'] for port in ports] == ['veth42101']
    assert ports[0]['status'][0]['value'] == 'TX only'
    assert ports[0]['port'][0]['id'][0]['value'] == 'smoke-uplink'
    assert ports[0]['port'][0]['vlanTX'][0] == {'id': '123', 'prio': '5', 'dei': '1'}


@pytest.mark.parametrize('selector', ['all', 'veth421*'])
def test_patterns_cannot_have_overrides(config, selector):
    config.set(f'set service lldp interface {selector} mode receive-only')
    assert_config_commit_rejected(config, 'exact interface name')


def test_remove_override_restores_global_default(config):
    config.delete('delete service lldp interface veth42101')
    config.commit()
    port = lldp.control('show', 'interfaces', 'details', raw=True)['lldp'][0]['interface'][0]
    assert port['status'][0]['value'] == 'RX only'
    assert port['port'][0]['id'][0]['value'] == 'veth42101'
    assert 'vlanTX' not in port['port'][0]


def test_chassis_selection_and_advertisement_options(config):
    config.delete('delete service lldp chassis-id')
    config.set('set service lldp chassis-interface veth421*')
    config.set('set service lldp management-interface veth42101')
    config.set('set service lldp disable-capability-advertisement')
    config.set('set service lldp disable-management-address-advertisement')
    config.set('set service lldp agent-type nearest-non-tpmr-bridge')
    config.commit()

    settings = lldp.control('show', 'configuration', raw=True)['configuration'][0]['config'][0]
    assert settings['cid-pattern'][0]['value'] == 'veth421*'
    assert 'veth42101' in settings['mgmt-pattern'][0]['value']
    assert settings['lldp-agent-type'][0]['value'] == 'nearest non-TPMR bridge'
    text = (lldp.ROOT / 'lldpd.conf').read_text()
    assert 'unconfigure lldp capabilities-advertisements' in text
    assert 'unconfigure lldp management-addresses-advertisements' in text


def test_disable_and_remove(config):
    config.set('set service lldp disable')
    config.commit()
    assert not lldp.SOCKET.exists()
    config.delete('delete service lldp')
    config.commit()
    assert cmd(['systemctl', 'show', lldp.UNIT, '--property=ActiveState', '--value']).strip() == 'inactive'
