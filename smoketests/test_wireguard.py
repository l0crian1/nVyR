"""Validate WireGuard CLI translation to wg/kernel state with a stable interface.

No tunnel establishment or packet tests here. Endpoint edits and peer removal
are independent cases; the common interface and VRF stay instantiated.
"""
import pytest
from pathlib import Path

from nvyr.helpers import wireguard
from nvyr.helpers.process import cmd
from smoketests.assertions import assert_config_commit_rejected, assert_link, assert_configured_link_addresses
from smoketests.interface_support import interface_case, interface_suite
from smoketests.support import wait_for

PRIVATE = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE='
PUBLIC = 'AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI='
PSK = 'AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM='


@pytest.fixture(scope='module')
def wireguard_suite(config, request):
    with interface_suite(config, request, {'wireguard': ['wg990']},
                         [f'set interfaces wireguard wg990 private-key {PRIVATE}'],
                         vrfs=('NVYRIFSMOKE',)) as reset:
        yield reset


@pytest.fixture(autouse=True)
def environment(request, wireguard_suite):
    with interface_case(request, wireguard_suite):
        yield


def test_link_settings(config):
    config.set('set interfaces wireguard wg990 address 198.18.99.1/24 address 2001:db8:99::1/64 mtu 1380 description "WG smoke" link-group 99')
    config.set('set interfaces wireguard wg990 listen-port 51990 firewall-mark 0x1234')
    config.commit()
    assert_link('wg990', kind='wireguard', mtu=1380, description='WG smoke', up=True)
    assert wireguard.state('wg990')['listen-port'] == 51990
    assert wireguard.state('wg990')['firewall-mark'] == '0x1234'
    config.delete('delete interfaces wireguard wg990 firewall-mark')
    config.commit()
    assert wireguard.state('wg990')['firewall-mark'] == 'off'
    assert_configured_link_addresses('wg990', '198.18.99.1/24', '2001:db8:99::1/64')


def test_peer_settings_and_removals(config):
    config.set(f'set interfaces wireguard wg990 peer remote public-key {PUBLIC} preshared-key {PSK} allowed-ips 10.0.0.0/8 allowed-ips 2001:db8::/32 persistent-keepalive 25')
    config.set('set interfaces wireguard wg990 peer remote endpoint address 192.0.2.1 port 51820')
    config.commit()
    peer = wireguard.state('wg990')['peers'][PUBLIC]
    assert peer['endpoint'] == '192.0.2.1:51820' and peer['keepalive'] == 25 and peer['preshared']
    config.delete('delete interfaces wireguard wg990 peer remote preshared-key')
    config.delete('delete interfaces wireguard wg990 peer remote persistent-keepalive')
    config.delete('delete interfaces wireguard wg990 peer remote endpoint')
    config.commit()
    peer = wireguard.state('wg990')['peers'][PUBLIC]
    assert not peer['preshared'] and peer['keepalive'] == 0 and peer['endpoint'] is None
    config.delete('delete interfaces wireguard wg990 peer remote allowed-ips')
    config.commit()
    assert wireguard.state('wg990')['peers'][PUBLIC]['allowed-ips'] == []
    config.set('set interfaces wireguard wg990 peer remote disable')
    config.commit()
    assert not wireguard.state('wg990')['peers']


def test_auto_port_and_roaming_preserved(config):
    assert_link('wg990', mtu=1420)
    config.set(f'set interfaces wireguard wg990 peer remote public-key {PUBLIC}')
    config.set('set interfaces wireguard wg990 peer remote endpoint address 192.0.2.1 port 51820')
    config.commit()
    port = wireguard.state('wg990')['listen-port']
    cmd(['wg', 'set', 'wg990', 'peer', PUBLIC, 'endpoint', '192.0.2.2:55555'])
    config.set('set interfaces wireguard wg990 description "Keep native endpoint"')
    config.commit()
    assert wireguard.state('wg990')['listen-port'] == port
    assert wireguard.state('wg990')['peers'][PUBLIC]['endpoint'] == '192.0.2.2:55555'


def test_incomplete_endpoint_rejected(config):
    config.set(f'set interfaces wireguard wg990 peer remote public-key {PUBLIC}')
    config.set('set interfaces wireguard wg990 peer remote endpoint port 51820')
    assert_config_commit_rejected(config, 'endpoint requires address and port')


def test_inner_vrf_and_disable(config):
    config.set('set interfaces wireguard wg990 vrf NVYRIFSMOKE disable')
    config.commit()
    assert_link('wg990', master='NVYRIFSMOKE', up=False)
    config.delete('delete interfaces wireguard wg990 disable')
    config.delete('delete interfaces wireguard wg990 vrf')
    config.commit()
    assert_link('wg990', up=True)


def test_link_recreation(config):
    config.set(f'set interfaces wireguard wg990 peer remote public-key {PUBLIC} allowed-ips 192.0.2.0/24')
    config.set('set interfaces wireguard wg990 listen-port 51990 address 198.18.99.1/24')
    config.commit()
    cmd(['ip', 'link', 'delete', 'wg990'])

    def restored():
        assert_link('wg990', kind='wireguard', up=True)
        assert wireguard.state('wg990')['listen-port'] == 51990
        assert wireguard.state('wg990')['peers'][PUBLIC]['allowed-ips'] == ['192.0.2.0/24']
        assert_configured_link_addresses('wg990', '198.18.99.1/24')
        return True

    wait_for(restored, bool, description='recreated WireGuard configuration')


def test_hostname_failure_and_refresh_schedule(config):
    config.set(f'set interfaces wireguard wg990 peer remote public-key {PUBLIC}')
    config.set('set interfaces wireguard wg990 peer remote endpoint address nonexistent.invalid port 51820 address-family ipv4 resolve-interval 1d')
    config.commit()
    assert wireguard.state('wg990')['peers'][PUBLIC]['endpoint'] is None
    timers = list(Path('/run/systemd/system').glob('nvyr-task-wireguard-op-wg990-*.timer'))
    assert len(timers) == 1
    assert cmd(['systemctl', 'is-active', timers[0].name]).strip() == 'active'
    initial = Path('/run/systemd/system/nvyr-task-wireguard-op-wg990-initial.service')
    assert initial.exists() and 'Restart=on-failure' in initial.read_text()
    config.set('set interfaces wireguard wg990 peer remote disable')
    config.commit()
    assert not timers[0].exists()
    assert not initial.exists()


def test_operational_output_hides_secrets(config):
    config.set(f'set interfaces wireguard wg990 peer remote public-key {PUBLIC} preshared-key {PSK}')
    config.commit()
    output = cmd(['wireguard.nvyr.op', 'show', '--interface', 'wg990', '--detail'])
    assert 'remote' in output and PUBLIC in output
    assert PRIVATE not in output and PSK not in output
