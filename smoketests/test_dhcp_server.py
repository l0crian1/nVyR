"""Kea configuration lifecycle on isolated dummy interfaces and a test VRF."""

import json

import pytest

if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))

from nvyr.errors import RouterError
from nvyr.helpers import kea
from nvyr.helpers.process import cmd
from nvyr.tree import lookup
from smoketests.assertions import (
    assert_raises,
    assert_config_commit_rejected, assert_config_names_unused, assert_equal, assert_not_in,
)
from smoketests.support import configuration_case, prepared_test


@pytest.fixture(scope='module')
def dhcp_suite(config, request):
    """Reserve one private link/VRF per module; remove servers before their links."""
    prepared = False

    def standup(session):
        nonlocal prepared
        running = session.get_config()
        assert_config_names_unused(running, 'NVYRDHCPSMOKE', 'dum980')
        links = json.loads(cmd(['ip', '-d', '-j', 'link', 'show']))
        assert_not_in('dum980', [link['ifname'] for link in links])
        assert_not_in('NVYRDHCPSMOKE', [link['ifname'] for link in links])
        assert_not_in(41980, [link.get('linkinfo', {}).get('info_data', {}).get('table') for link in links])
        prepared = True

        session.set('set vrf name NVYRDHCPSMOKE table 41980')
        session.set('set interfaces dummy dum980 vrf NVYRDHCPSMOKE')
        session.set('set interfaces dummy dum980 address 198.18.210.1/24')
        session.set('set interfaces dummy dum980 address 2001:db8:210::1/64')
        session.commit()

    def cleanup(session):
        if not prepared:
            return
        session.discard()
        running = session.get_config()
        if lookup(running, ('vrf', 'name', 'NVYRDHCPSMOKE', 'service'), None) is not None:
            session.delete('delete vrf name NVYRDHCPSMOKE service')
            session.commit()
        if lookup(running, ('interfaces', 'dummy', 'dum980'), None) is not None:
            session.delete('delete interfaces dummy dum980')
            session.commit()
        if lookup(running, ('vrf', 'name', 'NVYRDHCPSMOKE'), None) is not None:
            session.delete('delete vrf name NVYRDHCPSMOKE')
            session.commit()

    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, standup, cleanup, stop=stop):
        yield config.get_config()


@pytest.fixture(autouse=True)
def dhcp_environment(config, request, dhcp_suite):
    """Restore case settings in one commit while retaining unchanged suite objects."""
    with configuration_case(config, request, dhcp_suite):
        yield


def test_ipv4_disjoint_ranges_and_reservation(config):
    """One subnet accepts disjoint ranges and a client reservation outside them."""
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server shared-network LAN subnet 198.18.210.0/24 range 198.18.210.10-198.18.210.20')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server shared-network LAN subnet 198.18.210.0/24 range 198.18.210.30-198.18.210.40')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server shared-network LAN subnet 198.18.210.0/24 reservation PRINTER mac-address 02:00:00:00:98:01')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server shared-network LAN subnet 198.18.210.0/24 reservation PRINTER address 198.18.210.50')
    config.commit()

    path = kea.RUNTIME / (kea.instance_name(4, 'NVYRDHCPSMOKE') + '.sock')
    server = kea.control(path, 'config-get')['arguments']['Dhcp4']
    subnet = server['shared-networks'][0]['subnet4'][0]
    assert_equal(server['valid-lifetime'], 86400)
    assert_equal(len(subnet['pools']), 2)
    assert_equal(subnet['reservations'][0]['ip-address'], '198.18.210.50')


def test_ipv4_ha_active_active_role_split(config):
    """The native HA hooks partition both ranges and retain the Unix control socket."""
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server ha name ROUTER1 source-address 198.18.210.1 role primary')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server ha peer ROUTER2 address 198.18.210.2 role secondary')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server shared-network LAN subnet 198.18.210.0/24 range 198.18.210.10-198.18.210.20')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server shared-network LAN subnet 198.18.210.0/24 range 198.18.210.30-198.18.210.39')
    config.commit()

    path = kea.RUNTIME / (kea.instance_name(4, 'NVYRDHCPSMOKE') + '.sock')
    server = kea.control(path, 'config-get')['arguments']['Dhcp4']
    ha = server['hooks-libraries'][1]['parameters']['high-availability'][0]
    assert_equal(ha['mode'], 'load-balancing')
    assert_equal(ha['this-server-name'], 'ROUTER1')
    assert_equal(ha['peers'][1]['url'], 'http://198.18.210.2:8005/')
    pools = server['shared-networks'][0]['subnet4'][0]['pools']
    assert_equal([(pool['pool'].replace(' ', ''), pool['client-classes']) for pool in pools], [
        ('198.18.210.10-198.18.210.15', ['HA_ROUTER1']),
        ('198.18.210.16-198.18.210.20', ['HA_ROUTER2']),
        ('198.18.210.30-198.18.210.34', ['HA_ROUTER1']),
        ('198.18.210.35-198.18.210.39', ['HA_ROUTER2']),
    ])


def test_ipv6_ha_active_active_secondary_and_backup(config):
    """A local secondary emits the same role-owned pools and IPv6 peer URLs."""
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server ha name ROUTER2 source-address 2001:db8:210::1 role secondary')
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server ha peer ROUTER1 address 2001:db8:210::2 role primary port 9006')
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server ha peer COPY address 2001:db8:210::3 role backup')
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server shared-network LAN subnet 2001:db8:210::/64 range 2001:db8:210::10-2001:db8:210::1f')
    config.commit()

    path = kea.RUNTIME / (kea.instance_name(6, 'NVYRDHCPSMOKE') + '.sock')
    server = kea.control(path, 'config-get')['arguments']['Dhcp6']
    ha = server['hooks-libraries'][1]['parameters']['high-availability'][0]
    peers = {peer['name']: peer for peer in ha['peers']}
    assert_equal(peers['ROUTER2']['url'], 'http://[2001:db8:210::1]:8006/')
    assert_equal(peers['ROUTER1']['url'], 'http://[2001:db8:210::2]:9006/')
    assert_equal(peers['COPY']['auto-failover'], False)
    pools = server['shared-networks'][0]['subnet6'][0]['pools']
    assert_equal(pools[0]['client-classes'], ['HA_ROUTER1'])
    assert_equal(pools[1]['client-classes'], ['HA_ROUTER2'])


def test_ipv4_ha_active_passive_and_removal(config):
    """Hot standby keeps complete pools; deleting HA unloads both native hooks."""
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server ha mode active-passive name ROUTER2 source-address 198.18.210.1 port 9005 role standby')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server ha peer ROUTER1 address 198.18.210.2 role primary')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server shared-network LAN subnet 198.18.210.0/24 range 198.18.210.10-198.18.210.20')
    config.commit()

    path = kea.RUNTIME / (kea.instance_name(4, 'NVYRDHCPSMOKE') + '.sock')
    server = kea.control(path, 'config-get')['arguments']['Dhcp4']
    ha = server['hooks-libraries'][1]['parameters']['high-availability'][0]
    assert_equal(ha['mode'], 'hot-standby')
    assert_equal(ha['peers'][0]['url'], 'http://198.18.210.1:9005/')
    assert_equal(ha['peers'][1]['url'], 'http://198.18.210.2:8005/')
    assert_equal(len(server['shared-networks'][0]['subnet4'][0]['pools']), 1)

    config.delete('delete vrf name NVYRDHCPSMOKE service dhcp-server ha')
    config.commit()
    server = kea.control(path, 'config-get')['arguments']['Dhcp4']
    assert_equal(server['hooks-libraries'], [])


def test_ipv6_ha_active_passive(config):
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server ha mode active-passive name ROUTER1 source-address 2001:db8:210::1 role primary')
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server ha peer ROUTER2 address 2001:db8:210::2 role standby')
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server shared-network LAN subnet 2001:db8:210::/64 range 2001:db8:210::10-2001:db8:210::20')
    config.commit()

    path = kea.RUNTIME / (kea.instance_name(6, 'NVYRDHCPSMOKE') + '.sock')
    server = kea.control(path, 'config-get')['arguments']['Dhcp6']
    assert_equal(server['hooks-libraries'][1]['parameters']['high-availability'][0]['mode'], 'hot-standby')
    assert_equal(len(server['shared-networks'][0]['subnet6'][0]['pools']), 1)


def test_ha_requires_local_identity(config):
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server ha')
    assert_config_commit_rejected(config, 'requires name, role, source-address')


def test_ha_requires_mode_appropriate_partner(config):
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server ha name ROUTER1 source-address 198.18.210.1 role primary')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server ha peer ROUTER2 address 198.18.210.2 role standby')
    assert_config_commit_rejected(config, 'requires exactly one primary and one secondary')


def test_ha_source_address_must_be_local_to_vrf(config):
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server ha name ROUTER1 source-address 198.18.210.99 role primary')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server ha peer ROUTER2 address 198.18.210.2 role secondary')
    assert_config_commit_rejected(config, 'source-address must belong to an interface in this VRF')


def test_ipv6_derived_interface_and_lifetimes(config):
    """DHCPv6 derives its selector from the local prefix and inherits timers."""
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server shared-network LAN subnet 2001:db8:210::/64 range 2001:db8:210::10-2001:db8:210::20')
    config.commit()

    path = kea.RUNTIME / (kea.instance_name(6, 'NVYRDHCPSMOKE') + '.sock')
    server = kea.control(path, 'config-get')['arguments']['Dhcp6']
    assert_equal(server['shared-networks'][0]['interface'], 'dum980')
    assert_equal(server['preferred-lifetime'], 43200)
    assert_equal(server['valid-lifetime'], 86400)


def test_ipv4_address_watch_rebinds_server(config):
    """Changing the primary address reconfigures an otherwise unchanged server."""
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server shared-network LAN subnet 198.18.210.0/24 range 198.18.210.10-198.18.210.20')
    config.commit()

    config.delete('delete interfaces dummy dum980 address 198.18.210.1/24')
    config.set('set interfaces dummy dum980 address 198.18.210.2/24')
    config.commit()

    path = kea.RUNTIME / (kea.instance_name(4, 'NVYRDHCPSMOKE') + '.sock')
    server = kea.control(path, 'config-get')['arguments']['Dhcp4']
    assert_equal(server['interfaces-config']['interfaces'], ['dum980/198.18.210.2'])


def test_ipv4_reject_overlapping_listener_selections(config):
    """Whole-interface and address selections cannot bind duplicate receive sockets."""
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server listen-address 198.18.210.1')
    assert_config_commit_rejected(config, 'overlaps listen-interface')


def test_ipv4_reject_range_outside_subnet(config):
    """A syntactically valid range still has to belong to its declared subnet."""
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcp-server shared-network LAN subnet 198.18.210.0/24 range 198.18.211.10-198.18.211.20')
    assert_config_commit_rejected(config, 'outside')


def test_ipv6_reject_preferred_lifetime_exceeding_valid(config):
    """An IPv6 lease must remain valid for its entire preferred lifetime."""
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server listen-interface dum980')
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server preferred-lifetime 2d')
    config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server valid-lifetime 1d')
    assert_config_commit_rejected(config, 'preferred-lifetime cannot exceed')


def test_ipv6_reject_link_local_listener_at_entry(config):
    """Address-qualified listeners add a non-link-local unicast socket."""
    with assert_raises(RouterError, match='non-link-local unicast IPv6'):
        config.set('set vrf name NVYRDHCPSMOKE service dhcpv6-server listen-address fe80::1')


def test_ipv6_reject_multicast_listener_at_entry(config):
    """DHCPv6 multicast reception is managed by Kea, not a listen-address value."""
    with assert_raises(RouterError, match='non-link-local unicast IPv6'):
        config.set('set service dhcpv6-server listen-address ff02::1')
