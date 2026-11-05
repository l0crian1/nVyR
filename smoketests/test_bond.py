"""Verify Linux bond attributes across mode changes without rebuilding the test ports."""

from contextlib import closing
from pathlib import Path

import pytest

from nvyr.helpers import bond_netlink
from nvyr.helpers.netlink import Kernel
from smoketests.assertions import assert_config_commit_rejected, assert_link
from smoketests.interface_support import interface_case, interface_suite


@pytest.fixture(scope='module')
def ports(config, request):
    with interface_suite(config, request, {'bond': ['bond990'], 'dummy': ['dum990', 'dum991']}, [
        'set interfaces dummy dum990', 'set interfaces dummy dum991',
        'set interfaces bond bond990 mode active-backup',
        'set interfaces bond bond990 member interface dum990',
        'set interfaces bond bond990 member interface dum991',
    ]) as reset:
        yield reset


@pytest.fixture(autouse=True)
def reset_case(request, ports):
    with interface_case(request, ports):
        yield


def bond_values(expected):
    """Read independent kernel attributes, including the numeric enum suffix when present."""
    for name, value in expected.items():
        actual = Path(f'/sys/class/net/bond990/bonding/{name}').read_text().strip()
        assert actual == value, f'{name}: expected {value!r}, got {actual!r}'


def test_monitor_and_primary(config, ports):
    config.set('set interfaces bond bond990 primary dum991')
    config.set('set interfaces bond bond990 link-monitor mii interval 50ms up-delay 100ms')
    config.commit()
    data = assert_link('bond990', kind='bond', up=True)['linkinfo']['info_data']
    assert data['miimon'] == 50 and data['updelay'] == 100
    assert Path('/sys/class/net/bond990/bonding/primary').read_text().strip() == 'dum991'


def test_lacp_only_options(config, ports):
    config.set('set interfaces bond bond990 lacp rate fast')
    assert_config_commit_rejected(config, 'require mode 802.3ad')
    config.set('set interfaces bond bond990 mode 802.3ad')
    config.commit()
    assert_link('dum990', master='bond990')
    data = assert_link('bond990', kind='bond', up=True)['linkinfo']['info_data']
    assert data['ad_lacp_rate'] == 'fast'


@pytest.mark.parametrize(('mode', 'settings', 'expected'), [
    ('balance-rr', ['packets-per-member 7'], {'mode': 'balance-rr 0', 'packets_per_slave': '7'}),
    ('active-backup', ['primary dum991', 'primary-reselect failure', 'fail-over-mac follow',
                     'peer-notifications 3'],
     {'mode': 'active-backup 1', 'primary_reselect': 'failure 2', 'fail_over_mac': 'follow 2',
      'num_grat_arp': '3', 'num_unsol_na': '3'}),
    ('balance-xor', ['transmit-hash-policy encap3+4'],
     {'mode': 'balance-xor 2', 'xmit_hash_policy': 'encap3+4 4'}),
    ('broadcast', [], {'mode': 'broadcast 3'}),
    ('802.3ad', ['lacp rate fast passive min-links 2 aggregator-select count system-priority 100',
                'lacp system-mac 02:00:00:99:00:01 user-port-key 17 strict independent-control broadcast-neighbor',
                'transmit-hash-policy layer3+4'],
     {'mode': '802.3ad 4', 'lacp_rate': 'fast 1', 'lacp_active': 'off 0', 'min_links': '2',
      'ad_select': 'count 2', 'ad_actor_sys_prio': '100', 'ad_actor_system': '02:00:00:99:00:01',
      'ad_user_port_key': '17',
      'xmit_hash_policy': 'layer3+4 1'}),
    ('balance-tlb', ['disable-dynamic-load-balancing', 'learning-packet-interval 3s'],
     {'mode': 'balance-tlb 5', 'tlb_dynamic_lb': '0', 'lp_interval': '3'}),
    ('balance-alb', ['disable-dynamic-load-balancing', 'learning-packet-interval 4s', 'resend-igmp 3'],
     {'mode': 'balance-alb 6', 'tlb_dynamic_lb': '0', 'lp_interval': '4', 'resend_igmp': '3'}),
])
def test_modes_and_controls(config, mode, settings, expected):
    config.set(f'set interfaces bond bond990 mode {mode}')
    for setting in settings:
        config.set(f'set interfaces bond bond990 {setting}')
    config.commit()

    bond_values(expected)
    if mode == '802.3ad':
        # These newer UAPI fields have no sysfs files in the shipping kernel.
        with closing(Kernel()) as kernel:
            actual = bond_netlink.attributes(kernel.device('bond990'))
        assert actual['LACP_STRICT'] == 1
        assert actual['COUPLED_CONTROL'] == 0
        assert actual['BROADCAST_NEIGH'] == 1
    assert_link('dum990', master='bond990')
    assert_link('dum991', master='bond990')


def test_delays_and_inactive_frames(config):
    config.set('set interfaces bond bond990 link-monitor mii interval 50ms up-delay 100ms down-delay 150ms')
    config.set('set interfaces bond bond990 peer-notification-delay 200ms deliver-inactive-frames')
    config.commit()
    bond_values({'miimon': '50', 'updelay': '100', 'downdelay': '150', 'peer_notif_delay': '200',
                 'all_slaves_active': '1'})


def test_lacp_member_priority(config):
    config.set('set interfaces bond bond990 mode 802.3ad lacp aggregator-select actor-port-priority')
    config.set('set interfaces bond bond990 member interface dum990 lacp port-priority 100')
    config.set('set interfaces bond bond990 member interface dum991 lacp port-priority 200')
    config.commit()
    bond_values({'ad_select': 'actor_port_prio 3'})
    with closing(Kernel()) as kernel:
        for name, priority in [('dum990', 100), ('dum991', 200)]:
            assert bond_netlink.attributes(kernel.device(name), member=True)['ACTOR_PORT_PRIO'] == priority

    config.delete('delete interfaces bond bond990 member interface dum990 lacp')
    config.commit()
    with closing(Kernel()) as kernel:
        assert bond_netlink.attributes(kernel.device('dum990'), member=True)['ACTOR_PORT_PRIO'] == 255


def test_probe_targets_replacement_and_removal(config):
    config.set('set interfaces bond bond990 link-monitor probe interval 1s missed-max 3 validate all target-policy all')
    config.set('set interfaces bond bond990 link-monitor probe ipv4-target 192.0.2.1')
    config.set('set interfaces bond bond990 link-monitor probe ipv6-target 2001:db8::1')
    config.commit()
    bond_values({'miimon': '0', 'arp_interval': '1000', 'arp_missed_max': '3', 'arp_validate': 'all 3',
                 'arp_all_targets': 'all 1', 'arp_ip_target': '192.0.2.1'})
    with closing(Kernel()) as kernel:
        assert bond_netlink.attributes(kernel.device('bond990'))['NS_IP6_TARGET'] == ['2001:db8::1']

    config.delete('delete interfaces bond bond990 link-monitor probe ipv4-target 192.0.2.1')
    config.delete('delete interfaces bond bond990 link-monitor probe ipv6-target 2001:db8::1')
    config.set('set interfaces bond bond990 link-monitor probe ipv4-target 192.0.2.2')
    config.set('set interfaces bond bond990 link-monitor probe ipv6-target 2001:db8::2')
    config.commit()
    bond_values({'arp_ip_target': '192.0.2.2'})
    with closing(Kernel()) as kernel:
        assert bond_netlink.attributes(kernel.device('bond990'))['NS_IP6_TARGET'] == ['2001:db8::2']

    config.delete('delete interfaces bond bond990 link-monitor probe')
    config.set('set interfaces bond bond990 link-monitor mii interval 100ms')
    config.commit()
    bond_values({'arp_interval': '0', 'miimon': '100', 'arp_ip_target': ''})
    with closing(Kernel()) as kernel:
        assert not bond_netlink.attributes(kernel.device('bond990')).get('NS_IP6_TARGET')


def test_member_priority_and_queue_swap(config):
    config.set('set interfaces bond bond990 member interface dum990 priority 20 queue-id 1')
    config.set('set interfaces bond bond990 member interface dum991 priority -5 queue-id 2')
    config.commit()
    for port, priority, queue in [('dum990', 20, 1), ('dum991', -5, 2)]:
        data = assert_link(port, master='bond990')['linkinfo']['info_slave_data']
        assert data['prio'] == priority and data['queue_id'] == queue

    config.set('set interfaces bond bond990 member interface dum990 queue-id 2')
    config.set('set interfaces bond bond990 member interface dum991 queue-id 1')
    config.commit()
    for port, queue in [('dum990', 2), ('dum991', 1)]:
        assert assert_link(port, master='bond990')['linkinfo']['info_slave_data']['queue_id'] == queue


@pytest.mark.parametrize(('setting', 'reason'), [
    ('link-monitor mii interval 100ms up-delay 150ms', 'multiple'),
    ('link-monitor probe interval 1s', 'at least one'),
    ('primary dum992', 'must be a member'),
    ('packets-per-member 3', 'requires'),
])
def test_rejected_relationships(config, setting, reason):
    config.set(f'set interfaces bond bond990 {setting}')
    assert_config_commit_rejected(config, reason)
