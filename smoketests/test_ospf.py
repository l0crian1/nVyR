"""OSPFv2/v3 translation and rejection with one persistent VRF and dummy interface.

These checks inspect FRR configuration only. Adjacency, routing and packet tests
use functionaltests/network/test_ospf.py. Stub and NSSA modes, authentication
modes and shutdown are incompatible variants and are reset between cases.
"""

import pytest

from nvyr.config_session import CommitError
from nvyr.helpers.process import cmd
from smoketests.assertions import assert_config_names_unused, assert_bgp_resources_unused
from smoketests.support import configuration_case, prepared_test


def standup(config):
    assert_config_names_unused(config.get_config(), 'NVYROSPF', 'dum41043')
    assert_bgp_resources_unused(config.get_config(), 'NVYROSPF', 41043)
    config.set('set vrf name NVYROSPF table 41043')
    config.set('set interfaces dummy dum41043 vrf NVYROSPF address 192.0.2.1/24 address 2001:db8:43::1/64')
    config.set('set policy key-chain NVYROSPF key 1 secret ospf-smoke algorithm hmac-sha-256')
    config.set('set policy prefix-list ipv4 NVYROSPF rule 10 action permit prefix 192.0.2.0/24')
    config.set('set policy prefix-list ipv6 NVYROSPF rule 10 action permit prefix 2001:db8:43::/64')
    config.set('set policy route-map NVYROSPF rule 10 action permit set metric 15 metric-type type-1 tag 43')
    config.set('set vrf name NVYROSPF protocols ospf options router-id 192.0.2.1')
    config.set('set vrf name NVYROSPF protocols ospfv3 options router-id 192.0.2.1')
    config.commit()


@pytest.fixture(scope='module')
def ospf_suite(config, request):
    original = config.get_config()

    def cleanup(session):
        session.discard()
        session.load(original, replace=True)
        session.commit()

    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, standup, cleanup, stop=stop):
        yield config.get_config()


@pytest.fixture(autouse=True)
def ospf_environment(config, request, ospf_suite):
    with configuration_case(config, request, ospf_suite):
        yield


def assert_native(*commands):
    lines = {' '.join(line.split()) for line in cmd(['vtysh', '-c', 'show running-config no-header']).splitlines()}
    for command in commands:
        assert command in lines


@pytest.mark.parametrize('protocol,native', [('ospf', 'ospf'), ('ospfv3', 'ospf6')])
def test_common_process_and_interface_options(config, protocol, native):
    base = f'set vrf name NVYROSPF protocols {protocol}'
    for tail in (
        'options write-multiplier 25 send-extra-data',
        'reference-bandwidth 10000 maximum-paths 8 distance 115 log-adjacency-changes detail',
        'route-distance intra-area 116 inter-area 117 external 118',
        'timers spf delay 20 initial-hold 100 maximum-hold 1000',
        'timers lsa-min-arrival 50 aggregation 10',
        'redistribute connected metric 20 metric-type 1 route-map NVYROSPF',
        'redistribute local',
        'default-information originate always metric 25 metric-type 1 route-map NVYROSPF',
        'graceful-restart grace-period 90',
        'graceful-restart-helper all planned-only supported-grace-time 60 disable-strict-lsa-checking',
        'interface dum41043 area 0 cost 15 priority 5 hello-interval 2 dead-interval 8',
        'interface dum41043 retransmit-interval 7 transmit-delay 3 mtu-ignore passive',
        'interface dum41043 authentication key-chain NVYROSPF',
    ):
        config.set(base + ' ' + tail)
    config.commit()

    family = 'ipv6 ospf6' if protocol == 'ospfv3' else 'ip ospf'
    assert_native(f'router {native} vrf NVYROSPF', 'auto-cost reference-bandwidth 10000',
                  'timers throttle spf 20 100 1000', 'graceful-restart grace-period 90',
                  'redistribute connected metric 20 metric-type 1 route-map NVYROSPF',
                  f'{family} area 0.0.0.0', f'{family} cost 15', f'{family} passive')


def test_ipv4_specific_options(config):
    for tail in (
        'options abr-type standard rfc1583-compatibility',
        'disable-proactive-arp disable-socket-per-interface forwarding-address-self flood-reduction',
        'socket buffer send 262144 receive 524288',
        'max-metric administrative on-startup 10',
        'timers lsa-generation 100 refresh 20',
        'neighbor 192.0.2.2 priority 5 poll-interval 10',
        'redistribute table 41044 metric 15',
        'redistribute table-direct 41045 metric 16',
        'interface dum41043 network non-broadcast',
        'interface dum41043 fast-hello 5 retransmit-window 75 prefix-suppression',
        'interface dum41043 dscp all 12 low-control 14',
        'interface dum41043 disable-opaque-capability dead-timer-reset-any-control',
        'interface dum41043 neighbor-filter NVYROSPF',
        'interface dum41043 address 192.0.2.1 cost 16 priority 2 passive disable',
    ):
        config.set('set vrf name NVYROSPF protocols ospf ' + tail)
    config.commit()

    assert_native('no proactive-arp', 'no socket-per-interface', 'socket buffer send 262144',
                  'socket buffer recv 524288', 'refresh timer 20', 'ospf abr-type standard',
                  'ip ospf dead-interval minimal hello-multiplier 5', 'ip ospf cost 16 192.0.2.1',
                  'redistribute table-direct 41045 metric 16')


def test_ipv6_specific_options(config):
    for tail in (
        'stub-router',
        'summary-address 2001:db8:43::/48 tag 20 metric 10 metric-type 1',
        'interface dum41043 network point-to-multipoint instance-id 7 mtu 1400',
        'interface dum41043 advertise-prefix-list NVYROSPF',
        'interface dum41043 neighbor-options disable-multicast-hello configured-neighbors-only connected-prefixes include',
        'interface dum41043 neighbor fe80::2 cost 25 poll-interval 30',
        'interface dum41043 authentication key 1 algorithm hmac-sha-256 secret manual-ospf-key',
    ):
        config.set('set vrf name NVYROSPF protocols ospfv3 ' + tail)
    config.commit()

    assert_native('stub-router administrative', 'ipv6 ospf6 instance-id 7', 'ipv6 ospf6 ifmtu 1400',
                  'ipv6 ospf6 p2p-p2mp config-neighbors-only', 'ipv6 ospf6 neighbor fe80::2 cost 25',
                  'ipv6 ospf6 authentication key-id 1 hash-algo hmac-sha-256 key manual-ospf-key')


@pytest.mark.parametrize('protocol', ['ospf', 'ospfv3'])
@pytest.mark.parametrize('kind', ['stub', 'nssa'])
def test_area_types_and_summaries(config, protocol, kind):
    base = f'set vrf name NVYROSPF protocols {protocol} area 1'
    prefix = '192.0.2.0/24' if protocol == 'ospf' else '2001:db8:43::/64'
    config.set(base + f' {kind} no-summary')
    config.set(base + f' range {prefix} cost 10')
    config.set(base + ' filter-list in NVYROSPF out NVYROSPF')
    if kind == 'nssa':
        config.set(base + ' nssa default-information originate metric 20 metric-type 1')
    config.commit()

    assert_native(f'area 0.0.0.1 range {prefix} cost 10', 'area 0.0.0.1 filter-list prefix NVYROSPF in')


def test_plaintext_and_md5_replacement(config):
    config.set('set vrf name NVYROSPF protocols ospf interface dum41043 authentication plaintext secret43')
    config.commit()
    assert_native('ip ospf authentication', 'ip ospf authentication-key secret43')

    config.delete('delete vrf name NVYROSPF protocols ospf interface dum41043 authentication')
    config.set('set vrf name NVYROSPF protocols ospf interface dum41043 authentication md5 key 1 secret digest43')
    config.commit()
    assert_native('ip ospf authentication message-digest', 'ip ospf message-digest-key 1 md5 digest43')


def test_passive_default_and_interface_exception(config):
    config.set('set vrf name NVYROSPF protocols ospf passive-default')
    config.set('set vrf name NVYROSPF protocols ospf interface dum41043 area 0 passive disable')
    config.commit()

    assert_native('passive-interface default', 'no ip ospf passive')


def test_area_authentication_and_default_cost(config):
    config.set('set vrf name NVYROSPF protocols ospf area 1 stub default-cost 15 authentication message-digest')
    config.set('set vrf name NVYROSPF protocols ospf area 1 network 192.0.2.0/24 shortcut enable flood-reduction')
    config.set('set vrf name NVYROSPF protocols ospf summary-address 192.0.2.0/24 tag 43')
    config.commit()

    assert_native('area 0.0.0.1 default-cost 15', 'area 0.0.0.1 authentication message-digest',
                  'network 192.0.2.0/24 area 0.0.0.1', 'summary-address 192.0.2.0/24 tag 43')


def test_default_instance_router_information(config):
    config.set('set protocols ospf options router-id 192.0.2.43 opaque-lsa')
    config.set('set protocols ospf router-info as max-metric administrative')
    config.commit()

    assert_native('router ospf', 'capability opaque', 'router-info as',
                  'max-metric router-lsa administrative')


def test_key_lifetime_replacement(config):
    config.set('set policy key-chain NVYROSPF key 1 accept-lifetime start 1993-01-01T00:00:00 infinite')
    config.set('set policy key-chain NVYROSPF key 1 send-lifetime start 1993-01-02T00:00:00 duration 86400')
    config.commit()
    assert_native('accept-lifetime 00:00:00 Jan 1 1993 infinite', 'send-lifetime 00:00:00 Jan 2 1993 duration 86400')

    config.delete('delete policy key-chain NVYROSPF key 1 send-lifetime')
    config.set('set vrf name NVYROSPF protocols ospf options write-multiplier 30')
    config.commit()
    assert_native('accept-lifetime 00:00:00 Jan 1 1993 infinite', 'ospf write-multiplier 30')


def test_area_alias_and_mode_conflicts(config):
    config.set('set vrf name NVYROSPF protocols ospf area 1 stub')
    config.set('set vrf name NVYROSPF protocols ospf area 0.0.0.1 nssa')
    with pytest.raises(CommitError, match='more than one spelling'):
        config.commit()
