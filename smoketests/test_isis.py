"""IS-IS native configuration, policy references and removal on stable resources.

The default instance, one VRF and two dummy interfaces serve every case. Tests
check CLI translation/readback, not adjacency or forwarding. Authentication,
level and topology variants change configuration without recreating interfaces.
"""

import pytest

from nvyr.config_session import CommitError
from nvyr.helpers.process import cmd
from smoketests.assertions import assert_config_names_unused, assert_bgp_resources_unused
from smoketests.support import configuration_case, prepared_test


def standup(config):
    assert_config_names_unused(config.get_config(), 'NVYRISIS', 'dum41045', 'dum41046')
    assert_bgp_resources_unused(config.get_config(), 'NVYRISIS', 41045)
    for command in (
        'set vrf name NVYRISIS table 41045',
        'set interfaces dummy dum41045 address 192.0.2.45/32 address 2001:db8:45::1/128',
        'set interfaces dummy dum41046 vrf NVYRISIS address 192.0.2.46/32 address 2001:db8:46::1/128',
        'set policy access-list ipv4 NVYRISIS rule 10 action permit prefix 192.0.2.0/24',
        'set policy route-map NVYRISIS rule 10 action permit set metric 25',
        'set protocols isis net 49.0001.0000.0000.0045.00',
        'set protocols isis interface dum41045 address-family ipv4-unicast address-family ipv6-unicast passive',
        'set vrf name NVYRISIS protocols isis net 49.0001.0000.0000.0046.00',
        'set vrf name NVYRISIS protocols isis interface dum41046 address-family ipv4-unicast address-family ipv6-unicast passive',
    ):
        config.set(command)
    config.commit()


@pytest.fixture(scope='module')
def isis_suite(config, request):
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
def isis_environment(config, request, isis_suite):
    with configuration_case(config, request, isis_suite):
        yield


def assert_native(*commands):
    lines = {' '.join(line.split()) for line in cmd(['vtysh', '-c', 'show running-config no-header']).splitlines()}
    for command in commands:
        assert command in lines


@pytest.mark.parametrize('scope', ['protocols isis', 'vrf name NVYRISIS protocols isis'])
def test_process_options_and_policy(config, scope):
    for tail in (
        'options level level-2 disable-dynamic-hostname log-adjacency-changes log-pdu-drops purge-originator lsp-mtu 1400',
        'options overload administrative on-startup 10',
        'options advertise-high-metrics advertise-passive-only attached-bit ignore',
        'level level-2 authentication mode md5 password smoke-isis snp validate',
        'level level-2 timers lsp-generation 20 lsp-refresh 600 lsp-lifetime 1000 spf-interval 3',
        'level level-2 fast-reroute priority-limit high disable-load-sharing tiebreaker 1 type downstream',
        'spf delay initial 50 short 100 long 500 hold-down 1000 time-to-learn 500',
        'spf prefix-priority critical access-list NVYRISIS',
        'address-family ipv4-unicast level level-2 redistribute connected metric 20 route-map NVYRISIS',
        'address-family ipv6-unicast level level-2 redistribute static metric 30 route-map NVYRISIS',
        'address-family ipv4-unicast level level-2 default-originate always metric 40 route-map NVYRISIS',
        'topology ipv6-unicast overload',
    ):
        config.set(f'set {scope} {tail}')
    config.commit()
    assert_native('is-type level-2-only', 'no hostname dynamic', 'set-overload-bit',
                  'domain-password md5 smoke-isis authenticate snp validate',
                  'redistribute ipv4 connected level-2 metric 20 route-map NVYRISIS',
                  'redistribute ipv6 static level-2 metric 30 route-map NVYRISIS',
                  'topology ipv6-unicast overload')
    assert_native('log-adjacency-changes', 'log-pdu-drops', 'purge-originator', 'lsp-mtu 1400',
                  'set-overload-bit on-startup 10', 'advertise-high-metrics', 'advertise-passive-only',
                  'attached-bit receive ignore',
                  'lsp-timers level-2 gen-interval 20 refresh-interval 600 max-lifetime 1000',
                  'spf-interval level-2 3', 'fast-reroute priority-limit high level-2',
                  'fast-reroute load-sharing disable level-2',
                  'fast-reroute lfa tiebreaker downstream index 1 level-2',
                  'spf-delay-ietf init-delay 50 short-delay 100 long-delay 500 holddown 1000 time-to-learn 500',
                  'spf prefix-priority critical NVYRISIS',
                  'default-information originate ipv4 level-2 always route-map NVYRISIS metric 40')


@pytest.mark.parametrize('tail,expected', [
    ('network point-to-point', 'isis network point-to-point'),
    ('authentication mode plaintext password smoke-isis', 'isis password clear smoke-isis'),
    ('authentication mode md5 password smoke-isis', 'isis password md5 smoke-isis'),
    ('disable-three-way-handshake', 'no isis three-way-handshake'),
    ('hello-padding disabled', 'no isis hello padding'),
    ('hello-padding during-adjacency-formation', 'isis hello padding during-adjacency-formation'),
    ('circuit-type level-1', 'isis circuit-type level-1'),
    ('level level-2 metric 30', 'isis metric level-2 30'),
    ('level level-2 priority 32', 'isis priority 32 level-2'),
    ('level level-2 timers hello-interval 5 hello-multiplier 4 csnp-interval 15 psnp-interval 3', 'isis hello-interval level-2 5'),
    ('level level-2 fast-reroute lfa exclude-interface lo', 'isis fast-reroute lfa level-2 exclude interface lo'),
])
def test_interface_options(config, tail, expected):
    config.set('set vrf name NVYRISIS protocols isis interface dum41046 ' + tail)
    config.commit()
    assert_native(expected)


def test_invalid_net_relationship(config):
    config.set('set protocols isis net 49.0002.0000.0000.9999.00')
    with pytest.raises(CommitError, match='system ID'):
        config.commit()


def test_named_instance_delete_preserves_global(config):
    config.delete('delete vrf name NVYRISIS protocols isis')
    config.commit()
    output = cmd(['vtysh', '-c', 'show running-config no-header'])
    assert 'router isis nvyr vrf NVYRISIS' not in output
    assert 'router isis nvyr\n' in output



@pytest.mark.parametrize('protocol,family', [
    ('bgp', 'ipv4-unicast'), ('bgp', 'ipv6-unicast'),
    ('ospf', None), ('ospfv3', None), ('rip', None), ('ripng', None),
])
def test_redistribute_isis_into_other_protocols(config, protocol, family):
    base = f'set vrf name NVYRISIS protocols {protocol}'
    if protocol == 'bgp':
        config.set(base + ' local-as 64545')
    if protocol in ('ospf', 'ospfv3'):
        config.set(base + ' options router-id 192.0.2.45')
    scope = base + (' address-family ' + family if family else '')
    config.set(scope + ' redistribute isis metric 5 route-map NVYRISIS')
    config.commit()
    assert_native('redistribute isis metric 5 route-map NVYRISIS')
