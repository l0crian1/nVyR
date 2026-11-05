"""RIP/RIPng native configuration, references and removal on stable test resources.

One VRF and dummy link serve every case. These tests do not wait for peers or
packets. Authentication and passive/split-horizon modes are incompatible variants;
the per-case restore changes protocol settings without recreating the link or VRF.
"""

import pytest

from nvyr.config_session import CommitError
from nvyr.helpers.process import cmd
from smoketests.assertions import assert_config_names_unused, assert_bgp_resources_unused
from smoketests.support import configuration_case, prepared_test


def standup(config):
    assert_config_names_unused(config.get_config(), 'NVYRRIP', 'dum41044')
    assert_bgp_resources_unused(config.get_config(), 'NVYRRIP', 41044)
    for command in (
        'set vrf name NVYRRIP table 41044',
        'set interfaces dummy dum41044 vrf NVYRRIP address 192.0.2.1/24 address 2001:db8:44::1/64',
        'set policy key-chain NVYRRIP key 1 secret rip-smoke algorithm md5',
        'set policy access-list ipv4 NVYRRIP rule 10 action permit prefix 192.0.2.0/24',
        'set policy access-list ipv6 NVYRRIP rule 10 action permit prefix 2001:db8:44::/64',
        'set policy prefix-list ipv4 NVYRRIP rule 10 action permit prefix 192.0.2.0/24',
        'set policy prefix-list ipv6 NVYRRIP rule 10 action permit prefix 2001:db8:44::/64',
        'set policy route-map NVYRRIP rule 10 action permit set metric 3 tag 44',
        'set vrf name NVYRRIP protocols rip',
        'set vrf name NVYRRIP protocols ripng',
    ):
        config.set(command)
    config.commit()


@pytest.fixture(scope='module')
def rip_suite(config, request):
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
def rip_environment(config, request, rip_suite):
    with configuration_case(config, request, rip_suite):
        yield


def assert_native(*commands):
    lines = {' '.join(line.split()) for line in cmd(['vtysh', '-c', 'show running-config no-header']).splitlines()}
    for command in commands:
        assert command in lines


@pytest.mark.parametrize('protocol', ['rip', 'ripng'])
def test_process_and_policy_options(config, protocol):
    prefix = '192.0.2.0/24' if protocol == 'rip' else '2001:db8:44::/64'
    base = f'set vrf name NVYRRIP protocols {protocol}'
    for tail in (
        f'network {prefix} route {prefix}',
        'maximum-paths 4 default-metric 5',
        'default-information originate',
        'timers update 10 timeout 60 garbage-collection 40',
        'redistribute connected metric 3 route-map NVYRRIP',
        'redistribute local',
        'distribute-list in access-list NVYRRIP prefix-list NVYRRIP',
        'distribute-list out prefix-list NVYRRIP',
        'offset-list in access-list NVYRRIP metric 1',
        'offset-list out access-list NVYRRIP metric 2',
        'interface dum41044 passive',
        'interface dum41044 split-horizon poisoned-reverse',
        'interface dum41044 distribute-list in prefix-list NVYRRIP',
        'interface dum41044 distribute-list out access-list NVYRRIP',
        'interface dum41044 offset-list in access-list NVYRRIP metric 3',
        'interface dum41044 offset-list out access-list NVYRRIP metric 4',
        'interface dum41044 route-map in NVYRRIP out NVYRRIP',
    ):
        config.set(base + ' ' + tail)
    if protocol == 'ripng':
        config.set(base + ' aggregate-address 2001:db8:44::/48')
    config.commit()
    assert_native(f'router {protocol} vrf NVYRRIP', 'allow-ecmp 4', 'default-metric 5',
                  'timers basic 10 60 40', 'redistribute connected metric 3 route-map NVYRRIP',
                  'route-map NVYRRIP in dum41044', 'offset-list NVYRRIP out 4 dum41044')


@pytest.mark.parametrize('version', ['1', '2', 'both', 'none'])
def test_ipv4_versions(config, version):
    config.set(f'set vrf name NVYRRIP protocols rip interface dum41044 send-version {version} receive-version {version} v2-broadcast')
    config.commit()
    native = '1 2' if version == 'both' else version
    assert_native(f'ip rip send version {native}', f'ip rip receive version {native}', 'ip rip v2-broadcast')


@pytest.mark.parametrize('authentication', ['mode text password rip-smoke', 'mode md5 password rip-smoke',
                                           'mode md5 key-chain NVYRRIP md5-auth-length rfc',
                                           'mode md5 key-chain NVYRRIP md5-auth-length old-ripd'])
def test_authentication_and_distance(config, authentication):
    base = 'set vrf name NVYRRIP protocols rip'
    config.set(base + ' version 2 neighbor 192.0.2.2 distance 125 log-neighbor-changes')
    config.set(base + ' source-distance 192.0.2.0/24 distance 126 access-list NVYRRIP')
    config.set(base + ' interface dum41044 authentication ' + authentication)
    config.commit()
    assert_native('distance 125', 'distance 126 192.0.2.0/24 NVYRRIP', 'neighbor 192.0.2.2')


def test_passive_default_removal_restores_active_interface(config):
    config.set('set vrf name NVYRRIP protocols rip passive-default')
    config.set('set vrf name NVYRRIP protocols rip interface dum41044 passive disable')
    config.commit()
    assert_native('passive-interface default', 'no passive-interface dum41044')
    config.delete('delete vrf name NVYRRIP protocols rip passive-default')
    config.delete('delete vrf name NVYRRIP protocols rip interface dum41044 passive')
    config.commit()
    output = cmd(['vtysh', '-c', 'show running-config no-header'])
    assert 'passive-interface dum41044' not in output


@pytest.mark.parametrize('protocol', ['rip', 'ripng'])
def test_split_horizon_disable(config, protocol):
    config.set(f'set vrf name NVYRRIP protocols {protocol} interface dum41044 split-horizon disable')
    config.commit()
    assert_native('no ' + ('ip rip' if protocol == 'rip' else 'ipv6 ripng') + ' split-horizon')


@pytest.mark.parametrize('tail', ['offset-list in metric 3',
                                'interface dum41044 split-horizon disable poisoned-reverse',
                                'interface dum41044 authentication mode md5 password test key-chain NVYRRIP'])
def test_incomplete_and_conflicting_settings(config, tail):
    config.set('set vrf name NVYRRIP protocols rip ' + tail)
    with pytest.raises(CommitError):
        config.commit()
