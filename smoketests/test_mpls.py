"""MPLS kernel settings and LDP translation using one stable interface pair.

Checks native settings, filters, synchronization and removal; no adjacency or
packet tests. The routed functional scenario owns those observations. Named-VRF
LDP and VPNs are outside this feature's scope.
"""

from pathlib import Path

import pytest

from nvyr.helpers.process import cmd
from smoketests.assertions import assert_config_names_unused
from smoketests.support import configuration_case, prepared_test, wait_for


def standup(config):
    assert_config_names_unused(config.get_config(), 'veth41091', 'veth41092', 'MPLS4', 'MPLS6')
    for command in (
        'set interfaces virtual-ethernet veth41091 peer-name veth41092 address 192.0.2.91/30 address 2001:db8:91::1/64',
        'set interfaces virtual-ethernet veth41092 peer-name veth41091',
        'set protocols mpls interface veth41091',
        'set protocols ldp options router-id 192.0.2.91',
        'set protocols ldp address-family ipv4 transport-address 192.0.2.91 interface veth41091',
        'set protocols ldp address-family ipv6 transport-address 2001:db8:91::1 interface veth41091',
        'set policy access-list ipv4 MPLS4 rule 10 action permit prefix 192.0.2.0/24',
        'set policy access-list ipv6 MPLS6 rule 10 action permit prefix 2001:db8::/32',
    ):
        config.set(command)
    config.commit()


@pytest.fixture(scope='module')
def mpls_suite(config, request):
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
def mpls_environment(config, request, mpls_suite):
    with configuration_case(config, request, mpls_suite):
        yield


def native_lines():
    return {' '.join(line.split()) for line in cmd(['vtysh', '-c', 'show running-config no-header']).splitlines()}


def test_kernel_default_and_membership(config):
    assert Path('/proc/sys/net/mpls/platform_labels').read_text().strip() == '1048575'
    assert Path('/proc/sys/net/mpls/conf/veth41091/input').read_text().strip() == '1'
    assert Path('/proc/sys/net/mpls/conf/veth41092/input').read_text().strip() == '0'
    config.set('set protocols mpls interface veth41092')
    config.commit()
    assert Path('/proc/sys/net/mpls/platform_labels').read_text().strip() == '1048575'
    assert Path('/proc/sys/net/mpls/conf/veth41092/input').read_text().strip() == '1'
    config.delete('delete protocols mpls interface veth41092')
    config.commit()
    assert Path('/proc/sys/net/mpls/conf/veth41092/input').read_text().strip() == '0'


def test_ttl_controls(config):
    config.set('set protocols mpls disable-ttl-propagation default-ttl 64')
    config.commit()
    assert Path('/proc/sys/net/mpls/ip_ttl_propagate').read_text().strip() == '0'
    assert Path('/proc/sys/net/mpls/default_ttl').read_text().strip() == '64'
    config.delete('delete protocols mpls disable-ttl-propagation')
    config.delete('delete protocols mpls default-ttl')
    config.commit()
    assert Path('/proc/sys/net/mpls/ip_ttl_propagate').read_text().strip() == '1'
    assert Path('/proc/sys/net/mpls/default_ttl').read_text().strip() == '255'


def test_static_labels_and_recursive_resolution(config):
    config.set('set protocols mpls fec nexthop-resolution')
    config.set('set protocols mpls lsp 16000 description smoke next-hop 192.0.2.92 outgoing-label 17000')
    config.set('set protocols mpls lsp 16001 next-hop 192.0.2.92 outgoing-label implicit-null')
    config.set('set protocols mpls lsp 16002 next-hop 2001:db8:91::2 outgoing-label explicit-null')
    config.set('set protocols static route 198.51.100.91/32 next-hop 192.0.2.92 label 17000/18000')
    config.set('set protocols static route6 2001:db8:92::/64 next-hop 2001:db8:91::2 label 17000/18000')
    config.commit()
    assert {'mpls fec nexthop-resolution', 'mpls label dynamic-block 100000 1048574',
            'mpls lsp 16000 192.0.2.92 17000', 'mpls lsp 16001 192.0.2.92 implicit-null',
            'mpls lsp 16002 2001:db8:91::2 explicit-null',
            'ip route 198.51.100.91/32 192.0.2.92 label 17000/18000',
            'ipv6 route 2001:db8:92::/64 2001:db8:91::2 label 17000/18000'} <= native_lines()


@pytest.mark.parametrize('tail,expected', [
    ('options ordered-control wait-for-sync 20 allow-broken-lsps', ('ordered-control', 'wait-for-sync 20', 'install allow-broken-lsp')),
    ('options dual-stack transport-preference ipv4 cisco-interop', ('dual-stack transport-connection prefer ipv4', 'dual-stack cisco-interop')),
    ('discovery hello interval 3 holdtime 12', ('discovery hello interval 3', 'discovery hello holdtime 12')),
    ('discovery targeted-hello interval 7 holdtime 30', ('discovery targeted-hello interval 7', 'discovery targeted-hello holdtime 30')),
    ('neighbor 192.0.2.92 password smoke-md5 session-holdtime 30 ttl-security hops 3',
     ('neighbor 192.0.2.92 password smoke-md5', 'neighbor 192.0.2.92 session holdtime 30', 'neighbor 192.0.2.92 ttl-security hops 3')),
    ('neighbor 192.0.2.92 ttl-security disable', ('neighbor 192.0.2.92 ttl-security disable',)),
])
def test_ldp_process_settings(config, tail, expected):
    config.set('set protocols ldp ' + tail)
    config.commit()
    assert set(expected) <= native_lines()


@pytest.mark.parametrize('family,transport,policy', [('ipv4', '192.0.2.92', 'MPLS4'), ('ipv6', '2001:db8:91::2', 'MPLS6')])
def test_ldp_family_settings(config, family, transport, policy):
    scope = 'set protocols ldp address-family ' + family
    for tail in (
        'session-holdtime 30', 'ttl-security disable',
        'discovery targeted-hello accept from-access-list ' + policy,
        'targeted-neighbor ' + transport,
        'interface veth41091 hello interval 2 holdtime 10',
        'interface veth41091 disable-establish-hello',
        'label local allocate access-list ' + policy,
        'label local advertise to-access-list MPLS4 for-access-list ' + policy,
        'label local advertise explicit-null for-access-list ' + policy,
        'label remote accept from-access-list MPLS4 for-access-list ' + policy,
    ):
        config.set(scope + ' ' + tail)
    config.commit()
    lines = native_lines()
    assert 'neighbor ' + transport + ' targeted' in lines
    assert 'label local allocate for ' + policy in lines
    assert 'label remote accept from MPLS4 for ' + policy in lines


@pytest.mark.parametrize('protocol', ['ospf', 'isis'])
def test_igp_synchronization(config, protocol):
    if protocol == 'ospf':
        config.set('set protocols ospf interface veth41091 area 0 network point-to-point')
        prefix = 'ip ospf'
    else:
        config.set('set protocols isis net 49.0001.0000.0000.0091.00')
        config.set('set protocols isis interface veth41091 address-family ipv4-unicast network point-to-point')
        prefix = 'isis'
    config.set(f'set protocols {protocol} ldp-sync hold-down 20')
    config.set(f'set protocols {protocol} interface veth41091 ldp-sync hold-down 12')
    config.commit()
    assert 'mpls ldp-sync holddown 20' in native_lines()
    assert prefix + ' mpls ldp-sync holddown 12' in native_lines()
    config.set(f'set protocols {protocol} interface veth41091 ldp-sync disable')
    config.commit()
    assert 'no ' + prefix + ' mpls ldp-sync' in native_lines()
    config.delete(f'delete protocols {protocol} interface veth41091 ldp-sync')
    config.commit()
    assert 'no ' + prefix + ' mpls ldp-sync' not in native_lines()


def test_delete_ldp_keeps_existing_links(config):
    config.delete('delete protocols ldp')
    config.commit()
    assert 'mpls ldp' not in native_lines()
    assert Path('/sys/class/net/veth41091').exists()
    config.delete('delete protocols mpls')
    config.commit()
    wait_for(lambda: Path('/proc/sys/net/mpls/conf/veth41091/input').read_text().strip(),
             lambda value: value == '0', description='MPLS input disabled after removal')
