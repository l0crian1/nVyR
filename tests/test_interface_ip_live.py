"""Opt-in kernel tests; run in a private network namespace, never the host namespace."""

import os
from pathlib import Path
import socket
import struct
import time

import pytest

from nvyr.helpers import interface_ip
from nvyr.helpers.link_manager import Manager
from nvyr.helpers.netlink import Kernel
from tests.test_netlink import Leases

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_IP_OPTIONS_TEST') != '1',
                                reason='requires an isolated native network namespace')


@pytest.fixture
def native(tmp_path):
    assert os.geteuid() == 0
    assert os.stat('/proc/self/ns/net').st_ino != os.stat('/proc/1/ns/net').st_ino
    kernel = Kernel()
    kernel.ip_controller = interface_ip.Controller(secret=tmp_path / 'secret.json', profile=tmp_path / 'profile.conf')
    manager = Manager(kernel, Leases(), tmp_path / 'state')
    yield manager
    for owner in list(manager.state['owners']):
        manager.replace(owner, {})
    kernel.close()


def dummy(options=None):
    return {'dum987': {'kind': 'dummy', 'ip-options': options or {}}}


def pair(options=None):
    return {
        'veth987': {'kind': 'virtual-ethernet', 'attributes': {'peer-name': 'veth988'}, 'ip-options': options or {}},
        'veth988': {'kind': 'virtual-ethernet', 'attributes': {'peer-name': 'veth987'}},
    }


def value(interface, key, family='ipv6', area='conf'):
    return (Path('/proc/sys/net') / family / area / interface / key).read_text().strip()


def advertise(*, lifetime=600):
    """Send a real RA without installing another router service or packet library."""
    source = socket.inet_pton(socket.AF_INET6, 'fe80::abcd')
    destination = socket.inet_pton(socket.AF_INET6, 'ff02::1')
    prefix = socket.inet_pton(socket.AF_INET6, '2001:db8:987::')
    payload = (struct.pack('!BBHBBHII', 134, 0, 0, 42, 0, 1800, 0, 0)
               + struct.pack('!BBBBIII16s', 3, 4, 64, 0xc0, lifetime, lifetime, 0, prefix)
               + struct.pack('!BBHI', 5, 1, 0, 1400))
    pseudo = source + destination + struct.pack('!I3xB', len(payload), 58) + payload
    total = sum(struct.unpack(f'!{len(pseudo) // 2}H', pseudo))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    payload = payload[:2] + struct.pack('!H', (~total) & 65535) + payload[4:]
    header = struct.pack('!IHBB16s16s', 6 << 28, len(payload), 58, 255, source, destination)
    ethernet = bytes.fromhex('33330000000102000000098786dd')
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as stream:
        stream.bind(('veth988', 0))
        stream.send(ethernet + header + payload)
        time.sleep(.05)
        stream.send(ethernet + header + payload)


def wait_addresses(kernel, predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        addresses = kernel.addresses('veth987', fresh=True)
        if predicate(addresses):
            return addresses
        time.sleep(.05)
    raise AssertionError(f'Expected IPv6 addresses did not appear: {addresses}')


def test_ipv4_options_and_removal(native):
    native.replace('dummy', dummy({'ip': {'arp-ignore': '2', 'arp-announce': 'best-local',
                                         'arp-cache-timeout': '2m', 'disable-forwarding': True}}))
    assert value('dum987', 'arp_ignore', 'ipv4') == '2'
    assert value('dum987', 'arp_announce', 'ipv4') == '2'
    assert value('dum987', 'forwarding', 'ipv4') == '0'
    assert value('dum987', 'base_reachable_time_ms', 'ipv4', 'neigh') == '120000'

    native.state['kernel-settings'] = {'ipv4 arp ignore': '1'}
    native.replace('dummy', dummy())
    assert value('dum987', 'arp_ignore', 'ipv4') == '1'
    assert value('dum987', 'forwarding', 'ipv4') == '1'


def test_ipv6_eui64_mac_change_and_link_local(native):
    links = dummy({'ipv6': {'eui64': ['2001:db8:987::/64'], 'link-local-address': 'fe80::1234'}})
    native.replace('dummy', links)
    assert 'fe80::1234/64' in native.kernel.addresses('dum987')
    assert len(native.kernel.addresses('dum987')) == 2
    old = next(prefix for prefix in native.kernel.addresses('dum987') if prefix.startswith('2001:'))
    links['dum987']['attributes'] = {'mac': '02:00:00:12:34:56'}
    native.replace('dummy', links)
    assert '2001:db8:987::ff:fe12:3456/64' in native.kernel.addresses('dum987')
    assert old not in native.kernel.addresses('dum987')


def test_ipv6_disabled_and_restored(native):
    native.replace('dummy', dummy({'ipv6': {'disable': True}}))
    assert value('dum987', 'disable_ipv6') == '1'
    assert not native.kernel.addresses('dum987')
    native.replace('dummy', dummy())
    assert value('dum987', 'disable_ipv6') == '0'
    assert any(prefix.startswith('fe80:') for prefix in native.kernel.addresses('dum987'))


def test_ipv6_slaac_token_lifetimes_survive_reconciliation(native):
    links = pair({'ipv6': {'autoconf': True, 'interface-identifier': '::1234'}})
    native.replace('virtual-ethernet', links)
    advertise()
    addresses = wait_addresses(native.kernel, lambda items: '2001:db8:987::1234/64' in items)
    assert addresses['2001:db8:987::1234/64']['valid_lft'] <= 600
    assert value('veth987', 'hop_limit') == '42'

    native.replace('virtual-ethernet', links)
    addresses = native.kernel.addresses('veth987', fresh=True)
    assert 0 < addresses['2001:db8:987::1234/64']['valid_lft'] <= 600
    assert value('veth987', 'hop_limit') == '42'


def test_ipv6_ra_without_slaac_and_no_default(native):
    native.replace('virtual-ethernet', pair({'ipv6': {
        'accept-router-advertisements': True, 'no-default-route': True, 'no-ra-mtu': True}}))
    advertise()
    time.sleep(.2)
    assert not any(prefix.startswith('2001:') for prefix in native.kernel.addresses('veth987', fresh=True))
    assert value('veth987', 'mtu') == '1500'
    routes = native.kernel.ipr.get_routes(family=socket.AF_INET6)
    assert not any(route['dst_len'] == 0 and route['proto'] == 9 for route in routes)


def test_ipv6_stable_privacy_survives_recreation(native):
    links = dummy({'ipv6': {'address-generation': 'stable-privacy'}})
    native.replace('dummy', links)
    first = set(native.kernel.addresses('dum987'))
    assert first
    native.replace('dummy', {})
    native.replace('dummy', links)
    assert set(native.kernel.addresses('dum987')) == first


def test_ipv6_temporary_addresses_survive_reconciliation(native):
    links = pair({'ipv6': {'autoconf': True, 'temporary-addresses': 'prefer-temporary'}})
    native.replace('virtual-ethernet', links)
    advertise()
    addresses = wait_addresses(native.kernel, lambda items: any(state['flags'] & 1 for state in items.values()))
    temporary = {prefix for prefix, state in addresses.items() if state['flags'] & 1}
    native.replace('virtual-ethernet', links)
    assert temporary <= native.kernel.addresses('veth987', fresh=True).keys()

    native.replace('virtual-ethernet', pair({'ipv6': {'autoconf': True}}))
    assert not temporary & native.kernel.addresses('veth987', fresh=True).keys()


def test_ipv6_infinite_slaac_lifetime_survives_reconciliation(native):
    links = pair({'ipv6': {'autoconf': True}})
    native.replace('virtual-ethernet', links)
    advertise(lifetime=0xffffffff)
    addresses = wait_addresses(native.kernel, lambda items: any(prefix.startswith('2001:') for prefix in items))
    public = {prefix for prefix in addresses if prefix.startswith('2001:')}
    native.replace('virtual-ethernet', links)
    assert public <= native.kernel.addresses('veth987', fresh=True).keys()


def test_ipv6_link_local_suppression_and_removal(native):
    native.replace('dummy', dummy({'ipv6': {'no-default-link-local': True}}))
    assert not native.kernel.addresses('dum987')
    native.replace('dummy', dummy())
    assert any(prefix.startswith('fe80:') for prefix in native.kernel.addresses('dum987'))


def test_ipv6_remove_slaac_and_token(native):
    native.replace('virtual-ethernet', pair({'ipv6': {'autoconf': True, 'interface-identifier': '::1234'}}))
    advertise()
    wait_addresses(native.kernel, lambda items: '2001:db8:987::1234/64' in items)
    native.replace('virtual-ethernet', pair())
    assert not any(prefix.startswith('2001:') for prefix in native.kernel.addresses('veth987', fresh=True))
    assert value('veth987', 'accept_ra') == '0'
    assert not any(route['proto'] == 9 for route in native.kernel.ipr.get_routes(family=socket.AF_INET6))


def test_ipv6_disable_learned_default_route(native):
    native.replace('virtual-ethernet', pair({'ipv6': {'accept-router-advertisements': True}}))
    advertise()
    time.sleep(.2)
    assert any(route['dst_len'] == 0 and route['proto'] == 9
               for route in native.kernel.ipr.get_routes(family=socket.AF_INET6))
    native.replace('virtual-ethernet', pair({'ipv6': {'accept-router-advertisements': True, 'no-default-route': True}}))
    assert not any(route['dst_len'] == 0 and route['proto'] == 9
                   for route in native.kernel.ipr.get_routes(family=socket.AF_INET6))


def test_ipv6_dad_and_neighbor_parameters(native):
    native.replace('dummy', dummy({'ipv6': {
        'duplicate-address-detection': {'disable': True}, 'neighbor-reachable-time': '2m',
        'neighbor-retransmit-interval': '500ms', 'neighbor-stale-time': '3m', 'hop-limit': '42'}}))
    assert value('dum987', 'accept_dad') == '0'
    assert value('dum987', 'hop_limit') == '42'
    assert value('dum987', 'base_reachable_time_ms', area='neigh') == '120000'
    assert value('dum987', 'retrans_time_ms', area='neigh') == '500'
    assert value('dum987', 'gc_stale_time', area='neigh') == '180'
    native.replace('dummy', dummy())
    assert value('dum987', 'accept_dad') == '1'


def test_ipv4_invalid_apply_restores_previous_policy(native, monkeypatch):
    native.replace('dummy', dummy({'ip': {'arp-ignore': '1'}}))
    original = native.kernel.set_addresses
    failed = False

    def fail_once(*args, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise RuntimeError('injected address failure')
        return original(*args, **kwargs)

    monkeypatch.setattr(native.kernel, 'set_addresses', fail_once)
    with pytest.raises(Exception, match='previous configuration restored'):
        native.replace('dummy', dummy({'ip': {'arp-ignore': '8'}}))
    assert value('dum987', 'arp_ignore', 'ipv4') == '1'
