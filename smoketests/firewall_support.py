"""Shared firewall links, independent rule configurations, and local packet probes."""

import json
import socket
import struct

import pytest

from nvyr.helpers.process import cmd
from nvyr.tree import lookup
from smoketests.assertions import assert_config_names_unused, assert_false, assert_not_in, assert_raises
from smoketests.support import prepared_test


def clear_firewall(config):
    """Remove NAT consumers before firewall providers in one candidate transaction."""
    config.discard()
    running = config.get_config()
    changed = False
    for section in ('nat', 'firewall'):
        if section in running:
            config.delete('delete ' + section)
            changed = True
    if changed:
        config.commit()


def reset_firewall(config):
    """Release rules before resetting link attributes, retaining both native devices."""
    clear_firewall(config)
    running = config.get_config()
    changed = False
    for name in ('dum998', 'dum999'):
        settings = lookup(running, ('interfaces', 'dummy', name), None)
        if settings != {}:
            if settings is not None:
                config.delete('delete interfaces dummy ' + name)
            config.set('set interfaces dummy ' + name)
            changed = True
    if changed:
        config.commit()


def standup(config, resources):
    """Provide two exclusively owned CLI-created links without touching management."""
    running = config.get_config()
    assert_config_names_unused(running, 'dum998', 'dum999')
    for link in json.loads(cmd(['ip', '-j', 'link', 'show'])):
        assert_not_in(link['ifname'], ('dum998', 'dum999'), msg='Smoketest link is already in use')

    resources['prepared'] = True
    clear_firewall(config)

    # Mark ownership before the commit so partial setup failures still clean up.
    resources['links'] = True
    config.set('set interfaces dummy dum998')
    config.set('set interfaces dummy dum999')
    config.commit()


def cleanup(config, resources):
    """Release rule references before removing test links; global teardown restores the snapshot."""
    if not resources['prepared']:
        return

    clear_firewall(config)
    if resources['links']:
        running = config.get_config()
        for name in ('dum998', 'dum999'):
            if lookup(running, ('interfaces', 'dummy', name), None) is not None:
                config.delete('delete interfaces dummy ' + name)
        config.commit()


@pytest.fixture(scope='module')
def firewall_suite(config, request):
    """Create dummy links once per module; release them after every consumer exits."""
    def stop(message):
        request.session.shouldstop = message

    resources = {'prepared': False, 'links': False}
    with prepared_test(
        config,
        lambda session: standup(session, resources),
        lambda session: cleanup(session, resources),
        stop=stop,
    ):
        yield resources


@pytest.fixture(autouse=True)
def firewall_environment(config, request, firewall_suite):
    """Reset rules and changed attributes without recreating supporting interfaces."""
    def stop(message):
        request.session.shouldstop = message

    with prepared_test(config, lambda session: None, reset_firewall, stop=stop):
        yield firewall_suite


def send_firewall_udp(count, *, family='ipv4', source='127.0.0.2', ttl=None, port=53098):
    """Send only loopback traffic to a bound receiver; return delivered packet count."""
    address_family = socket.AF_INET if family == 'ipv4' else socket.AF_INET6
    destination = '127.0.0.1' if family == 'ipv4' else '::1'
    source = source if family == 'ipv4' else '::1'
    delivered = 0

    with socket.socket(address_family, socket.SOCK_DGRAM) as receiver:
        receiver.bind((destination, port))
        receiver.settimeout(0.05)
        with socket.socket(address_family, socket.SOCK_DGRAM) as sender:
            sender.bind((source, 0))
            if ttl is not None:
                level = socket.IPPROTO_IP if family == 'ipv4' else socket.IPPROTO_IPV6
                option = socket.IP_TTL if family == 'ipv4' else socket.IPV6_UNICAST_HOPS
                sender.setsockopt(level, option, ttl)

            for _ in range(count):
                try:
                    sender.sendto(b'nvyr-smoke', (destination, port))
                except PermissionError:
                    # An output DROP reports EPERM; counters separately verify the verdict.
                    continue

                try:
                    receiver.recv(128)
                    delivered += 1
                except TimeoutError:
                    # Timeout is an observation, not a passing assertion.
                    pass

    return delivered


def send_ingress_udp(*, family='ipv4', vlan=None, priority=0, port=53098):
    """Inject one Ethernet frame through the ingress suite's disposable veth pair.

    The destination is the peer's own MAC. Checksums cover both IP families, so
    tests can distinguish header matching from failures parsing malformed frames.
    """
    links = json.loads(cmd(['ip', '-j', 'link', 'show']))
    addresses = {link['ifname']: bytes.fromhex(link['address'].replace(':', ''))
                 for link in links if link['ifname'] in ('veth994', 'veth995')}

    def checksum(data):
        data += bytes(len(data) % 2)
        total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
        while total >> 16:
            total = (total & 65535) + (total >> 16)
        return (~total) & 65535

    payload = b'nvyr-ingress'
    udp = struct.pack('!HHHH', 53097, port, 8 + len(payload), 0) + payload
    if family == 'ipv4':
        source = socket.inet_aton('192.0.2.1')
        destination = socket.inet_aton('192.0.2.2')
        header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0, source, destination)
        packet = header[:10] + struct.pack('!H', checksum(header)) + header[12:] + udp
        protocol = 0x0800
    else:
        source = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
        destination = socket.inet_pton(socket.AF_INET6, '2001:db8::2')
        pseudo = source + destination + struct.pack('!I3xB', len(udp), 17)
        udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 65535) + udp[8:]
        packet = struct.pack('!IHBB16s16s', 6 << 28, len(udp), 17, 64, source, destination) + udp
        protocol = 0x86dd

    if vlan is not None:
        packet = struct.pack('!HH', (priority << 13) | vlan, protocol) + packet
        protocol = 0x8100

    frame = addresses['veth995'] + addresses['veth994'] + struct.pack('!H', protocol) + packet
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sender:
        sender.bind(('veth994', 0))
        sender.send(frame)


def send_firewall_vrf_udp(destination, *, vrf='NVYRFWSMOKE'):
    """Probe both OUTPUT passes; callers assert which native verdict counted it."""
    family = socket.AF_INET6 if ':' in destination else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sender:
        sender.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, vrf.encode() + b'\0')
        try:
            sender.sendto(b'nvyr-zone-smoke', (destination, 53098))
        except PermissionError:
            # OUTPUT drops may report EPERM; the calling test must check the drop counter.
            pass


def send_firewall_transport(protocol, *, family='ipv4', destination_port=53098):
    """Probe port extraction in output raw, independently of transport-stack support.

    These synthetic headers are dropped by the test rule before tracking or
    local delivery. They test packet classification, not transport handshakes.
    """
    address_family = socket.AF_INET if family == 'ipv4' else socket.AF_INET6
    destination = '127.0.0.1' if family == 'ipv4' else '::1'
    number = {'sctp': 132, 'udplite': 136, 'dccp': 33}[protocol]
    packet = struct.pack('!HH', 53097, destination_port) + bytes(28)

    with socket.socket(address_family, socket.SOCK_RAW, number) as sender:
        # Output drops return EPERM to the sender; counters separately prove which rule dropped it.
        with assert_raises(PermissionError):
            sender.sendto(packet, (destination, 0))


@pytest.fixture(scope='module')
def firewall_vrf_suite(config, firewall_suite, request):
    """Retain the optional routing domain across compatible VRF-aware cases."""
    running = config.get_config()
    assert_config_names_unused(running, 'NVYRFWSMOKE')
    for link in json.loads(cmd(['ip', '-j', '-d', 'link', 'show'])):
        assert_false(link['ifname'] == 'NVYRFWSMOKE', msg='Test VRF name is already in use')
        assert_false(link.get('linkinfo', {}).get('info_data', {}).get('table') == 41002,
                     msg='Test VRF table is already in use')
    for vrf in lookup(running, ('vrf', 'name'), {}).values():
        assert_false(str(vrf.get('table')) == '41002', msg='Test VRF table is already configured')
    for route in json.loads(cmd(['ip', '-j', 'route', 'show', 'table', 'all'])):
        assert_false(str(route.get('table')) == '41002', msg='Test VRF table already contains routes')
    for route in json.loads(cmd(['ip', '-j', '-6', 'route', 'show', 'table', 'all'])):
        assert_false(str(route.get('table')) == '41002', msg='Test VRF table already contains IPv6 routes')

    try:
        config.set('set vrf name NVYRFWSMOKE table 41002')
        config.commit()
        yield
    finally:
        try:
            clear_firewall(config)
            running = config.get_config()
            for interface in ('dum998', 'dum999'):
                if lookup(running, ('interfaces', 'dummy', interface, 'vrf'), None) is not None:
                    config.delete('delete interfaces dummy ' + interface + ' vrf')
            config.commit()
            if lookup(config.get_config(), ('vrf', 'name', 'NVYRFWSMOKE'), None) is not None:
                config.delete('delete vrf name NVYRFWSMOKE')
                config.commit()
        except BaseException:
            request.session.shouldstop = 'Firewall VRF cleanup failed; restoring the original configuration.'
            raise


@pytest.fixture
def vrf_environment(firewall_vrf_suite, firewall_environment):
    """Expose the shared VRF after case-level firewall isolation is ready."""
    yield
