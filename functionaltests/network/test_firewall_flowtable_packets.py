"""Global flowtable enrollment/accounting and teardown packet behavior.

IPv4 and IPv6 use host namespaces and router veth pairs from the package topology.
The module temporarily installs global offload policy; counter deltas and exact
connection ports distinguish probes. Prefix and teardown cases change only their
required settings. Ordinary scoped offload coexists with the main network rules.
"""

from contextlib import contextmanager
import os
import socket
import struct

import pytest


if __name__ == '__main__':
    import sys

    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from nvyr.helpers.process import cmd
from smoketests.assertions import (
    assert_equal, assert_in, assert_connection_accounting,
    firewall_rule_packets, assert_firewall_rule_packets, assert_raises,
)
from smoketests.support import configuration_case


@pytest.fixture(scope='module')
def global_offload(config, request, routed_network):
    """Global early acceptance conflicts with detailed rule counters, not topology."""
    with configuration_case(config, request, routed_network):
        config.delete('delete firewall')
        config.set('set firewall global-options connection-accounting')
        config.set('set firewall flowtable FAST interface veth41050 interface veth41052 counter')
        config.set('set firewall global-options state-policy established action accept')
        config.set('set firewall global-options flowtable FAST')
        config.commit()
        yield config.get_config()


@pytest.fixture(autouse=True)
def network_case(config, request, global_offload):
    """Keep common offload policy installed; restore only prefix/teardown mutations."""
    with configuration_case(config, request, global_offload):
        yield


@contextmanager
def endpoint_socket(namespace, family, kind):
    """Create a socket in its host namespace and immediately restore the test thread."""
    with open('/proc/self/ns/net', 'rb') as original, open('/run/netns/' + namespace, 'rb') as target:
        try:
            os.setns(target.fileno(), 0)
            endpoint = socket.socket(family, kind)
        finally:
            os.setns(original.fileno(), 0)
    with endpoint:
        endpoint.settimeout(3)
        yield endpoint


def exchange_datagrams(family):
    """Reply on one UDP tuple, then send more packets without creating another flow."""
    ipv6 = family == 'ipv6'
    address_family = socket.AF_INET6 if ipv6 else socket.AF_INET
    source = '2001:db8:5050::2' if ipv6 else '198.18.50.2'
    destination = '2001:db8:5051::2' if ipv6 else '198.18.51.2'

    with (
        endpoint_socket('nvyr-ft-source', address_family, socket.SOCK_DGRAM) as sender,
        endpoint_socket('nvyr-ft-destination', address_family, socket.SOCK_DGRAM) as receiver,
    ):
        sender.settimeout(3)
        receiver.settimeout(3)
        sender.bind((source, 0))
        receiver.bind((destination, 0))

        for number in range(6):
            message = f'nvyr-flow-{number}'.encode()
            sender.sendto(message, receiver.getsockname())
            data, peer = receiver.recvfrom(128)
            assert_equal(data, message)
            receiver.sendto(data, peer)
            assert_equal(sender.recv(128), message)

        return sender.getsockname()[1], receiver.getsockname()[1]


@contextmanager
def established_tcp(family):
    """Complete the handshake before the test enables flow offload."""
    ipv6 = family == 'ipv6'
    address_family = socket.AF_INET6 if ipv6 else socket.AF_INET
    source = '2001:db8:5050::2' if ipv6 else '198.18.50.2'
    destination = '2001:db8:5051::2' if ipv6 else '198.18.51.2'

    with (
        endpoint_socket('nvyr-ft-source', address_family, socket.SOCK_STREAM) as sender,
        endpoint_socket('nvyr-ft-destination', address_family, socket.SOCK_STREAM) as listener,
    ):
        sender.settimeout(3)
        listener.settimeout(3)
        sender.bind((source, 0))
        listener.bind((destination, 0))
        listener.listen(1)
        sender.connect(listener.getsockname())
        receiver, _ = listener.accept()
        with receiver:
            receiver.settimeout(3)
            yield sender, receiver


def reset_connection(sender, receiver):
    """Send RST on an established tuple: flow add must skip teardown packets."""
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
    sender.close()
    with assert_raises(ConnectionResetError):
        receiver.recv(128)


def test_ipv4_successful_enrollment_counter(config):
    """Count one successful enrollment, not every packet on the established IPv4 flow."""
    before = firewall_rule_packets('forward', 'global-offload')
    exchange_datagrams('ipv4')
    assert_firewall_rule_packets('forward', 'global-offload', before + 1)


def test_ipv6_successful_enrollment_counter(config):
    """IPv6 forwarding also counts only the newly installed flow."""
    before = firewall_rule_packets('forward', 'global-offload')
    exchange_datagrams('ipv6')
    assert_firewall_rule_packets('forward', 'global-offload', before + 1)


def test_ipv4_flowtable_packet_accounting(config):
    """The flowtable counter records accelerated IPv4 packets in conntrack."""
    source_port, destination_port = exchange_datagrams('ipv4')
    assert_connection_accounting('ipv4', '198.18.50.2', '198.18.51.2', 6,
                                 source_port=source_port, destination_port=destination_port)


def test_ipv6_flowtable_packet_accounting(config):
    """Accelerated IPv6 traffic updates the same per-connection accounting."""
    source_port, destination_port = exchange_datagrams('ipv6')
    assert_connection_accounting('ipv6', '2001:db8:5050::2', '2001:db8:5051::2', 6,
                                 source_port=source_port, destination_port=destination_port)


def test_ipv4_prefix_enrollment_counter(config):
    """A native interface prefix enrolls the same IPv4 forwarding path exactly once."""
    config.delete('delete firewall flowtable FAST interface')
    config.set('set firewall flowtable FAST interface veth4105*')
    config.set('set firewall global-options state-policy established action accept')
    config.set('set firewall global-options flowtable FAST')
    config.commit()
    before = firewall_rule_packets('forward', 'global-offload')

    exchange_datagrams('ipv4')
    assert_firewall_rule_packets('forward', 'global-offload', before + 1)
    assert_in('[OFFLOAD]', cmd(['conntrack', '-L', '-f', 'ipv4', '-p', 'udp',
                               '--orig-src', '198.18.50.2', '--orig-dst', '198.18.51.2']))


def test_ipv6_prefix_enrollment_counter(config):
    """IPv6 flow enrollment works through native prefix hook registration too."""
    config.delete('delete firewall flowtable FAST interface')
    config.set('set firewall flowtable FAST interface veth4105*')
    config.set('set firewall global-options state-policy established action accept')
    config.set('set firewall global-options flowtable FAST')
    config.commit()
    before = firewall_rule_packets('forward', 'global-offload')

    exchange_datagrams('ipv6')
    assert_firewall_rule_packets('forward', 'global-offload', before + 1)
    assert_in('[OFFLOAD]', cmd(['conntrack', '-L', '-f', 'ipv6', '-p', 'udp',
                               '--orig-src', '2001:db8:5050::2', '--orig-dst', '2001:db8:5051::2']))


def test_ipv4_failed_enrollment_not_counted(config):
    """An established IPv4 reset matches the rule but cannot enroll the closing flow."""
    # The connection must exist before enrollment is enabled.
    config.delete('delete firewall global-options flowtable')
    config.commit()
    with established_tcp('ipv4') as (sender, receiver):
        config.set('set firewall flowtable FAST interface veth41050 interface veth41052')
        config.set('set firewall global-options state-policy established action accept')
        config.set('set firewall global-options flowtable FAST')
        config.commit()
        before = firewall_rule_packets('forward', 'global-offload')
        reset_connection(sender, receiver)
    assert_firewall_rule_packets('forward', 'global-offload', before)


def test_ipv6_failed_enrollment_not_counted(config):
    """An established IPv6 reset cannot reach the counter after flow add."""
    # The connection must exist before enrollment is enabled.
    config.delete('delete firewall global-options flowtable')
    config.commit()
    with established_tcp('ipv6') as (sender, receiver):
        config.set('set firewall flowtable FAST interface veth41050 interface veth41052')
        config.set('set firewall global-options state-policy established action accept')
        config.set('set firewall global-options flowtable FAST')
        config.commit()
        before = firewall_rule_packets('forward', 'global-offload')
        reset_connection(sender, receiver)
    assert_firewall_rule_packets('forward', 'global-offload', before)
