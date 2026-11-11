"""CGN TCP/UDP return translation and ICMP identifiers on the shared routed LANs.

Uses network-cgnat.conf in the single routed scenario. No configuration changes
or additional interfaces. Incompatible with notrack or NAT replacing these tuples.
"""

import re
import socket

import pytest

from functionaltests.routed_network import host_socket
from nvyr.helpers.process import cmd


@pytest.mark.parametrize('kind', [socket.SOCK_DGRAM, socket.SOCK_STREAM])
def test_translated_transport_roundtrip(kind):
    port = 52600 if kind == socket.SOCK_DGRAM else 52601
    with host_socket('nvyr-routed-left', socket.AF_INET, kind) as sender, \
            host_socket('nvyr-routed-right', socket.AF_INET, kind) as listener:
        sender.bind(('198.18.61.2', 0))
        listener.bind(('198.18.62.2', port))
        sender.settimeout(3)
        listener.settimeout(3)
        if kind == socket.SOCK_DGRAM:
            sender.sendto(b'cgn', listener.getsockname())
            data, peer = listener.recvfrom(128)
            assert data == b'cgn'
            listener.sendto(b'reply', peer)
            assert sender.recvfrom(128)[0] == b'reply'
        else:
            listener.listen(1)
            sender.connect(listener.getsockname())
            receiver, peer = listener.accept()
            with receiver:
                receiver.settimeout(3)
                sender.sendall(b'cgn')
                assert receiver.recv(128) == b'cgn'
                receiver.sendall(b'reply')
                assert sender.recv(128) == b'reply'
        assert peer[0] == '198.18.62.1'
        assert 40000 <= peer[1] <= 40999


def test_echo_identifier_translation():
    cmd(['ip', 'netns', 'exec', 'nvyr-routed-left', 'ping', '-n', '-c', '1', '-W', '2',
         '-e', '50000', '198.19.62.2'])
    entries = cmd(['conntrack', '-L', '-p', 'icmp', '--orig-src', '198.18.61.2', '--orig-dst', '198.19.62.2'])
    identifiers = re.findall(r'dst=198\.18\.62\.1 type=0 code=0 id=(\d+)', entries)
    assert identifiers and all(40000 <= int(identifier) <= 40999 for identifier in identifiers), entries
