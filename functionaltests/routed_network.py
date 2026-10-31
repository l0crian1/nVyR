"""One owned topology for routing, policy and firewall functional observations.

Configuration lives in configs/routed-network.conf and network-*.conf. Tests use
distinct routes and ports; deliberate mutations are restored by the package fixture.
The simulated hosts are the only objects configured outside the nVyR CLI.
"""

from contextlib import contextmanager
from pathlib import Path
import json
import os
import socket
import shlex
import uuid

from nvyr.helpers.process import cmd, rc_cmd
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.tree import lookup
from smoketests.assertions import (
    assert_bgp_path, assert_bgp_resources_unused, assert_config_names_unused,
    assert_equal, assert_link_addresses, assert_not_in, firewall_rule_packets,
    link_inventory,
)
from smoketests.support import defer_interrupt, wait_for


CONFIGURATION = Path(__file__).with_name('configs') / 'routed-network.conf'
CONFIGURATIONS = (CONFIGURATION, CONFIGURATION.with_name('network-features.conf'),
                  CONFIGURATION.with_name('network-policies.conf'),
                  CONFIGURATION.with_name('network-bgp-unicast.conf'),
                  CONFIGURATION.with_name('network-static.conf'),
                  CONFIGURATION.with_name('network-services.conf'))
LINKS = ('veth42061', 'veth42062', 'veth42063', 'veth42064', 'veth42065', 'veth42066',
         'veth42067', 'veth42068',
         'dum42061', 'dum977', 'dum980', 'dum997', 'dum998', 'dum999', 'veth994', 'veth995',
         'veth41050', 'veth41051', 'veth41052', 'veth41053')
NAMESPACES = ('nvyr-routed-left', 'nvyr-routed-right', 'nvyr-ft-source', 'nvyr-ft-destination')
POLICIES = ('RNCOMM', 'RNLARGE', 'RNAS', 'RNCALL', 'RNIN4', 'RNIN6', 'RNOUT4', 'RNOUT6',
            'RN4ACL', 'RN6ACL', 'RN4PREFIX', 'RN6PREFIX', 'RN4LAN', 'RN6LAN',
            'RN4P1', 'RN4P2', 'RN4P3', 'RN4P4', 'RN4P5', 'RN4P6',
            'RN6P1', 'RN6P2', 'RN6P3', 'RN6P4', 'RN6P5', 'RN6P6')


def commands():
    """Read the reviewed CLI configuration in installation order."""
    for path in CONFIGURATIONS:
        for line in path.read_text().splitlines():
            if line and not line.startswith('#'):
                yield line


def owned_names():
    """Reserve every provider named by the literal feature configs before staging."""
    names = set()
    for command in commands():
        tokens = shlex.split(command)
        if tokens[1:3] == ['firewall', 'group']:
            index = 5 if tokens[4] in {'ipv4', 'ipv6', 'inet'} else 4
            names.add(tokens[index])
        elif tokens[1] == 'policy':
            index = 4 if tokens[3] in {'ipv4', 'ipv6', 'standard', 'expanded'} else 3
            names.add(tokens[index])
        elif tokens[1] == 'firewall' and tokens[3] == 'name':
            names.add(tokens[4])
    return names


def configure(config):
    """Stage readable literal CLI commands and install the complete scenario once."""
    config.discard()
    running = config.get_config()
    for section in ('nat', 'firewall'):
        if section in running:
            config.delete('delete ' + section)
    if lookup(running, ('protocols', 'static'), None) is not None:
        config.delete('delete protocols static')
    if lookup(running, ('system', 'ntp'), None) is not None:
        config.delete('delete system ntp')

    config.set('set interfaces dummy dum998')
    config.set('set interfaces dummy dum999')
    config.set('set vrf name NVYRFWSMOKE table 41002')
    config.set('set interfaces virtual-ethernet veth994 peer-name veth995')
    config.set('set interfaces virtual-ethernet veth995 peer-name veth994')
    for line in commands():
        config.set(line)
    config.commit()


def preflight(config):
    """Reject configured or native resource collisions before taking ownership."""
    original = config.get_config()
    assert_config_names_unused(original, *LINKS, *POLICIES, *owned_names(), 'NVYRLEFT', 'NVYRRIGHT',
                               'RNMAP', 'RNMATCH', 'RNINNER', 'RNOUTER',
                               'RNTTLWITHIN', 'RNTTLOUTSIDE', 'RNIN', 'RNPORT',
                               'RNHOST', 'RNHOSTS', 'RNDEST', 'RNLEARN', 'RNTUPLE', 'RNECHO', 'RNFAST', 'RNCATCH', 'RNDEFAULT')
    assert_bgp_resources_unused(original, 'NVYRLEFT', 42061)
    assert_bgp_resources_unused(original, 'NVYRRIGHT', 42062)
    assert_bgp_resources_unused(original, 'NVYRFWSMOKE', 41002)
    assert_bgp_resources_unused(original, 'NVYRSMOKE', 41001)
    assert_bgp_resources_unused(original, 'NVYRDHCPSMOKE', 41980)
    assert_bgp_resources_unused(original, 'NTPTEST', 41977)
    devices = link_inventory()
    for name in LINKS:
        assert_not_in(name, devices)
    namespaces = {line.split()[0] for line in cmd(['ip', 'netns', 'list']).splitlines()}
    for name in NAMESPACES:
        assert_not_in(name, namespaces)
    return original


def configure_host(namespace, interface, ipv4, gateway4, ipv6, gateway6):
    """Represent an external dual-stack host behind each CLI-managed router LAN."""
    cmd(['ip', '-n', namespace, 'link', 'set', 'lo', 'up'])
    cmd(['ip', '-n', namespace, 'link', 'set', interface, 'up'])
    cmd(['ip', '-n', namespace, 'address', 'add', ipv4, 'dev', interface])
    cmd(['ip', '-n', namespace, '-6', 'address', 'add', ipv6, 'dev', interface, 'nodad'])
    cmd(['ip', '-n', namespace, 'route', 'add', 'default', 'via', gateway4])
    cmd(['ip', '-n', namespace, '-6', 'route', 'add', 'default', 'via', gateway6])


def converge():
    """Establish the common path; policy-specific failures belong to named tests."""
    assert_link_addresses('veth42063', '198.18.61.1/24', '2001:db8:61::1/64')
    assert_link_addresses('veth42065', '198.18.62.1/24', '2001:db8:62::1/64')
    assert_bgp_path('NVYRLEFT', 'ipv4', '198.18.62.0/24')
    assert_bgp_path('NVYRLEFT', 'ipv6', '2001:db8:62::/64')
    assert_bgp_path('NVYRRIGHT', 'ipv4', '198.18.61.0/24')
    assert_bgp_path('NVYRRIGHT', 'ipv6', '2001:db8:61::/64')
    end_of_rib('198.18.60.2', 'ipv4Unicast')
    end_of_rib('2001:db8:60::2', 'ipv6Unicast')

    # Establish LAN connectivity independently of the packet assertions below;
    # no case should depend on another case warming its BGP-routed path.
    for destination in ('198.18.62.2', '2001:db8:62::2'):
        arguments = ['ip', 'netns', 'exec', 'nvyr-routed-left', 'ping',
                     '-n', '-c', '1', '-W', '1', destination]
        wait_for(lambda: rc_cmd(arguments, timeout=3), lambda result: result[0] == 0,
                 description=f'simulated-host reachability to {destination}', timeout=10)


def end_of_rib(neighbor, family):
    """Do not classify an advertised route as filtered before its update has arrived."""
    def read():
        document = json.loads(cmd(['vtysh', '-c', f'show bgp vrf NVYRLEFT neighbors {neighbor} json']))
        return document.get(neighbor, {})

    def received(value):
        completed = value.get('gracefulRestartInfo', {}).get('endOfRibRecv', {})
        return value.get('bgpState') == 'Established' and completed.get(family) is True

    wait_for(read, received, description=f'{neighbor} initial {family} updates complete', timeout=30)


def restore(config, original, moved, namespaces):
    """Return managed peers before restoring configuration, even after failed setup."""
    errors = []
    for namespace, interface in reversed(moved):
        try:
            cmd(['ip', '-n', namespace, 'address', 'flush', 'dev', interface])
            cmd(['ip', '-n', namespace, 'link', 'set', interface, 'netns', str(os.getpid())])
        except Exception as error:
            errors.append(error)

    try:
        config.discard()
        config.load(original, replace=True)
        config.commit()
        assert_equal(config.get_config(), original)
    except Exception as error:
        errors.append(error)

    for namespace in reversed(namespaces):
        try:
            cmd(['ip', 'netns', 'delete', namespace])
        except Exception as error:
            errors.append(error)

    if errors:
        raise ExceptionGroup('Routed-network restoration failed', errors)


@contextmanager
def scenario(config, stop):
    """Own setup once and restore the entry configuration after the whole package."""
    original = preflight(config)
    namespaces = []
    moved = []
    try:
        configure(config)
        for namespace in NAMESPACES:
            cmd(['ip', 'netns', 'add', namespace])
            namespaces.append(namespace)
        for namespace, interface in (('nvyr-routed-left', 'veth42064'),
                                     ('nvyr-routed-right', 'veth42066'),
                                     ('nvyr-ft-source', 'veth41051'),
                                     ('nvyr-ft-destination', 'veth41053')):
            cmd(['ip', 'link', 'set', interface, 'netns', namespace])
            moved.append((namespace, interface))

        configure_host('nvyr-routed-left', 'veth42064', '198.18.61.2/24', '198.18.61.1',
                       '2001:db8:61::2/64', '2001:db8:61::1')
        configure_host('nvyr-routed-right', 'veth42066', '198.18.62.2/24', '198.18.62.1',
                       '2001:db8:62::2/64', '2001:db8:62::1')
        configure_host('nvyr-ft-source', 'veth41051', '198.18.50.2/30', '198.18.50.1',
                       '2001:db8:5050::2/64', '2001:db8:5050::1')
        configure_host('nvyr-ft-destination', 'veth41053', '198.18.51.2/30', '198.18.51.1',
                       '2001:db8:5051::2/64', '2001:db8:5051::1')
        cmd(['ip', '-n', 'nvyr-routed-right', 'address', 'add', '198.19.62.2/32', 'dev', 'lo'])
        cmd(['ip', '-n', 'nvyr-routed-right', '-6', 'address', 'add', '2001:db8:64::2/128',
             'dev', 'lo', 'nodad'])
        converge()
        yield
    finally:
        try:
            with defer_interrupt():
                restore(config, original, moved, namespaces)
        except BaseException:
            stop('Routed-network cleanup failed; stopping tests and restoring the session snapshot.')
            raise


@contextmanager
def host_socket(namespace, family, kind=socket.SOCK_DGRAM):
    """Create a host socket without leaving the test thread in its namespace."""
    with open('/proc/self/ns/net', 'rb') as original, open('/run/netns/' + namespace, 'rb') as target:
        try:
            os.setns(target.fileno(), 0)
            endpoint = socket.socket(family, kind)
        finally:
            os.setns(original.fileno(), 0)
    with endpoint:
        yield endpoint


def assert_traffic(family, port, *, allowed=True, static=False, counter=None, map_entry=None, dscp=None):
    """Prove delivery/reply or a drop; rule counters use deltas, never suite totals."""
    ipv6 = family == 'ipv6'
    address_family = socket.AF_INET6 if ipv6 else socket.AF_INET
    source = '2001:db8:61::2' if ipv6 else '198.18.61.2'
    destination = '2001:db8:62::2' if ipv6 else '198.18.62.2'
    if static:
        destination = '2001:db8:64::2' if ipv6 else '198.19.62.2'
    before = firewall_rule_packets(*counter) if counter else None
    map_before = map_packets(map_entry) if map_entry else None
    payload = uuid.uuid4().bytes

    with host_socket('nvyr-routed-left', address_family) as sender, \
            host_socket('nvyr-routed-right', address_family) as receiver:
        sender.bind((source, 0))
        if dscp is not None:
            level, option = (socket.IPPROTO_IPV6, socket.IPV6_TCLASS) if ipv6 else (socket.IPPROTO_IP, socket.IP_TOS)
            sender.setsockopt(level, option, dscp << 2)
        sender.settimeout(2)
        receiver.bind((destination, port))
        receiver.settimeout(2 if allowed else 0.2)
        sender.sendto(payload, (destination, port))
        try:
            received, peer = receiver.recvfrom(256)
        except TimeoutError:
            assert not allowed, f'{family} UDP/{port}: packet did not reach {destination}'
        else:
            assert allowed, f'{family} UDP/{port}: packet passed the configured drop'
            assert_equal(received, payload)
            receiver.sendto(payload, peer)
            assert_equal(sender.recv(256), payload)

    if counter:
        wait_for(lambda: firewall_rule_packets(*counter), lambda count: count == before + 1,
                 description=f'{counter}: one additional forwarded packet')
    if map_entry:
        assert_equal(map_packets(map_entry), map_before + 1)


def assert_offloaded_traffic(family):
    """Exchange repeated packets on one tuple and require native offload accounting."""
    from smoketests.assertions import assert_connection_accounting

    ipv6 = family == 'ipv6'
    address_family = socket.AF_INET6 if ipv6 else socket.AF_INET
    source = '2001:db8:61::2' if ipv6 else '198.18.61.2'
    destination = '2001:db8:62::2' if ipv6 else '198.18.62.2'
    with host_socket('nvyr-routed-left', address_family) as sender, \
            host_socket('nvyr-routed-right', address_family) as receiver:
        sender.bind((source, 0))
        receiver.bind((destination, 52150))
        sender.settimeout(3)
        receiver.settimeout(3)
        for number in range(6):
            payload = f'flow-{number}'.encode()
            sender.sendto(payload, receiver.getsockname())
            received, peer = receiver.recvfrom(128)
            assert_equal(received, payload)
            receiver.sendto(payload, peer)
            assert_equal(sender.recv(128), payload)
        assert_connection_accounting(family, source, destination, 6,
                                     source_port=sender.getsockname()[1], destination_port=52150)


def named_packets(name):
    """Read a named counter without resetting state shared by other observations."""
    document = json.loads(cmd(['nft', '-j', 'list', 'counter', 'inet', 'nvyr_filter',
                               'counter_group_' + name]))
    counters = [item['counter'] for item in document['nftables'] if 'counter' in item]
    assert_equal(len(counters), 1)
    return counters[0]['packets']


def map_packets(entry):
    """Require the selected map element to account for a dropped/delivered probe."""
    document = json.loads(cmd(['nft', '-j', 'list', 'map', 'inet', 'nvyr_filter', 'inet_map_RNMAP']))
    group = normalize(document)['tables']['inet']['nvyr_filter']['maps']['inet_map_RNMAP']
    entries = [item for item in group['entries'] if item.get('name') == entry]
    assert_equal(len(entries), 1)
    return entries[0]['counter']['packets']


def assert_tcp_traffic(family):
    """Observe SYN matching with a real handshake and bidirectional stream payload."""
    ipv6 = family == 'ipv6'
    address_family = socket.AF_INET6 if ipv6 else socket.AF_INET
    source = '2001:db8:61::2' if ipv6 else '198.18.61.2'
    destination = '2001:db8:62::2' if ipv6 else '198.18.62.2'
    before = firewall_rule_packets(family + '_forward', 42130)
    with host_socket('nvyr-routed-left', address_family, socket.SOCK_STREAM) as sender, \
            host_socket('nvyr-routed-right', address_family, socket.SOCK_STREAM) as listener:
        sender.bind((source, 0))
        listener.bind((destination, 52130))
        listener.listen(1)
        sender.settimeout(3)
        listener.settimeout(3)
        sender.connect(listener.getsockname())
        receiver, _ = listener.accept()
        with receiver:
            receiver.settimeout(3)
            sender.sendall(b'tcp-probe')
            assert_equal(receiver.recv(128), b'tcp-probe')
            receiver.sendall(b'reply')
            assert_equal(sender.recv(128), b'reply')
    assert_equal(firewall_rule_packets(family + '_forward', 42130), before + 1)
