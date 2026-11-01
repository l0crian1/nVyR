"""Opt-in packet tests in a disposable privileged container, never a router LAN."""

import json
import os
from pathlib import Path
import subprocess
import threading
import time

import pytest

from nvyr.helpers import kea
from nvyr.errors import RouterError
from nvyr.config_scripts import service_dhcp
from tests.dhcp_config import generated_server
from nvyr.op_scripts import dhcp_server

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_KEA_TEST') != '1',
                                reason='requires isolated privileged Kea container')


def run(*arguments):
    return subprocess.run(arguments, check=True, capture_output=True, text=True).stdout


def client4(interface, requested=None, hostname=None):
    """Exchange real DHCP packets; use the same client identity for renewals."""
    from scapy.all import AsyncSniffer, BOOTP, DHCP, Ether, IP, UDP, get_if_hwaddr, sendp

    mac = get_if_hwaddr(interface)
    hardware = bytes.fromhex(mac.replace(':', ''))
    xid = 0x76543210

    def exchange(message, expected, address='0.0.0.0', server='255.255.255.255'):
        ready = threading.Event()
        packet = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / IP(src=address, dst=server) / UDP(sport=68, dport=67)
        packet /= BOOTP(chaddr=hardware, xid=xid, ciaddr=address, flags=0x8000 if address == '0.0.0.0' else 0)
        if hostname:
            message = message + [('hostname', hostname)]
        packet /= DHCP(options=message + ['end'])
        capture = AsyncSniffer(iface=interface, store=True, count=1, timeout=4,
                               started_callback=ready.set,
                               lfilter=lambda reply: BOOTP in reply and reply[BOOTP].op == 2
                               and reply[BOOTP].xid == xid and DHCP in reply
                               and dict(item for item in reply[DHCP].options if isinstance(item, tuple)).get('message-type') == expected)
        capture.start()
        assert ready.wait(2)
        sendp(packet, iface=interface, verbose=False)
        capture.join()
        assert capture.results, 'No DHCP reply'
        return capture.results[0]

    if requested:
        address, server = requested
        run('ip', 'address', 'replace', address + '/24', 'dev', interface)
        reply = exchange([('message-type', 'request')], 5, address, server)
    else:
        offer = exchange([('message-type', 'discover')], 2)
        options = dict(item for item in offer[DHCP].options if isinstance(item, tuple))
        address = offer[BOOTP].yiaddr
        server = options['server_id']
        reply = exchange([('message-type', 'request'), ('requested_addr', address), ('server_id', server)], 5)
    return {'address': reply[BOOTP].yiaddr, 'server': server}


def client6(interface):
    """Solicit and request an IA_NA address, including the server-selected DUID."""
    from scapy.all import AsyncSniffer, Ether, IPv6, UDP, get_if_hwaddr, sendp
    from scapy.layers.dhcp6 import (DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply,
                                   DHCP6OptClientId, DHCP6OptServerId, DHCP6OptIA_NA, DHCP6OptIAAddress, DUID_LL)

    mac = get_if_hwaddr(interface)
    addresses = json.loads(run('ip', '-j', '-6', 'address', 'show', 'dev', interface))[0]['addr_info']
    source = next(item['local'] for item in addresses if item['scope'] == 'link')
    identifier = DHCP6OptClientId(duid=DUID_LL(lladdr=mac))
    base = Ether(src=mac, dst='33:33:00:01:00:02') / IPv6(src=source, dst='ff02::1:2') / UDP(sport=546, dport=547)

    def exchange(message, expected):
        ready = threading.Event()
        capture = AsyncSniffer(iface=interface, store=True, count=1, timeout=4,
                               started_callback=ready.set, lfilter=lambda reply: expected in reply)
        capture.start()
        assert ready.wait(2)
        sendp(base / message, iface=interface, verbose=False)
        capture.join()
        assert capture.results, 'No DHCPv6 reply'
        return capture.results[0]

    offer = exchange(DHCP6_Solicit(trid=1234) / identifier / DHCP6OptIA_NA(iaid=1), DHCP6_Advertise)
    request = DHCP6_Request(trid=1235) / identifier / DHCP6OptServerId(duid=offer[DHCP6OptServerId].duid)
    reply = exchange(request / DHCP6OptIA_NA(iaid=1), DHCP6_Reply)
    assert DHCP6OptIAAddress in reply, reply.summary()
    return {'address': reply[DHCP6OptIAAddress].addr}


@pytest.fixture
def native(tmp_path):
    """Keep all test ports, clients, daemons and leases inside the disposable container."""
    assert Path('/.dockerenv').exists() and os.geteuid() == 0
    processes = []
    for index, vrf in ((1, None), (2, 'KBLUE')):
        run('ip', 'netns', 'add', f'kclient{index}')
        run('ip', 'link', 'add', f'ksrv{index}', 'type', 'veth', 'peer', 'name', f'kcli{index}')
        run('ip', 'link', 'set', f'kcli{index}', 'netns', f'kclient{index}')
        if vrf:
            run('ip', 'link', 'add', vrf, 'type', 'vrf', 'table', '40101')
            run('ip', 'link', 'set', vrf, 'up')
            run('ip', 'link', 'set', f'ksrv{index}', 'master', vrf)
        run('ip', 'address', 'add', f'192.0.2.{index}/24', 'dev', f'ksrv{index}')
        run('ip', '-6', 'address', 'add', '2001:db8::1/64', 'dev', f'ksrv{index}', 'nodad')
        run('ip', 'link', 'set', f'ksrv{index}', 'up')
        run('ip', '-n', f'kclient{index}', 'link', 'set', f'kcli{index}', 'up')

    def start(family, index, configuration):
        folder = tmp_path / f'{family}-{index}'
        folder.mkdir(mode=0o700)
        devices = kea.inventory()
        if not configuration.get('listen-interface') and not configuration.get('listen-address'):
            configuration = configuration | {'listen-interface': [f'ksrv{index}']}
        vrf = devices[f'ksrv{index}']['vrf']
        listeners = service_dhcp.verify_listeners(configuration, family, vrf, devices)
        service_dhcp.verify_shared_interfaces(configuration, family, listeners, devices)
        kea.wait_listeners(family, listeners)
        native_config = generated_server(configuration, family, devices, vrf=vrf, state_directory=tmp_path)
        # Each manually launched fixture has isolated lease and control paths.
        native_config[f'Dhcp{family}']['lease-database']['name'] = str(folder / 'leases.csv')
        native_config[f'Dhcp{family}']['control-sockets'][0]['socket-name'] = str(folder / 'control.sock')
        native_config[f'Dhcp{family}']['loggers'][0]['output-options'] = [{'output': 'stdout'}]
        path = folder / 'config.json'
        path.write_text(json.dumps(native_config))
        env = os.environ | {'KEA_CONTROL_SOCKET_DIR': str(folder), 'KEA_PIDFILE_DIR': str(folder),
                            'KEA_DHCP_DATA_DIR': str(folder)}
        command = [f'/usr/sbin/kea-dhcp{family}', '-c', str(path)]
        if vrf != 'default':
            command = ['ip', 'vrf', 'exec', vrf, *command]
        output = (folder / 'log').open('w')
        process = subprocess.Popen(command, env=env, stdout=output, stderr=subprocess.STDOUT)
        processes.append((process, output))
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                status = kea.control(folder / 'control.sock', 'status-get')
                if kea.waiting_for_carrier(status, listeners):
                    return folder, native_config
                if kea.sockets_ready(status):
                    return folder, native_config
            except (OSError, RouterError):
                if process.poll() is not None:
                    pytest.fail((folder / 'log').read_text())
                time.sleep(0.1)
        pytest.fail((folder / 'log').read_text())

    start.processes = processes
    try:
        yield start
    finally:
        for process, output in processes:
            process.terminate()
            process.wait(timeout=10)
            output.close()
        for index in (1, 2):
            run('ip', 'netns', 'delete', f'kclient{index}')
        run('ip', 'link', 'delete', 'KBLUE')


def request(family, index, requested=None, hostname=None):
    code = f'from tests.test_kea_live import client{family}; import json; print(json.dumps(client{family}("kcli{index}"'
    if requested:
        code += ', ' + repr(requested)
    if hostname:
        code += ', hostname=' + repr(hostname)
    code += ')))'
    return json.loads(run('ip', 'netns', 'exec', f'kclient{index}', 'python3', '-c', code))


def release4(interface, address, server):
    """Send a real DHCPRELEASE using the same client identity as client4()."""
    from scapy.all import BOOTP, DHCP, Ether, IP, UDP, get_if_hwaddr, sendp

    mac = get_if_hwaddr(interface)
    packet = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') / IP(src=address, dst=server) / UDP(sport=68, dport=67)
    packet /= BOOTP(chaddr=bytes.fromhex(mac.replace(':', '')), ciaddr=address)
    packet /= DHCP(options=[('message-type', 'release'), ('server_id', server), 'end'])
    sendp(packet, iface=interface, verbose=False)


def test_ipv4_hostfile_native_events(native, tmp_path):
    """The packaged hook publishes a real ACK/renewal and removes a released lease.

    This container has no systemd PID 1. A systemctl stand-in executes the same
    oneshot against test files; Kea and its run-script library are unmodified.
    """
    from nvyr.helpers import dhcp_hosts

    assert Path('/.dockerenv').exists()
    systemctl = Path('/usr/bin/systemctl')
    assert not systemctl.exists(), 'Use the dedicated Kea test image without systemd'
    hook = Path(dhcp_hosts.HOOK_SCRIPT)
    hook.parent.mkdir(parents=True, exist_ok=True)
    hook.write_bytes(Path('packaging/nvyr-dhcp-hosts-hook').read_bytes())
    hook.chmod(0o755)
    configuration_path = tmp_path / '4-1/config.json'
    host_file = tmp_path / 'hosts'
    systemctl.write_text('#!/usr/bin/python3\n'
                        'from nvyr.helpers.dhcp_hosts import reconcile\n'
                        f'reconcile({str(configuration_path)!r}, {str(host_file)!r})\n')
    systemctl.chmod(0o755)
    host_file.write_text('127.0.0.1 localhost\n')
    configuration = {'update-hostfile': {}, 'lease-time': '1d',
                     'option': {'domain-name': 'home.example'}, 'shared-network': {'LAN': {
                         'subnet': {'192.0.2.0/24': {'range': ['192.0.2.10-192.0.2.20']}}}}}

    def wait_for_text(value, present=True):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if (value in host_file.read_text()) == present:
                return
            time.sleep(0.05)
        pytest.fail(f'Hostfile did not converge: {host_file.read_text()}\n'
                    f'Leases: {(folder / "leases.csv").read_text()}\n'
                    f'Kea: {(folder / "log").read_text()}')

    try:
        folder, configuration = native(4, 1, configuration)
        lease = request(4, 1, hostname='printer')
        wait_for_text(f"{lease['address']}\tprinter.home.example printer\n")

        request(4, 1, (lease['address'], lease['server']), hostname='renamed')
        wait_for_text('renamed.home.example renamed\n')
        assert 'printer' not in host_file.read_text()

        code = 'from tests.test_kea_live import release4; release4("kcli1", ' + repr(lease['address']) + ', ' + repr(lease['server']) + ')'
        run('ip', 'netns', 'exec', 'kclient1', 'python3', '-c', code)
        wait_for_text('renamed', present=False)

        # Removing the feature unloads the native hook instead of retaining it.
        configuration['Dhcp4']['hooks-libraries'] = []
        kea.control(folder / 'control.sock', 'config-set', configuration)
        current = kea.control(folder / 'control.sock', 'config-get')['arguments']['Dhcp4']
        assert current['hooks-libraries'] == []
    finally:
        systemctl.unlink()
        hook.unlink()


def relay4(server):
    """Relay a complete exchange over UDP to a server address on a different interface."""
    import socket

    from scapy.all import BOOTP, DHCP

    hardware = bytes.fromhex('020000000099')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
        relay.bind(('192.0.2.100', 67))
        relay.settimeout(4)

        def exchange(options, expected):
            packet = BOOTP(chaddr=hardware, xid=0x12345678, giaddr='192.0.2.100', hops=1)
            packet /= DHCP(options=options + ['end'])
            relay.sendto(bytes(packet), (server, 67))
            reply = BOOTP(relay.recv(4096))
            values = dict(item for item in reply[DHCP].options if isinstance(item, tuple))
            assert reply.op == 2 and reply.xid == packet.xid
            assert values['message-type'] == expected
            return reply, values

        offer, options = exchange([('message-type', 'discover')], 2)
        reply, _ = exchange([('message-type', 'request'), ('requested_addr', offer.yiaddr),
                             ('server_id', options['server_id'])], 5)
        return reply.yiaddr


def test_udp_relay_to_dummy_address(native):
    """UDP accepts routed relays arriving on a veth but addressed to a dummy /32."""
    run('ip', 'link', 'add', 'kdummy', 'type', 'dummy')
    try:
        run('ip', 'address', 'add', '198.51.100.1/32', 'dev', 'kdummy')
        run('ip', 'link', 'set', 'kdummy', 'up')
        run('ip', '-n', 'kclient1', 'address', 'add', '192.0.2.100/24', 'dev', 'kcli1')
        run('ip', '-n', 'kclient1', 'route', 'add', '198.51.100.1/32', 'via', '192.0.2.1')
        section = {'socket-type': 'udp', 'listen-address': ['198.51.100.1'],
                   'listen-interface': ['ksrv1'],
                   'lease-time': '1d', 'shared-network': {'LAN': {'subnet': {
                       '192.0.2.0/24': {'range': ['192.0.2.10-192.0.2.20']}}}}}
        folder, _ = native(4, 1, section)

        code = "from tests.test_kea_live import relay4; print(relay4('198.51.100.1'))"
        try:
            address = run('ip', 'netns', 'exec', 'kclient1', 'python3', '-c', code).strip()
        except subprocess.CalledProcessError as error:
            pytest.fail(error.stderr + '\n' + (folder / 'log').read_text())

        assert address == '192.0.2.10'
        applied = kea.control(folder / 'control.sock', 'config-get')['arguments']['Dhcp4']
        assert applied['interfaces-config']['dhcp-socket-type'] == 'udp'
        assert applied['interfaces-config']['interfaces'] == ['kdummy/198.51.100.1', 'ksrv1/192.0.2.1']
    finally:
        run('ip', 'link', 'delete', 'kdummy')


def test_ipv4_operational_leases_pools_and_listeners(native, monkeypatch):
    """A real ACK produces one current lease and one occupied allocation slot."""
    section = {'lease-time': '1d', 'shared-network': {'LAN': {'subnet': {
        '192.0.2.0/24': {'range': ['192.0.2.10-192.0.2.20']}}}}}
    folder, _ = native(4, 1, section)
    lease = request(4, 1)
    request(4, 1, (lease['address'], lease['server']))

    control = kea.control
    monkeypatch.setattr(dhcp_server.services, 'running_configuration', lambda: {'service': {'dhcp-server': section}})
    monkeypatch.setattr(kea, 'control', lambda path, command, **kwargs: control(folder / 'control.sock', command, **kwargs))
    records = json.loads(dhcp_server.show(4, 'leases', raw=True))['records']
    assert len(records) == 1
    assert records[0]['address'] == lease['address']
    assert records[0]['pool'] == 'LAN'
    assert records[0]['expires_in'] > 0
    pools = json.loads(dhcp_server.show(4, 'pools', raw=True))['records']
    assert pools[0]['assigned'] == 1 and pools[0]['total'] == 11
    listeners = json.loads(dhcp_server.show(4, 'listeners', raw=True))['records']
    assert listeners[0]['state'] == 'Listening'
    assert listeners[0]['address'] == '192.0.2.1'


def test_ipv6_operational_leases_pools_and_listeners(native, monkeypatch):
    """Real IA_NA leases retain their DUID/IAID and count against the IPv6 range."""
    section = {'preferred-lifetime': '12h', 'valid-lifetime': '1d', 'shared-network': {'LAN': {
        'subnet': {'2001:db8::/64': {'range': ['2001:db8::10-2001:db8::20']}}}}}
    folder, _ = native(6, 1, section)
    lease = request(6, 1)

    control = kea.control
    monkeypatch.setattr(dhcp_server.services, 'running_configuration', lambda: {'service': {'dhcpv6-server': section}})
    monkeypatch.setattr(kea, 'control', lambda path, command, **kwargs: control(folder / 'control.sock', command, **kwargs))
    records = json.loads(dhcp_server.show(6, 'leases', raw=True))['records']
    assert len(records) == 1
    assert records[0]['address'] == lease['address']
    assert records[0]['duid'] and records[0]['iaid'] is not None
    pools = json.loads(dhcp_server.show(6, 'pools', raw=True))['records']
    assert pools[0]['assigned'] == 1 and pools[0]['total'] == 17
    listeners = json.loads(dhcp_server.show(6, 'listeners', raw=True))['records']
    assert listeners[0]['state'] == 'Listening'
    assert listeners[0]['address'].startswith('fe80:')


def test_ipv4_vrf_isolation_renewal_and_reconfiguration(native):
    """Overlapping subnets have separate leases; a config-set preserves renewal."""
    first = {'lease-time': '1d', 'shared-network': {'LAN': {'subnet': {
        '192.0.2.0/24': {'range': ['192.0.2.10-192.0.2.10', '192.0.2.20-192.0.2.20']}}}}}
    first['option'] = {'name-server': ['192.0.2.1'], 'domain-search': ['example.net', 'office.example.net'],
                       'domain-name': 'example.net', 'ntp-server': ['192.0.2.2'], 'default-router': '192.0.2.1'}
    first['shared-network']['LAN']['subnet']['192.0.2.0/24']['reservation'] = {
        'printer': {'mac-address': '02:00:00:00:ff:01', 'address': '192.0.2.50', 'hostname': 'printer'}}
    second = {'lease-time': '1d', 'shared-network': {'LAN': {'subnet': {
        '192.0.2.0/24': {'range': ['192.0.2.30-192.0.2.30']}}}}}
    folder, config = native(4, 1, first)
    native(4, 2, second)

    lease = request(4, 1)
    assert lease['address'] in {'192.0.2.10', '192.0.2.20'}
    assert request(4, 2)['address'] == '192.0.2.30'

    config['Dhcp4']['shared-networks'][0]['subnet4'].append({
        'id': 100, 'subnet': '198.51.100.0/24', 'pools': [{'pool': '198.51.100.10-198.51.100.20'}]})
    kea.control(folder / 'control.sock', 'config-set', config)
    assert request(4, 1, (lease['address'], lease['server']))['address'] == lease['address']


def test_ipv6_vrf_isolation(native):
    """The same IPv6 prefix in two VRFs must use only its own server's pool."""
    first = {'preferred-lifetime': '12h', 'valid-lifetime': '1d', 'shared-network': {'LAN': {
        'interface': 'ksrv1', 'subnet': {'2001:db8::/64': {'range': ['2001:db8::10-2001:db8::10']}}}}}
    first['option'] = {'name-server': ['2001:db8::1'], 'domain-search': ['example.net', 'office.example.net']}
    first['shared-network']['LAN']['subnet']['2001:db8::/64']['reservation'] = {
        'printer': {'duid': '00:03:00:01:02:00:00:00:ff:01', 'address': '2001:db8::50', 'hostname': 'printer'}}
    second = {'preferred-lifetime': '12h', 'valid-lifetime': '1d', 'shared-network': {'LAN': {
        'interface': 'ksrv2', 'subnet': {'2001:db8::/64': {'range': ['2001:db8::20-2001:db8::20']}}}}}
    native(6, 1, first)
    native(6, 2, second)

    assert request(6, 1)['address'] == '2001:db8::10'
    assert request(6, 2)['address'] == '2001:db8::20'


def test_ipv6_subnet_selection_without_shared_interface(native):
    """An ordinary listener selects the shared network from its assigned prefix."""
    configuration = {'preferred-lifetime': '12h', 'valid-lifetime': '1d', 'shared-network': {
        'LAN': {'subnet': {'2001:db8::/64': {'range': ['2001:db8::30-2001:db8::30']}}}}}
    native(6, 1, configuration)

    assert request(6, 1)['address'] == '2001:db8::30'


def test_ipv4_named_vrfs_allow_identical_listener_addresses(native):
    """The default-VRF restriction must not prohibit two device-bound instances."""
    run('ip', 'link', 'add', 'KRED', 'type', 'vrf', 'table', '40102')
    try:
        run('ip', 'link', 'set', 'KRED', 'up')
        run('ip', 'link', 'set', 'ksrv1', 'master', 'KRED')
        run('ip', 'address', 'del', '192.0.2.2/24', 'dev', 'ksrv2')
        run('ip', 'address', 'add', '192.0.2.1/24', 'dev', 'ksrv2')
        first = {'lease-time': '1d', 'shared-network': {'LAN': {'subnet': {
            '192.0.2.0/24': {'range': ['192.0.2.10-192.0.2.10']}}}}}
        second = {'lease-time': '1d', 'shared-network': {'LAN': {'subnet': {
            '192.0.2.0/24': {'range': ['192.0.2.20-192.0.2.20']}}}}}
        native(4, 1, first)
        native(4, 2, second)

        assert request(4, 1)['address'] == '192.0.2.10'
        assert request(4, 2)['address'] == '192.0.2.20'
    finally:
        run('ip', 'link', 'delete', 'KRED')


def test_ipv4_listener_without_carrier(native):
    """An unplugged member link must not prevent configuring its DHCP server."""
    run('ip', '-n', 'kclient1', 'link', 'set', 'kcli1', 'down')
    configuration = {'lease-time': '1d', 'shared-network': {'LAN': {'subnet': {
        '192.0.2.0/24': {'range': ['192.0.2.10-192.0.2.10']}}}}}
    folder, _ = native(4, 1, configuration)

    run('ip', '-n', 'kclient1', 'link', 'set', 'kcli1', 'up')
    wait_for_sockets(folder)
    assert request(4, 1)['address'] == '192.0.2.10'


def wait_for_sockets(folder):
    """Wait for native socket retries before sending a single test transaction."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if kea.sockets_ready(kea.control(folder / 'control.sock', 'status-get')):
            return
        time.sleep(0.1)
    pytest.fail((folder / 'log').read_text())


def test_ipv6_listener_without_carrier(native):
    """IPv6 also starts serving automatically after an unplugged port gains carrier."""
    # Start with a newly created port whose peer has never provided carrier.
    run('ip', 'link', 'delete', 'ksrv1')
    run('ip', 'link', 'add', 'ksrv1', 'type', 'veth', 'peer', 'name', 'kcli1')
    run('ip', 'link', 'set', 'kcli1', 'netns', 'kclient1')
    run('ip', '-6', 'address', 'add', '2001:db8::1/64', 'dev', 'ksrv1', 'nodad')
    run('ip', 'link', 'set', 'ksrv1', 'up')
    configuration = {'preferred-lifetime': '12h', 'valid-lifetime': '1d', 'shared-network': {
        'LAN': {'subnet': {'2001:db8::/64': {'range': ['2001:db8::30-2001:db8::30']}}}}}
    folder, _ = native(6, 1, configuration)

    run('ip', '-n', 'kclient1', 'link', 'set', 'kcli1', 'up')
    wait_for_sockets(folder)
    assert request(6, 1)['address'] == '2001:db8::30'


def test_carrier_retry_exhaustion_requests_service_restart(native):
    """An unplugged port outlasting native retries must trigger Restart=on-failure."""
    run('ip', '-n', 'kclient1', 'link', 'set', 'kcli1', 'down')
    configuration = {'lease-time': '1d', 'shared-network': {'LAN': {'subnet': {
        '192.0.2.0/24': {'range': ['192.0.2.10-192.0.2.10']}}}}}
    native(4, 1, configuration)

    process, _ = native.processes[-1]
    assert process.wait(timeout=20) != 0
