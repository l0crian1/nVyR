"""Shared assertion names for live tests, backed by unittest and pytest.

Value checks raise AssertionError and accept an optional msg argument.
assert_true/assert_false check truthiness, not identity with True/False.
assert_raises is pytest.raises, including match= and captured exception details.
"""

import json
import os
import re
import socket
import unittest
from pathlib import Path

import pytest

from nvyr.helpers.process import cmd, rc_cmd
from smoketests.support import wait_for


def assert_sysctl(path, expected):
    """Check a native sysctl, allowing asynchronous udev interface initialization."""
    target = Path('/proc/sys') / path
    wait_for(lambda: target.read_text().strip() if target.exists() else None,
             lambda value: value == str(expected), description=f'{target} = {expected}')


def assert_vrf_conntrack_zone(vrf, *interfaces, absent=()):
    """Read the generated map and verify one shared nondefault zone per VRF."""
    ruleset = json.loads(cmd(['nft', '-j', 'list', 'map', 'inet', 'nvyr_vrf_conntrack', 'interfaces']))
    mapping = next(item['map'] for item in ruleset['nftables'] if 'map' in item)
    elements = dict(mapping.get('elem', []))
    zone = elements[vrf]
    assert_true(1 <= zone <= 65535)
    for interface in interfaces:
        assert_equal(elements.get(interface), zone, msg=f'{interface} must use {vrf} conntrack zone')
    for interface in absent:
        assert_not_in(interface, elements)
    return zone


def assert_connection_accounting(family, source, destination, minimum_packets, *, source_port=None, destination_port=None):
    """Wait for offloaded flow accounting to synchronize into conntrack."""
    from nvyr.helpers import conntrack

    def counters():
        return conntrack.read(family=family, protocol='udp', source_address=source,
                              destination_address=destination)

    wait_for(counters, lambda records: any(
        'offload' in record.get('status', [])
        and (source_port is None or record.get('original', {}).get('source-port') == source_port)
        and (destination_port is None or record.get('original', {}).get('destination-port') == destination_port)
        and record.get('original', {}).get('packets', 0) >= minimum_packets
        and record.get('reply', {}).get('packets', 0) >= minimum_packets
        for record in records), description='Offloaded connection packet accounting', timeout=10)


_checks = unittest.TestCase()

assert_true = _checks.assertTrue
assert_false = _checks.assertFalse
assert_equal = _checks.assertEqual
assert_not_equal = _checks.assertNotEqual
assert_less = _checks.assertLess
assert_in = _checks.assertIn
assert_not_in = _checks.assertNotIn
assert_is_none = _checks.assertIsNone
assert_is_not_none = _checks.assertIsNotNone

assert_raises = pytest.raises


def assert_ping_reply(address, *, vrf=None, timeout=10):
    """Wait for reachability while ARP/ND recovers from previously blocked probes."""
    command = ['ping', '-n', '-c', '1', '-W', '2', address]
    if vrf is not None:
        command = ['ip', 'vrf', 'exec', vrf, *command]

    location = f' in VRF {vrf}' if vrf is not None else ''
    wait_for(lambda: rc_cmd(command), lambda result: result[0] == 0,
             description=f'{address} to answer ICMP{location}', timeout=timeout)


def assert_log_output(service, *arguments, expected=(), absent=()):
    """Wait for asynchronous collectors, then inspect the installed log command."""
    command = ['logs.nvyr.op', 'show', service, *arguments]
    output = wait_for(lambda: cmd(command),
                      lambda text: all(value in text for value in expected),
                      description='selected log records')
    for value in expected:
        assert_in(value, output)
    for value in absent:
        assert_not_in(value, output)


def assert_failsafe_lifecycle(family, scenario):
    """Run boot firewall checks without altering the router's management firewall."""
    import subprocess
    import sys

    # Pytest's import path is not inherited by children started from the user's shell directory.
    result = subprocess.run(
        ['unshare', '--net', sys.executable, '-m', 'smoketests.failsafe_support', family, scenario],
        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=60)
    assert_equal(result.returncode, 0, result.stdout + result.stderr)


def assert_firewall_trace_capture(address, path):
    """Capture installed trace output while sending probes; remove only our own file."""
    import json
    from pathlib import Path
    import subprocess
    import uuid

    target = Path('/config/traces') / (str(uuid.uuid4()) + '.jsonl')
    line = f'monitor firewall trace duration 2s save {target}'
    process = subprocess.Popen(['firewall_trace.nvyr.op', 'monitor', line],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        # Repeated probes cover native netlink subscription startup without a fixed sleep.
        cmd(['ping', '-n', '-c', '6', '-i', '0.2', '-W', '1', address])
        output, error = process.communicate(timeout=5)
        assert_equal(process.returncode, 0, output + error)
        assert_in('Captured ', output)
        assert_in(str(target), output)
        events = [json.loads(line) for line in target.read_text().splitlines()]
        assert_true(any(event.get('path') == path for event in events), msg=str(events))

        # The installed reader must explain the same saved evidence without querying rules again.
        trace_id = next(event['id'] for event in events if event.get('path') == path)
        show = f'show firewall trace {target} id {trace_id}'
        story = cmd(['firewall_trace.nvyr.op', 'show', show])
        assert_in('Trace ' + trace_id, story)
        assert_in('The packet', story)
        assert_in('TABLES AND CHAINS VISITED', story)
        assert_in('RULES HIT', story)
        assert_in('OBSERVED CHANGES', story)
        assert_in('OUTCOME', story)
        assert_in(path, story)
        detail = cmd(['firewall_trace.nvyr.op', 'show', show + ' detail'])
        assert_in(path, detail)
        assert_in('Capture line ', detail)
        report = json.loads(cmd(['firewall_trace.nvyr.op', 'show', show, '--raw']))
        assert_true(any(trace['id'] == trace_id for trace in report['traces']))
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
        process.stderr.close()
        target.unlink(missing_ok=True)


def assert_probe_command(command, address):
    """Run the installed streaming wrapper and require a successful numeric reply."""
    import subprocess

    name = command.split()[0]
    result = subprocess.run([name + '.nvyr.op', name, command], capture_output=True, text=True, timeout=10)
    assert_equal(result.returncode, 0, result.stdout + result.stderr)
    assert_in(address, result.stdout)
    if name == 'traceroute':
        assert_true(any(line.lstrip().startswith('1 ') and address in line
                        for line in result.stdout.splitlines()), msg=result.stdout)


def assert_operational_output(command, *expected, absent=()):
    """Check the public operational command path and its formatted runtime report."""
    from contextlib import closing
    from nvyr.protocol import Client

    with closing(Client('/run/nvyr/configd.sock')) as client:
        output = client.request('execute', text=command)['text']
    for value in expected:
        assert_in(value, output)
    for value in absent:
        assert_not_in(value, output)


def assert_diagnostic_archive(output):
    """Inspect the newly generated snapshot, then remove only that test artifact."""
    import stat
    import tarfile

    match = re.search(r'^Diagnostic archive: (/config/diagnostics/nvyr-diagnostics-[a-zA-Z0-9-]+\.tar\.gz)$',
                      output, re.MULTILINE)
    assert_is_not_none(match, output)
    path = Path(match.group(1))
    try:
        assert_equal(stat.S_IMODE(path.stat().st_mode), 0o600)
        with tarfile.open(path) as archive:
            manifest = json.load(archive.extractfile('manifest.json'))
            reports = {item['name']: item for item in manifest['reports']}
            assert_in('failed-units', reports)
            assert_in('container-networks', reports)
            assert_in('ipv6-routes', reports)
            assert_equal(reports['storage']['status'], 'ok', reports['storage'])
            assert_equal(reports['processes']['status'], 'ok', reports['processes'])
            assert_true(sum(item['bytes'] for item in reports.values()) <= manifest['limits']['total_bytes'])
            for item in reports.values():
                if 'file' in item:
                    assert_true(archive.getmember(item['file']).size <= manifest['limits']['report_bytes'])
    finally:
        path.unlink()


def assert_firewall_runtime_keys(family, rule, address, *, group=None):
    """Observe keys learned by packets, not just the configured limit expression."""
    output = cmd(['firewall.nvyr.op', 'runtime', 'limit', '--family', family,
                  '--hook', 'output', '--stage', 'filter', '--rule', str(rule), '--raw'])
    sections = json.loads(output)
    assert_equal(len(sections), 1)
    assert_false(sections[0]['incomplete'])
    records = sections[0]['records']
    assert_true(records, msg='No installed limit records')
    for record in records:
        assert_true(record['active-keys'] > 0)
        assert_true(any(entry['key'][0] == address for entry in record['entries']))
        if record['kind'] == 'limit':
            assert_true(all(entry['expires'] > 0 for entry in record['entries']))
        else:
            assert_not_in('timeout', record)
        if group is not None:
            assert_equal(record['group'], group)


def assert_firewall_runtime_quota(family, *, rules=(10, 20), group='RUNTIME'):
    """Inline and shared quota usage is nonzero and remains unchanged by reads."""
    arguments = ['firewall.nvyr.op', 'runtime', 'quota', '--family', family,
                 '--hook', 'output', '--stage', 'filter', '--raw']
    sections = json.loads(cmd(arguments))
    records = [record for record in sections[0]['records'] if int(record['rule']) in rules]
    assert_equal(len(records), 2)
    assert_equal(records[1]['group'], group)
    for record in records:
        assert_true(record['used'] > 0)
        assert_equal(record['remaining'], max(0, record['bytes'] - record['used']))
    assert_equal(json.loads(cmd(arguments)), sections)


def assert_ntp_directives(*directives, absent=()):
    """Check the installed Chrony directives without testing daemon responsiveness."""
    from nvyr.helpers.ntp import CONFIGURATION

    actual = CONFIGURATION.read_text().splitlines()
    for directive in directives:
        assert_in(directive, actual)
    for directive in absent:
        assert_not_in(directive, actual)



def assert_ntp_configuration(*directives, absent=()):
    """Check configured directives and the responsive control socket in functional tests."""
    from nvyr.helpers.ntp import SOCKET

    assert_ntp_directives(*directives, absent=absent)
    cmd(['chronyc', '-h', SOCKET, 'tracking'], timeout=5)


def assert_ntp_client_access(address, *, allowed):
    """Query Chrony's actual client ACL, independently of the generated text."""
    from nvyr.helpers.ntp import SOCKET

    output = cmd(['chronyc', '-h', SOCKET, 'accheck', address], timeout=5)
    expected = '208 Access allowed' if allowed else '209 Access denied'
    assert_in(expected, output)


def assert_ntp_vrf(name):
    """Check the daemon's process routing domain, including inherited DNS sockets."""
    pid = Path('/run/nvyr-chrony/chronyd.pid').read_text().strip()
    assert_equal(cmd(['ip', 'vrf', 'identify', pid]).strip(), name)


def assert_ntp_response(address, *, port=123):
    """Send one NTPv4 request and validate its reply without adjusting the clock."""
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    request = bytearray(48)
    request[0] = 0x23  # NTP version 4, client mode.
    request[40:48] = os.urandom(8)

    with socket.socket(family, socket.SOCK_DGRAM) as client:
        client.settimeout(5)
        client.connect((address, port))
        client.send(request)
        response = client.recv(1024)

    assert_true(len(response) >= 48, msg='Incomplete NTP response')
    assert_equal(response[0] & 7, 4, msg='Expected NTP server mode')
    assert_equal(response[24:32], request[40:48], msg='Reply does not identify our request')


def assert_ntp_serving_activity(address):
    """Confirm a real request appears in client and server reports without resetting counters."""
    before = json.loads(cmd(['ntp.nvyr.op', 'server_statistics', '--raw']))
    assert_ntp_response(address)

    clients = json.loads(cmd(['ntp.nvyr.op', 'clients', '--raw']))
    matching = [client for client in clients if client['Client'] == address]
    assert_equal(len(matching), 1, msg=f'Missing recorded NTP client {address}')
    assert_true(matching[0]['Requests'] >= 1)
    assert_is_not_none(matching[0]['Last seen (s)'])
    assert_in(address, cmd(['ntp.nvyr.op', 'clients']))

    after = json.loads(cmd(['ntp.nvyr.op', 'server_statistics', '--raw']))
    assert_true(after['NTP requests received'] > before['NTP requests received'])
    summary = cmd(['ntp.nvyr.op', 'server_statistics'])
    detail = cmd(['ntp.nvyr.op', 'server_statistics', '--detail'])
    assert_in('NTP requests received', summary)
    assert_not_in('NTS-KE connections accepted', summary)
    assert_in('NTS-KE connections accepted', detail)
    assert_in('NTP hardware TX timestamps', detail)

    repeated = json.loads(cmd(['ntp.nvyr.op', 'server_statistics', '--raw']))
    assert_true(repeated['NTP requests received'] >= after['NTP requests received'])


def assert_bridge(name, **expected):
    """Check native bridge attributes, including settings represented in clock ticks."""
    device = assert_link(name, kind='bridge')
    data = device['linkinfo']['info_data']
    for key, value in expected.items():
        actual = data.get(key)
        if key == 'vlan_protocol':
            protocols = {'802.1Q': 0x8100, '802.1ad': 0x88a8}
            actual = protocols[actual] if actual in protocols else int(actual.strip('[]'))
            value = protocols[value]
        assert_equal(actual, value, msg=f'{name}: unexpected bridge {key}')
    return data


def assert_bridge_port(name, **expected):
    """Check acknowledged port policy without hiding native state behind a formatter."""
    ports = json.loads(cmd(['bridge', '-d', '-j', 'link', 'show', 'dev', name]))
    assert_equal(len(ports), 1, msg=f'{name}: expected one bridge port')
    for key, value in expected.items():
        assert_equal(ports[0].get(key), value, msg=f'{name}: unexpected port {key}')
    return ports[0]


def assert_bridge_vlans(name, expected):
    """Compare VLAN IDs and ingress/egress flags, including an empty VLAN table."""
    data = json.loads(cmd(['bridge', '-j', 'vlan', 'show', 'dev', name]))
    actual = {}
    for device in data:
        for entry in device.get('vlans', []):
            flags = entry.get('flags', [])
            actual[entry['vlan']] = ('PVID' in flags, 'Egress Untagged' in flags)
    assert_equal(actual, expected, msg=f'{name}: unexpected VLAN memberships')


def assert_bridge_mac(bridge, mac, *, port=None, vlan=None, present=True):
    """Locate one forwarding entry and distinguish its output port and VLAN."""
    entries = json.loads(cmd(['bridge', '-j', 'fdb', 'show', 'br', bridge]))
    matched = [entry for entry in entries if entry['mac'].lower() == mac.lower()
               and (port is None or entry['ifname'] == port)
               and (vlan is None or entry.get('vlan', 0) == vlan)]
    assert_equal(bool(matched), present, msg=f'{bridge}: unexpected MAC entries: {matched}')


def assert_bridge_multicast(bridge, address, *, port=None, source=None, present=True):
    """Locate a configured multicast membership without assuming dump ordering."""
    devices = json.loads(cmd(['bridge', '-j', 'mdb', 'show', 'dev', bridge]))
    matched = [entry for device in devices for entry in device.get('mdb', [])
               if entry['grp'] == address and (port is None or entry['port'] == port)
               and (source is None or entry.get('src') == source)]
    assert_equal(bool(matched), present, msg=f'{bridge}: unexpected multicast entries: {matched}')


def assert_frr_policy_commands(*expected, daemon='bgpd', absent=()):
    """Check installed native policy commands and confirm removed commands are absent."""
    output = cmd(['vtysh', '-d', daemon, '-c', 'show running-config'])
    lines = {line.strip() for line in output.splitlines()}
    for command in expected:
        assert_in(command, lines, msg=f'{daemon} did not install {command!r}')
    for command in absent:
        assert_not_in(command, lines, msg=f'{daemon} retained {command!r}')


def assert_bgp_commands(*expected, vrf='NVYRBGP', family=None, absent=()):
    """Check commands in exactly one native BGP instance, not another VRF."""
    from nvyr.helpers.frr_bgp import adapter

    output = cmd(['vtysh', '-c', 'show running-config no-header'])
    blocks = adapter.select(output, [vrf])[vrf]
    lines = set()
    for block in blocks:
        selected_family = None
        for line in block.splitlines():
            line = line.strip()
            if line.startswith('address-family '):
                selected_family = line.removeprefix('address-family ')
            elif line == 'exit-address-family':
                selected_family = None
            if family is None or selected_family == family + ' unicast':
                lines.add(line)
    for command in expected:
        assert_in(command, lines, msg=f'BGP VRF {vrf} did not install {command!r}')
    for command in absent:
        assert_not_in(command, lines, msg=f'BGP VRF {vrf} retained {command!r}')


def assert_bgp_resources_unused(configuration, name='NVYRBGP', table=41040):
    """Protect existing native devices, tables and BGP instances before smoke setup."""
    from nvyr.helpers.frr_bgp import adapter
    from nvyr.tree import lookup

    devices = link_inventory()
    assert_not_in(name, devices, msg=f'Smoketest device {name} is already in use')
    for device in devices.values():
        assert_not_equal(device.get('linkinfo', {}).get('info_data', {}).get('table'), table,
                         msg=f'Smoketest table {table} is already in use')
    for instance in lookup(configuration, ('vrf', 'name'), {}).values():
        assert_not_equal(str(instance.get('table')), str(table), msg=f'Smoketest table {table} is configured')
    for family in ('-4', '-6'):
        output = cmd(['ip', family, '-j', 'route', 'show', 'table', 'all'])
        for route in json.loads(output):
            assert_not_equal(str(route.get('table')), str(table), msg=f'Smoketest table {table} contains routes')

    native = cmd(['vtysh', '-c', 'show running-config no-header'])
    assert_false(adapter.select(native, [name])[name], msg=f'Native BGP instance {name} already exists')


def assert_bgp_path(vrf, family, prefix, *, attributes=None, present=True):
    """Observe policy results on a received route, allowing BGP time to reconverge."""
    def read():
        output = cmd(['vtysh', '-c', f'show bgp vrf {vrf} {family} unicast {prefix} json'])
        return json.loads(output).get('paths', [])

    def matches(paths):
        if not present:
            return not paths
        for path in paths:
            if not path.get('valid'):
                continue
            matched = True
            for key, expected in (attributes or {}).items():
                value = path
                for component in key.split('.'):
                    value = value.get(component) if isinstance(value, dict) else None
                if value != expected:
                    matched = False
                    break
            if matched:
                return True
        return False

    return wait_for(read, matches, description=f'{family} BGP policy result for {prefix} in {vrf}', timeout=30)


def assert_bgp_neighbor(vrf, address, *, state='Established', minimum_drops=0):
    """Wait for session recovery even when graceful restart retains the old routes."""
    def read():
        output = cmd(['vtysh', '-c', f'show bgp vrf {vrf} neighbors {address} json'])
        return json.loads(output).get(address, {})

    def matches(neighbor):
        return (neighbor.get('bgpState') == state
                and neighbor.get('connectionsDropped', 0) >= minimum_drops)

    return wait_for(read, matches, description=f'BGP neighbor {address} in {vrf} reaching {state}', timeout=30)


def link_inventory():
    """Observe all interfaces so peer indices and master names remain comparable."""
    return {item['ifname']: item for item in json.loads(cmd(['ip', '-N', '-j', '-d', 'address', 'show']))}


def assert_link(name, *, kind=None, mtu=None, mac=None, description=None, group=None,
                master=None, up=None, peer=None, table=None):
    """Wait for the requested native attributes, including asynchronous recovery."""
    attributes = {'mtu': mtu, 'address': mac, 'ifalias': description, 'group': group, 'master': master}
    expected = {key: value for key, value in attributes.items() if value is not None}

    def read():
        """Keep failure reports scoped to this link and its optional peer."""
        devices = link_inventory()
        return {key: devices[key] for key in (name, peer) if key in devices}

    def matches(devices):
        """Require all requested properties in one native snapshot."""
        device = devices.get(name)
        if device is None:
            return False

        for key, value in expected.items():
            default = 0 if key == 'group' else ''
            actual = device.get(key, default)
            if key == 'group':
                # iproute2 prints this unsigned 32-bit Netlink field as signed.
                actual = int(actual) & 0xffffffff
            if actual != value:
                return False

        if kind is not None and device.get('linkinfo', {}).get('info_kind') != kind:
            return False
        if table is not None and device.get('linkinfo', {}).get('info_data', {}).get('table') != table:
            return False
        if up is not None and ('UP' in device['flags']) != up:
            return False
        if peer is not None and (peer not in devices or device.get('link') != peer):
            return False

        return True

    devices = wait_for(read, matches, description=f'{name} attributes {expected}, peer={peer}')
    return devices[name]


def assert_link_absent(name):
    """Require native deletion rather than only removal from running configuration."""
    wait_for(link_inventory, lambda devices: name not in devices, description=f'{name} deletion')


def assert_vlan(name, parent, vlan, **attributes):
    """Require the native VLAN ID and parent as well as ordinary link attributes."""
    device = assert_link(name, kind='vlan', **attributes)
    assert_equal(device['link'], parent)
    assert_equal(device['linkinfo']['info_data']['id'], vlan)
    return device


def assert_configured_link_addresses(name, *present, absent=()):
    """Check installed prefixes even while carrier-dependent IPv6 DAD is pending."""
    def addresses():
        device = link_inventory().get(name, {})
        return {f"{item['local']}/{item['prefixlen']}" for item in device.get('addr_info', [])}

    wait_for(addresses, lambda values: set(present) <= values and not set(absent) & values,
             description=f'{name} configured addresses present={present}, absent={absent}')


def assert_link_addresses(name, *present, absent=()):
    """Match configured prefixes without depending on link-local address generation."""
    def addresses():
        """Only addresses ready for use can satisfy the assertion."""
        device = link_inventory().get(name, {})
        return {f"{item['local']}/{item['prefixlen']}" for item in device.get('addr_info', [])
                if not item.get('tentative') and not item.get('dadfailed')}

    wait_for(addresses, lambda values: set(present) <= values and not set(absent) & values,
             description=f'{name} addresses present={present}, absent={absent}')


def assert_config_commit_rejected(config, message):
    """Expected verification failures must preserve the explicit running configuration."""
    from nvyr.config_session import CommitError

    before = config.get_config()
    with assert_raises(CommitError, match=message):
        config.commit()
    assert_equal(config.get_config(), before)


def assert_container_running(name):
    """Wait for a managed workload to become running and return its native inspection."""
    from nvyr.helpers.process import rc_cmd

    def inspect():
        status, output = rc_cmd(['podman', 'inspect', name])
        return json.loads(output)[0] if status == 0 else None

    return wait_for(inspect, lambda value: value is not None and value['State']['Running'],
                    description=f'container {name} running')


def assert_container_restarted(name, previous_id):
    """Require a replacement running instance after systemd's five-second restart delay."""
    from nvyr.helpers.process import rc_cmd

    def inspect():
        status, output = rc_cmd(['podman', 'inspect', name])
        return json.loads(output)[0] if status == 0 else None

    wait_for(inspect, lambda value: value is not None and value['State']['Running']
             and value['Id'] != previous_id, description=f'container {name} restarted', timeout=20)


def assert_dhcp_client(name, *, active):
    """Check the real service and client generation, without requiring a DHCP server."""
    def state():
        """Observe both the service and netlinkd's current client record."""
        properties = cmd(['systemctl', 'show', f'nvyr-dhcp4@{name}.service', '-p', 'ActiveState', '--value']).strip()
        record = Path('/run/nvyr-netlink/clients') / f'{name}.json'
        return properties, record.exists()

    def matches(value):
        """Starting needs both components; stopping must release the record too."""
        if active:
            return value == ('active', True)
        return value[0] != 'active' and not value[1]

    wait_for(state, matches, description=f'{name} DHCP client active={active}')


def assert_dhcp_lease(name, *, after=None):
    """Optional server-backed test: require a current lease installed on the link."""
    from nvyr.helpers.dhcp import DHCP

    def lease():
        """Ignore leases left behind by an earlier incarnation of the interface."""
        device = link_inventory().get(name)
        return DHCP().lease(name, device['ifindex']) if device else None

    result = wait_for(lease, lambda value: value is not None and (after is None or value['expires'] > after),
                      description=f'{name} DHCP lease', timeout=60)
    assert_link_addresses(name, result['address'])
    return result


def assert_dhcp_client_options(name, **options):
    """Observe the active client's wire settings and return its generation."""
    assert_dhcp_client(name, active=True)
    return assert_dhcp_client_configuration(name, **options)


def assert_dhcp_client_configuration(name, **options):
    """Read the options supplied to the client without waiting for process or lease state."""
    path = Path('/run/nvyr-netlink/clients') / f'{name}.json'

    def read():
        return json.loads(path.read_text()) if path.exists() else None

    return wait_for(read, lambda value: value is not None and all(
        value['options'].get(key) == expected for key, expected in options.items()),
        description=f'{name} DHCP client options')


def assert_dhcp_default_route(name, *, distance=None, absent=False):
    """Read the real DHCP route's encoded administrative distance in any VRF."""
    def routes():
        entries = json.loads(cmd(['ip', '-j', '-4', 'route', 'show', 'table', 'all',
                                  'dev', name, 'proto', '16']))
        return [route for route in entries if route['dst'] == 'default']

    def matches(entries):
        if absent:
            return not entries
        return bool(entries) and all(route.get('metric', 0) >> 24 == distance for route in entries)

    return wait_for(routes, matches,
        description=f'{name} DHCP default route absent={absent}, distance={distance}')


def firewall_listing(kind='table', name='nvyr_filter', *, state=False, handles=False):
    """Read native nft text; suppress changing statistics for configuration checks."""
    arguments = ['nft']
    if not state:
        arguments.append('-s')
    if handles:
        arguments.append('-a')

    target = ['inet', name] if kind == 'table' else ['inet', 'nvyr_filter', name]
    return cmd([*arguments, 'list', kind, *target], timeout=10)


def assert_firewall_object(kind, name, *patterns, absent=()):
    """Check independent expected regexes against one installed native object."""
    output = firewall_listing(kind, name)
    for pattern in patterns:
        _checks.assertRegex(output, pattern)
    for pattern in absent:
        _checks.assertNotRegex(output, pattern)
    return output


def assert_firewall_chain(name, **attributes):
    """Compare native chain properties without symbolic priority rendering."""
    document = json.loads(cmd(['nft', '-j', 'list', 'chain', 'inet', 'nvyr_filter', name]))
    chains = [item['chain'] for item in document['nftables'] if item.get('chain', {}).get('name') == name]
    assert_equal(len(chains), 1, msg=f'Expected one installed chain {name}')
    for key, expected in attributes.items():
        assert_equal(chains[0].get(key), expected, msg=f'{name}: {key}')
    return chains[0]


def firewall_timeout_object(name):
    """Find a named timeout in the table listing used by the operational view."""
    document = json.loads(cmd(['nft', '--json', '--terse', 'list', 'table', 'inet', 'nvyr_filter']))
    objects = [item['ct timeout'] for item in document['nftables']
               if item.get('ct timeout', {}).get('name') == name]
    assert_equal(len(objects), 1, msg=f'Expected one installed timeout policy {name}')
    return objects[0]


def assert_firewall_timeout(name, protocol, family, **states):
    """Check the installed backend and numeric lifetimes without text formatting assumptions."""
    installed = firewall_timeout_object(name)
    assert_equal(installed['protocol'], protocol)
    assert_equal(installed['l3proto'], family)
    for state, seconds in states.items():
        assert_equal(installed['policy'][state], seconds)
    return installed


def assert_firewall_rule(chain, number, *patterns, absent=()):
    """Match only the numbered/commented rule, never a neighboring rule."""
    output = firewall_listing('chain', chain)
    marker = f'comment "{number}|'
    rules = [line.strip() for line in output.splitlines() if marker in line]
    assert_equal(len(rules), 1, msg=f'Expected one rule {number} in {chain}:\n{output}')
    rule = rules[0]
    for pattern in patterns:
        _checks.assertRegex(rule, pattern)
    for pattern in absent:
        _checks.assertNotRegex(rule, pattern)
    return rule


def assert_firewall_rule_absent(chain, number):
    """Require removal from the kernel, not merely from the configuration dict."""
    assert_not_in(f'comment "{number}|', firewall_listing('chain', chain))


def assert_firewall_commit_rejected(config, message):
    """A verify failure must preserve both running configuration and installed rules."""
    from nvyr.config_session import CommitError

    running = config.get_config()
    installed = firewall_listing()
    with assert_raises(CommitError, match=message):
        config.commit()

    assert_equal(config.get_config(), running)
    assert_equal(firewall_listing(), installed)


def firewall_object_handle(kind, name):
    """Read an object's identity to detect unwanted destruction during a commit."""
    output = firewall_listing(kind, name, handles=True)
    match = re.search(rf'^\s*{kind} {re.escape(name)}.*# handle (\d+)', output, re.MULTILINE)
    assert_is_not_none(match, msg=f'Missing {kind} handle:\n{output}')
    return int(match.group(1))


def assert_firewall_counter(name, packets):
    """Check a named counter's actual datapath packet count."""
    output = firewall_listing('counter', 'counter_group_' + name, state=True)
    match = re.search(r'packets (\d+) bytes (\d+)', output)
    assert_is_not_none(match, msg=output)
    assert_equal(int(match.group(1)), packets, msg=output)


def firewall_rule_packets(chain, identifier):
    """Read one rule by its comment, including generated rules without a pipe suffix."""
    document = json.loads(cmd(['nft', '-j', 'list', 'chain', 'inet', 'nvyr_filter', chain]))
    rules = [item['rule'] for item in document['nftables'] if 'rule' in item
             and item['rule'].get('comment', '').split('|')[0] == str(identifier)]
    assert_equal(len(rules), 1, msg=f'Expected one rule {identifier} in {chain}')
    counters = [part['counter'] for part in rules[0]['expr'] if 'counter' in part]
    assert_equal(len(counters), 1, msg=f'Expected one counter on {chain} rule {identifier}')
    return counters[0]['packets']


def assert_firewall_rule_packets(chain, identifier, packets, *, timeout=None):
    """Require an exact packet count, optionally waiting for asynchronously injected frames."""
    if timeout is not None:
        wait_for(lambda: firewall_rule_packets(chain, identifier), lambda value: value == packets,
                 description=f'{chain} rule {identifier} to count {packets} packets', timeout=timeout)
        return

    assert_equal(firewall_rule_packets(chain, identifier), packets,
                 msg=f'{chain} rule {identifier} packet count')


def assert_firewall_map_counter(name, key, *, minimum_packets):
    """Check traffic on one interface-keyed zone element using the native listing."""
    output = firewall_listing('map', name, state=True)
    pattern = rf'{re.escape(json.dumps(key))}\s+counter packets (\d+) bytes (\d+)'
    match = re.search(pattern, output)
    assert_is_not_none(match, msg=f'Missing counter for {key!r}:\n{output}')
    _checks.assertGreaterEqual(int(match.group(1)), minimum_packets, msg=output)
    _checks.assertGreater(int(match.group(2)), 0, msg=output)


def assert_firewall_map_default_counter(name, packets):
    """Read the whole-key catch-all's counter independently of ordinary entries."""
    from nvyr.helpers.nftables_normalizer import normalize

    document = json.loads(cmd(['nft', '-j', 'list', 'map', 'inet', 'nvyr_filter', name]))
    group = normalize(document)['tables']['inet']['nvyr_filter']['maps'][name]
    defaults = [entry for entry in group['entries'] if entry.get('default')]
    assert_equal(len(defaults), 1, msg=f'Expected one catch-all element in {name}')
    assert_equal(defaults[0].get('counter', {}).get('packets'), packets)


def assert_config_names_unused(configuration, *names):
    """Reject test resource names already present as configuration keys or values."""
    if isinstance(configuration, dict):
        for key, value in configuration.items():
            assert_not_in(key, names, msg='Test resource is already configured or referenced')
            assert_config_names_unused(value, *names)
    elif isinstance(configuration, list):
        for value in configuration:
            assert_config_names_unused(value, *names)
    elif isinstance(configuration, str):
        assert_not_in(configuration, names, msg='Test resource is already configured or referenced')


def _frr_static_routes(vrf='default'):
    """Read static CLI lines from exactly one FRR routing instance."""
    output = cmd(['vtysh', '-c', 'show running-config'], timeout=10)
    routes = []
    current_vrf = 'default'

    for line in output.splitlines():
        if line.startswith('vrf '):
            current_vrf = line.split()[1]
        elif line == 'exit-vrf':
            current_vrf = 'default'
        elif current_vrf == vrf and line.strip().startswith(('ip route ', 'ipv6 route ')):
            routes.append(line.strip())

    return routes


def _kernel_route(prefix, *, vrf='default', source=None):
    """Read an exact destination, optionally filtered by VRF and IPv6 source."""
    family = '-6' if ':' in prefix else '-4'
    scope = ['table', 'main'] if vrf == 'default' else ['vrf', vrf]
    arguments = ['ip', family, 'route', 'show', *scope, 'exact', prefix]
    if source is not None:
        arguments.extend(['from', source])

    return cmd(arguments, timeout=10)


def assert_static_route_configured(prefix, action):
    """Check the default-VRF FRR directive without waiting for kernel route selection."""
    family = 'ipv6' if ':' in prefix else 'ip'
    assert_frr_routes(f'{family} route {prefix} {action}')


def assert_static_route_unconfigured(prefix, action):
    """Check deletion from FRR independently of asynchronous kernel withdrawal."""
    family = 'ipv6' if ':' in prefix else 'ip'
    assert_frr_route_absent(f'{family} route {prefix} {action}')


def assert_no_static_configuration():
    """Require an empty default-VRF static configuration."""
    assert_false(_frr_static_routes(), msg='Default-VRF static routes remain in FRR')


def assert_route_present(prefix, action):
    """Check a default-VRF static route and await its kernel installation."""
    family = 'ipv6' if ':' in prefix else 'ip'
    expected_config = f'{family} route {prefix} {action}'
    configured_routes = _frr_static_routes()

    assert_in(expected_config, configured_routes)

    kernel_action = 'unreachable' if action == 'reject' else action
    expected_route = f'{kernel_action} {prefix}'

    assert_kernel_route(prefix, expected_route)


def assert_route_absent(prefix, action):
    """Check removal from default-VRF static configuration and the kernel."""
    family = 'ipv6' if ':' in prefix else 'ip'
    expected_config = f'{family} route {prefix} {action}'
    configured_routes = _frr_static_routes()

    assert_not_in(expected_config, configured_routes)
    assert_kernel_route_absent(prefix)


def assert_no_static_routes(*prefixes):
    """Require empty default-VRF static configuration and unused test prefixes."""
    configured_routes = _frr_static_routes()
    assert_false(configured_routes, msg='Default-VRF static routes remain in FRR')

    for prefix in prefixes:
        assert_kernel_route_absent(prefix)


def assert_frr_routes(*commands, vrf='default'):
    """Check exact FRR CLI lines immediately after the configuration commit."""
    routes = _frr_static_routes(vrf)
    for command in commands:
        assert_in(command, routes, msg=f'Missing static configuration in VRF {vrf}')


def assert_frr_route_absent(command, *, vrf='default'):
    """Check that a particular path is absent while other paths may remain."""
    assert_not_in(command, _frr_static_routes(vrf))


def assert_kernel_route(prefix, *expected, absent=(), vrf='default', source=None):
    """Wait for all expected and no forbidden fragments in one route snapshot."""
    def read_route():
        """Fetch one fresh snapshot of the selected kernel route."""
        return _kernel_route(prefix, vrf=vrf, source=source)

    def route_matches(output):
        """Require all conditions together, rather than across different polls."""
        if not output.strip():
            return False

        for fragment in expected:
            if fragment not in output:
                return False

        for fragment in absent:
            if fragment in output:
                return False

        return True

    return wait_for(
        read_route,
        route_matches,
        description=f'{prefix} in VRF {vrf}: expected {expected}, absent {absent}',
    )


def assert_kernel_route_absent(prefix, *, vrf='default', source=None):
    """Wait for a destination/source route to be removed from the selected VRF."""
    def read_route():
        """Fetch the routes whose withdrawal the caller is asserting."""
        return _kernel_route(prefix, vrf=vrf, source=source)

    def route_is_removed(output):
        """Whitespace alone does not represent an installed route."""
        return not output.strip()

    wait_for(read_route, route_is_removed, description=f'withdrawal of {prefix} in VRF {vrf}')


def assert_kernel_multipath_weights(prefix, weights, *, vrf='default'):
    """Check gateway/interface weight ratios; Zebra scales weights for the kernel."""
    def read_route():
        """Read all members from the same installed multipath route."""
        return _kernel_route(prefix, vrf=vrf)

    def weights_match(output):
        """Match membership and relative weights, including the interface identity."""
        members = re.findall(r'nexthop via (?:inet6 )?(\S+) dev (\S+) weight (\d+)', output)
        if len(members) != len(weights):
            return False

        actual = {}
        for gateway, interface, weight in members:
            actual[gateway, interface] = int(weight)

        if actual.keys() != weights.keys():
            return False

        actual_total = sum(actual.values())
        expected_total = sum(weights.values())
        if actual_total == 0:
            return False

        for member, weight in weights.items():
            if actual[member] * expected_total != weight * actual_total:
                return False

        return True

    wait_for(read_route, weights_match, description=f'multipath weights for {prefix}: {weights}')


def assert_static_instance_empty(vrf='default'):
    """Read FRR's datastore to confirm CLI route deletion retains the native instance."""
    output = cmd(['vtysh', '-c', 'show mgmt datastore-contents running json'], timeout=10)
    datastore = json.loads(output)
    instances = datastore['frr-routing:routing']['control-plane-protocols']['control-plane-protocol']

    for instance in instances:
        if instance['type'] == 'frr-staticd:staticd' and instance['name'] == 'staticd' and instance['vrf'] == vrf:
            # MGMTd omits empty non-presence containers; the protocol must remain.
            routes = instance.get('frr-staticd:staticd', {}).get('route-list', [])
            assert_equal(routes, [])
            return

    raise AssertionError(f'Static protocol instance missing for VRF {vrf}')
