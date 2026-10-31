"""Inspect SNAT, DNAT, double NAT, both families, ICMP, counters, zones and labels.

All records coexist in one module-lived namespace with distinct original sources.
Host conntrack and routed-network connections are untouched. Flushing this table
or testing an empty table would need its own namespace.
"""

import json

import pytest


if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from nvyr.helpers.process import cmd
from smoketests.assertions import assert_equal, assert_in, assert_not_in, assert_true
from functionaltests.native_network import native_namespace


def insert(namespace, arguments):
    """Create a deterministic test connection; it sends no traffic to any network."""
    cmd(['ip', 'netns', 'exec', namespace, 'conntrack', '-I', '--timeout', '600', *arguments])


def query(namespace, line):
    """Run the same operational entry point against the isolated namespace."""
    output = cmd(['ip', 'netns', 'exec', namespace, 'python3', '-m',
                  'nvyr.op_scripts.conntrack', 'show', line, '--raw'])
    return json.loads(output)


@pytest.fixture(scope='module')
def namespace(native_namespace):
    """Populate the distinct connections once, independently of selected cases."""
    namespace = native_namespace
    cmd(['ip', 'netns', 'exec', namespace, 'sysctl', '-w', 'net.netfilter.nf_conntrack_acct=1'])
    insert(namespace, ['-p', 'tcp', '-s', '192.0.2.10', '-d', '198.51.100.20',
                       '--sport', '12345', '--dport', '443', '--state', 'ESTABLISHED',
                       '--src-nat', '203.0.113.1:45678'])
    insert(namespace, ['-p', 'tcp', '-s', '192.0.2.11', '-d', '198.51.100.20',
                       '--sport', '12345', '--dport', '443', '--state', 'ESTABLISHED',
                       '--dst-nat', '10.0.0.10:8443'])
    insert(namespace, ['-p', 'tcp', '-s', '192.0.2.12', '-d', '198.51.100.20',
                       '--sport', '12345', '--dport', '443', '--state', 'ESTABLISHED',
                       '--src-nat', '203.0.113.1:45678', '--dst-nat', '10.0.0.10:8443'])
    insert(namespace, ['-p', 'tcp', '-s', '2001:db8::10', '-d', '2001:db8::20',
                       '--sport', '12345', '--dport', '443', '--state', 'ESTABLISHED'])
    insert(namespace, ['-p', 'icmp', '-s', '192.0.2.10', '-d', '198.51.100.20',
                       '--icmp-type', '8', '--icmp-code', '0', '--icmp-id', '42'])
    insert(namespace, ['-p', 'udp', '-s', '192.0.2.10', '-d', '198.51.100.20',
                       '--sport', '12345', '--dport', '53'])
    insert(namespace, ['-p', 'udp', '-s', '192.0.2.16', '-d', '198.51.100.20',
                       '--sport', '12345', '--dport', '53', '--zone', '7', '--mark', '42'])
    return namespace


def test_ipv4_source_nat(namespace):
    """The original endpoint and translated reply endpoint retain their distinct ports."""
    records = query(namespace, 'show nat source translations ipv4 protocol tcp state established source-address 192.0.2.10')
    assert_equal(len(records), 1)
    assert_equal(records[0]['nat'], ['snat'])
    assert_equal(records[0]['original']['source-address'], '192.0.2.10')
    assert_equal(records[0]['reply']['destination-address'], '203.0.113.1')
    assert_equal(records[0]['reply']['destination-port'], 45678)
    assert_equal(query(namespace, 'show nat destination translations source-address 192.0.2.10'), [])
    assert_equal(query(namespace, 'show conntrack source-address 203.0.113.1'), [])


def test_ipv4_destination_nat(namespace):
    """Destination NAT filters select translated destinations without inventing source NAT."""
    records = query(namespace, 'show nat destination translations source-address 192.0.2.11')
    assert_equal(len(records), 1)
    assert_equal(records[0]['nat'], ['dnat'])
    assert_equal(records[0]['reply']['source-address'], '10.0.0.10')
    assert_equal(records[0]['reply']['source-port'], 8443)
    assert_equal(query(namespace, 'show nat source translations source-address 192.0.2.11'), [])


def test_ipv4_double_nat(namespace):
    """A double-NAT connection appears once in the combined view and in each scoped view."""
    records = query(namespace, 'show nat translations source-address 192.0.2.12')
    assert_equal(len(records), 1)
    assert_equal(records[0]['nat'], ['snat', 'dnat'])
    assert_equal(len(query(namespace, 'show nat source translations source-address 192.0.2.12')), 1)
    assert_equal(len(query(namespace, 'show nat destination translations source-address 192.0.2.12')), 1)
    output = cmd(['ip', 'netns', 'exec', namespace, 'python3', '-m',
                  'nvyr.op_scripts.conntrack', 'show', 'show nat translations source-address 192.0.2.12'])
    assert_in('SNAT+DNAT', output)
    assert_in('203.0.113.1:45678', output)
    assert_in('10.0.0.10:8443', output)


def test_ipv6_connections(namespace):
    """Family and original-address filters work for IPv6 and exclude the IPv4 table."""
    records = query(namespace, 'show conntrack ipv6 source-address 2001:db8::10')
    assert_equal(len(records), 1)
    assert_equal(records[0]['family'], 'ipv6')
    assert_equal(records[0]['state'], 'established')
    assert_true(all(record['family'] == 'ipv4' for record in query(namespace, 'show conntrack ipv4')))
    assert_equal(len(query(namespace, 'show conntrack source-address 2001:0db8:0:0:0:0:0:10')), 1)
    assert_equal(len(query(namespace, 'show conntrack destination-address 2001:db8::20')), 1)
    assert_equal(query(namespace, 'show conntrack source-address 2001:db8::99'), [])
    assert_equal(query(namespace, 'show conntrack destination-address 2001:db8::99'), [])
    assert_equal(query(namespace, 'show conntrack ipv6 state syn-sent'), [])
    assert_equal(query(namespace, 'show nat translations ipv6'), [])


def test_icmp_metadata(namespace):
    """ICMP ID, type and code survive normalization even though they are not transport ports."""
    record = query(namespace, 'show conntrack protocol icmp detail')[0]
    assert_equal(record['original']['icmp-id'], 42)
    assert_equal(record['original']['icmp-type'], 8)
    assert_equal(record['reply']['icmp-type'], 0)
    assert_not_in('source-port', record['original'])


def test_statistics(namespace):
    """Table occupancy includes the inserted connection and exposes summed kernel counters."""
    result = json.loads(cmd(['ip', 'netns', 'exec', namespace, 'python3', '-m',
                             'nvyr.op_scripts.conntrack', 'statistics', '--raw']))
    assert_true(result['entries'] >= 1)
    assert_true(result['maximum'] > 0)
    assert_in('insert_failed', result['counters'])
    assert_not_in('cpu', result['counters'])


def test_accounting_and_zone(namespace):
    """Kernel accounting extensions and non-default zones survive the raw display path."""
    record = query(namespace, 'show conntrack source-address 192.0.2.16 detail')[0]
    assert_equal(record['zone'], 7)
    assert_equal(record['mark'], 42)
    assert_equal(record['original']['packets'], 0)
    assert_equal(record['reply']['bytes'], 0)


def test_connection_labels(namespace, tmp_path):
    """Read both ends of the 128-bit label field from an actual tracked packet."""
    rules = tmp_path / 'labels.nft'
    rules.write_text('''
table inet label_test {
    chain output {
        type filter hook output priority filter; policy accept;
        udp dport 53099 ct label set 0 | 127
    }
}
''')
    cmd(['ip', 'netns', 'exec', namespace, 'ip', 'link', 'set', 'lo', 'up'])
    cmd(['ip', 'netns', 'exec', namespace, 'nft', '-f', str(rules)])
    send = '''
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
    receiver.bind(('127.0.0.1', 53099))
    receiver.settimeout(2)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sender.sendto(b'nvyr', receiver.getsockname())
        receiver.recv(128)
'''
    cmd(['ip', 'netns', 'exec', namespace, 'python3', '-c', send])
    record = query(namespace, 'show conntrack protocol udp destination-address 127.0.0.1')[0]
    assert_equal(record['labels'], [0, 127])
