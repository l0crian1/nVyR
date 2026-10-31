"""Inspect IPv4/IPv6 neighbors, VRF scope and positive/negative DNS responses.

One namespace holds the default and VRF neighbor tables and one DNS responder.
All observations reuse it; destructive neighbor flushing or responder replacement
would require a separate scenario. No router configuration is changed.
"""

import json
from pathlib import Path
import select
import subprocess

import pytest


if __name__ == '__main__':
    import sys
    raise SystemExit(pytest.main([__file__, '-v', '-s', *sys.argv[1:]]))


from nvyr.errors import RouterError
from nvyr.helpers.process import cmd
from smoketests.assertions import assert_equal, assert_in, assert_raises
from functionaltests.native_network import native_namespace


def ip(namespace, *arguments):
    """Program only the disposable namespace, never an existing router interface."""
    return cmd(['ip', '-n', namespace, *arguments])


def run(namespace, script, function, line, raw=True):
    """Invoke the actual opmode entry point with optional structured output."""
    arguments = ['ip', 'netns', 'exec', namespace, 'python3', '-m',
                 'nvyr.op_scripts.' + script, function, line]
    if raw:
        arguments.append('--raw')
    output = cmd(arguments)
    return json.loads(output) if raw else output


@pytest.fixture(scope='module')
def namespace(native_namespace):
    """Install both neighbor families and the VRF once for this module."""
    namespace = native_namespace
    ip(namespace, 'link', 'add', 'test0', 'type', 'dummy')
    ip(namespace, 'link', 'set', 'test0', 'up')
    ip(namespace, 'neigh', 'add', '192.0.2.10', 'lladdr', '02:00:00:00:00:01', 'dev', 'test0', 'nud', 'permanent')
    ip(namespace, 'neigh', 'add', '192.0.2.11', 'dev', 'test0', 'nud', 'failed')
    ip(namespace, '-6', 'neigh', 'add', '2001:db8::10', 'lladdr', '02:00:00:00:00:01', 'dev', 'test0', 'nud', 'permanent')
    ip(namespace, 'link', 'add', 'BLUE', 'type', 'vrf', 'table', '100')
    ip(namespace, 'link', 'add', 'br0', 'type', 'bridge')
    ip(namespace, 'link', 'set', 'br0', 'master', 'BLUE')
    ip(namespace, 'link', 'set', 'BLUE', 'up')
    ip(namespace, 'link', 'set', 'br0', 'up')
    ip(namespace, 'neigh', 'add', '192.0.2.10', 'lladdr', '02:00:00:00:00:01', 'dev', 'br0', 'nud', 'permanent')
    return namespace


def test_ipv4_arp(namespace):
    """Permanent and failed neighbors appear together; unresolved hardware stays absent."""
    records = run(namespace, 'neighbors', 'show', 'show arp interface test0')
    assert_equal(len(records), 2)
    assert_equal(records[0]['state'], 'Permanent')
    assert_equal(records[1]['state'], 'Failed')
    assert_equal(records[1]['mac'], None)
    assert_in('MAC address', run(namespace, 'neighbors', 'show', 'run show arp', raw=False))


def test_ipv6_neighbors(namespace):
    """IPv6 neighbors use their own family and do not leak into the ARP view."""
    records = run(namespace, 'neighbors', 'show', 'show ipv6 neighbors interface test0')
    assert_equal(records[0]['address'], '2001:db8::10')
    assert_equal(records[0]['vrf'], 'default')
    assert_equal(len(run(namespace, 'neighbors', 'show', 'show arp interface test0')), 2)


def test_neighbor_vrf_scope(namespace):
    """Kernel VRF membership, including a bridge master, determines the table scope."""
    records = run(namespace, 'neighbors', 'show', 'show arp vrf BLUE interface br0')
    assert_equal(records[0]['vrf'], 'BLUE')
    assert_equal({record['interface'] for record in run(namespace, 'neighbors', 'show', 'show arp vrf default')}, {'test0'})


@pytest.fixture(scope='module')
def dns_server(namespace):
    """Bind a local DNS test server in isolation and always stop it before namespace cleanup."""
    ip(namespace, 'link', 'set', 'lo', 'up')
    # Resolve the installed smoketests package independently of the caller's working directory.
    process = subprocess.Popen(['ip', 'netns', 'exec', namespace, 'python3', '-m', 'smoketests.dns_support'],
                               cwd=Path(__file__).resolve().parents[1],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready, _, _ = select.select([process.stdout], [], [], 5)
        assert_equal(bool(ready), True, 'DNS responder did not become ready')
        announcement = process.stdout.readline().strip()
        if announcement != 'ready':
            process.terminate()
            output, error = process.communicate(timeout=5)
            pytest.fail(f'DNS responder failed to start: {announcement}\n{output}{error}')
        yield namespace
    finally:
        process.terminate()
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate()


def lookup(namespace, question):
    """Keep all queries on the local test responder, independent of public DNS."""
    return run(namespace, 'resolver', 'lookup', 'lookup ' + question + ' server 127.0.0.1')


def test_lookup_default_families(dns_server):
    """An ordinary hostname returns both A and AAAA records with their TTLs."""
    result = lookup(dns_server, 'example.test')
    assert_equal([record['type'] for record in result['records']], ['A', 'AAAA'])
    assert_equal(result['records'][0]['ttl'], 300)
    assert_equal(result['queries'][0]['server'], '127.0.0.1')


def test_lookup_mail_records(dns_server):
    """A selected record type retains structured record data such as MX preference."""
    result = lookup(dns_server, 'example.test type mx')
    assert_equal(result['records'][0]['answer'], '10 mail.example.test.')


def test_lookup_ipv4_reverse(dns_server):
    """An IPv4 literal automatically requests its reverse PTR record."""
    assert_equal(lookup(dns_server, '192.0.2.10')['records'][0]['answer'], 'host.example.test.')


def test_lookup_ipv6_reverse(dns_server):
    """An IPv6 literal automatically requests its reverse nibble-form PTR record."""
    assert_equal(lookup(dns_server, '2001:db8::10')['records'][0]['answer'], 'host6.example.test.')


def test_lookup_alias(dns_server):
    """The canonical-name chain is visible once alongside both address families."""
    result = lookup(dns_server, 'alias.example.test')
    assert_equal([record['type'] for record in result['records']], ['CNAME', 'A', 'AAAA'])


def test_lookup_tcp_fallback(dns_server):
    """Truncated UDP answers transparently retry over TCP."""
    result = lookup(dns_server, 'tcp.example.test type a')
    assert_equal(result['records'][0]['answer'], '192.0.2.11')


def test_lookup_no_data(dns_server):
    """An existing name without the selected record is not mislabeled NXDOMAIN."""
    result = lookup(dns_server, 'example.test type txt')
    assert_equal(result['records'], [])
    assert_equal(result['queries'][0]['status'], 'no-data')


def test_lookup_nonexistent_name(dns_server):
    """A negative DNS answer produces an explicit NXDOMAIN operational error."""
    with assert_raises(RouterError, match='NXDOMAIN'):
        lookup(dns_server, 'missing.example.test')


def test_lookup_server_failure(dns_server):
    """A broken upstream is reported as a server failure rather than an empty table."""
    with assert_raises(RouterError, match='SERVFAIL'):
        lookup(dns_server, 'broken.example.test')
