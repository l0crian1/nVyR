"""Operational neighbor and DNS views retain scope, provenance and useful failures."""

import json
from types import SimpleNamespace

import dns.exception
import dns.message
import dns.resolver
import dns.rrset
import pytest

from nvyr.errors import OperationalError, RouterError
from nvyr.helpers import access
from nvyr.helpers.interfaces import interface_vrfs
from nvyr.op_scripts import neighbors, resolver


LINKS = [
    {'ifname': 'eth0', 'ifindex': 1},
    {'ifname': 'BLUE', 'ifindex': 2, 'linkinfo': {'info_kind': 'vrf'}},
    {'ifname': 'br0', 'ifindex': 3, 'master': 'BLUE'},
    {'ifname': 'pd-app-0', 'ifindex': 4, 'master': 3},
]


def test_interface_domains_follow_both_master_formats():
    assert interface_vrfs(LINKS) == {'eth0': 'default', 'BLUE': 'BLUE', 'br0': 'BLUE', 'pd-app-0': 'BLUE'}


def test_invalid_topology_is_not_reported_as_default():
    with pytest.raises(RouterError, match='topology changed'):
        interface_vrfs([{'ifname': 'eth0', 'ifindex': 1, 'master': 'missing'}])
    with pytest.raises(RouterError, match='Cycle'):
        interface_vrfs([{'ifname': 'eth0', 'ifindex': 1, 'master': 1}])


@pytest.fixture
def neighbor_data(monkeypatch):
    calls = []
    entries = [
        {'dst': '192.0.2.20', 'dev': 'eth0', 'state': ['FAILED']},
        {'dst': '192.0.2.3', 'dev': 'eth0', 'lladdr': '02:00:00:00:00:01', 'state': ['STALE']},
        {'dst': '198.51.100.1', 'dev': 'pd-app-0', 'state': ['INCOMPLETE']},
    ]

    def execute(argv):
        calls.append(argv)
        if argv[3] == 'link':
            return json.dumps(LINKS)
        if 'dev' in argv:
            selected = argv[-1]
            scoped = [{key: value for key, value in record.items() if key != 'dev'}
                      for record in entries if record['dev'] == selected]
            return json.dumps(scoped)
        return json.dumps(entries)

    monkeypatch.setattr(neighbors, 'cmd', execute)
    return calls


def test_neighbors_keep_unresolved_entries_and_sort_addresses(neighbor_data):
    records = neighbors.records('ipv4')
    assert records[0]['vrf'] == 'BLUE'
    assert [record['address'] for record in records[1:]] == ['192.0.2.3', '192.0.2.20']
    assert records[-1]['mac'] is None
    output = neighbors.show('show arp')
    assert 'MAC address' in output and 'Failed' in output and 'Incomplete' in output
    assert '—' in output


def test_neighbors_scoped_options_reach_kernel_and_filter_vrf(neighbor_data):
    output = json.loads(neighbors.show('show ipv6 neighbors vrf BLUE interface pd-app-0', raw=True))
    assert len(output) == 1 and output[0]['interface'] == 'pd-app-0'
    assert neighbor_data[-1] == ['ip', '-j', '-6', 'neighbor', 'show', 'nud', 'all', 'dev', 'pd-app-0']


def test_neighbors_reject_unknown_filters(neighbor_data):
    with pytest.raises(OperationalError, match='Interface absent does not exist'):
        neighbors.records('ipv4', interface='absent')
    with pytest.raises(OperationalError, match='VRF RED does not exist'):
        neighbors.records('ipv4', vrf='RED')


def test_empty_neighbors_are_explicit(monkeypatch):
    monkeypatch.setattr(neighbors, 'records', lambda *args, **kwargs: [])
    assert neighbors.show('show arp') == 'No matching ARP entries.\n'
    assert neighbors.show('show ipv6 neighbors') == 'No matching IPv6 neighbors.\n'


@pytest.mark.parametrize('line,script,function', [
    ('show arp', 'neighbors', 'show'),
    ('show arp interface eth0 vrf default', 'neighbors', 'show'),
    ('show ipv6 neighbors vrf BLUE', 'neighbors', 'show'),
    ('show system name-server', 'resolver', 'servers'),
    ('lookup example.com', 'resolver', 'lookup'),
    ('lookup example.com type mx server 1.1.1.1', 'resolver', 'lookup'),
    ('lookup 2001:db8::1', 'resolver', 'lookup'),
])
def test_operator_dispatch(controller, session, monkeypatch, line, script, function):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    token = access.role.set('read-only')
    try:
        controller.execute(line)
    finally:
        access.role.reset(token)
    token = access.role.set('net-admin')
    try:
        controller.execute('run ' + line, session)
    finally:
        access.role.reset(token)
    expected = [script + '.nvyr.op', function]
    configured = list(expected)
    if function != 'servers':
        expected.append(line)
        configured.append('run ' + line)
    assert calls == [expected, configured]


def test_published_servers_include_source_domain_and_warnings(monkeypatch, capsys):
    observation = {'servers': [
        {'server': '1.1.1.1', 'source': 'Static', 'interface': None},
        {'server': '192.0.2.53', 'source': 'DHCP', 'interface': 'pd-app-0'},
        {'server': '192.0.2.54', 'source': 'Unknown', 'interface': None},
    ], 'pending': True, 'error': 'Publication failed'}
    calls = []
    monkeypatch.setattr(resolver, 'manager', SimpleNamespace(request=lambda op: calls.append(op) or observation))
    monkeypatch.setattr(resolver, 'cmd', lambda argv: json.dumps(LINKS))
    result = json.loads(resolver.servers(raw=True))
    assert [record['vrf'] for record in result['servers']] == ['default', 'BLUE', None]
    resolver.servers()
    output = capsys.readouterr().out
    assert 'DHCP' in output and 'BLUE' in output and 'Publication failed' in output
    assert 'recovery is pending' in output and calls == ['dns-status', 'dns-status']


def answer(name, kind, *values):
    response = dns.message.make_response(dns.message.make_query(name, kind))
    if values:
        response.answer.append(dns.rrset.from_text(name, 300, 'IN', kind, *values))
    return dns.resolver.Answer(dns.name.from_text(name), dns.rdatatype.from_text(kind),
                               1, response, nameserver='192.0.2.53')


@pytest.fixture
def dns_client(monkeypatch):
    client = SimpleNamespace(nameservers=['192.0.2.53'])
    configured = []
    monkeypatch.setattr(resolver.dns.resolver, 'Resolver', lambda **kwargs: configured.append(kwargs) or client)
    return client, configured


def test_lookup_default_queries_both_families(dns_client):
    client, configured = dns_client
    calls = []

    def resolve(name, kind, **kwargs):
        calls.append((str(name), kind, kwargs))
        return answer('example.test.', kind, '192.0.2.1' if kind == 'A' else '2001:db8::1')

    client.resolve = resolve
    result = resolver.query('example.test')
    assert [record['type'] for record in result['records']] == ['A', 'AAAA']
    assert all(call[2] == {'search': False, 'raise_on_no_answer': False} for call in calls)
    assert configured == [{'configure': True}]
    assert client.timeout == 2 and client.lifetime == 5


@pytest.mark.parametrize('address,reverse', [
    ('192.0.2.1', '1.2.0.192.in-addr.arpa.'),
    ('2001:db8::1', dns.reversename.from_address('2001:db8::1').to_text()),
])
def test_reverse_lookup_uses_ptr(dns_client, address, reverse):
    client, configured = dns_client

    def resolve(name, kind, **kwargs):
        assert str(name) == reverse and kind == 'PTR'
        return answer(reverse, kind, 'router.example.test.')

    client.resolve = resolve
    result = resolver.query(address, server='::1')
    assert result['records'][0]['answer'] == 'router.example.test.'
    assert configured == [{'configure': False}] and client.nameservers == ['::1']


def test_lookup_schema_options_and_empty_answer(dns_client, capsys):
    client, _ = dns_client
    client.resolve = lambda name, kind, **kwargs: answer(str(name), kind)
    resolver.lookup('lookup example.test server 1.1.1.1 type mx')
    output = capsys.readouterr().out
    assert 'No MX records' in output and 'Query time:' in output
    assert client.nameservers == ['1.1.1.1']


@pytest.mark.parametrize('error,message', [
    (dns.resolver.NXDOMAIN(), 'NXDOMAIN'),
    (dns.exception.Timeout(), 'timeout'),
    (dns.resolver.NoNameservers(), 'could not answer'),
])
def test_dns_failures_remain_distinct(dns_client, error, message):
    client, _ = dns_client

    def fail(*args, **kwargs):
        raise error

    client.resolve = fail
    with pytest.raises(OperationalError, match=message):
        resolver.query('example.test')


def test_reverse_rejects_unrelated_record_types():
    with pytest.raises(OperationalError, match='reverse lookup'):
        resolver.query('192.0.2.1', record_type='MX')
