"""DNS forwarding contracts: schema, cross-field checks and dynamic inputs."""

from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import service_dns_forwarding as service
from nvyr.errors import ValidationError
from nvyr.helpers import dns_forwarding as dns
from nvyr.helpers import kea_leases
from nvyr.lexer import lex
from nvyr.schema import Schema


def device(addresses=('192.0.2.1', '2001:db8::1'), vrf='default'):
    return {'eth1': {'vrf': vrf, 'addresses': list(addresses), 'tentative': [], 'dadfailed': []}}


def verify(section, devices=None):
    service.verify({'instances': {'default': section}, 'devices': devices}, SimpleNamespace())


@pytest.mark.parametrize('section,message', [
    ({'name-server': {'192.0.2.2': {'tls': {}}}}, 'authentication-name'),
    ({'name-server': {'192.0.2.2': {'tls': {'authentication-name': 'dns.test'}}, '192.0.2.3': {}}}, 'plaintext'),
    ({'name-server': {'192.0.2.2': {'tls': {'authentication-name': 'dns.test'}}}, 'name-server-interface': ['eth1']}, 'plaintext'),
    ({'domain': {'Test': {}, 'test.': {}}}, 'duplicate'),
    ({'cache': {'minimum-ttl': '60', 'maximum-ttl': '30'}}, 'minimum-ttl'),
])
def test_relationship_validation(section, message):
    with pytest.raises(ValidationError, match=message):
        verify(section)


def test_self_loop_and_vrf_validation():
    with pytest.raises(ValidationError, match='points to this'):
        verify({'listen-address': ['0.0.0.0'], 'name-server': {'192.0.2.1': {}}}, device())
    with pytest.raises(ValidationError, match='not present in this VRF'):
        verify({'listen-interface': ['eth1']}, device(vrf='BLUE'))
    # A separate resolver on the same address but a different port is legitimate.
    verify({'listen-address': ['192.0.2.1'], 'name-server': {'192.0.2.1': {'port': '1053'}}}, device())


def test_learned_upstreams_are_independent_of_system_resolver(monkeypatch):
    calls = []
    def request(operation, **arguments):
        calls.append((operation, arguments))
        return {'eth1': [{'server': '192.0.2.1'}, {'server': '192.0.2.2'}, {'server': '2001:db8::53'}]}
    monkeypatch.setattr(dns.interfaces.manager, 'request', request)
    intent = {'instances': {'default': {'listen-address': ['192.0.2.1'], 'name-server-interface': ['eth1']}}, 'static': {}}
    before = deepcopy(intent)

    result = dns.generate(intent, devices=device())['default']

    assert calls == [('dns-sources', {'sources': ['eth1']})]
    assert result['excluded-upstreams'] == ['192.0.2.1']
    assert result['learned']['.'] == ['192.0.2.2', '2001:db8::53']
    assert 'forward-first: no' in result['text']
    assert intent == before


def test_unaddressed_listener_waits_without_falling_back_to_localhost():
    intent = {'instances': {'default': {'listen-interface': ['eth1']}}, 'static': {}}
    result = dns.generate(intent, devices=device(addresses=()))['default']
    assert result['waiting']
    assert result['listeners'] == []


def test_interface_listener_scopes_link_local_addresses():
    devices = device(addresses=('192.0.2.1', 'fe80::1', '2001:db8::1'))
    devices['eth1']['tentative'] = ['2001:db8::1']
    assert dns.listener_addresses({'listen-interface': ['eth1']}, 'default', devices) == [
        '192.0.2.1', 'fe80::1%eth1']
    assert dns.is_listener('fe80::1%eth1', ['fe80::1%eth1'], set())
    assert not dns.is_listener('fe80::1%eth2', ['fe80::1%eth1'], set())


def test_learned_upstreams_withdraw_when_interface_moves_vrf(monkeypatch):
    monkeypatch.setattr(dns.interfaces.manager, 'request', lambda *args, **kwargs: {
        'eth1': [{'server': '192.0.2.53'}]})
    intent = {'instances': {'default': {'name-server-interface': ['eth1']}}, 'static': {}}

    result = dns.generate(intent, devices=device(vrf='BLUE'))['default']

    assert result['learned']['.'] == []
    assert 'forward-addr:' not in result['text']
    assert 'forward-first: no' in result['text']


def test_dhcp_records_expire_independently_and_remain_vrf_scoped(tmp_path, monkeypatch):
    monkeypatch.setattr(dns.kea, 'RUNTIME', tmp_path)
    clock = [1000]
    monkeypatch.setattr(kea_leases.time, 'time', lambda: clock[0])
    for vrf in ('default', 'BLUE'):
        for family, address in ((4, '192.0.2.10'), (6, '2001:db8::10')):
            journal = tmp_path / f'{vrf}-{family}.csv'
            expiry = 2000 if family == 4 else 1200
            journal.write_text('address,valid_lifetime,expire,subnet_id,state,hostname,lease_type,iaid\n'
                               f'{address},1000,{expiry},1,0,printer-{vrf.lower()},0,1\n')
            # No update-hostfile hook is configured: DNS publication is independently selected.
            native = {f'Dhcp{family}': {'lease-database': {'name': str(journal)},
                      'shared-networks': [{f'subnet{family}': [{'id': 1}]}]}}
            path = tmp_path / (dns.kea.instance_name(family, vrf) + '.json')
            path.write_text(json.dumps(native))

    section = {'local-data': {'dhcp-leases': None}}
    records = dns.local_records(section, {}, 'default')
    assert 'printer-default. 300 IN A 192.0.2.10' in records
    assert 'printer-default. 300 IN AAAA 2001:db8::10' in records
    assert not any('printer-blue' in record for record in records)

    clock[0] = 1300
    records = dns.local_records(section, {}, 'default')
    assert 'printer-default. 300 IN A 192.0.2.10' in records
    assert not any(' IN AAAA ' in record or 'ip6.arpa' in record for record in records)


def test_static_records_both_families_and_reverse(monkeypatch):
    static = {'router.test': {'address': ['192.0.2.1', '2001:db8::1'], 'alias': ['gw.test']}}
    section = {'local-data': {'static-host-mapping': None, 'ttl': '45'}}
    records = dns.local_records(section, static, 'default')
    assert 'gw.test. 45 IN A 192.0.2.1' in records
    assert 'router.test. 45 IN AAAA 2001:db8::1' in records
    assert '1.2.0.192.in-addr.arpa. 45 IN PTR router.test.' in records
    section['local-data']['disable-reverse'] = None
    assert not any(' IN PTR ' in record for record in dns.local_records(section, static, 'default'))


@pytest.mark.parametrize('line', [
    'show dns forwarding', 'show dns forwarding statistics', 'show dns forwarding upstreams',
    'show dns forwarding cache name router.test', 'show dns forwarding local-data',
    'show dns forwarding vrf BLUE', 'show dns forwarding vrf BLUE cache name router.test',
    'clear dns forwarding cache all', 'clear dns forwarding cache name router.test',
    'clear dns forwarding cache domain test', 'clear dns forwarding statistics',
    'clear dns forwarding vrf BLUE cache domain test', 'clear dns forwarding vrf BLUE statistics',
    'show log dns forwarding', 'show log dns forwarding vrf BLUE follow',
])
def test_operational_tree(line):
    cursor = Schema.bundled('operational').operational(lex(line))
    assert cursor.node.get('command')


def test_complete_configuration_cli(controller, engine, session, monkeypatch):
    captured = []
    monkeypatch.setattr(service.kea, 'inventory', lambda: device(addresses=('127.0.0.1', '::1')))
    monkeypatch.setattr(dns, 'install', captured.append)
    commands = [
        'listen-address 127.0.0.1', 'listen-address ::1', 'port 1053', 'allow-from 127.0.0.0/8',
        'name-server 192.0.2.53 port 853 tls authentication-name dns.test',
        'domain home.test name-server 192.0.2.54', 'domain home.test disable-cache',
        'cache message-size 4m', 'cache rrset-size 8m', 'cache minimum-ttl 0', 'cache maximum-ttl 600',
        'cache maximum-negative-ttl 30', 'cache prefetch', 'cache prefetch-dnssec',
        'cache serve-expired maximum-age 300 reply-ttl 10 client-timeout 200',
        'dnssec insecure-domain home.test', 'local-data static-host-mapping', 'local-data ttl 60',
        'options threads 2', 'options edns-buffer-size 1232', 'options maximum-udp-size 1232',
        'options outgoing-range 512', 'options queries-per-thread 512', 'options incoming-tcp 10',
        'options outgoing-tcp 10', 'options tcp-idle-timeout 5000', 'options minimal-responses',
        'options hide-identity', 'options hide-version', 'options qname-minimisation strict',
        'logging verbosity 2', 'logging queries', 'logging replies', 'logging servfail', 'logging validation-failures',
    ]
    for command in commands:
        controller.execute('set service dns forwarding ' + command, session)
    result = engine.commit(session)
    assert result['results']['dns-forwarding']['success'], result
    text = captured[-1]['bundles']['default']['text']
    json.dumps(captured[-1])  # The background refresh consumes a serialized plan snapshot.
    assert 'forward-addr: 192.0.2.53@853#dns.test' in text
    assert 'qname-minimisation-strict: yes' in text
    assert 'serve-expired-client-timeout: 200' in text
    assert 'forward-no-cache: yes' in text

    controller.execute('delete service dns forwarding', session)
    assert engine.commit(session)['results']['dns-forwarding']['success']
    assert captured[-1]['bundles'] == {}
