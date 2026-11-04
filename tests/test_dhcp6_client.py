"""DHCPv6 association handling and PID-independent lease/RA lifetimes."""

import ipaddress
import struct

import pytest

from nvyr.errors import ValidationError
from nvyr.helpers import dhcp6, interfaces, ipv6_ra
from nvyr.storage import atomic_json


def option(code, payload):
    return struct.pack('!HH', code, len(payload)) + payload


def test_prefix_exclusion_and_smaller_grants_affect_only_the_selected_lan():
    base = ipaddress.IPv6Address('2001:db8:1234::').packed
    excluded = option(67, bytes([64, 0x10]))
    prefix = option(26, struct.pack('!IIB16s', 60, 120, 60, base) + excluded)
    reply = bytes([7, 0, 0, 1]) + option(25, struct.pack('!III', 42, 30, 45) + prefix)
    entries = dhcp6.decode_reply(reply, 100)
    targets = {name: {'subnet-id': index} for name, index in [('lan0', '0'), ('lan1', '1'), ('lan16', '16')]}
    lans, errors = dhcp6.assignments({'requests': {'42': {'interface': targets}}}, entries)
    assert [lan['address'] for lan in lans] == ['2001:db8:1234::1/64']
    assert lans[0]['preferred'] == 160 and lans[0]['valid'] == 220
    assert [e.split(':')[0] for e in errors] == ['lan1', 'lan16']


def test_ra_expiry_is_per_advertiser_and_scopes_link_local_dns(tmp_path, monkeypatch):
    source = ipv6_ra.Learned(tmp_path / 'ra.json')
    now = 10
    monkeypatch.setattr(ipv6_ra.time, 'monotonic', lambda: now)

    def advertise(router, lifetime):
        dns = struct.pack('!BBHI', 25, 3, 0, lifetime) + ipaddress.IPv6Address('fe80::53').packed
        attr = struct.pack('=HH', 20, 1) + ipaddress.IPv6Address(router).packed
        payload = struct.pack('=BBHiBB6x', 10, 0, len(dns), 4, 134, 0) + dns + attr
        source.receive(struct.pack('=IHHII', len(payload) + 16, 68, 0, 0, 0) + payload)

    advertise('fe80::1', 5)
    advertise('fe80::2', 10)
    advertise('fe80::1', 0)
    assert list(source.records(4, 'eth0')) == [{'server': 'fe80::53%eth0', 'source': 'RA', 'interface': 'eth0'}]
    assert not list(source.records(5, 'eth1'))
    now += 11
    assert not list(source.records(4, 'eth0'))


def test_expiry_and_explicit_withdrawal_do_not_restore_old_leases(tmp_path, monkeypatch):
    monkeypatch.setattr(dhcp6, 'ROOT', tmp_path)
    monkeypatch.setattr(dhcp6.time, 'monotonic', lambda: 100)
    directory = tmp_path / 'eth0'
    atomic_json(directory / 'client.json', dict(index=10, duid='test', spec={'requests': {}}, token='abcdef'))
    atomic_json(directory / 'abcdef.json', dict(entries=[{'type': 'IA_NA', 'valid': 99}], dns=['::1']))
    client = dhcp6.Client()
    assert 'dns' not in client.observation('eth0', 10)
    assert client.observation('eth0', 11) == {}
    atomic_json(directory / 'abcdef.json', dict(entries=[], refresh=99, search=['old.example']))
    assert 'search' not in client.observation('eth0', 10)


def test_renewal_deprecates_omitted_prefix_and_honors_explicit_withdrawal(tmp_path, monkeypatch):
    monkeypatch.setattr(dhcp6, 'ROOT', tmp_path)
    monkeypatch.setattr(dhcp6, 'LEASE_DIR', tmp_path)
    monkeypatch.setattr(dhcp6.time, 'monotonic', lambda: 100)
    monkeypatch.setenv('interface', 'eth0')
    monkeypatch.setenv('reason', 'RENEW6')
    monkeypatch.setenv('NVYR_DHCP_TOKEN', 'abcd')
    atomic_json(tmp_path / 'eth0/client.json', {'token': 'abcd'})
    record = tmp_path / 'eth0/abcd.json'
    old = {'type': 'IA_PD', 'id': '42', 'prefix': '2001:db8:1::/56', 'preferred': 180, 'valid': 240}
    atomic_json(record, {'entries': [old]})

    def renew(prefixes):
        binding = struct.pack('!III', 42, 30, 45)
        for prefix, lifetime in prefixes:
            value = struct.pack('!IIB16s', lifetime, lifetime, 56, ipaddress.IPv6Address(prefix).packed)
            binding += option(26, value)
        (tmp_path / 'eth0.lease6').write_bytes(bytes([7, 0, 0, 1]) + option(25, binding))
        dhcp6.hook_main()
        return {e['prefix']: e for e in dhcp6.read(record)['entries']}

    state = renew([('2001:db8:2::', 200)])
    assert state[old['prefix']]['preferred'] == 100 and state[old['prefix']]['valid'] == 240
    assert state['2001:db8:2::/56']['preferred'] == 300

    state = renew([('2001:db8:1::', 0), ('2001:db8:2::', 200)])
    assert state[old['prefix']]['valid'] == 100


def test_downstream_vrf_and_duplicate_duid_constraints():
    pd = {'1': {'interface': {'br1': {'subnet-id': '0'}}}}
    uplink = {'dhcpv6-pd': pd, 'dhcpv6-options': {'duid': '00:04:aa'}}
    interfaces.verify_pd({'eth0': uplink, 'br1': {}}, set())
    with pytest.raises(ValidationError, match='same VRF'):
        interfaces.verify_pd({'eth0': uplink, 'br1': {'vrf': 'ISP'}}, set())
    with pytest.raises(ValidationError, match='same DHCPv6 DUID'):
        interfaces.verify_pd({'eth0': uplink, 'br1': {}, 'eth1': uplink}, set())


def test_pd_schema_accepts_decimal_host_and_multiple_associations(controller, session, engine):
    root = 'set interfaces ethernet eth0'
    for line in ['address dhcpv6', 'dhcpv6-pd 0 length 56', 'dhcpv6-pd 7 length 60 interface eth2 subnet-id 1 address 254',
                 'dhcpv6-options rapid-commit no-request-domain-search']:
        controller.execute(f'{root} {line}', session)
    spec = dhcp6.configuration(engine.view(session)['interfaces']['ethernet']['eth0'])
    assert spec['requests']['7']['interface']['eth2'] == {'subnet-id': '1', 'address': '254'}
    assert set(spec['requests']) == {'0', '7'}
    with pytest.raises(ValidationError):
        controller.execute(f'{root} dhcpv6-pd 7 interface eth2 address 18446744073709551616', session)
