import ipaddress
import json
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import protocols_static
from nvyr.helpers import frr_reload, interfaces
from nvyr.errors import RouterError


@pytest.fixture
def applied(monkeypatch):
    records = []
    monkeypatch.setattr(interfaces, 'local_addresses', lambda vrf=None: set())
    monkeypatch.setattr(frr_reload.manager, 'apply', lambda owner, sections, directory, **options: records.append((owner, sections, options)))

    return records


def test_static_ipv4_ipv6_multiple_hops_distances_defaults_and_deletion(controller, engine, session, applied):
    for command in [
        'set protocols static route 192.0.2.0/24 next-hop 192.0.2.1',
        'set protocols static route 192.0.2.0/24 next-hop 192.0.2.2 distance 10',
        'set protocols static route 192.0.2.0/24 next-hop 192.0.2.3 distance 10',
        'set protocols static route6 2001:db8:100::/64 next-hop 2001:db8::1 distance 10',
    ]:
        controller.execute(command, session)

    assert engine.commit(session)['results']['static']['success']
    assert len(applied) == 1 and applied[0][0] == 'static'

    assert applied[0][1]['default'] == [
        'ip route 192.0.2.0/24 192.0.2.1',
        'ip route 192.0.2.0/24 192.0.2.2 10',
        'ip route 192.0.2.0/24 192.0.2.3 10',
        'ipv6 route 2001:db8:100::/64 2001:db8::1 10',
    ]

    engine.save(session)

    assert engine.store.read('boot.json')['protocols']['static']['route']['192.0.2.0/24']['next-hop']['192.0.2.1'] == {}

    controller.execute('delete protocols static', session)

    assert engine.commit(session)['results']['static']['success']
    assert applied[-1][1] == {'default': []}


@pytest.mark.parametrize('path', [
    'route 192.0.2.1/24 next-hop 192.0.2.1',
    'route 192.0.2.0/33 next-hop 192.0.2.1',
    'route6 2001:db8::/64 next-hop 192.0.2.1',
    'route6 2001:db8::/64 next-hop fe80::1%eth0',
    'route 192.0.2.0/24 next-hop 192.0.2.1 distance 0',
    'route 192.0.2.0/24 next-hop 192.0.2.1 distance 256',
])
def test_static_schema_rejects_invalid_values(controller, session, path):
    with pytest.raises(RouterError):
        controller.execute('set protocols static ' + path, session)

    assert not session.mutations


@pytest.mark.parametrize('family,prefix,hop,local', [
    ('route', '192.0.2.0/24', '192.0.2.1', '192.0.2.1'),
    ('route6', '2001:db8:100::/64', '2001:db8:0:0::1', '2001:db8::1'),
])
def test_local_next_hop_fails_whole_owner_before_apply(controller, engine, session, applied, monkeypatch, family, prefix, hop, local):
    monkeypatch.setattr(interfaces, 'local_addresses', lambda vrf=None: {ipaddress.ip_address(local)})
    controller.execute('set protocols static route 198.51.100.0/24 next-hop 192.0.2.2', session)
    controller.execute(f'set protocols static {family} {prefix} next-hop {hop}', session)
    result = engine.commit(session)['results']['static']

    assert not result['success'] and hop in result['error'] and 'local system' in result['error']
    assert not applied and engine.running == {} and session.mutations


def test_local_address_helper_includes_down_links_and_both_families(monkeypatch):
    def run(argv, **kwargs):
        assert argv == ['ip', '-j', 'address', 'show']

        return json.dumps([
            {'flags': [], 'addr_info': [{'local': '192.0.2.1'}, {'local': '2001:db8::1'}]},
            {'flags': ['UP'], 'addr_info': [{'local': '127.0.0.1'}]},
        ])

    monkeypatch.setattr(interfaces, 'cmd', run)

    assert interfaces.local_addresses() == {ipaddress.ip_address(value) for value in ['192.0.2.1', '2001:db8::1', '127.0.0.1']}


def test_static_completion_and_edit_context_use_generic_tree(controller, session):
    controller.execute('edit protocols static', session)

    assert controller.completion('set route ', session)['hints'] == [('x.x.x.x/x', 'IPv4 destination network with prefix length')]
    assert {'distance', 'disable'} <= dict(controller.completion(
        'set route 192.0.2.0/24 next-hop invalid ', session, explicit=True)['candidates']).keys()

    controller.execute('set route 192.0.2.0/24 next-hop 192.0.2.1 distance 10', session)

    assert len(session.mutations) == 1


def test_vrf_sections_separate_identical_prefixes_and_next_hop_resolution(monkeypatch):
    route = {'route': {'192.0.2.0/24': {'next-hop': {'198.51.100.1': {'distance': '10'}}}},
             'route6': {'2001:db8:100::/64': {'next-hop': {'2001:db8::1': {'distance': '1'}}}}}
    configuration = {'blue': route, 'red': route, 'default': {}}
    monkeypatch.setattr(interfaces, 'local_addresses', lambda vrf: set())
    protocols_static.verify(configuration, SimpleNamespace(check_only=False))
    sections = protocols_static.generate(configuration, None)

    assert sections == {
        'default': [],
        'blue': ['ip route 192.0.2.0/24 198.51.100.1 10', 'ipv6 route 2001:db8:100::/64 2001:db8::1'],
        'red': ['ip route 192.0.2.0/24 198.51.100.1 10', 'ipv6 route 2001:db8:100::/64 2001:db8::1'],
    }



def test_local_next_hop_validation_uses_resolution_vrf_and_reports_route_vrf(monkeypatch):
    own = ipaddress.ip_address('198.51.100.1')
    calls = []

    def addresses(vrf):
        calls.append(vrf)
        return {'blue': {own}, 'red': set()}[vrf]

    monkeypatch.setattr(interfaces, 'local_addresses', addresses)
    values = {'distance': '1'}
    config = {'red': {'route': {'192.0.2.0/24': {'next-hop': {'198.51.100.1': values}}}}}
    protocols_static.verify(config, SimpleNamespace(check_only=False))  # An address local in blue is valid in red.

    assert calls == ['red']

    values['vrf'] = 'blue'

    with pytest.raises(RouterError, match='VRF red:.*198.51.100.1.*local system in VRF blue'):
        protocols_static.verify(config, SimpleNamespace(check_only=False))

    assert protocols_static.generate(config, None) == {
        'red': ['ip route 192.0.2.0/24 198.51.100.1 nexthop-vrf blue']}



def test_local_addresses_follow_vrf_master_topology_and_include_down_links(monkeypatch):
    devices = [
        {'ifindex': 1, 'ifname': 'lo'},
        {'ifindex': 2, 'ifname': 'blue', 'linkinfo': {'info_kind': 'vrf'}},
        {'ifindex': 3, 'ifname': 'br0', 'master': 'blue', 'linkinfo': {'info_kind': 'bridge'}},
        {'ifindex': 4, 'ifname': 'eth0', 'master': 3},
        {'ifindex': 5, 'ifname': 'eth1'},
        {'ifindex': 6, 'ifname': 'red', 'linkinfo': {'info_kind': 'vrf'}},
        {'ifindex': 7, 'ifname': 'eth2', 'master': 'red'},
    ]
    links = [{'ifname': name, 'flags': [], 'addr_info': [{'local': address} for address in addresses]}
             for name, addresses in [('lo', ['127.0.0.1']), ('blue', ['192.0.2.1']),
                                     ('br0', ['2001:db8::1']), ('eth0', ['198.51.100.1']),
                                     ('eth1', ['203.0.113.1']), ('eth2', ['198.51.100.1'])]]

    def run(argv, **kwargs):
        assert argv in (['ip', '-j', 'address', 'show'], ['ip', '-d', '-j', 'link', 'show'])

        return json.dumps(devices if 'link' in argv else links)

    monkeypatch.setattr(interfaces, 'cmd', run)

    def addresses(*values):
        return {ipaddress.ip_address(value) for value in values}

    assert interfaces.local_addresses(vrf='default') == addresses('127.0.0.1', '203.0.113.1')
    assert interfaces.local_addresses(vrf='blue') == addresses('192.0.2.1', '2001:db8::1', '198.51.100.1')
    assert interfaces.local_addresses(vrf='red') == addresses('198.51.100.1')

    with pytest.raises(RouterError, match="VRF 'missing'.*does not exist"):
        interfaces.local_addresses(vrf='missing')

    devices[2]['master'] = 'missing'

    with pytest.raises(RouterError, match='topology changed'):
        interfaces.local_addresses(vrf='blue')


def test_static_template_normalizes_addresses():
    configuration = {'blue': {'route6': {'2001:0db8:0100::/64': {'next-hop': {
        '2001:0db8:0000::1': {'distance': '10', 'vrf': 'red'}}}}}}
    assert protocols_static.generate(configuration, None) == {
        'blue': ['ipv6 route 2001:db8:100::/64 2001:db8::1 10 nexthop-vrf red']}


@pytest.mark.parametrize('configuration', [
    {'vrf': {'name': {'blue\nend': {'protocols': {'static': {}}}}}},
    {'protocols': {'static': {'route': {'192.0.2.0/24': {'interface': {'eth0\nend': {}}}}}}},
    {'protocols': {'static': {'route': {'192.0.2.0/24': {'next-hop': {
        '198.51.100.1': {'interface': 'eth0\nend'}}}}}}},
    {'protocols': {'static': {'route': {'192.0.2.0/24': {'next-hop': {
        '198.51.100.1': {'vrf': 'red\nend'}}}}}}},
])
def test_loaded_static_identifiers_reject_command_injection(controller, session, configuration):
    with pytest.raises(RouterError):
        controller.load(session, json.dumps(configuration), replace=True)

    assert not session.mutations


@pytest.mark.parametrize('configuration', [{}, {'route': {'192.0.2.0/24': {}}},
    {'route': {'192.0.2.0/24': {'next-hop': {}}}, 'route6': {'2001:db8::/64': {}}}])
def test_generate_empty_routes_is_defensive_but_verify_rejects_them(configuration):
    if configuration:
        with pytest.raises(RouterError, match='at least one enabled next-hop'):
            protocols_static.verify({'blue': configuration}, SimpleNamespace(check_only=False))

    assert protocols_static.generate({'blue': configuration}, None) == {'blue': []}


@pytest.mark.parametrize('family,prefix,hop', [
    ('route', '192.0.2.0/24', '192.0.2.1'),
    ('route6', '2001:db8:100::/64', '2001:db8::1'),
])
def test_last_next_hop_deletion_keeps_route_and_verify_rejects_until_repaired(
        controller, engine, session, applied, family, prefix, hop):
    path = f'protocols static {family} {prefix}'
    controller.execute(f'set {path} next-hop {hop}', session)

    assert engine.commit(session)['results']['static']['success']

    applied.clear()
    controller.execute(f'delete {path} next-hop {hop}', session)

    assert engine.view(session)['protocols']['static'][family][prefix] == {'next-hop': {}}

    result = engine.commit(session)['results']['static']

    assert not result['success'] and 'at least one enabled next-hop' in result['error']
    assert prefix in result['error'] and 'VRF default' in result['error']
    assert not applied and session.mutations

    controller.execute(f'set {path} next-hop {hop}', session)
    engine.commit(session)

    assert not session.mutations

    controller.execute(f'delete {path}', session)

    assert engine.commit(session)['results']['static']['success']
    assert engine.running['protocols']['static'][family] == {}


@pytest.mark.parametrize('family,prefix', [('route', '192.0.2.0/24'), ('route6', '2001:db8::/64')])
def test_empty_route_created_directly_fails_verify(controller, engine, session, applied, family, prefix):
    controller.execute(f'set protocols static {family} {prefix}', session)
    result = engine.commit(session)['results']['static']

    assert not result['success'] and prefix in result['error']
    assert not applied


def test_template_receives_original_effective_config_dict(monkeypatch):
    from nvyr.tree import ReadOnlyTree

    configuration = ReadOnlyTree({
        'route': {'192.0.2.0/24': {}, '198.51.100.0/24': {
            'next-hop': {'192.0.2.2': {'distance': '10'}}}},
        'route6': {'2001:db8:100::/64': {'next-hop': {'2001:db8::2': {'distance': '1'}}},
                   '2001:db8:200::/64': {}},
    })
    shared_render = protocols_static.render

    def render(name, variables):
        assert variables == {'vrf': 'blue', 'configuration': configuration}
        assert variables['configuration'] is configuration

        return shared_render(name, variables)

    monkeypatch.setattr(protocols_static, 'render', render)
    assert protocols_static.generate({'blue': configuration}, None) == {'blue': [
        'ip route 198.51.100.0/24 192.0.2.2 10',
        'ipv6 route 2001:db8:100::/64 2001:db8::2',
    ]}



def test_template_failure_stops_before_apply(controller, engine, session, applied, monkeypatch):
    from nvyr.helpers.template import RenderingError

    def broken(*args):
        raise RenderingError('Cannot render static configuration')

    monkeypatch.setattr(protocols_static, 'render', broken)
    controller.execute('set protocols static route 192.0.2.0/24 next-hop 198.51.100.1', session)
    result = engine.commit(session)['results']['static']
    assert not result['success'] and 'Cannot render static' in result['error']
    assert not applied and engine.running == {}
