"""Static route schema, validation, rendering and commit lifecycle coverage."""

from copy import deepcopy
import ipaddress
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import protocols_static as static
from nvyr.errors import RouterError
from nvyr.helpers import interfaces
from nvyr.schema import Schema
from tests.test_static import applied


SCOPES = [
    'route 192.0.2.0/24',
    'route6 2001:db8:100::/64',
    'route6 2001:db8:100::/64 source-specific from 2001:db8:200::/64',
]


def payload(config):
    effective = Schema.bundled().defaults({'protocols': {'static': config}})
    return static.generate({'default': effective['protocols']['static']}, None)['default']


@pytest.mark.parametrize('scope', SCOPES)
@pytest.mark.parametrize('vrf', [None, 'BLUE'])
def test_all_path_options_in_default_and_named_vrf(controller, engine, session, applied, scope, vrf):
    root = f'vrf name {vrf} ' if vrf else ''
    if vrf:
        controller.execute(f'set vrf name {vrf} table 100', session)

    route = f'{root}protocols static {scope}'
    hop = '198.51.100.1' if scope.startswith('route ') else '2001:db8::1'
    for suffix in [
        'description "Branch networks"',
        f'next-hop {hop} interface eth1', f'next-hop {hop} vrf default',
        f'next-hop {hop} onlink', f'next-hop {hop} distance 10',
        f'next-hop {hop} metric 50', f'next-hop {hop} tag 123',
        f'next-hop {hop} weight 20', f'next-hop {hop} description "Primary upstream"',
        'interface eth2', 'interface eth2 vrf default', 'interface eth2 distance 10',
        'interface eth2 metric 50', 'interface eth2 tag 123', 'interface eth2 weight 30',
        'interface eth2 description "Second upstream"',
        'blackhole distance 254', 'blackhole metric 100', 'blackhole tag 456',
        'blackhole description "Fallback discard"',
        'reject disable', 'reject description "Inactive alternative"',
    ]:
        controller.execute(f'set {route} {suffix}', session)

    assert engine.commit(session)['results']['static']['success']
    commands = applied[-1][1][vrf or 'default']
    prefix = '192.0.2.0/24' if scope.startswith('route ') else '2001:db8:100::/64'
    base = ('ip' if scope.startswith('route ') else 'ipv6') + ' route ' + prefix
    if 'source-specific' in scope:
        base += ' from 2001:db8:200::/64'
    resolution = ' nexthop-vrf default' if vrf else ''
    assert commands == sorted([
        f'{base} {hop} eth1 tag 123 10 metric 50{resolution} weight 20 onlink',
        f'{base} eth2 tag 123 10 metric 50{resolution} weight 30',
        f'{base} blackhole tag 456 254 metric 100',
    ])



def test_ipv4_over_ipv6_gateway_and_default_omission(controller, engine, session, applied):
    controller.execute('set protocols static route 192.0.2.0/24 next-hop fe80::1 interface eth0', session)
    assert engine.commit(session)['results']['static']['success']
    assert applied[-1][1]['default'] == ['ip route 192.0.2.0/24 fe80::1 eth0']

    effective = engine.schema.defaults(engine.running)
    hop = effective['protocols']['static']['route']['192.0.2.0/24']['next-hop']['fe80::1']
    assert hop['distance'] == '1' and hop['metric'] == '0'
    engine.save(session)
    saved = engine.store.read('boot.json')['protocols']['static']['route']['192.0.2.0/24']['next-hop']['fe80::1']
    assert saved == {'interface': 'eth0'}


@pytest.mark.parametrize('suffix', [
    'next-hop 198.51.100.1 metric -1', 'next-hop 198.51.100.1 metric 4294967296',
    'next-hop 198.51.100.1 weight 0', 'next-hop 198.51.100.1 weight 65536',
    'interface eth0 tag 0', 'blackhole tag 4294967296',
    'reject distance 256', 'next-hop 198.51.100.1 interface bad/name',
    'next-hop 198.51.100.1 vrf bad/name', 'next-hop 198.51.100.1 next-hop-vrf BLUE',
    'next-hop 198.51.100.1 bfd', 'blackhole weight 10',
    'source-specific from 2001:db8::/64 reject',
])
def test_invalid_or_out_of_scope_schema_values(controller, session, suffix):
    with pytest.raises(RouterError):
        controller.execute(f'set protocols static route 192.0.2.0/24 {suffix}', session)
    assert not session.mutations


@pytest.mark.parametrize('scope', SCOPES)
@pytest.mark.parametrize('root', ['protocols static', 'vrf name BLUE protocols static'])
@pytest.mark.parametrize('path', ['interface Null0', 'next-hop 2001:db8::1 interface ReJeCt'])
def test_reserved_interface_rejected_at_entry(controller, session, scope, root, path):
    with pytest.raises(RouterError, match='reserved by FRR'):
        controller.execute(f'set {root} {scope} {path}', session)

    assert not session.mutations


@pytest.mark.parametrize('paths', [
    {'interface': {'BLACKHOLE': {}}},
    {'next-hop': {'198.51.100.1': {'interface': 'null0'}}},
])
def test_reserved_interface_rejected_in_loaded_configuration(paths):
    configuration = {'protocols': {'static': {'route': {'192.0.2.0/24': paths}}}}
    with pytest.raises(RouterError, match='reserved by FRR'):
        Schema.bundled().validate_configuration(configuration)


@pytest.mark.parametrize('route, message', [
    ({'next-hop': {'198.51.100.1': {'disable': True}}}, 'at least one enabled'),
    ({'interface': {'eth0': {'disable': True}}}, 'at least one enabled'),
    ({'blackhole': {'disable': True}}, 'at least one enabled'),
    ({'next-hop': {'198.51.100.1': {'onlink': True}}}, 'onlink requires an interface'),
    ({'next-hop': {'fe80::1': {}}}, 'link-local next hop requires an interface'),
    ({'blackhole': {}, 'reject': {'distance': '10'}}, 'mutually exclusive'),
    ({'blackhole': {}, 'next-hop': {'198.51.100.1': {}}}, 'cannot share distance'),
    ({'reject': {'metric': '10'}, 'interface': {'eth0': {'metric': '10'}}}, 'cannot share distance'),
    ({'next-hop': {'2001:db8::1': {}, '2001:0db8::1': {}}}, 'duplicates another enabled'),
])
def test_cross_field_errors_in_check_and_commit(route, message, monkeypatch):
    monkeypatch.setattr(interfaces, 'local_addresses', lambda vrf: set())
    config = {'default': {'route': {'192.0.2.0/24': route}}}
    for check_only in (True, False):
        with pytest.raises(RouterError, match=message):
            static.verify(config, SimpleNamespace(check_only=check_only, report=lambda text: None))


def test_disabled_paths_skip_checks_but_enabled_alternatives_are_valid(monkeypatch):
    def no_query(**kwargs):
        pytest.fail('Disabled next hops must not query host addresses')

    monkeypatch.setattr(interfaces, 'local_addresses', no_query)
    route = {'next-hop': {'fe80::1': {'disable': True, 'onlink': True, 'vrf': 'absent'}},
             'interface': {'eth0': {'disable': True}}, 'blackhole': {'disable': True}, 'reject': {}}
    config = {'route': {'192.0.2.0/24': route}}
    before = deepcopy(config)
    static.verify({'default': config}, SimpleNamespace(check_only=False))
    assert payload(config) == ['ip route 192.0.2.0/24 reject']
    assert config == before


def test_source_specific_coexistence_disable_and_duplicate_detection(monkeypatch):
    monkeypatch.setattr(interfaces, 'local_addresses', lambda vrf: set())
    route = {'next-hop': {'2001:db8::1': {}}, 'source-specific': {'from': {
        '2001:db8:200::/64': {'interface': {'eth1': {}}},
        '2001:db8:300::/64': {'reject': {}},
        '2001:db8:400::/64': {'disable': True},
    }}}
    config = {'route6': {'2001:db8:100::/64': route}}
    static.verify({'default': config}, SimpleNamespace(check_only=False))
    assert payload(config) == ['ipv6 route 2001:db8:100::/64 2001:db8::1',
                               'ipv6 route 2001:db8:100::/64 from 2001:db8:200::/64 eth1',
                               'ipv6 route 2001:db8:100::/64 from 2001:db8:300::/64 reject']

    route['source-specific']['from']['::/0'] = {'blackhole': {}}
    with pytest.raises(RouterError, match='duplicates another destination/source'):
        static.verify({'default': config}, SimpleNamespace(check_only=False))

    route['disable'] = True
    static.verify({'default': config}, SimpleNamespace(check_only=False))
    assert payload(config) == []


def test_empty_enabled_source_specific_entry_rejected():
    config = {'default': {'route6': {'2001:db8::/64': {'blackhole': {},
        'source-specific': {'from': {'2001:db8:100::/64': {}}}}}}}
    with pytest.raises(RouterError, match='source-specific from 2001:db8:100::/64: at least one enabled'):
        static.verify(config, SimpleNamespace(check_only=True))


def test_check_only_skips_host_queries_and_commit_caches_by_resolution_vrf(monkeypatch):
    queries, messages = [], []

    def addresses(vrf):
        queries.append(vrf)
        return {ipaddress.ip_address('198.51.100.99')}

    monkeypatch.setattr(interfaces, 'local_addresses', addresses)
    config = {'BLUE': {'route': {'192.0.2.0/24': {'next-hop': {
        '198.51.100.1': {'vrf': 'RED'}, '198.51.100.2': {'vrf': 'RED'},
        '198.51.100.99': {'vrf': 'RED', 'disable': True},
    }}}}}
    static.verify(config, SimpleNamespace(check_only=True, report=messages.append))
    assert not queries and len(messages) == 1
    static.verify(config, SimpleNamespace(check_only=False))
    assert queries == ['RED']


def test_dependencies_and_edit_context(controller, engine, session):
    controller.execute('set vrf name BLUE table 100', session)
    controller.execute('set interfaces dummy dum0', session)
    controller.execute('edit protocols static route 192.0.2.0/24', session)
    controller.execute('set next-hop 198.51.100.1 interface dum0', session)
    controller.execute('set next-hop 198.51.100.1 vrf BLUE', session)
    controller.execute('set next-hop 198.51.100.1 disable', session)
    controller.execute('set reject', session)
    assert 'onlink' in dict(controller.completion('set next-hop 198.51.100.1 ', session, explicit=True)['candidates'])
    controller.execute('top', session)

    for command in ('delete interfaces dummy dum0', 'delete vrf name BLUE'):
        with pytest.raises(RouterError, match='referenc'):
            controller.execute(command, session)

    controller.execute('delete protocols static', session)
    controller.execute('delete interfaces dummy dum0', session)
    controller.execute('delete vrf name BLUE', session)


def test_disable_reenable_delete_and_commit_confirm_restore(controller, engine, session, applied):
    path = 'protocols static route 192.0.2.0/24'
    controller.execute(f'set {path} interface eth0', session)
    engine.commit(session)
    original = deepcopy(applied[-1][1])
    controller.execute(f'set {path} disable', session)
    engine.commit(session, minutes=1, confirmed_minutes=1)
    assert applied[-1][1]['default'] == []

    engine.clock = lambda: engine.pending['deadline'] + 1
    engine.tick()
    assert applied[-1][1] == original
    assert 'disable' not in engine.running['protocols']['static']['route']['192.0.2.0/24']

    controller.execute(f'set {path} disable', session)
    engine.commit(session)
    controller.execute(f'delete {path} disable', session)
    engine.commit(session)
    assert applied[-1][1] == original
    controller.execute(f'delete {path}', session)
    engine.commit(session)
    assert applied[-1][1]['default'] == []
