"""Typed one-field sets, field conflicts, CLI references and atomic cleanup."""

from copy import deepcopy
from types import SimpleNamespace
import json

import pytest

from nvyr.config_scripts import firewall
from nvyr.errors import RouterError
from nvyr.helpers import nftables
from nvyr.helpers.nftables_formatters import nft_singleton_group
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree
from tests.test_firewall_maps import rendered
from tests.test_firewall_matches import PATHS, configured


CASES = [
    ('interface-group', None, 'interface', ['eth0', 'eth1'], 'inbound-interface-group', 'ifname', 'iifname'),
    ('interface-group', None, 'interface', ['eth0'], 'outbound-interface-group', 'ifname', 'oifname'),
    ('address-group', 'ipv4', 'address', ['192.0.2.0/24', '198.51.100.1-198.51.100.10'], 'source-address-group', 'ipv4_addr', 'ip saddr'),
    ('address-group', 'ipv6', 'address', ['2001:db8::/64', '2001:db8:1::1-2001:db8:1::10'], 'destination-address-group', 'ipv6_addr', 'ip6 daddr'),
    ('mac-group', None, 'address', ['02:00:00:00:00:01'], 'source-mac-group', 'ether_addr', 'ether saddr'),
    ('mac-group', None, 'address', ['02:00:00:00:00:02'], 'destination-mac-group', 'ether_addr', 'ether daddr'),
    ('port-group', None, 'port', ['80', '443', '8000-8080'], 'destination-port-group', 'inet_service', 'th dport'),
    ('port-group', None, 'port', ['1024-65535'], 'source-port-group', 'inet_service', 'th sport'),
]


def definitions(kind, family, definition):
    groups = {'G': definition}
    return {kind: {family: groups} if family else groups}


@pytest.mark.parametrize('kind,family,member,values,reference,datatype,expression', CASES)
def test_typed_sets_and_rule_references(kind, family, member, values, reference, datatype, expression):
    rule = {reference: 'G', 'action': 'accept', 'counter': {}, 'protocol': ['tcp']}
    tree = configured(rule, (family or 'ipv4', 'forward', 'filter'))
    tree['firewall']['group'] = definitions(kind, family, {member: values, 'description': 'Reusable members'})
    original = deepcopy(tree)

    text = rendered(tree)
    assert f'type {datatype};' in text
    assert 'comment "Reusable members";' in text
    line = next(line for line in text.splitlines() if f'{expression} @' in line)
    assert line.index(expression) < line.index('counter') < line.index('accept')
    assert tree == original


@pytest.mark.parametrize('path', PATHS + [('ipv4', 'name', 'CUSTOM'), ('ipv6', 'name', 'CUSTOM')])
def test_singleton_groups_on_all_firewall_paths(path):
    tree = configured({'source-port-group': 'G', 'protocol': ['udp'], 'action': 'accept'}, path)
    tree['firewall']['group'] = {'port-group': {'G': {'port': ['53']}}}
    assert 'th sport @port_group_G' in rendered(tree)


@pytest.mark.parametrize('kind,family,member,values,reference,datatype,expression', CASES)
def test_cli_members_suggestions_dependencies_and_commit(controller, engine, session, kind, family, member, values, reference, datatype, expression):
    path = kind + (' ' + family if family else '')
    for value in values:
        controller.execute(f'set firewall group {path} G {member} {value}', session)
    controller.execute(f'set firewall {family or "ipv4"} forward filter rule 10 {reference} G protocol tcp action accept', session)

    command = f'set firewall {family or "ipv4"} forward filter rule 20 {reference} '
    assert 'G' in dict(controller.completion(command, session)['candidates'])
    if family:
        other = 'ipv6' if family == 'ipv4' else 'ipv4'
        assert 'G' not in dict(controller.completion(command.replace(family, other), session)['candidates'])
    with pytest.raises(RouterError, match='referenced'):
        controller.execute(f'delete firewall group {path} G', session)
    assert engine.commit(session)['results']['firewall']['success']


def test_interface_members_protect_configured_interfaces(controller, session):
    controller.execute('set interfaces dummy dum9', session)
    controller.execute('set firewall group interface-group G interface dum9', session)
    with pytest.raises(RouterError, match='referenced'):
        controller.execute('delete interfaces dummy dum9', session)


@pytest.mark.parametrize('source', ['rule', 'map', 'match-group'])
@pytest.mark.parametrize('reference,field,kind', [
    ('inbound-interface-group', 'inbound-interface', 'interface-group'),
    ('source-address-group', 'source-address', 'address-group'),
    ('source-mac-group', 'source-mac', 'mac-group'),
    ('destination-port-group', 'destination-port', 'port-group'),
])
def test_duplicates_rejected_across_all_sources(source, reference, field, kind):
    rule = {reference: 'G', 'action': 'accept'}
    mapping = None
    group = None
    if source == 'rule':
        rule[field] = []
    elif source == 'map':
        mapping = {'match': {field: True}}
    else:
        group = {'match': {field: True}}
    groups = definitions(kind, 'ipv4' if kind == 'address-group' else None, {})

    with pytest.raises(RouterError, match=f'{reference} duplicates {field}'):
        nftables.verify_singleton_references(rule, ('firewall', 'ipv4'), 'ipv4', groups, mapping, group)


def test_disjoint_singletons_map_and_match_group_can_coexist():
    rule = {'source-address-group': 'A', 'outbound-interface-group': 'I', 'destination-port-group': 'P',
            'map': 'M', 'match-group': 'G', 'protocol': ['tcp']}
    tree = configured(rule, ('ipv4', 'forward', 'filter'))
    tree['firewall']['group'] = {
        'address-group': {'ipv4': {'A': {'address': ['192.0.2.0/24']}}},
        'interface-group': {'I': {'interface': ['eth0']}},
        'port-group': {'P': {'port': ['443']}},
        'map': {'ipv4': {'M': {'match': {'destination-address': True}, 'result-type': 'verdict',
                              'entry': {'A': {'destination-address': '203.0.113.1', 'result': {'action': 'accept'}}}}}},
        'match-group': {'ipv4': {'G': {'match': {'source-mac': True},
                                      'entry': {'A': {'source-mac': '02:00:00:00:00:01'}}}}},
    }
    text = rendered(tree)
    assert 'ip saddr @ipv4_address_group_A' in text
    assert 'th dport @port_group_P' in text
    assert 'vmap @ipv4_map_M' in text


@pytest.mark.parametrize('source', ['rule', 'map', 'match-group'])
def test_port_groups_require_tcp_udp_from_any_source(source):
    rule = {'destination-port-group': 'P', 'action': 'accept'}
    tree = configured(rule, ('ipv4', 'forward', 'filter'))
    groups = tree['firewall']['group'] = {'port-group': {'P': {'port': ['443']}}}
    with pytest.raises(RouterError, match='requires an explicit port protocol'):
        rendered(tree)

    if source == 'rule':
        rule['protocol'] = ['tcp', 'udp']
    else:
        definition = {'match': {'protocol': True}, 'entry': {'TCP': {'protocol': 'tcp'}}}
        groups[source] = {'ipv4': {'G': definition}}
        rule[source] = 'G'
        if source == 'map':
            rule.pop('action')
            definition['result-type'] = 'verdict'
            definition['entry']['TCP']['result'] = {'action': 'accept'}
    rendered(tree)

    if source == 'rule':
        rule['protocol'] = ['icmp']
    else:
        definition['entry']['TCP']['protocol'] = 'icmp'
    with pytest.raises(RouterError, match='requires an explicit port protocol'):
        rendered(tree)


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_icmp_rejects_port_group_and_address_family_must_match(family):
    rule = {'destination-port-group': 'P', 'icmp-type': ['echo-request'],
            'protocol': ['icmp' if family == 'ipv4' else 'ipv6-icmp'], 'action': 'accept'}
    tree = configured(rule, (family, 'forward', 'filter'))
    tree['firewall']['group'] = {'port-group': {'P': {'port': ['443']}}}
    with pytest.raises(RouterError, match='ICMP matching cannot be combined'):
        rendered(tree)

    tree = configured({'source-address-group': 'A', 'action': 'accept'}, (family, 'forward', 'filter'))
    other = 'ipv6' if family == 'ipv4' else 'ipv4'
    tree['firewall']['group'] = {'address-group': {other: {'A': {}}}}
    with pytest.raises(RouterError, match='not configured'):
        rendered(tree)


@pytest.mark.parametrize('direction,reference', [('source', 'outbound-interface-group'), ('destination', 'inbound-interface-group')])
def test_nat_singletons_supply_interface_address_and_ports(direction, reference):
    tree = {'firewall': {'group': {'interface-group': {'I': {'interface': ['eth0']}},
                                 'port-group': {'P': {'port': ['443']}}}},
            'nat': {direction: {'rule': {'10': {reference: 'I', 'destination-port-group': 'P',
                     'protocol': ['tcp'], 'translation': {'address': '192.0.2.1'}}}}}}
    text = rendered(tree)
    assert '@interface_group_I' in text and 'th dport @port_group_P' in text


def test_prerouting_cannot_match_outbound_interface_group():
    groups = {'interface-group': {'G': {'interface': ['eth0']}}}
    tree = configured({'outbound-interface-group': 'G', 'action': 'accept'}, ('ipv4', 'prerouting', 'raw'))
    tree['firewall']['group'] = groups
    with pytest.raises(RouterError, match='outbound-interface'):
        rendered(tree)
    tree = {'firewall': {'group': groups}, 'nat': {'destination': {'rule': {
        '10': {'outbound-interface-group': 'G', 'translation': {'address': '192.0.2.1'}}}}}}
    with pytest.raises(RouterError, match='outbound-interface'):
        rendered(tree)


@pytest.mark.parametrize('kind,family,member,values,reference,datatype,expression', CASES)
def test_empty_sets_and_full_subtree_deletion(kind, family, member, values, reference, datatype, expression):
    previous = {'firewall': {'group': definitions(kind, family, {member: values})}}
    text = rendered({}, previous)
    assert 'destroy set inet nvyr_filter ' in text
    empty = nft_singleton_group(kind, family, 'G', ReadOnlyTree({}))
    assert 'elements' not in empty and f'type {datatype}' in empty


def test_overlap_and_equivalent_members_render_as_union():
    group = {'address': ['192.0.2.5/24', '192.0.2.0/24', '192.0.2.1', '192.0.2.0-192.0.2.20']}
    text = nft_singleton_group('address-group', 'ipv4', 'G', group)
    assert text.count('192.0.2.0/24') == 1
    assert 'auto-merge;' in text
    mac = nft_singleton_group('mac-group', None, 'G', {'address': ['AA:BB:CC:DD:EE:FF', 'aa:bb:cc:dd:ee:ff']})
    assert mac.count('aa:bb:cc:dd:ee:ff') == 1


@pytest.mark.parametrize('groups', [
    {'address-group': {'ipv4': {'G': {'address': ['2001:db8::1']}}}},
    {'address-group': {'ipv6': {'G': {'address': ['192.0.2.1']}}}},
    {'port-group': {'G': {'port': ['0']}}},
    {'port-group': {'G': {'port': ['100-10']}}},
    {'mac-group': {'G': {'address': ['not-a-mac']}}},
    {'interface-group': {'G': {'interface': ['bad name']}}},
])
def test_schema_validates_members(groups):
    with pytest.raises(RouterError):
        Schema.bundled().validate_configuration({'firewall': {'group': groups}})


def test_restart_cleanup_discovers_only_owned_singleton_sets(monkeypatch):
    names = ['interface_group_G', 'mac_group_G', 'port_group_G', 'ipv4_address_group_G', 'ipv6_address_group_G',
             'ipv4_match_group_G', 'unrelated', 'ipv4_address_group_bad.name']
    data = [{'set': {'family': 'inet', 'table': 'nvyr_filter', 'name': name}} for name in names]
    data.append({'set': {'family': 'inet', 'table': 'other', 'name': 'interface_group_FOREIGN'}})
    monkeypatch.setattr(nftables, 'cmd', lambda argv: json.dumps({'nftables': data}))
    assert nftables.Manager().singleton_groups() == names[:5]
    monkeypatch.setattr(nftables, 'manager', SimpleNamespace(
        rule_limits=lambda: [], named_state=lambda: [], icmp_groups=lambda: [], singleton_groups=lambda: names[:5], maps=lambda: [], match_groups=lambda: [],
        named_chains=lambda: [], flowtables=lambda: []))
    text = rendered({}, recovery=True)
    for name in names[:5]:
        assert f'destroy set inet nvyr_filter {name}' in text


@pytest.mark.parametrize('kind,family,member,values,reference,datatype,expression', CASES)
@pytest.mark.parametrize('local', [{}, {'counter': True}, {'last-used': True}, {'counter': True, 'last-used': True}])
@pytest.mark.parametrize('global_options', [{}, {'counter': True}, {'last-used': True}, {'counter': True, 'last-used': True}])
def test_group_tracking_local_and_inherited(kind, family, member, values, reference, datatype, expression, local, global_options):
    definition = {member: values, **local}
    tree = {'firewall': {'group': definitions(kind, family, definition), 'global-options': global_options}}
    original = deepcopy(tree)

    text = rendered(tree)
    for option, statement in [('counter', 'counter'), ('last-used', 'last')]:
        expected = option in local or option in global_options
        assert text.count(f'    {statement};') == int(expected)
    assert tree == original


@pytest.mark.parametrize('path', ['interface-group G', 'address-group ipv4 G', 'address-group ipv6 G',
                                 'mac-group G', 'port-group G'])
def test_cli_group_tracking_flags(controller, engine, session, path):
    controller.execute(f'set firewall group {path} counter last-used', session)
    assert engine.commit(session)['results']['firewall']['success']
    with pytest.raises(RouterError):
        controller.execute(f'set firewall group {path} counter true', session)
