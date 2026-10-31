"""Zone schema, dispatch selection, hook validation and complete-object lifecycle."""

from copy import deepcopy

import pytest

from nvyr.errors import RouterError, ValidationError
from nvyr.helpers import nftables_zones as zones
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.op_scripts import firewall as operational
from nvyr.schema import Schema
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed


def configuration():
    return {'firewall': {
        'zone': {'USERS': {'interface': ['eth1', 'eth2']},
                 'WAN': {'interface': ['eth0'], 'intra-zone': {'default-action': 'drop'}},
                 'LOCAL': {'local-zone': True}},
        'zone-policy': {'from-zone': {'USERS': {'to-zone': {
            'WAN': {'ipv4-policy': 'WEB'}, 'LOCAL': {'ipv4-policy': 'SSH'}}},
            'LOCAL': {'to-zone': {'USERS': {'ipv4-policy': 'OUT'}}}}},
        'ipv4': {'name': {'WEB': {'default-action': 'accept'},
                          'SSH': {'default-action': 'drop'}, 'OUT': {'default-action': 'accept'}},
                 'forward': {'filter': {'default-action': 'drop', 'rule': {
                     '10': {'source-address': {'192.0.2.10': {}}, 'action': 'accept'}}}}},
    }}


def test_cli_anchors_defaults_suggestions_and_dependencies(controller, engine, session):
    controller.execute('set interfaces dummy dum998', session)
    controller.execute('set firewall zone USERS interface dum998 description Users', session)
    controller.execute('set firewall zone LOCAL local-zone', session)
    controller.execute('set firewall ipv4 name SSH default-action accept', session)
    controller.execute('set firewall zone-policy from-zone USERS to-zone LOCAL ipv4-policy SSH', session)

    candidate = engine.view(session)
    assert 'default-action' not in candidate['firewall']['zone']['USERS']
    effective = engine.schema.defaults(candidate)
    assert effective['firewall']['zone']['USERS']['default-action'] == 'drop'
    assert 'SSH' in dict(controller.completion(
        'set firewall zone USERS intra-zone ipv4-policy ', session)['candidates'])
    assert 'LOCAL' in dict(controller.completion(
        'set firewall zone-policy from-zone USERS to-zone ', session)['candidates'])

    for command in ('delete firewall zone LOCAL', 'delete firewall ipv4 name SSH',
                    'delete interfaces dummy dum998'):
        with pytest.raises(RouterError, match='referenced'):
            controller.execute(command, session)

    with pytest.raises(ValidationError):
        controller.execute('set firewall zone USERS default-action reject', session)


def test_ipv4_dispatch_comments_and_position_before_hook_default():
    text = rendered(configuration())
    assert '"eth1" . "eth0" comment "USERS to WAN" : jump ipv4_name_WEB' in text
    assert '"eth0" . "eth1" comment "WAN to USERS" : drop' in text
    assert '"eth1" . "eth2" comment "USERS to USERS" : accept' in text
    assert '"eth0" . "eth0" comment "WAN to WAN" : drop' in text
    assert '"eth1" comment "USERS" : jump ipv4_name_SSH' in text
    assert '"eth1" comment "USERS" : jump ipv4_name_OUT' in text
    body = text.split('chain ipv4_forward {')[1].split('\n    }')[0]
    assert body.index('192.0.2.10') < body.index('vmap @ipv4_zone_forward') < body.index('default|')
    assert text.count('meta iifname vmap @ipv4_zone_input') == 1
    assert text.count('meta sdifname vmap @ipv4_zone_input') == 1
    assert text.count('    counter;') == 6
    assert 'set zone_' not in text and 'zone_reject' not in text


def test_ipv6_independent_policies_and_intra_zone_fallback():
    config = configuration()
    config['firewall']['ipv6'] = {'name': {'INTERNAL': {'default-action': 'drop'}}}
    config['firewall']['zone']['USERS']['intra-zone'] = {
        'default-action': 'accept', 'ipv6-policy': 'INTERNAL'}
    text = rendered(config)
    assert '"eth1" . "eth2" comment "USERS to USERS" : jump ipv6_name_INTERNAL' in text
    assert '"eth1" . "eth2" comment "USERS to USERS" : accept' in text
    ipv6 = zones.entries(Schema.bundled().defaults(config)['firewall'], 'ipv6', 'forward')
    assert (('eth1', 'eth0'), 'drop', 'USERS to WAN') in ipv6


def test_zones_alone_create_family_chains_without_writing_defaults():
    config = {'firewall': {'zone': {'USERS': {'interface': ['eth1']}}}}
    text = rendered(config)
    assert 'chain ipv4_forward {' in text and 'chain ipv6_forward {' in text
    assert 'chain input {' not in text and 'chain output {' not in text
    assert 'default-action accept' in text
    assert config == {'firewall': {'zone': {'USERS': {'interface': ['eth1']}}}}


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_output_vrf_bypass_follows_rules_and_precedes_zone_dispatch(family):
    config = configuration()
    config['firewall'].setdefault(family, {})['output'] = {
        'filter': {'default-action': 'drop', 'rule': {'10': {'action': 'drop'}}},
        'raw': {'rule': {'10': {'action': 'accept'}}},
    }
    text = rendered(config)
    body = text.split(f'chain {family}_output {{')[1].split('\n    }')[0]

    assert 'meta oifkind "vrf" counter accept comment "vrf-bypass"' in body
    assert (body.index('comment "10|') < body.index('vrf-bypass')
            < body.index(f'vmap @{family}_zone_output') < body.index('default|'))
    assert text.count('comment "vrf-bypass"') == 2
    assert all('vrf-bypass' not in line for line in zones.dispatch(config['firewall'], family, 'input'))
    assert all('vrf-bypass' not in line for line in zones.dispatch(config['firewall'], family, 'forward'))

    # Removing the local zone must also remove the bypass from ordinary output chains.
    del config['firewall']['zone']['LOCAL']
    del config['firewall']['zone-policy']
    assert 'vrf-bypass' not in rendered(config)


def test_output_vrf_bypass_is_readable_in_operational_output(monkeypatch, capsys):
    document = {'nftables': [{'rule': {
        'family': 'inet', 'table': 'nvyr_filter', 'chain': 'ipv4_output',
        'comment': 'vrf-bypass', 'expr': [
            {'match': {'op': '==', 'left': {'meta': {'key': 'oifkind'}}, 'right': 'vrf'}},
            {'counter': {'packets': 2, 'bytes': 80}}, {'accept': None},
        ],
    }}]}
    table = normalize(document)['tables']['inet']['nvyr_filter']
    rule = table['chains']['ipv4_output']['rules'][0]
    assert rule['outbound-interface-kind'] == 'vrf'
    assert 'unsupported' not in rule
    monkeypatch.setattr(operational, '_load_table', lambda *, failsafe=False: table)

    operational.show(family='ipv4', hook='output')
    output = capsys.readouterr().out
    assert 'vrf-bypass' in output and 'accept' in output
    assert '[incomplete]' not in output


@pytest.mark.parametrize('change, message', [
    ({'EMPTY': {}}, 'at least one interface'),
    ({'SECOND': {'local-zone': True}}, 'only one local-zone'),
    ({'SECOND': {'interface': ['eth1']}}, 'already belongs'),
    ({'LOCAL': {'local-zone': True, 'interface': ['eth9']}}, 'cannot have'),
    ({'LOCAL': {'local-zone': True, 'intra-zone': {'default-action': 'drop'}}}, 'cannot have'),
])
def test_invalid_zone_membership(change, message):
    config = configuration()
    config['firewall']['zone'].update(change)
    with pytest.raises(ValidationError, match=message):
        rendered(config)


def test_vrf_master_rejected_but_members_can_span_zones_and_vrfs():
    config = configuration()
    config['vrf'] = {'name': {'BLUE': {'table': '100'}, 'RED': {'table': '101'}}}
    config['interfaces'] = {'ethernet': {'eth1': {'vrf': 'BLUE'}, 'eth2': {'vrf': 'RED'},
                                        'eth0': {'vrf': 'BLUE'}}}
    rendered(config)
    config['firewall']['zone']['USERS']['interface'].append('BLUE')
    with pytest.raises(ValidationError, match='VRF master'):
        rendered(config)


def test_later_vrf_creation_cannot_claim_an_existing_zone_interface(controller, engine, session):
    controller.execute('set firewall zone USERS interface BLUE', session)
    assert engine.commit(session)['results']['firewall']['success']
    controller.execute('set vrf name BLUE table 100', session)
    result = engine.commit(session)
    assert not result['results']['vrf']['success']
    assert 'cannot belong' in result['results']['vrf']['error']


@pytest.mark.parametrize('source,destination,policies,message', [
    ('UNKNOWN', 'WAN', {'ipv4-policy': 'WEB'}, 'source zone'),
    ('USERS', 'UNKNOWN', {'ipv4-policy': 'WEB'}, 'destination zone'),
    ('USERS', 'USERS', {'ipv4-policy': 'WEB'}, 'intra-zone'),
    ('USERS', 'WAN', {}, 'is required'),
    ('USERS', 'WAN', {'ipv6-policy': 'WEB'}, 'ipv6 policy'),
])
def test_invalid_pairings(source, destination, policies, message):
    config = configuration()
    config['firewall']['zone-policy'] = {'from-zone': {source: {'to-zone': {destination: policies}}}}
    with pytest.raises(ValidationError, match=message):
        rendered(config)


def test_zone_policy_nested_hooks_and_vrf_shared_chain_restriction():
    config = configuration()
    config['firewall']['ipv4']['name']['SSH']['rule'] = {
        '10': {'action': 'jump', 'jump-target': 'DEEP'}}
    config['firewall']['ipv4']['name']['DEEP'] = {'rule': {
        '10': {'outbound-link-group': ['1'], 'action': 'accept'}}}
    with pytest.raises(ValidationError, match='unavailable in input'):
        rendered(config)

    config['firewall']['ipv4']['name']['DEEP']['rule']['10'] = {
        'inbound-interface': ['eth1'], 'action': 'accept'}
    config['interfaces'] = {'ethernet': {'eth1': {'vrf': 'BLUE'}}}
    config['vrf'] = {'name': {'BLUE': {'table': '100'}}}
    assert 'meta sdifname { "eth1" }' in rendered(config)
    config['firewall']['zone-policy']['from-zone']['USERS']['to-zone']['WAN']['ipv4-policy'] = 'SSH'
    with pytest.raises(ValidationError, match='cannot be shared'):
        rendered(config)


def test_policy_edit_rebuilds_consuming_map_and_hook_only():
    before = configuration()
    after = deepcopy(before)
    after['firewall']['ipv4']['name']['WEB']['default-action'] = 'drop'
    text = rendered(after, before)
    assert destroyed(text) == {'ipv4_name_WEB', 'ipv4_forward', 'forward'}
    assert 'destroy map inet nvyr_filter ipv4_zone_forward' in text
    assert 'destroy map inet nvyr_filter ipv4_zone_input' not in text


def test_membership_removal_and_full_zone_removal_release_maps():
    before = configuration()
    after = deepcopy(before)
    after['firewall']['zone']['USERS']['interface'].remove('eth2')
    text = rendered(after, before)
    assert 'destroy map inet nvyr_filter ipv6_zone_forward' in text
    assert '"eth2"' not in text

    del after['firewall']['zone']
    del after['firewall']['zone-policy']
    text = rendered(after, before)
    assert 'destroy map inet nvyr_filter ipv4_zone_input' in text
    assert 'vmap @ipv4_zone_' not in text
    assert 'chain ipv4_forward {' in text
    assert 'chain ipv6_forward {' not in text


def test_nested_policy_edit_rebuilds_zone_map_and_callers():
    before = configuration()
    chains = before['firewall']['ipv4']['name']
    chains['WEB']['rule'] = {'10': {'action': 'jump', 'jump-target': 'DEEP'}}
    chains['DEEP'] = {'default-action': 'accept'}
    after = deepcopy(before)
    after['firewall']['ipv4']['name']['DEEP']['default-action'] = 'drop'

    text = rendered(after, before)

    assert destroyed(text) == {'ipv4_name_DEEP', 'ipv4_name_WEB', 'ipv4_forward', 'forward'}
    assert 'destroy map inet nvyr_filter ipv4_zone_forward' in text
    assert 'destroy map inet nvyr_filter ipv4_zone_output' not in text


def test_zone_map_normalization_and_operational_display(monkeypatch, capsys):
    document = {'nftables': [{'map': {
        'family': 'inet', 'table': 'nvyr_filter', 'name': 'ipv4_zone_forward',
        'type': ['ifname', 'ifname'], 'map': 'verdict', 'stmt': [{'counter': None}],
        'elem': [[{'elem': {'val': {'concat': ['eth1', 'eth0']}, 'comment': 'USERS to WAN',
                           'counter': {'packets': 123, 'bytes': 45678}}},
                  {'jump': {'target': 'ipv4_name_WEB'}}]],
    }}]}
    table = normalize(document)['tables']['inet']['nvyr_filter']
    monkeypatch.setattr(operational, '_load_table', lambda *, failsafe=False: table)
    operational.show(section='zone')
    output = capsys.readouterr().out
    assert 'IPv4 zone forward' in output and 'USERS to WAN' in output and 'jump WEB' in output
    assert 'Inbound interface' in output and 'Outbound interface' in output
    assert 'Packets' in output and 'Bytes' in output
    assert '123' in output and '45678' in output

    operational.show(section='zone', detail=True)
    detail = capsys.readouterr().out
    assert 'Packets' in detail and '123' in detail
    assert 'Bytes' in detail and '45678' in detail


@pytest.mark.parametrize('family', ['ipv4', 'ipv6'])
def test_zone_display_filters_by_source_including_local(monkeypatch, capsys, family):
    config = configuration()
    documents = []
    for hook in zones.active_hooks(config['firewall']):
        elements = []
        for key, verdict, comment in zones.entries(config['firewall'], family, hook):
            value = {'concat': list(key)} if len(key) > 1 else key[0]
            elements.append([{'elem': {'val': value, 'comment': comment}}, {'accept': None}])
        documents.append({'map': {
            'family': 'inet', 'table': 'nvyr_filter', 'name': zones.map_name(family, hook),
            'type': ['ifname', 'ifname'] if hook == 'forward' else 'ifname',
            'map': 'verdict', 'elem': elements,
        }})
    table = normalize({'nftables': documents}, configuration=config)['tables']['inet']['nvyr_filter']
    other_family = 'ipv6' if family == 'ipv4' else 'ipv4'
    for name, mapping in list(table['maps'].items()):
        other = deepcopy(mapping)
        other['name'] = name.replace(family, other_family, 1)
        table['maps'][other['name']] = other
    monkeypatch.setattr(operational, '_load_table', lambda *, failsafe=False: table)

    operational.show(section='zone', family=family, zone_name='USERS')
    output = capsys.readouterr().out
    assert 'USERS to WAN' in output and 'USERS to USERS' in output
    assert 'WAN to USERS' not in output and 'zone output' not in output
    assert 'zone input (from USERS)' in output
    assert other_family.replace('ip', 'IP') not in output

    operational.show(section='zone', family=family, zone_name='LOCAL', detail=True)
    output = capsys.readouterr().out
    assert 'zone output (from LOCAL)' in output
    assert 'zone input' not in output and 'zone forward' not in output

    with pytest.raises(operational.OperationalError, match='not installed'):
        operational.show(section='zone', zone_name='MISSING')
