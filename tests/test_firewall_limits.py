"""Rate buckets and connection counts use independent, typed per-rule keys."""

from copy import deepcopy

import pytest

from nvyr.errors import RouterError
from nvyr.helpers.validators import limit_rate, limit_burst
from tests.test_firewall_maps import rendered
from tests.test_nftables_lifecycle import destroyed, nested_tree


def limit_tree(options=None, kind='limit', family='ipv4', hook='forward', stage='filter'):
    if options is None:
        options = {'rate': {'packets': '10/s'}, 'burst': {'packets': '20'}, 'over': True}
    rule = {'action': 'drop', 'counter': {}}
    if kind == 'connection-limit':
        rule['connection'] = {'limit': options}
    else:
        rule['limit'] = options
    return {'firewall': {family: {hook: {stage: {'rule': {'10': rule}}}}}}


@pytest.mark.parametrize('unit,value,valid', [
    ('packets', '10/s', True), ('packets', '60/m', True),
    ('packets', '1/h', True), ('packets', '2/d', True),
    ('packets', '0/s', False), ('packets', '1/w', False),
    ('packets', '1.5/s', False), ('packets', '1mbps', False),
    ('packets', '1/s drop', False), ('packets', '9' * 5000 + '/s', False),
    ('packets', '4294967295/s', True), ('packets', '4294967296/s', False),
    ('packets', '1k/s', False), ('packets', '1m/s', False), ('packets', '1g/s', False),
    ('bytes', '1024/s', True), ('bytes', '64k/m', True), ('bytes', '1m/s', True),
    ('bytes', '1g/s', True), ('bytes', '17g/s', True), ('bytes', '18g/s', False),
    ('bytes', '18446744073/s', True), ('bytes', '18446744074/s', False),
    ('bytes', '1g/m', False), ('bytes', '0/s', False), ('bytes', '1.5m/s', False),
    ('bytes', '1t/s', False), ('bytes', '1M/s', False), ('bytes', '1mbytes/s', False),
    ('bytes', '1m/second', False), ('bytes', '9' * 5000 + '/s', False),
])
def test_rate_value_validation(unit, value, valid):
    assert limit_rate(value, unit=unit) is valid


@pytest.mark.parametrize('unit,value,valid', [
    ('packets', '20', True), ('packets', '0', False), ('packets', '-1', False),
    ('packets', '1k', False), ('packets', '1m', False), ('packets', '1g', False),
    ('bytes', '64k', True), ('bytes', '1m', True), ('bytes', '0', True),
    ('bytes', '1g', True), ('bytes', '3g', True), ('bytes', '4g', False),
    ('bytes', '4294967295', True), ('bytes', '4294967296', False),
    ('bytes', '-1', False), ('bytes', '1bytes;drop', False), ('bytes', '4096m', False),
    ('bytes', '64kbytes', False), ('bytes', '1.5k', False),
])
def test_burst_value_validation(unit, value, valid):
    assert limit_burst(value, unit=unit) is valid


def test_shared_limits_precede_counters_and_do_not_allocate_sets():
    text = rendered(limit_tree())

    assert 'limit rate over 10/second burst 20 packets counter drop' in text
    assert 'set rule_limit_' not in text

    text = rendered(limit_tree({'rate': {'bytes': '1m/s'}, 'burst': {'bytes': '64k'}}))
    assert 'limit rate 1048576 bytes/second burst 65536 bytes counter drop' in text

    text = rendered(limit_tree({'over': '5'}, 'connection-limit'))
    assert 'ct count over 5 counter drop' in text


@pytest.mark.parametrize('value,amount', [('1024', 1024), ('64k', 65536), ('1m', 1048576), ('1g', 1073741824)])
def test_short_byte_units_render_as_native_bytes(value, amount):
    text = rendered(limit_tree({'rate': {'bytes': value + '/s'}, 'burst': {'bytes': value}}))

    assert f'limit rate {amount} bytes/second burst {amount} bytes' in text


@pytest.mark.parametrize('short,full', [('s', 'second'), ('m', 'minute'), ('h', 'hour'), ('d', 'day')])
def test_short_periods_render_native_units(short, full):
    text = rendered(limit_tree({'rate': {'bytes': '1/' + short}}))

    assert f'limit rate 1 bytes/{full}' in text


@pytest.mark.parametrize('family,datatype,expression', [
    ('ipv4', 'ipv4_addr', 'ip'), ('ipv6', 'ipv6_addr', 'ip6'),
])
def test_concatenated_rate_and_connection_keys(family, datatype, expression):
    options = {'rate': {'packets': '6/m'}, 'per': 'source-address,destination-address,destination-port'}
    tree = limit_tree(options, family=family)
    text = rendered(tree)

    assert f'type {datatype} . {datatype} . inet_service;' in text
    assert 'size 65536;' in text and 'timeout 1m;' in text
    assert f'{expression} saddr . {expression} daddr . th dport limit rate 6/minute' in text
    assert 'meta l4proto { dccp, sctp, tcp, udp, udplite } update @rule_limit_' in text

    text = rendered(limit_tree({'over': '5', 'per': 'source-address'}, 'connection-limit', family))
    assert f'add @rule_connection_limit_{family}_forward_10 {{ {expression} saddr ct count over 5 }}' in text
    assert 'timeout' not in text


@pytest.mark.parametrize('kind,options,error', [
    ('limit', {}, 'requires rate'),
    ('connection-limit', {}, 'requires over'),
    ('limit', {'rate': {}}, 'exactly one'),
    ('limit', {'rate': {'packets': '10/s', 'bytes': '1m/s'}}, 'exactly one'),
    ('limit', {'rate': {'packets': '10/s'}, 'burst': {}}, 'same packet or byte'),
    ('limit', {'rate': {'packets': '10/s'}, 'burst': {'packets': '20', 'bytes': '64k'}}, 'same packet or byte'),
    ('limit', {'rate': {'packets': '10/s'}, 'burst': {'bytes': '1k'}}, 'same packet or byte'),
    ('limit', {'rate': {'bytes': '1k/s'}, 'burst': {'packets': '20'}}, 'same packet or byte'),
    ('limit', {'rate': {'packets': '1/s'}, 'size': '20'}, 'require per'),
    ('limit', {'rate': {'packets': '1/s'}, 'per': 'source-address,source-address'}, 'must not repeat'),
    ('limit', {'rate': {'packets': '1/m'}, 'per': 'source-address', 'timeout': '1s'}, 'refill time'),
    ('limit', {'rate': {'packets': '1/d'}, 'burst': {'packets': '4294967295'}}, 'bucket capacity'),
    ('limit', {'rate': {'bytes': '17g/s'}, 'burst': {'bytes': '1g'}}, 'bucket capacity'),
    ('limit', {'rate': {'bytes': '1/d'}, 'burst': {'bytes': '1m'}}, 'bucket capacity'),
    ('limit', {'rate': {'packets': '1/s'}, 'per': 'source-address,destination-address,source-port,destination-port,protocol,packet-mark'}, 'maximum 5'),
])
def test_limit_relationships_are_checked(kind, options, error):
    with pytest.raises(RouterError, match=error):
        rendered(limit_tree(options, kind))


def test_aligned_ipv6_key_limit():
    options = {'rate': {'packets': '1/s'}, 'per': 'source-address,destination-address,inbound-interface,outbound-interface,destination-port'}
    with pytest.raises(RouterError, match='66 bytes'):
        rendered(limit_tree(options, family='ipv6'))


@pytest.mark.parametrize('family,length,mask', [
    ('ipv4', '0', '0.0.0.0'), ('ipv4', '2', '192.0.0.0'),
    ('ipv4', '24', '255.255.255.0'), ('ipv4', '32', '255.255.255.255'),
    ('ipv6', '64', 'ffff:ffff:ffff:ffff::'),
    ('ipv6', '128', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'),
])
@pytest.mark.parametrize('kind', ['limit', 'connection-limit'])
def test_subnet_prefixes_compose_with_joined_keys(family, length, mask, kind):
    options = {'per': 'source-address,destination-port', 'source-prefix-length': length}
    options.update({'rate': {'packets': '10/s'}} if kind == 'limit' else {'over': '5'})
    text = rendered(limit_tree(options, kind, family))
    expression = 'ip' if family == 'ipv4' else 'ip6'
    assert f'({expression} saddr & {mask}) . th dport' in text


@pytest.mark.parametrize('options,error', [
    ({'per': 'destination-port', 'source-prefix-length': '24'}, 'requires per source-address'),
    ({'per': 'source-address', 'destination-prefix-length': '24'}, 'requires per destination-address'),
    ({'per': 'source-address', 'source-prefix-length': '33'}, 'between 0 and 32'),
])
def test_subnet_masks_require_the_correct_key_and_family(options, error):
    with pytest.raises(RouterError, match=error):
        rendered(limit_tree({'rate': {'packets': '10/s'}, **options}))


@pytest.mark.parametrize('hook,stage,kind,options,error', [
    ('output', 'filter', 'limit', {'rate': {'packets': '1/s'}, 'per': 'inbound-interface'}, 'inbound-interface'),
    ('input', 'filter', 'limit', {'rate': {'packets': '1/s'}, 'per': 'outbound-interface'}, 'outbound-interface'),
    ('output', 'filter', 'limit', {'rate': {'packets': '1/s'}, 'per': 'source-mac'}, 'MAC keys'),
    ('prerouting', 'raw', 'connection-limit', {'over': '5'}, 'unavailable in raw'),
    ('output', 'raw', 'limit', {'rate': {'packets': '1/s'}, 'per': 'connection-mark'}, 'unavailable in raw'),
])
def test_hook_constraints_include_nested_jumps(hook, stage, kind, options, error):
    with pytest.raises(RouterError, match=error):
        rendered(limit_tree(options, kind, hook=hook, stage=stage))

    tree = {'firewall': {'ipv4': {
        hook: {stage: {'rule': {'10': {'action': 'jump', 'jump-target': 'FIRST'}}}},
        'name': {
            'FIRST': {'rule': {'10': {'action': 'jump', 'jump-target': 'SECOND'}}},
            'SECOND': limit_tree(options, kind)['firewall']['ipv4']['forward']['filter'],
        },
    }}}
    with pytest.raises(RouterError, match=error):
        rendered(tree)


@pytest.mark.parametrize('kind', ['limit', 'connection-limit'])
def test_private_sets_follow_whole_chain_lifecycle(kind):
    before = nested_tree()
    rule = before['firewall']['ipv4']['name']['BOTTOM']['rule']['10']
    if kind == 'limit':
        rule['limit'] = {'rate': {'packets': '10/s'}, 'per': 'source-address'}
    else:
        rule['connection'] = {'limit': {'over': '5', 'per': 'source-address'}}
    private = f'rule_{kind.replace("-", "_")}_ipv4_name_BOTTOM_10'

    assert f'set {private}' in rendered(before)
    assert not destroyed(rendered(before, before), 'set')

    after = deepcopy(before)
    after['firewall']['ipv4']['name']['UNRELATED']['rule']['10']['description'] = 'Unrelated'
    assert private not in rendered(after, before)

    after = deepcopy(before)
    after['firewall']['group']['address-group']['ipv4']['A']['address'] = ['192.0.2.2']
    text = rendered(after, before)
    assert private in destroyed(text, 'set')
    assert f'set {private} {{' in text
    assert text.index('flush chain') < text.index(f'destroy set inet nvyr_filter {private}')

    after = deepcopy(before)
    rule = after['firewall']['ipv4']['name']['BOTTOM']['rule']['10']
    if kind == 'limit':
        del rule['limit']
    else:
        # Removing the only connection condition also requires removing its node.
        del rule['connection']
    text = rendered(after, before)
    assert private in destroyed(text, 'set')
    assert f'set {private} {{' not in text


def test_user_groups_named_limit_are_not_private_meter_sets():
    tree = limit_tree({'rate': {'packets': '10/s'}, 'per': 'source-address'})
    tree['firewall']['group'] = {'address-group': {'ipv4': {
        'limit': {'address': ['192.0.2.1']},
        'connection-limit': {'address': ['192.0.2.2']},
    }}}
    text = rendered(tree)
    assert 'set ipv4_address_group_limit {' in text
    assert 'set ipv4_address_group_connection-limit {' in text
    assert 'set rule_limit_ipv4_forward_10 {' in text


def test_cli_joinable_per_completion_roundtrip_and_single_owner(controller, engine, session):
    controller.execute('set firewall ipv4 input filter rule 10 action drop limit rate packets 10/s burst packets 20 over', session)
    command = 'set firewall ipv4 input filter rule 10 limit per source-address and '
    candidates = dict(controller.completion(command, session, explicit=True)['candidates'])
    assert 'destination-address' in candidates and 'destination-port' in candidates
    controller.execute(command + 'destination-address and destination-port', session)
    controller.execute('set firewall ipv4 input filter rule 10 limit source-prefix-length 24', session)

    rule = engine.view(session)['firewall']['ipv4']['input']['filter']['rule']['10']
    assert rule['limit']['per'] == 'source-address,destination-address,destination-port'
    assert engine.commit(session)['results']['firewall']['success']
    controller.execute('delete firewall ipv4 input filter rule 10 limit source-prefix-length', session)
    controller.execute('delete firewall ipv4 input filter rule 10 limit per', session)
    assert 'per' not in engine.view(session)['firewall']['ipv4']['input']['filter']['rule']['10']['limit']


def test_connection_limit_nested_cli_and_packet_keys(controller, engine, session):
    prefix = 'set firewall ipv4 input filter rule 10 '
    candidates = dict(controller.completion(prefix, session, explicit=True)['candidates'])
    assert 'connection-limit' not in candidates
    assert 'limit' in dict(controller.completion(prefix + 'connection ', session, explicit=True)['candidates'])

    controller.execute(prefix + 'action drop connection state new limit over 5 per source-address', session)
    rule = engine.view(session)['firewall']['ipv4']['input']['filter']['rule']['10']
    assert rule['connection'] == {'state': ['new'], 'limit': {'over': '5', 'per': 'source-address'}}

    text = rendered(engine.view(session))
    assert 'add @rule_connection_limit_ipv4_input_10 { ip saddr ct count over 5 }' in text
    assert 'ct original ip saddr' not in text

    # The old flat command is removed rather than retained as an alias.
    with pytest.raises(RouterError):
        controller.execute(prefix + 'connection-limit over 5', session)

    controller.execute('delete firewall ipv4 input filter rule 10 connection limit', session)
    rule = engine.view(session)['firewall']['ipv4']['input']['filter']['rule']['10']
    assert rule['connection'] == {'state': ['new']}


def test_cli_byte_nodes_completion_and_replacement(controller, engine, session):
    command = 'set firewall ipv4 forward filter rule 10 limit '
    for node in ('rate', 'burst'):
        assert set(dict(controller.completion(command + node + ' ', session)['candidates'])) == {'bytes', 'packets'}

    controller.execute('set firewall ipv4 forward filter rule 10 action drop', session)
    controller.execute(command + 'rate bytes 1g/s burst bytes 64k over', session)
    options = engine.view(session)['firewall']['ipv4']['forward']['filter']['rule']['10']['limit']
    assert options == {'rate': {'bytes': '1g/s'}, 'burst': {'bytes': '64k'}, 'over': True}
    result = engine.commit(session)
    assert result['results']['firewall']['success'], result

    controller.execute('delete firewall ipv4 forward filter rule 10 limit rate bytes', session)
    controller.execute('delete firewall ipv4 forward filter rule 10 limit burst bytes', session)
    controller.execute(command + 'rate packets 10/s burst packets 20', session)
    result = engine.commit(session)
    assert result['results']['firewall']['success'], result


@pytest.mark.parametrize('suffix', [
    'rate 10/second', 'rate packets 10/second', 'rate packets 1k/s',
    'rate bytes 64kbytes/s', 'rate bytes 1.5g/s', 'rate bytes 18g/s',
    'burst 20', 'burst packets 1k', 'burst bytes 4g',
])
def test_cli_rejects_invalid_rate_and_burst_values(controller, session, suffix):
    with pytest.raises(RouterError):
        controller.execute('set firewall ipv4 forward filter rule 10 limit ' + suffix, session)

    assert not session.mutations
