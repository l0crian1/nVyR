"""Real packet membership and atomic lifecycle in isolated disposable namespaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def test_sets_maps_and_explicit_matches_all_constrain_real_packets():
    isolated('''
run('ip', 'link', 'set', 'lo', 'up')
for family, version, address in [('ipv4', '-4', '127.0.0.1'), ('ipv6', '-6', '::1')]:
    protocol = 'icmp' if family == 'ipv4' else 'ipv6-icmp'
    group = {'match': {'protocol': True, 'icmp-type': True}, 'description': 'Echo requests',
             'entry': {'ECHO': {'protocol': protocol, 'icmp-type': 'echo-request', 'description': 'Probe'}}}
    mapping = {'match': {'destination-address': True}, 'result-type': 'verdict',
               'entry': {'LOCAL': {'destination-address': address, 'result': {'action': 'drop'}}}}
    rule = {'match-group': 'G', 'map': 'M', 'outbound-interface': ['lo'], 'counter': {}}
    tree = {'firewall': {'global-options': {'counter': True, 'last-used': True},
                        'group': {'match-group': {family: {'G': group}}, 'map': {family: {'M': mapping}}},
                        family: {'output': {'filter': {'rule': {'10': rule}}}}}}
    def ping():
        return subprocess.run(['ping', version, '-c', '1', '-W', '1', address], capture_output=True).returncode

    # Both lookups and the explicit interface constraint must match before the drop.
    apply(tree)
    assert ping() != 0
    listing = run('nft', 'list', 'set', 'inet', 'nvyr_filter', family + '_match_group_G')
    assert 'ECHO|Probe' in listing and 'Echo requests' in listing
    assert 'counter packets 1' in listing and 'last used' in listing, listing

    rule['outbound-interface'] = ['missing0']
    apply(tree)
    assert ping() == 0
    rule['outbound-interface'] = ['lo']
    group['entry']['ECHO']['icmp-type'] = 'destination-unreachable'
    apply(tree)
    assert ping() == 0

    # Match-groups also work with an ordinary verdict, without a map.
    group['entry']['ECHO']['icmp-type'] = 'echo-request'
    del rule['map']
    rule['action'] = 'drop'
    apply(tree)
    assert ping() != 0

    # A failed kernel transaction cannot replace the installed group or its rules.
    before = run('nft', '-s', 'list', 'ruleset')
    bad = deepcopy(tree)
    bad['firewall'][family]['name'] = {'LOOP': {'rule': {'1': {'action': 'jump', 'jump-target': 'LOOP'}}}}
    bad['firewall'][family]['output']['filter']['rule']['10'].update(action='jump', **{'jump-target': 'LOOP'})
    try:
        apply(bad)
        raise AssertionError('Cyclic jump unexpectedly loaded')
    except RouterError:
        pass
    assert run('nft', '-s', 'list', 'ruleset') == before

    # Clearing an entry leaves an empty set that matches no packets.
    group['entry'].clear()
    apply(tree)
    assert ping() == 0

# Restart recovery must remove owned orphan sets even without previous config.
previous = {}
apply({}, recovery=True)
assert Manager().match_groups() == [] and Manager().maps() == []
''')


def test_set_intervals_and_exact_connection_status_membership():
    isolated('''
run('ip', 'link', 'set', 'lo', 'up')
for family, address in [('ipv4', '127.0.0.0/8'), ('ipv6', '::1/128')]:
    group = {'match': {'source-address': True, 'protocol': True, 'destination-port': True},
             'counter': True, 'last-used': True,
             'entry': {'DNS': {'source-address': address, 'protocol': 'udp', 'destination-port': '50-60'}}}
    tree = {'firewall': {'group': {'match-group': {family: {'G': group}}},
                        family: {'output': {'filter': {'rule': {'10': {'match-group': 'G', 'action': 'accept'}}}}}}}
    apply(tree)
    assert 'flags interval' in run('nft', 'list', 'set', 'inet', 'nvyr_filter', family + '_match_group_G')

# Status groups are exact set elements, including combined flags.
group = {'match': {'connection': {'status': True}},
         'entry': {'NAT': {'connection': {'status': 'snat,dnat'}}}}
tree = {'firewall': {'group': {'match-group': {'ipv4': {'G': group}}},
                    'ipv4': {'output': {'filter': {'rule': {'10': {'match-group': 'G', 'action': 'drop'}}}}}}}
apply(tree)
listing = run('nft', '-j', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_output')
rule = next(item['rule'] for item in json.loads(listing)['nftables']
            if item.get('rule', {}).get('comment') == '10|')
expressions = rule['expr']
match = next(item['match'] for item in expressions if 'match' in item)
assert match['op'] == '==' and match['right'] == '@ipv4_match_group_G', match
run('ping', '-4', '-c', '1', '-W', '1', '127.0.0.1')
apply({})
''')


def test_match_group_commit_confirm_restart_and_deletion():
    isolated('''
from nvyr.controller import Controller
from nvyr.engine import Engine
from nvyr.storage import Store
from tests.lifecycle import LifecycleStub, RecordingModule

modules = {owner: LifecycleStub() for owner in schema.owners}
modules['firewall'] = RecordingModule(firewall)
now = [100.0]
engine = Engine(schema, modules, Store(directory), clock=lambda: now[0])
session = engine.open('test', 'namespace')
controller = Controller(engine)

def execute(command):
    return controller.execute(command, session)

def members():
    return run('nft', '-s', 'list', 'set', 'inet', 'nvyr_filter', 'ipv4_match_group_G')

execute('set firewall group match-group ipv4 G match source-address')
execute('set firewall group match-group ipv4 G entry A source-address 192.0.2.1')
execute('set firewall ipv4 forward filter rule 10 match-group G action accept')
assert engine.commit(session)['results']['firewall']['success']
assert '192.0.2.1' in members()

execute('set firewall group match-group ipv4 G entry A source-address 192.0.2.2')
assert engine.commit(session, minutes=1, confirmed_minutes=1)['results']['firewall']['success']
assert '192.0.2.2' in members()
now[0] = 161
engine.tick()
assert '192.0.2.1' in members() and '192.0.2.2' not in members()

engine.save(session)
run('nft', 'flush', 'ruleset')
engine = Engine(schema, modules, Store(directory), clock=lambda: now[0])
assert '192.0.2.1' in members()
session = engine.open('test', 'namespace')
controller = Controller(engine)
execute('delete firewall')
assert engine.commit(session)['results']['firewall']['success']
assert Manager().match_groups() == []
''')
