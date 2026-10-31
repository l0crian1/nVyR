"""Opt-in NAT tests in fresh network namespaces in a disposable container."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')

COMMON = '''
import json, socket, subprocess, sys, tempfile, time
from pathlib import Path
from nvyr.config_scripts import firewall
from tests.lifecycle import firewall_context
from copy import deepcopy
from nvyr.helpers.nftables import Manager
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree
directory = Path(tempfile.mkdtemp(prefix='nvyr-nat-live-'))
def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True).stdout
def snapshot():
    return json.loads(run('nft', '-j', 'list', 'ruleset'))['nftables'][1:]
previous = {}

def apply(config, section='nat'):
    global previous
    schema = Schema.bundled()
    tree = deepcopy(previous)
    tree[section] = config
    schema.validate_configuration(tree)
    effective = ReadOnlyTree(schema.defaults(tree))
    before = ReadOnlyTree(schema.defaults(previous))
    context = firewall_context(effective, before, 'firewall', ('firewall',), previous_effective=before)
    firewall.verify(effective, context)
    text = firewall.generate(effective, context)
    Manager().apply(text, directory)
    previous = deepcopy(tree)
    return text

'''


def isolated(script):
    assert Path('/.dockerenv').exists() and os.geteuid() == 0

    result = subprocess.run(['unshare', '-n', sys.executable, '-c', COMMON + script],
                            text=True, capture_output=True, timeout=90)

    assert result.returncode == 0, result.stdout + result.stderr


def test_real_nat_syntax_family_dispatch_and_filter_coexistence():
    isolated('''
from nvyr.errors import RouterError
run('nft', 'add', 'table', 'inet', 'unrelated')
filter_config = {'ipv4': {'prerouting': {'raw': {'rule': {'1': {'action': 'continue'}}}},
                         'forward': {'filter': {'rule': {'10': {'action': 'accept'}}}}}}
apply(filter_config, 'firewall')
filter_before = [item for item in snapshot() if 'chain' in item]
rules = {}
number = 1
for address in ['203.0.113.1', '203.0.113.0/24', '203.0.113.1-203.0.113.10', None]:
    for mode in ['default', 'random', 'fully-random']:
        translation = {'port': '8000-8100', 'port-mapping': mode}
        if address:
            translation.update(address=address, persistent=True)
        rules[str(number)] = {'protocol': ['tcp', 'udp'], 'destination-port': ['80', '100-200'],
                              'translation': translation, 'log': {}}
        number += 1
config = {'source': {'rule': dict(rules, **{'90': {'translation': {'address': 'masquerade'}},
          '91': {'translation': {'address': 'masquerade', 'port': '9000-9100',
                                'persistent': True, 'port-mapping': 'random'}, 'protocol':['tcp','udp']},
          '92': {'exclude': True, 'log': {}}, '93': {'disable': True}})},
          'destination': {'rule': rules}}
for direction, options in config.items():
    field = 'outbound-interface' if direction == 'source' else 'inbound-interface'
    options['rule'] = deepcopy(options['rule'])
    for rule in options['rule'].values():
        rule[field] = ['eth0']
text = apply(config)
apply(config)
assert {item['chain']['name'] for item in filter_before} <= {item['chain']['name'] for item in snapshot() if 'chain' in item}
chains = {item['chain']['name']: item['chain'] for item in snapshot() if 'chain' in item}
assert chains['nat_prerouting']['hook'] == 'prerouting' and chains['nat_prerouting']['prio'] == -100
assert chains['nat_postrouting']['hook'] == 'postrouting' and chains['nat_postrouting']['prio'] == 100
assert 'hook' not in chains['ipv4_nat_prerouting']
assert not any('ipv6_nat' in name for name in chains)
nat_before = [item for item in snapshot() if ('nat_' in item.get('chain', {}).get('name', '')
              or 'nat_' in item.get('rule', {}).get('chain', ''))]
apply(filter_config, 'firewall')
assert len([item for item in snapshot() if 'nat_' in item.get('rule', {}).get('chain', '')]) == len([item for item in nat_before if 'rule' in item])
before = snapshot()
last_good = (directory / 'firewall.nft').read_text()
try:
    Manager().apply(text + '\\nadd rule inet nvyr_filter ipv4_nat_postrouting jump missing_chain\\n', directory)
    raise AssertionError('Invalid NAT batch accepted')
except RouterError:
    pass
assert snapshot() == before and (directory / 'firewall.nft').read_text() == last_good
apply({})
assert not any('nat_' in item.get('chain', {}).get('name', '') for item in snapshot())
apply({}, 'firewall')
assert not any('chain' in item for item in snapshot())
assert any(item.get('table', {}).get('name') == 'unrelated' for item in snapshot())
''')


def test_native_translation_prefixes_match_legacy_ranges():
    isolated('''
from nvyr.helpers.nftables_formatters import nft_nat_rule
run('nft', 'add', 'table', 'inet', 'equivalence')
for direction, hook in [('source', 'postrouting'), ('destination', 'prerouting')]:
    run('nft', 'add', 'chain', 'inet', 'equivalence', hook,
        '{ type nat hook ' + hook + ' priority 0; }')
    for prefix, legacy in [('203.0.113.0/24', '203.0.113.0-203.0.113.255'),
                           ('203.0.113.10/31', '203.0.113.10-203.0.113.11'),
                           ('203.0.113.10/32', '203.0.113.10')]:
        for port in [None, '53', '8080-8090']:
            translation = {'address': prefix, 'persistent': True}
            if port:
                translation.update(port=port, **{'port-mapping': 'random'})
            rule = nft_nat_rule(direction, '10', {'protocol': ['tcp', 'udp'], 'translation': translation})
            expressions = []
            for rendered in [rule, rule.replace(prefix, legacy)]:
                run('nft', 'flush', 'chain', 'inet', 'equivalence', hook)
                subprocess.run(['nft', '-f', '-'], input='add rule inet equivalence ' + hook + ' ' + rendered,
                               text=True, capture_output=True, check=True)
                document = json.loads(run('nft', '-j', 'list', 'chain', 'inet', 'equivalence', hook))
                expressions.append(next(item['rule']['expr'] for item in document['nftables'] if 'rule' in item))
            assert expressions[0] == expressions[1], (prefix, port, expressions)
            if port == '53':
                action = 'snat' if direction == 'source' else 'dnat'
                assert next(expr[action]['port'] for expr in expressions[0] if action in expr) == 53
''')


def test_real_snat_dnat_masquerade_ports_exclusions_disable_and_ipv6_bypass():
    """Send traffic between two namespaces through a dual-stack router namespace.

    Receiver-observed addresses/ports prove translation, while native counters
    verify rule hits. Successive configs cover pools, exclusions, maps and IPv6
    bypass; cleanup releases peer processes even when an assertion fails.
    """
    isolated(r'''
peers = []
try:
    run('/usr/lib/systemd/systemd-sysctl', '/usr/lib/sysctl.d/50-nvyr-router.conf')
    for index in (1, 2):
        peer = subprocess.Popen(['unshare', '-n', 'sleep', '80'])
        peers.append(peer)
        deadline = time.monotonic() + 3
        while Path(f'/proc/{peer.pid}/ns/net').readlink() == Path('/proc/self/ns/net').readlink():
            assert time.monotonic() < deadline
            time.sleep(.01)
        run('ip', 'link', 'add', f'router{index}', 'type', 'veth', 'peer', 'name', f'peer{index}')
        run('ip', 'link', 'set', f'peer{index}', 'netns', str(peer.pid))
        prefix = ('nsenter', '-t', str(peer.pid), '-n')
        for command in [('link', 'set', f'peer{index}', 'up'),
                        ('address', 'add', f'10.10.{index}.2/24', 'dev', f'peer{index}'),
                        ('address', 'add', f'2001:db8:{index}::2/64', 'dev', f'peer{index}', 'nodad'),
                        ('route', 'add', 'default', 'via', f'10.10.{index}.1'),
                        ('-6', 'route', 'add', 'default', 'via', f'2001:db8:{index}::1')]:
            run(*prefix, 'ip', *command)
        run('ip', 'address', 'add', f'10.10.{index}.1/24', 'dev', f'router{index}')
        run('ip', 'address', 'add', f'2001:db8:{index}::1/64', 'dev', f'router{index}', 'nodad')
        run('ip', 'link', 'set', f'router{index}', 'up')
    def exchange(destination='203.0.113.99', port=53001, ipv6=False):
        family = 'AF_INET6' if ipv6 else 'AF_INET'
        bind = '2001:db8:2::2' if ipv6 else '10.10.2.2'
        receive = f"import socket,json; s=socket.socket(socket.{family},socket.SOCK_DGRAM); s.bind(('{bind}',8080)); s.settimeout(4); print('ready',flush=True); data,peer=s.recvfrom(100); print(json.dumps(peer),flush=True); s.sendto(data,peer)"
        receiver = subprocess.Popen(['nsenter','-t',str(peers[1].pid),'-n',sys.executable,'-c',receive],
                                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            assert receiver.stdout.readline().strip() == 'ready'
            # A fresh ephemeral source port selects a new conntrack flow each time.
            send = f"import socket; s=socket.socket(socket.{family},socket.SOCK_DGRAM); s.settimeout(4); s.sendto(b'nat',('{destination}',{port})); data,peer=s.recvfrom(100); assert data==b'nat' and peer[:2]==('{destination}',{port}),peer"
            run('nsenter','-t',str(peers[0].pid),'-n',sys.executable,'-c',send)
            output, error = receiver.communicate(timeout=6)
            assert receiver.returncode == 0, error
            return json.loads(output)
        finally:
            if receiver.poll() is None:
                receiver.kill()
                receiver.wait()
    config = {'destination': {'rule': {
        '1': {'disable':True, 'translation':{'address':'10.99.99.99'}},
        '10': {'inbound-interface':['router1'], 'protocol':['tcp','udp'], 'destination-port':['53001'],
               'translation': {'address':'10.10.2.2', 'port':'8080'}, 'log':{}, 'counter':{}, 'last-used':True}}},
        'source': {'rule': {'10': {'source-address':['10.10.1.0/24'], 'outbound-interface':['router2'],
            'protocol':['tcp','udp'], 'translation': {'address':'10.10.2.1', 'port':'40000-40010',
                'port-mapping':'fully-random', 'persistent':True}, 'log':{}, 'counter':{}, 'last-used':True}}}}
    apply(config)
    observed = exchange()
    assert observed[0] == '10.10.2.1' and 40000 <= observed[1] <= 40010, observed
    for chain in ('ipv4_nat_prerouting', 'ipv4_nat_postrouting'):
        rule = next(item['rule'] for item in snapshot() if item.get('rule', {}).get('chain') == chain
                    and item['rule'].get('comment') == '10|')
        counter = next(expr['counter'] for expr in rule['expr'] if 'counter' in expr)
        assert counter['packets'] == 1 and counter['bytes'] > 0, rule
        last = next(expr['last'] for expr in rule['expr'] if 'last' in expr)
        # nft JSON reports milliseconds since the last match in "used".
        assert type(last['used']) is int and last['used'] >= 0, rule
    config['source']['rule']['10']['translation'] = {'address':'masquerade', 'port':'40100-40110'}
    apply(config)
    observed = exchange()
    assert observed[0] == '10.10.2.1' and 40100 <= observed[1] <= 40110, observed
    for pool in ['172.16.0.0/30', '172.16.0.1-172.16.0.3']:
        config['source']['rule']['10']['translation'] = {'address':pool}
        apply(config)
        assert exchange()[0] in {'172.16.0.0','172.16.0.1','172.16.0.2','172.16.0.3'}
    config['source']['rule']['10']['translation'] = {'port':'40200-40210'}
    apply(config)
    observed = exchange()
    assert observed[0] == '10.10.1.2' and 40200 <= observed[1] <= 40210, observed
    config['source']['rule']['5'] = {'outbound-interface':['router2'], 'source-address':['10.10.1.2'], 'exclude':True, 'log':{}}
    apply(config)
    assert exchange()[0] == '10.10.1.2'
    config['destination']['rule']['5'] = {'inbound-interface':['router1'], 'destination-address':['10.10.2.2'], 'exclude':True}
    config['destination']['rule']['10']['destination-port'] = ['53001','8080']
    config['destination']['rule']['10']['translation']['port'] = '9999'
    apply(config)
    assert exchange('10.10.2.2',8080)[0] == '10.10.1.2'
    # Port-only DNAT preserves the destination address and translates replies.
    apply({'destination': {'rule': {'10': {'inbound-interface':['router1'], 'protocol':['tcp','udp'],
           'destination-port':['53001'], 'translation':{'port':'8080'}}}}})
    assert exchange('10.10.2.2',53001)[0] == '10.10.1.2'
    # Broad IPv4 masquerade and DNAT must leave IPv6 traffic alone.
    apply({'source':{'rule':{'1':{'outbound-interface':['router2'], 'translation':{'address':'masquerade'}}}},
           'destination':{'rule':{'1':{'inbound-interface':['router1'], 'translation':{'address':'10.99.99.99'}}}}})
    assert exchange('2001:db8:2::2',8080,True)[0] == '2001:db8:1::2'
    # Named translation maps must change packet addresses/ports, not only parse.
    for kind, target, destination, port in [
        ('address', {'address':'10.10.2.2'}, '203.0.113.99', 8080),
        ('port', {'port':'8080'}, '10.10.2.2', 53001),
        ('address-port', {'address':'10.10.2.2','port':'8080'}, '203.0.113.99', 53001),
    ]:
        mapping = {'match': {'protocol': True, 'destination-port': True},
            'result-type':kind, 'description':'Published UDP service',
            'entry':{'WEB':{'protocol':'udp',
                'destination-port':str(port),'result':target}}}
        clients = {'match': {'source-address': True},
                   'entry': {'LAN': {'source-address': '10.10.1.0/24'}}}
        apply({'group':{'map':{'ipv4':{'SERVICE':mapping}},
                        'match-group':{'ipv4':{'CLIENTS':clients}}},
               'global-options':{'counter':True,'last-used':True}}, 'firewall')
        apply({'destination':{'rule':{'10':{'map':'SERVICE', 'match-group':'CLIENTS', 'inbound-interface':['router1']}}}})
        assert exchange(destination,port)[0] == '10.10.1.2'
        listing = run('nft','list','map','inet','nvyr_filter','ipv4_map_SERVICE')
        assert 'counter packets 1' in listing and 'last used' in listing, listing
    for kind, target, expected_address, expected_port in [
        ('address', {'address':'10.10.2.1'}, '10.10.2.1', None),
        ('port', {'port':'40300'}, '10.10.1.2', 40300),
        ('address-port', {'address':'10.10.2.1','port':'40301'}, '10.10.2.1', 40301),
    ]:
        mapping = {'match': {'outbound-interface': True, 'protocol': True}, 'result-type':kind,
            'entry':{'CLIENT':{'outbound-interface':'router2','protocol':'udp','result':target}}}
        apply({'group':{'map':{'ipv4':{'SERVICE':previous['firewall']['group']['map']['ipv4']['SERVICE'],
                                    'CLIENTS':mapping}},
                        'match-group':previous['firewall']['group']['match-group']}}, 'firewall')
        apply({'destination':{'rule':{'10':{'map':'SERVICE', 'match-group':'CLIENTS', 'inbound-interface':['router1']}}},
               'source':{'rule':{'10':{'map':'CLIENTS'}}}})
        observed = exchange()
        assert observed[0] == expected_address, observed
        if expected_port is not None:
            assert observed[1] == expected_port, observed
    # Singleton groups constrain real translations, including the Ethernet source.
    apply({})
    client = json.loads(run('nsenter', '-t', str(peers[0].pid), '-n',
                            'ip', '-j', 'link', 'show', 'peer1'))[0]['address']
    groups = {'interface-group': {'LAN': {'interface': ['router1']}, 'WAN': {'interface': ['router2']}},
              'address-group': {'ipv4': {'CLIENTS': {'address': ['10.10.1.0/24']}}},
              'mac-group': {'CLIENT': {'address': [client], 'counter': True, 'last-used': True}},
              'port-group': {'SERVICE': {'port': ['53000-53002']}}}
    apply({'group': groups}, 'firewall')
    apply({'destination': {'rule': {'10': {
        'inbound-interface-group': 'LAN', 'source-address-group': 'CLIENTS',
        'source-mac-group': 'CLIENT', 'destination-port-group': 'SERVICE', 'protocol': ['udp'],
        'translation': {'address': '10.10.2.2', 'port': '8080'}}}},
        'source': {'rule': {'10': {'outbound-interface-group': 'WAN',
                                 'translation': {'address': '10.10.2.1'}}}}})
    assert exchange()[0] == '10.10.2.1'
    listing = run('nft', 'list', 'set', 'inet', 'nvyr_filter', 'mac_group_CLIENT')
    assert 'counter packets 1' in listing and 'last used' in listing, listing
    apply({})
    apply({}, 'firewall')
    assert exchange('10.10.2.2',8080)[0] == '10.10.1.2'
finally:
    for peer in peers:
        peer.terminate()
        peer.wait(timeout=5)
''')


def test_real_nat_commit_rollback_restart_and_shared_firewall_owner():
    isolated('''
from nvyr.controller import Controller
from nvyr.engine import Engine
from tests.lifecycle import LifecycleStub, RecordingModule
from nvyr.storage import Store
schema = Schema.bundled()
modules = {owner: LifecycleStub() for owner in schema.owners}
modules.update(firewall=RecordingModule(firewall))
now = [100.0]
engine = Engine(schema, modules, Store(directory), clock=lambda: now[0])
session = engine.open('test','namespace')
controller = Controller(engine)
def execute(command):
    return controller.execute(command, session)
def translation():
    return [item['rule'] for item in snapshot() if 'rule' in item
            and item['rule'].get('chain') == 'ipv4_nat_postrouting']
execute('set nat source rule 10 outbound-interface eth0 translation address masquerade')
execute('set firewall ipv4 forward filter rule 10 action accept')
result = engine.commit(session)
assert result['results'] == {'firewall': {'success': True}}
assert any('masquerade' in expr for expr in translation()[0]['expr'])
execute('set nat source rule 10 translation address 203.0.113.1')
engine.commit(session, minutes=1, confirmed_minutes=1)
assert any('snat' in expr for expr in translation()[0]['expr'])
now[0] = 161
engine.tick()
assert any('masquerade' in expr for expr in translation()[0]['expr'])
execute('set nat source rule 20 destination-port 80')
execute('set firewall ipv4 forward filter rule 20 action drop')
result = engine.commit(session)
assert not result['results']['firewall']['success']
assert '20' not in engine.running['firewall']['ipv4']['forward']['filter']['rule']
assert len(translation()) == 1
engine.discard(session)
engine.save(session)
run('nft', '--file', '/usr/lib/nvyr/router.nft')
engine = Engine(schema, modules, Store(directory), clock=lambda: now[0])
assert any('masquerade' in expr for expr in translation()[0]['expr'])
assert not any(item.get('rule',{}).get('comment') == '20|' for item in snapshot())
session = engine.open('test','namespace')
controller = Controller(engine)
execute('delete nat')
assert engine.commit(session)['results']['firewall']['success']
assert not translation()
assert any(item.get('chain',{}).get('name') == 'ipv4_forward' for item in snapshot())
''')
