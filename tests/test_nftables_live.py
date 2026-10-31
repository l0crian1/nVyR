"""Opt-in nftables checks in a new network namespace inside the test container."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')

COMMON = '''
import json, socket, subprocess, tempfile
from copy import deepcopy
from pathlib import Path
from nvyr.config_scripts import firewall as firewall
from nvyr.helpers.nftables import Manager
from nvyr.errors import RouterError
from nvyr.schema import Schema
from nvyr.tree import ReadOnlyTree
from tests.lifecycle import firewall_context
directory = Path(tempfile.mkdtemp(prefix='nvyr-nft-live-'))
def run(*args):
    return subprocess.run(args, text=True, capture_output=True, check=True).stdout
def snapshot():
    return json.loads(run('nft', '-j', 'list', 'ruleset'))['nftables'][1:]
previous = {}
def apply(config):
    global previous
    schema = Schema.bundled()
    schema.validate_configuration({'firewall': config})
    effective = ReadOnlyTree(schema.defaults({'firewall': config}))
    firewall.verify(effective, None)
    context = firewall_context(effective, ReadOnlyTree(previous), 'firewall', ('firewall',),
                            previous_effective=ReadOnlyTree(schema.defaults(previous)))
    text = firewall.generate(effective, context)
    Manager().apply(text, directory)
    previous = {'firewall': deepcopy(config)}
    return text
'''


def isolated(script):
    assert Path('/.dockerenv').exists() and os.geteuid() == 0

    result = subprocess.run(['unshare', '-n', sys.executable, '-c', COMMON + script],
                            capture_output=True, text=True, timeout=60)

    assert result.returncode == 0, result.stdout + result.stderr


def test_real_fib_queries_and_hook_validation():
    isolated('''
from nvyr.helpers.nftables_normalizer import normalize
run('ip', 'link', 'set', 'lo', 'up')
for family in ('ipv4', 'ipv6'):
    config = {family: {}}
    for hook, stage in [('prerouting', 'raw'), ('input', 'filter'),
                        ('forward', 'filter'), ('output', 'raw'), ('output', 'filter')]:
        rules = {}
        for modifier in (None, 'inbound-interface', 'outbound-interface'):
            for result in ({'outbound-interface': ['missing']}, {'outbound-interface': ['exists']},
                           {'outbound-interface': ['lo', 'dum0']}, {'route-type': ['local', 'unicast']}):
                lookup = {'destination-address': True, 'packet-mark': True}
                if modifier:
                    lookup[modifier] = True
                rule = {'action': 'continue', 'counter': {}, 'fib': {'lookup': lookup, 'result': result}}
                path = ('firewall', family, hook, stage, 'rule', str(len(rules) + 1))
                try:
                    firewall.verify_fib(rule['fib'], path, hook)
                except RouterError:
                    continue
                rules[str(len(rules) + 1)] = rule
        config[family].setdefault(hook, {})[stage] = {'rule': rules}
    config[family]['input']['filter']['rule']['100'] = {
        'action': 'continue', 'counter': {},
        'fib': {'lookup': {'source-address': True, 'inbound-interface': True},
                'result': {'outbound-interface': ['exists']}},
    }
    apply(config)
    normalized = normalize({'nftables': snapshot()})['tables']['inet']['nvyr_filter']
    for hook, stage in [('prerouting', 'raw'), ('input', 'filter'),
                        ('forward', 'filter'), ('output', 'raw'), ('output', 'filter')]:
        native = 'output_raw' if (hook, stage) == ('output', 'raw') else hook
        installed = {rule['number']: rule for rule in normalized['chains'][family + '_' + native]['rules']}
        for number, rule in config[family][hook][stage]['rule'].items():
            actual = installed[number]['fib']
            assert actual['lookup'] == rule['fib']['lookup'], installed[number]
            for field, values in rule['fib']['result'].items():
                assert set(actual['result'][field]) == set(values), installed[number]
            assert 'unsupported' not in installed[number], installed[number]
    # Real locally generated traffic reaches output, then prerouting/input on loopback.
    address = '127.0.0.1' if family == 'ipv4' else '::1'
    family_flag = '-4' if family == 'ipv4' else '-6'
    run('ping', family_flag, '-c', '1', '-W', '1', address)
    matched = normalize({'nftables': snapshot()})['tables']['inet']['nvyr_filter']['chains']
    for native in ('output_raw', 'output', 'prerouting', 'input'):
        assert any(rule.get('fib') and rule.get('counter', {}).get('packets', 0)
                   for rule in matched[family + '_' + native]['rules']), native
    strict = next(rule for rule in matched[family + '_input']['rules'] if rule['number'] == '100')
    assert strict['counter']['packets'] > 0, strict
    # The kernel independently rejects interface-result lookups in output.
    invalid = f'add rule inet nvyr_filter {family}_output fib saddr oif missing drop'
    result = subprocess.run(['nft', '-c', '-f', '-'], input=invalid, text=True, capture_output=True)
    assert result.returncode != 0
''')


def test_real_named_chains_jump_packets_and_atomic_replacement():
    isolated('''
run('ip', 'link', 'set', 'lo', 'up')
run('nft', 'add', 'table', 'inet', 'nvyr_filter')
run('nft', 'add', 'chain', 'inet', 'nvyr_filter', 'unmanaged_chain')
run('nft', 'add', 'rule', 'inet', 'nvyr_filter', 'unmanaged_chain', 'counter')
config = {family: {'name': {
    'FIRST': {'rule': {'10': {'action': 'jump', 'jump-target': 'LAST', 'log': {}}}},
    'LAST': {'default-action': 'drop', 'default-log': True}},
    'output': {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'FIRST'}}}}}
    for family in ('ipv4', 'ipv6')}
apply(config)
for family, address in [('-4', '127.0.0.1'), ('-6', '::1')]:
    result = subprocess.run(['ping', family, '-c', '1', '-W', '1', address], capture_output=True)
    assert result.returncode != 0
for family in ('ipv4', 'ipv6'):
    rules = [item['rule'] for item in snapshot() if item.get('rule', {}).get('chain') == family + '_name_LAST']
    assert any(expr.get('counter', {}).get('packets', 0) for rule in rules for expr in rule['expr'])
    chain = next(item['chain'] for item in snapshot() if item.get('chain', {}).get('name') == family + '_name_LAST')
    assert 'hook' not in chain
# Reverse dependency direction: cleanup must not depend on lexical or jump order.
config = {family: {'name': {'FIRST': {'default-action': 'accept'},
    'LAST': {'rule': {'10': {'action': 'jump', 'jump-target': 'FIRST'}}}},
    'output': {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'LAST'}}}}}
    for family in ('ipv4', 'ipv6')}
apply(config)
run('ping', '-4', '-c', '1', '-W', '1', '127.0.0.1')
run('ping', '-6', '-c', '1', '-W', '1', '::1')
# Invalid jump loops are rejected by nft --check without changing active rules.
baseline = snapshot()
bad = {'ipv4': {'name': {'A': {'rule': {'1': {'action': 'jump', 'jump-target': 'B'}}},
    'B': {'rule': {'1': {'action': 'jump', 'jump-target': 'A'}}}},
    'output': {'filter': {'rule': {'1': {'action': 'jump', 'jump-target': 'A'}}}}}}
try:
    apply(bad)
    raise AssertionError('jump loop accepted')
except RouterError:
    pass
assert snapshot() == baseline
apply({'ipv4': {'name': {'NEW-name': {}}}})
names = {item['chain']['name'] for item in snapshot() if 'chain' in item}
assert names == {'ipv4_name_NEW-name', 'unmanaged_chain'}, names
apply({})
names = {item['chain']['name'] for item in snapshot() if 'chain' in item}
assert names == {'unmanaged_chain'}, names
assert any(item.get('rule', {}).get('chain') == 'unmanaged_chain' for item in snapshot())
''')


def test_real_named_chain_recovery_removes_unpublished_chains():
    isolated('''
run('nft', 'add', 'table', 'inet', 'nvyr_filter')
run('nft', 'add', 'chain', 'inet', 'nvyr_filter', 'ipv4_name_ORPHAN')
run('nft', 'add', 'chain', 'inet', 'nvyr_filter', 'ipv6_name_ORPHAN')
run('nft', 'add', 'rule', 'inet', 'nvyr_filter', 'ipv4_name_ORPHAN', 'drop')
assert set(Manager().named_chains()) == {('ipv4', 'ORPHAN'), ('ipv6', 'ORPHAN')}
empty = ReadOnlyTree({})
context = firewall_context(empty, empty, 'firewall', ('firewall',), recovery=True, previous_effective=empty)
Manager().apply(firewall.generate(empty, context), directory)
assert Manager().named_chains() == []
''')


def test_real_extended_matches_and_address_masks():
    isolated('''
for family, address, mask in [('ipv4', '192.0.2.129', '255.0.255.0'),
                              ('ipv6', '2001:db8::1234', 'ffff:0:ffff::ffff')]:
    rule = {
        'action': 'accept',
        'packet-mark': ['0','10-20','4294967295'],
        'connection': {'mark': ['1-5','10']},
        'dscp': ['0','8-16','63'],
        'tcp-mss': ['0','536-1400','1460','65535'],
        'source-address': {address: {'mask':mask}},
        'destination-address': {address: {'mask':mask}},
        'source-mac': {'02:11:22:33:44:55':{'mask':'ff:ff:00:ff:00:ff'}},
        'destination-mac': {'01:00:5e:00:00:01':{},'ff:ff:ff:ff:ff:ff':{}},
    }
    for hook in ('input','output','forward'):
        apply({family:{hook:{'filter':{'rule':{'10':rule}}}}})
        expressions = next(item['rule']['expr'] for item in snapshot()
                           if item.get('rule',{}).get('comment') == '10|')
        assert all('mangle' not in expression for expression in expressions), expressions
    # Prefixes compose with the explicit bitmask, including zero/full masks.
    rule['source-address'] = {address + ('/24' if family == 'ipv4' else '/64'): {'mask': mask}}
    rule['destination-address'][address]['mask'] = '0.0.0.0' if family == 'ipv4' else '::'
    rule['destination-mac'] = {'ff:ff:ff:ff:ff:ff': {'mask': '00:00:00:00:00:00'}}
    rule['source-mac'][next(iter(rule['source-mac']))]['mask'] = 'ff:ff:ff:ff:ff:ff'
    apply({family:{'forward':{'filter':{'rule':{'10':rule}}}}})
    if family == 'ipv4':
        del rule['connection']
        apply({family:{'prerouting':{'raw':{'rule':{'10':rule}}}}})
''')


def test_real_named_ip_protocols():
    isolated('''
from nvyr.helpers.validators import IP_PROTOCOLS
rules = {str(index): {'action':'accept', 'protocol':[name]}
         for index, name in enumerate(sorted(IP_PROTOCOLS), 1)}
config = {family:{'forward':{'filter':{'rule':rules}}} for family in ('ipv4','ipv6')}
config['ipv4']['prerouting'] = {'raw':{'rule':rules}}
apply(config)
observed = [item['rule'] for item in snapshot()
            if item.get('rule',{}).get('comment','').split('|')[0].isdigit()]
assert len(observed) == 3 * len(IP_PROTOCOLS), len(observed)
''')


def test_real_mark_dscp_and_mask_packet_matches():
    isolated('''
run('ip','link','set','lo','up')
run('nft','add','table','inet','mark_test')
run('nft','add','chain','inet','mark_test','output', '{ type filter hook output priority -150; }')
for family, af, address, masked_address, mask in [
        ('ipv4',socket.AF_INET,'127.0.0.1','127.1.0.99','255.0.255.0'),
        ('ipv6',socket.AF_INET6,'::1','2001::1','::ffff')]:
    with socket.socket(af,socket.SOCK_DGRAM) as receiver, socket.socket(af,socket.SOCK_DGRAM) as sender:
        receiver.bind((address,0)); receiver.settimeout(.3)
        rule = {
            'action': 'drop',
            'packet-mark': ['10-20','42'],
            'dscp': ['8-16','63'] if family == 'ipv4' else ['10','63'],
            'connection': {'mark': ['10-20','42']},
            'source-address': {masked_address: {'mask':mask}},
            'destination-address': {masked_address: {'mask':mask}},
            'counter': {},
        }
        apply({family:{'output':{'filter':{'rule':{'10':rule}}}}})
        level, option = ((socket.IPPROTO_IP,socket.IP_TOS) if af == socket.AF_INET else
                         (socket.IPPROTO_IPV6,socket.IPV6_TCLASS))
        def packets():
            expressions = next(item['rule']['expr'] for item in snapshot()
                               if item.get('rule',{}).get('comment') == '10|')
            return next(expr['counter']['packets'] for expr in expressions if 'counter' in expr)
        for mark, ct_mark, dscp, blocked in [(15,15,10,True),(42,42,63,True),
                                           (21,15,10,False),(15,21,10,False),(15,15,17,False)]:
            # Assign a conntrack mark in a separate test-only chain before nVyR's filter.
            run('nft','flush','chain','inet','mark_test','output')
            run('nft','add','rule','inet','mark_test','output','ct','mark','set',str(ct_mark))
            before = packets()
            sender.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,mark)
            sender.setsockopt(level,option,dscp << 2)
            try:
                sender.sendto(b'match-test',receiver.getsockname())
            except PermissionError:
                assert blocked
            if blocked:
                try:
                    receiver.recv(32)
                    raise AssertionError((family, mark, dscp, run('nft','list','ruleset')))
                except socket.timeout:
                    pass
                assert packets() > before
            else:
                assert receiver.recv(32) == b'match-test'
                assert packets() == before
''')


def test_real_tcp_mss_matches_without_modification():
    isolated('''
run('ip','link','set','lo','up')
for family, af, address in [('ipv4',socket.AF_INET,'127.0.0.1'),('ipv6',socket.AF_INET6,'::1')]:
    apply({family:{'output':{'filter':{'rule':{
        '10':{'action':'accept','tcp-mss':['1','500-2000'],'counter':{}},
        '20':{'action':'accept','tcp-mss':['2-10'],'counter':{}}}}}}})
    with socket.socket(af,socket.SOCK_STREAM) as server, socket.socket(af,socket.SOCK_STREAM) as client:
        server.bind((address,0)); server.listen(1)
        client.settimeout(2)
        client.setsockopt(socket.IPPROTO_TCP,socket.TCP_MAXSEG,1200)
        client.connect(server.getsockname())
        accepted, peer = server.accept()
        accepted.close()
    rules = {item['rule']['comment']:item['rule']['expr'] for item in snapshot()
             if item.get('rule',{}).get('comment') in ('10|','20|')}
    assert next(expr['counter']['packets'] for expr in rules['10|'] if 'counter' in expr) > 0
    assert next(expr['counter']['packets'] for expr in rules['20|'] if 'counter' in expr) == 0
    assert all('mangle' not in expr for expressions in rules.values() for expr in expressions)
''')


def test_real_ipv6_dscp_range_packet_matching():
    # Keep this packet-level regression visible: nft 1.1.7 accepts the expression
    # but fails to match it in the test environment. Do not rewrite native ranges.
    isolated('''
run('ip','link','set','lo','up')
apply({'ipv6':{'output':{'filter':{'rule':{'10':{
    'action':'drop', 'dscp':['8-16','63'], 'counter':{}}}}}}})
with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as sender:
    receiver.bind(('::1',0)); receiver.settimeout(.3)
    sender.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_TCLASS,10 << 2)
    try:
        sender.sendto(b'dscp-range',receiver.getsockname())
    except PermissionError:
        pass
    try:
        receiver.recv(32)
        raise AssertionError('Native nftables IPv6 DSCP range did not match DSCP 10: ' + run('nft','list','ruleset'))
    except socket.timeout:
        pass
''')


def test_real_mac_bitmask_packet_matching():
    isolated('''
import time
peer = subprocess.Popen(['unshare','-n','sleep','60'])
try:
    deadline = time.monotonic() + 3
    while Path(f'/proc/{peer.pid}/ns/net').readlink() == Path('/proc/self/ns/net').readlink():
        assert time.monotonic() < deadline
        time.sleep(.01)
    run('ip','link','add','mac0','type','veth','peer','name','peer0')
    run('ip','link','set','peer0','netns',str(peer.pid))
    run('ip','link','set','mac0','address','02:aa:bb:cc:dd:01')
    run('ip','address','add','192.0.2.1/24','dev','mac0')
    run('ip','link','set','mac0','up')
    for args in [('link','set','peer0','address','02:11:22:33:44:55'),
                 ('address','add','192.0.2.2/24','dev','peer0'),('link','set','peer0','up')]:
        run('nsenter','-t',str(peer.pid),'-n','ip',*args)
    rule = {'action':'drop','source-mac':{'02:11:99:33:99:55':{'mask':'ff:ff:00:ff:00:ff'}},
            'destination-mac':{'02:aa:00:cc:00:01':{'mask':'ff:ff:00:ff:00:ff'}},'counter':{}}
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver:
        receiver.bind(('192.0.2.1',0)); receiver.settimeout(.3)
        port = receiver.getsockname()[1]
        for matching in (True,False):
            if not matching:
                rule['source-mac'][next(iter(rule['source-mac']))]['mask'] = 'ff:ff:ff:ff:ff:ff'
            apply({'ipv4':{'input':{'filter':{'rule':{'10':rule}}}}})
            code = f"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'mac-test',('192.0.2.1',{port}))"
            run('nsenter','-t',str(peer.pid),'-n','python3','-c',code)
            if matching:
                try:
                    receiver.recv(32)
                    raise AssertionError('MAC bitmask did not match')
                except socket.timeout:
                    pass
            else:
                assert receiver.recv(32) == b'mac-test'
            expressions = next(item['rule']['expr'] for item in snapshot()
                               if item.get('rule',{}).get('comment') == '10|')
            packets = next(expr['counter']['packets'] for expr in expressions if 'counter' in expr)
            assert (packets > 0) == matching
finally:
    peer.terminate()
    peer.wait(timeout=5)
''')


def test_real_nft_reload_removal_state_counters_and_unrelated_rules_survive():
    isolated('''
run('nft', 'add', 'table', 'inet', 'untouched')
run('nft', 'add', 'chain', 'inet', 'untouched', 'sentinel')
run('nft', 'add', 'rule', 'inet', 'untouched', 'sentinel', 'counter', 'accept')
unrelated = json.loads(run('nft', '-j', 'list', 'table', 'inet', 'untouched'))['nftables'][1:]
apply({})
run('nft', 'add', 'chain', 'inet', 'nvyr_filter', 'unmanaged')
run('nft', 'add', 'rule', 'inet', 'nvyr_filter', 'unmanaged', 'counter', 'accept')
config = {'ipv4': {'forward': {'filter': {'default-action': 'drop', 'rule': {
 '10': {
     'action': 'accept',
     'protocol': ['tcp', 'udp'],
     'destination-port': ['22','23','8000-8100'],
     'source-address': {'1.1.1.1': {}, '1.1.1.0/24': {}},
     'destination-address': {'2.2.2.2': {}},
     'counter': {},
     'last-used': True,
     'inbound-interface': ['future0', 'future1'],
     'outbound-interface': ['later0'],
     'connection': {'state': ['established','related']},
     'description': 'Allow SSH',
 },
 '999999': {'action':'reject', 'description':'a' * 121}}}}},
 'ipv6': {'forward': {'filter': {'rule': {'20': {'action': 'reject', 'protocol': ['ipv6-icmp'],
       'source-address': {'2001:db8::/64': {}}}}}}},
 'global-options': {'state-policy': {'established': {'action':'accept'},
       'related': {'action':'accept'}, 'invalid': {'action':'drop'}}}}
text = apply(config)
apply(config)  # Reapplying identical configuration preserves populated chains.
items = snapshot()
chains = {item['chain']['name'] for item in items if 'chain' in item and item['chain']['table'] == 'nvyr_filter'}
assert chains == {'forward','ipv4_forward','ipv6_forward','unmanaged'}, chains
comments = [item['rule'].get('comment') for item in items if 'rule' in item]
assert '10|Allow SSH' in comments and '999999|' + 'a' * 121 in comments
before = snapshot()
last_good = (directory / 'firewall.nft').read_text()
try:
    Manager().apply(text + '\\nadd rule inet nvyr_filter forward jump nonexistent_chain\\n', directory)
    raise AssertionError('Invalid transaction accepted')
except RouterError:
    pass
assert snapshot() == before
assert (directory / 'firewall.nft').read_text() == last_good
del config['ipv6']
del config['global-options']
apply(config)
chains = {item['chain']['name'] for item in snapshot() if 'chain' in item and item['chain']['table'] == 'nvyr_filter'}
assert chains == {'forward','ipv4_forward','unmanaged'}
apply({})
apply({})
chains = {item['chain']['name'] for item in snapshot() if 'chain' in item and item['chain']['table'] == 'nvyr_filter'}
assert chains == {'unmanaged'}
assert json.loads(run('nft','-j','list','table','inet','untouched'))['nftables'][1:] == unrelated
''')


def test_real_ipv4_ipv6_packet_filtering_counters_last_and_removal():
    isolated('''
run('ip', 'link', 'set', 'lo', 'up')
for family, af, address in [('ipv4',socket.AF_INET,'127.0.0.1'),('ipv6',socket.AF_INET6,'::1')]:
    with socket.socket(af,socket.SOCK_DGRAM) as receiver, socket.socket(af,socket.SOCK_DGRAM) as sender:
        receiver.bind((address,0)); receiver.settimeout(.3)
        port = receiver.getsockname()[1]
        config = {family: {'output': {'filter': {'rule': {'10': {'action':'drop','protocol':['udp','tcp'],
            'outbound-interface':['lo','future0'], 'source-address':{address: {}}, 'destination-address':{address: {}},
            'destination-port':[str(port)],'counter':{},'last-used':True}}}}}}
        apply(config)
        try:
            sender.sendto(b'blocked',(address,port))
        except PermissionError:
            pass  # A local OUTPUT drop can report EPERM to the sender.
        try:
            receiver.recv(32)
            raise AssertionError('Firewall did not drop the packet')
        except socket.timeout:
            pass
        rules = [item['rule'] for item in snapshot() if 'rule' in item and item['rule'].get('comment') == '10|']
        assert len(rules) == 1
        assert any(expr.get('counter',{}).get('packets',0) >= 1 for expr in rules[0]['expr'])
        assert any('last' in expr for expr in rules[0]['expr'])
        apply({})
        sender.sendto(b'allowed',(address,port))
        assert receiver.recv(32) == b'allowed'
''')


def test_real_firewall_commit_confirm_restart_and_delete():
    isolated('''
from nvyr.controller import Controller
from nvyr.engine import Engine
from tests.lifecycle import LifecycleStub, RecordingModule
from nvyr.storage import Store
schema = Schema.bundled()
modules = {owner: LifecycleStub() for owner in schema.owners}
modules['firewall'] = RecordingModule(firewall)
now = [100.0]
engine = Engine(schema, modules, Store(directory), clock=lambda: now[0])
session = engine.open('test', 'namespace')
controller = Controller(engine)
def execute(command):
    return controller.execute(command, session)
def verdict():
    rules = [item['rule'] for item in snapshot() if 'rule' in item
             and item['rule'].get('comment') == '10|']
    assert len(rules) == 1
    return rules[0]['expr']
execute('set firewall ipv4 forward filter rule 10 action accept')
assert engine.commit(session)['results']['firewall']['success']
assert {'accept': None} in verdict()
execute('set firewall ipv4 forward filter rule 10 action drop')
engine.commit(session, minutes=1, confirmed_minutes=1)
assert {'drop': None} in verdict()
now[0] = 161
engine.tick()
assert {'accept': None} in verdict()
execute('set firewall ipv4 forward filter rule 20 destination-port 22')
assert not engine.commit(session)['results']['firewall']['success']
assert {'accept': None} in verdict()
assert len([item for item in snapshot() if 'rule' in item and item['rule'].get('comment') == '20|']) == 0
engine.discard(session)
engine.save(session)
run('nft', 'flush', 'ruleset')  # Simulate nftables service restart.
engine = Engine(schema, modules, Store(directory), clock=lambda: now[0])
assert {'accept': None} in verdict()
session = engine.open('test', 'namespace')
controller = Controller(engine)
execute('delete firewall ipv4 forward filter')
assert engine.commit(session)['results']['firewall']['success']
assert not any('chain' in item for item in snapshot())
''')


def test_nft_normalizes_unmerged_sets_and_ipv6_icmp():
    isolated('''
from nvyr.helpers.nftables_formatters import nft_rule
port_sets = [(['100-200', '150-250'], ['100-250']),
             (['100-200', '201-250'], ['100-250']),
             (['100-200', '150', '150'], ['100-200']),
             (['80', '80'], ['80']),
             (['100-200', '200-250'], ['100-250'])]
address_sets = [
    ('ipv4', ['10.0.1.0/25', '10.0.1.128/25', '10.0.1.1', '10.0.1.0/25'], ['10.0.1.0/24']),
    ('ipv4', ['10.0.1.0/24', '10.0.1.0/25'], ['10.0.1.0/24']),
    ('ipv6', ['2001:db8::/65', '2001:db8:0:0:8000::/65', '2001:db8::1', '2001:db8::/65'], ['2001:db8::/64']),
    ('ipv6', ['2001:db8::/64', '2001:db8::/65'], ['2001:db8::/64']),
]
for family, addresses, normalized_addresses in address_sets:
    for ports, normalized_ports in port_sets:
        expressions = []
        for source, destination in [(addresses, ports), (normalized_addresses, normalized_ports)]:
            rule = {'action': 'accept', 'protocol': ['tcp', 'udp'],
                    'source-address': {address: {} for address in source}, 'destination-port': destination}
            # Address tags are unique by key; multi-value ports are also stored
            # distinctly. Exercise duplicate port rendering directly against nft.
            configured = dict(rule, **{'source-address': {address: {} for address in source},
                                      'destination-port': list(dict.fromkeys(destination))})
            apply({family: {'forward': {'filter': {'rule': {'10': configured}}}}})
            text = ('flush chain inet nvyr_filter ' + family + '_forward\\n'
                    'add rule inet nvyr_filter ' + family + '_forward ' + nft_rule(family, 'forward', '10', rule))
            for options in [('--check',), ()]:
                result = subprocess.run(['nft', *options, '-f', '-'], input=text,
                                        text=True, capture_output=True)
                assert result.returncode == 0, result.stderr
            observed = next(item['rule']['expr'] for item in snapshot()
                            if item.get('rule', {}).get('comment') == '10|')
            # nft may retain a singleton set after merging, but optimize an
            # originally singleton input into a direct range/prefix comparison.
            for expression in observed:
                match = expression.get('match', {})
                right = match.get('right')
                if isinstance(right, dict) and 'set' in right and len(right['set']) == 1:
                    match['right'] = right['set'][0]
            expressions.append(observed)
        assert expressions[0] == expressions[1], (family, addresses, ports, expressions)
text = apply({'ipv6': {'input': {'filter': {'rule': {'10': {'action': 'accept', 'protocol': ['ipv6-icmp']}}}}}})
assert 'meta l4proto { ipv6-icmp }' in text
assert 'ipv6-icmp' in run('nft', 'list', 'table', 'inet', 'nvyr_filter')
''')


def test_real_state_policy_element_counters():
    isolated('''
import re
run('ip', 'link', 'set', 'lo', 'up')
apply({'global-options': {'state-policy': {'established': {'action': 'accept'},
                                         'invalid': {'action': 'drop'}}},
       'ipv4': {'input': {'filter': {}}, 'output': {'filter': {}}}})
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
    receiver.bind(('127.0.0.1', 0))
    receiver.settimeout(1)
    sender.settimeout(1)
    sender.sendto(b'query', receiver.getsockname())
    message, peer = receiver.recvfrom(32)
    receiver.sendto(b'reply', peer)
    assert sender.recv(32) == b'reply'
text = run('nft', 'list', 'table', 'inet', 'nvyr_filter')
counts = re.findall(r'established counter packets ([0-9]+)', text)
assert len(counts) == 2 and all(int(value) > 0 for value in counts), text
assert 'invalid counter packets 0' in text
''')


def test_real_raw_hooks_both_families_and_independent_replacement():
    isolated('''
run('ip', 'link', 'set', 'lo', 'up')
config = {}
for family in ('ipv4', 'ipv6'):
    config[family] = {
        'prerouting': {'raw': {'rule': {'10': {
            'action': 'continue', 'notrack': True, 'counter': {}, 'log': {}}}}},
        'output': {
            'raw': {'rule': {'10': {'action': 'continue', 'notrack': True,
                                  'outbound-interface': ['lo'], 'counter': {}, 'log': {}}}},
            'filter': {'rule': {'20': {'action': 'accept', 'connection': {'state': ['untracked']}, 'counter': {}, 'log': {}}}},
        },
        'input': {'filter': {'rule': {'30': {'action': 'accept', 'connection': {'state': ['untracked']}, 'counter': {}}}}},
    }
apply(config)

def packets(chain, number):
    rule = next(item['rule'] for item in snapshot() if 'rule' in item
                and item['rule']['chain'] == chain and item['rule'].get('comment') == number + '|')
    return next(expression['counter']['packets'] for expression in rule['expr'] if 'counter' in expression)

# UDP loopback traverses both raw hooks and proves that notrack precedes filtering.
for family, address_family, address in [('ipv4', socket.AF_INET, '127.0.0.1'),
                                       ('ipv6', socket.AF_INET6, '::1')]:
    with socket.socket(address_family, socket.SOCK_DGRAM) as receiver:
        receiver.bind((address, 0))
        receiver.settimeout(2)
        with socket.socket(address_family, socket.SOCK_DGRAM) as sender:
            sender.sendto(b'raw-hooks', (address, receiver.getsockname()[1]))
        assert receiver.recv(32) == b'raw-hooks'
    for native, number in [('output_raw', '10'), ('prerouting', '10'), ('output', '20'), ('input', '30')]:
        assert packets(family + '_' + native, number) > 0, (family, native)

prefixes = {expression['log']['prefix'] for item in snapshot() if 'rule' in item
            for expression in item['rule']['expr'] if 'log' in expression}
for family in ('ipv4', 'ipv6'):
    assert f'[{family}-OUT-raw-10-C]' in prefixes
    assert f'[{family}-OUT-filter-20-A]' in prefixes
    assert f'[{family}-PRE-raw-10-C]' in prefixes

# Updating one raw family chain preserves filter counters and the other family.
retained = packets('ipv4_output', '20'), packets('ipv6_output_raw', '10')
config['ipv4']['output']['raw']['rule']['10']['description'] = 'Changed raw rule'
apply(config)
assert retained == (packets('ipv4_output', '20'), packets('ipv6_output_raw', '10'))

# Removing the final raw consumers leaves both filter hooks installed.
for family in ('ipv4', 'ipv6'):
    del config[family]['prerouting']
    del config[family]['output']['raw']
apply(config)
chains = {item['chain']['name'] for item in snapshot() if 'chain' in item}
assert chains == {'input', 'output', 'ipv4_input', 'ipv6_input', 'ipv4_output', 'ipv6_output'}, chains
''')


def test_real_prerouting_notrack_disable_logging_and_removal():
    isolated('''
import time
peer = subprocess.Popen(['unshare', '-n', 'sleep', '60'])
try:
    # Wait until unshare has entered the peer namespace before moving its link.
    deadline = time.monotonic() + 3
    while Path(f'/proc/{peer.pid}/ns/net').readlink() == Path('/proc/self/ns/net').readlink():
        assert time.monotonic() < deadline
        time.sleep(.01)
    run('ip','link','add','raw0','type','veth','peer','name','peer0')
    run('ip','link','set','peer0','netns',str(peer.pid))
    run('ip','address','add','192.0.2.1/24','dev','raw0')
    run('ip','link','set','raw0','up')
    for args in [('address','add','192.0.2.2/24','dev','peer0'), ('link','set','peer0','up')]:
        run('nsenter','-t',str(peer.pid),'-n','ip',*args)
    raw = {'default-log': True, 'rule': {
        '10': {'action':'continue','notrack':True,'counter':{},'log':{},
               'inbound-interface':['raw0'],'protocol':['udp']},
        '20': {'action':'accept','counter':{}},
        '30': {'disable':True}}}
    config = {'ipv4': {'prerouting': {'raw':raw}, 'input': {'filter': {
        'default-log': True, 'rule': {'40': {'action':'drop', 'connection': {'state': ['untracked']}, 'counter':{}, 'log':{}}}}}}}
    apply(config)
    def rule(number):
        return next(item['rule'] for item in snapshot() if 'rule' in item and item['rule'].get('comment') == number+'|')
    def packets(number):
        return next(expr['counter']['packets'] for expr in rule(number)['expr'] if 'counter' in expr)
    assert any(expr.get('log',{}).get('prefix') == '[ipv4-PRE-raw-10-C]' for expr in rule('10')['expr'])
    defaults = [item['rule'] for item in snapshot() if 'rule' in item and item['rule'].get('comment','').startswith('default|')]
    assert len(defaults) == 2
    for item in defaults:
        assert [next(iter(expr)) for expr in item['expr']] == ['counter','log','accept'], item
    assert not any('rule' in item and item['rule'].get('comment') == '30|' for item in snapshot())
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as receiver:
        receiver.bind(('192.0.2.1',0)); receiver.settimeout(.3)
        port = receiver.getsockname()[1]
        def send():
            code = f"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'raw-test',('192.0.2.1',{port}))"
            run('nsenter','-t',str(peer.pid),'-n','python3','-c',code)
        send()
        try:
            receiver.recv(32)
            raise AssertionError('Untracked input traffic was not dropped')
        except socket.timeout:
            pass
        assert packets('10') >= 1 and packets('20') >= 1 and packets('40') >= 1
        input_packets = packets('40')
        raw['rule']['10']['disable'] = True
        apply(config)
        send()
        assert receiver.recv(32) == b'raw-test'
        assert packets('40') == input_packets  # Unchanged input chain retains its counter.
        del config['ipv4']['prerouting']
        apply(config)
        chains = {item['chain']['name'] for item in snapshot() if 'chain' in item}
        assert chains == {'input','ipv4_input'}, chains
finally:
    peer.terminate()
    peer.wait(timeout=5)
''')
