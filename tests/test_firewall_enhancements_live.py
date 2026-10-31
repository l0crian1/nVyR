"""Opt-in kernel checks for additional firewall matches and flowtable lifecycle."""

from tests.test_nftables_live import isolated, pytestmark


def test_real_flowtables_replace_remove_and_recover_preserve_unmanaged_chains():
    isolated('''
for device in ('dum0', 'dum1', 'dum2', 'dum3'):
    run('ip', 'link', 'add', device, 'type', 'dummy')
    run('ip', 'link', 'set', device, 'up')

run('nft', 'add', 'table', 'inet', 'nvyr_filter')
run('nft', 'add', 'chain', 'inet', 'nvyr_filter', 'unmanaged_chain')
run('nft', 'add', 'rule', 'inet', 'nvyr_filter', 'unmanaged_chain', 'counter')

config = {'flowtable': {'FAST': {'interface': ['dum0', 'dum1'], 'offload': {'software': True}},
                      'UNUSED': {'interface': ['dum2']}}}
for family in ('ipv4', 'ipv6'):
    config[family] = {'forward': {'filter': {'default-action': 'drop', 'rule': {
        '10': {'action': 'offload', 'offload-target': 'FAST', 'log': {}},
        '20': {'action': 'continue'}, '30': {'action': 'return'},
    }}}}

text = apply(config)
assert set(Manager().flowtables()) == {'FAST', 'UNUSED'}
assert 'flow add @flowtable_FAST' in run('nft', 'list', 'ruleset')

# Change device membership and repeat the transaction to cover existing objects.
config['flowtable']['FAST']['interface'] = ['dum3']
text = apply(config)
apply(config)
table = next(item['flowtable'] for item in snapshot()
             if item.get('flowtable', {}).get('name') == 'flowtable_FAST')
assert table['dev'] == 'dum3', table

# Kernel validation failure must preserve the complete active transaction.
before = snapshot()
bad = text.replace('devices = { "dum3" }', 'devices = { "missing0" }')
try:
    Manager().apply(bad, directory)
    raise AssertionError('Nonexistent flowtable device accepted')
except RouterError:
    pass
assert snapshot() == before

# Delete one flowtable, rename the referenced one, then remove the whole owner.
del config['flowtable']['UNUSED']
config['flowtable']['RENAMED'] = config['flowtable'].pop('FAST')
for family in ('ipv4', 'ipv6'):
    config[family]['forward']['filter']['rule']['10']['offload-target'] = 'RENAMED'
apply(config)
assert Manager().flowtables() == ['RENAMED']
apply({})
assert Manager().flowtables() == []
assert any(item.get('chain', {}).get('name') == 'unmanaged_chain' for item in snapshot())

# Recovery discovers an unjournaled flowtable with a rule referencing it.
apply(config)
empty = ReadOnlyTree({})
context = firewall_context(empty, empty, 'firewall', ('firewall',), recovery=True,
                        previous_effective=empty)
Manager().apply(firewall.generate(empty, context), directory)
assert Manager().flowtables() == []
assert any(item.get('chain', {}).get('name') == 'unmanaged_chain' for item in snapshot())
''')


def test_real_status_flags_packet_types_and_ttl_parse_on_each_hook():
    isolated('''
flags = ('expected', 'seen-reply', 'assured', 'confirmed', 'snat', 'dnat',
         'seq-adjust', 'snat-done', 'dnat-done', 'dying', 'fixed-timeout', 'helper', 'offload')
for family in ('ipv4', 'ipv6'):
    rules = {}
    for index, flag in enumerate(flags, 1):
        rules[str(index)] = {'action': 'continue', 'connection': {'status': [flag if flag != 'offload' else 'offload,confirmed']}}
    for index, packet_type in enumerate(('broadcast', 'host', 'multicast', 'other'), 20):
        rules[str(index)] = {'action': 'return', 'packet-type': packet_type,
                             'ttl': {'gt': '1', 'lt': '255'}}
    rules['30'] = {'action': 'accept', 'connection': {'status': ['assured,seen-reply']}, 'ttl': {'eq': '64'}}
    for hook in ('input', 'forward', 'output'):
        apply({family: {hook: {'filter': {'rule': rules}}}})
    if family == 'ipv4':
        rules = {number: rule for number, rule in rules.items() if 'connection' not in rule}
        rules['40'] = {'action': 'continue', 'notrack': True}
        apply({family: {'prerouting': {'raw': {'rule': rules}}}})
''')


def test_real_ttl_and_hoplimit_match_packets():
    isolated('''
run('ip', 'link', 'set', 'lo', 'up')
for family, address, socket_family, level, option in [
    ('ipv4', '127.0.0.1', socket.AF_INET, socket.IPPROTO_IP, socket.IP_TTL),
    ('ipv6', '::1', socket.AF_INET6, socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS),
]:
    apply({family: {'output': {'filter': {'rule': {
        '10': {'action': 'drop', 'ttl': {'gt': '63', 'lt': '65'}, 'counter': {}},
    }}}}})
    with socket.socket(socket_family, socket.SOCK_DGRAM) as receiver:
        receiver.bind((address, 0))
        receiver.settimeout(.3)
        for ttl in (63, 64, 65):
            with socket.socket(socket_family, socket.SOCK_DGRAM) as sender:
                sender.setsockopt(level, option, ttl)
                try:
                    sender.sendto(b'ttl', receiver.getsockname())
                except PermissionError:
                    assert ttl == 64
                if ttl == 64:
                    try:
                        receiver.recv(32)
                        raise AssertionError('TTL 64 was not dropped')
                    except socket.timeout:
                        pass
                else:
                    assert receiver.recv(32) == b'ttl'
''')


def test_real_connection_status_matches_exact_combinations():
    isolated('''
run('ip', 'link', 'set', 'lo', 'up')
apply({'ipv4': {'output': {'filter': {'rule': {'10': {'action': 'drop', 'connection': {'status': ['expected', 'confirmed']}, 'counter': {}}}}}}})
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        receiver.bind(('127.0.0.1', 0))
        receiver.settimeout(.3)
        # The first outgoing packet has neither bit; its connection is then confirmed.
        sender.sendto(b'first', receiver.getsockname())
        assert receiver.recv(32) == b'first'
        try:
            sender.sendto(b'second', receiver.getsockname())
        except PermissionError:
            pass
        try:
            receiver.recv(32)
            raise AssertionError('confirmed alone must match the exact alternative')
        except socket.timeout:
            pass
''')


def test_real_continue_and_return_follow_calling_chain():
    isolated('''
run('ip', 'link', 'set', 'lo', 'up')
config = {'ipv4': {
    'name': {'CUSTOM': {'default-action': 'drop', 'rule': {
        '10': {'action': 'continue', 'counter': {}},
        '20': {'action': 'return', 'counter': {}},
    }}},
    'output': {'filter': {'rule': {
        '10': {'action': 'jump', 'jump-target': 'CUSTOM'},
        '20': {'action': 'accept'},
    }}},
}}
apply(config)
run('ping', '-4', '-c', '1', '-W', '1', '127.0.0.1')
rules = [item['rule'] for item in snapshot() if item.get('rule', {}).get('chain') == 'ipv4_name_CUSTOM']
for number in ('10', '20'):
    rule = next(rule for rule in rules if rule.get('comment') == number + '|')
    assert any(expr.get('counter', {}).get('packets', 0) for expr in rule['expr'])
default = next(rule for rule in rules if rule.get('comment', '').startswith('default|'))
assert all(expr.get('counter', {}).get('packets', 0) == 0 for expr in default['expr'])
''')


def test_real_status_groups_exclude_extra_bits():
    isolated('''
from nvyr.helpers.nftables_formatters import nft_rule

run('ip', 'link', 'set', 'lo', 'up')
rules = {
    '10': {'action': 'continue', 'connection': {'status': ['seen-reply']}, 'counter': {}},
    '20': {'action': 'continue', 'connection': {'status': ['seen-reply,confirmed']}, 'counter': {}},
    '30': {'action': 'continue', 'connection': {'status': ['seen-reply,confirmed,assured']}, 'counter': {}},
    '40': {'action': 'continue', 'connection': {'status': ['seen-reply,confirmed', 'seen-reply,confirmed,assured']}, 'counter': {}},
    '50': {'action': 'continue', 'connection': {'status': ['expected,seen-reply,confirmed']}, 'counter': {}},
}
rendered = [nft_rule('ipv4', 'output', number, rule) for number, rule in rules.items()]
batch = ('table inet status_test {\\nchain out {\\n'
         'type filter hook output priority 0; policy accept;\\n'
         + '\\n'.join(rendered) + '\\n}\\n}\\n')
subprocess.run(['nft', '-f', '-'], input=batch, text=True, capture_output=True, check=True)

# Reply traffic carries confirmed as well as seen-reply. It must not match
# seen-reply alone. Allow for the kernel's timing of the assured transition.
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        receiver.bind(('127.0.0.1', 0))
        receiver.settimeout(1)
        sender.settimeout(1)
        sender.sendto(b'first', receiver.getsockname())
        data, peer = receiver.recvfrom(32)
        receiver.sendto(b'reply', peer)
        assert sender.recv(32) == b'reply'
        sender.sendto(b'third', receiver.getsockname())
        assert receiver.recv(32) == b'third'

counts = {}
for item in snapshot():
    rule = item.get('rule', {})
    if rule.get('table') == 'status_test':
        counts[rule['comment']] = sum(expr.get('counter', {}).get('packets', 0)
                                      for expr in rule['expr'])
assert counts['10|'] == 0, counts
assert counts['20|'] + counts['30|'] == 2, counts
assert counts['40|'] == 2, counts
assert counts['50|'] == 0, counts
''')


def test_real_symbolic_status_groups_compile_to_exact_kernel_values():
    isolated('''
from nvyr.helpers.nftables_formatters import nft_rule

rules = [
    nft_rule('ipv4', 'output', '10', {'action': 'accept', 'connection': {'status': ['snat,dnat']}}),
    nft_rule('ipv4', 'output', '20', {'action': 'accept', 'connection': {'status': ['confirmed,offload']}}),
    nft_rule('ipv4', 'output', '30', {'action': 'accept', 'connection': {'status': ['helper']}}),
]
batch = 'table inet status_test {\\nchain matches {\\n' + '\\n'.join(rules) + '\\n}\\n}\\n'
result = subprocess.run(['nft', '--debug=netlink', '-f', '-'], input=batch,
                        text=True, capture_output=True, check=True)
# Check the kernel comparisons, not just nft's pretty-printed symbolic names.
for value in ('0x00000030', '0x00004008', '0x00002000'):
    assert 'cmp eq reg 1 ' + value in result.stdout, result.stdout
assert 'bitwise reg' not in result.stdout, result.stdout
''')
