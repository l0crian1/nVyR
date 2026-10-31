"""Actual kernel ingress installation and packet tests in disposable namespaces."""

from tests.test_nftables_live import isolated, pytestmark


LINKS = '''
from smoketests.firewall_support import send_ingress_udp
from smoketests.assertions import assert_firewall_rule_packets
run('ip', 'link', 'add', 'name', 'veth994', 'type', 'veth', 'peer', 'name', 'veth995')
for device in ('veth994', 'veth995'):
    Path('/proc/sys/net/ipv6/conf/' + device + '/disable_ipv6').write_text('1')
    run('ip', 'link', 'set', 'dev', device, 'up')
'''


def test_real_ingress_vlan_maps_groups_and_family_isolation():
    isolated(LINKS + '''
config = {'global-options': {'state-policy': {'established': {'action': 'accept'}}},
          'group': {'map': {}, 'match-group': {}}}
for family in ('ipv4', 'ipv6'):
    config['group']['map'][family] = {'VLAN': {
        'match': {'vlan': {'id': True, 'priority': True}}, 'result-type': 'verdict',
        'entry': {'one': {'vlan': {'id': '100', 'priority': '5'}, 'result': {'action': 'jump', 'jump-target': 'FIRST'}}},
    }}
    config['group']['match-group'][family] = {'EDGE': {
        'match': {'vlan': {'id': True}, 'source-address': True, 'protocol': True, 'destination-port': True},
        'entry': {'one': {'vlan': {'id': '100'}, 'source-address': '192.0.2.0/24' if family == 'ipv4' else '2001:db8::/64',
                          'protocol': 'udp', 'destination-port': '53098'}},
    }}
    config[family] = {
        'name': {
            'FIRST': {'rule': {'10': {'action': 'jump', 'jump-target': 'LAST'}}},
            'LAST': {'rule': {'10': {'match-group': 'EDGE', 'action': 'drop', 'counter': {}}}},
        },
        'ingress': {'filter': {'interface': ['veth995'], 'default-action': 'drop', 'rule': {
            '10': {'vlan': {'id': '100', 'priority': '5'}, 'counter': {}, 'action': 'continue'},
            '20': {'map': 'VLAN'},
        }}},
    }
text = apply(config)
assert 'ct state' not in text
for family in ('ipv4', 'ipv6'):
    send_ingress_udp(family=family, vlan=100, priority=5)
    send_ingress_udp(family=family, vlan=101, priority=5)
    assert_firewall_rule_packets(family + '_ingress', '10', 1, timeout=5)
    assert_firewall_rule_packets(family + '_ingress', 'default', 1, timeout=5)
    assert_firewall_rule_packets(family + '_name_LAST', '10', 1, timeout=5)

# Operational views use the actual installed listing, including VLAN group columns.
import contextlib, io
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.op_scripts import firewall as firewall_op
table = normalize({'nftables': snapshot()}, configuration={'firewall': config})['tables']['inet']['nvyr_filter']
firewall_op._load_table = lambda **kwargs: table
output = io.StringIO()
with contextlib.redirect_stdout(output):
    firewall_op.show(family='ipv4', hook='ingress', stage='filter', rule='10', detail=True)
    firewall_op.show(family='ipv6', section='group', group_kind='map', group_name='VLAN')
assert 'VLAN ID' in output.getvalue(), output.getvalue()
assert 'Unsupported expressions' not in output.getvalue(), output.getvalue()

# Move only IPv6's attachment; IPv4 must continue matching on the original peer.
config['ipv6']['ingress']['filter']['interface'] = ['future*']
apply(config)
send_ingress_udp(family='ipv6', vlan=100, priority=5)
send_ingress_udp(family='ipv4', vlan=100, priority=5)
assert_firewall_rule_packets('ipv4_ingress', '10', 2, timeout=5)
assert_firewall_rule_packets('ipv6_ingress', '10', 0)

# Replacing and removing a shared map rebuilds its consumers in one transaction.
config['group']['map']['ipv4']['VLAN']['entry']['one']['vlan']['id'] = '101'
apply(config)
send_ingress_udp(vlan=100, priority=5)
assert_firewall_rule_packets('ipv4_ingress', 'default', 1, timeout=5)
apply({})
assert not any(item.get('chain', {}).get('name') == 'ingress' for item in snapshot())
''')


def test_real_ingress_future_attachment_and_rate_quota_learning():
    isolated('''
from smoketests.firewall_support import send_ingress_udp
from smoketests.assertions import assert_firewall_rule_packets
config = {
    'group': {'address-group': {'ipv4': {'LEARNED': {'dynamic': {}}}},
              'limit-group': {'ipv4': {'RATE': {'rate': {'packets': '1/m'}, 'burst': {'packets': '1'}, 'per': 'source-address'}}},
              'quota-group': {'CAP': {'bytes': '1m'}}},
    'ipv4': {'ingress': {'filter': {'interface': ['veth99*'], 'default-action': 'drop', 'rule': {
        '10': {'protocol': ['udp'], 'destination-port': ['53098'], 'limit': {'group': 'RATE'},
               'quota': {'group': 'CAP'}, 'add-to-group': {'source-address': 'LEARNED'},
               'counter': {}, 'log': {}, 'notrack': True, 'action': 'drop'},
    }}}},
}
apply(config)
''' + LINKS + '''
send_ingress_udp()
send_ingress_udp()
assert_firewall_rule_packets('ipv4_ingress', '10', 1, timeout=5)
assert_firewall_rule_packets('ipv4_ingress', 'default', 1, timeout=5)
assert '192.0.2.1' in run('nft', 'list', 'set', 'inet', 'nvyr_filter', 'ipv4_address_group_LEARNED')
assert 'ipv4-ING-filter-10-D' in run('nft', 'list', 'chain', 'inet', 'nvyr_filter', 'ipv4_ingress')

# Device deletion/recreation must reattach the wildcard without a firewall commit.
config['ipv4']['ingress']['filter']['rule'] = {}
apply(config)
run('ip', 'link', 'del', 'dev', 'veth994')
''' + LINKS + '''
send_ingress_udp()
assert_firewall_rule_packets('ipv4_ingress', 'default', 1, timeout=5)
apply({})
''')


def test_real_ingress_reject_responses_and_priority():
    isolated(LINKS + '''
responses = {
    'ipv4': ('port-unreachable', 'admin-prohibited', 'no-route', 'host-unreachable', 'tcp-reset',
             'net-unreachable', 'prot-unreachable', 'frag-needed', 'net-prohibited', 'host-prohibited'),
    'ipv6': ('port-unreachable', 'admin-prohibited', 'no-route', 'host-unreachable', 'tcp-reset',
             'addr-unreachable', 'policy-fail', 'reject-route'),
}

# Install each schema-exposed response; --check alone misses hook validation errors.
for family in ('ipv4', 'ipv6'):
    for response in responses[family]:
        rule = {'action': 'reject', 'reject-response': response}
        if response == 'tcp-reset':
            rule['protocol'] = ['tcp']
        config = {family: {'ingress': {'filter': {'interface': ['veth995'], 'rule': {'10': rule}}}}}
        apply(config)

# Ingress filtering precedes the native flowtable priority, even on shared devices.
config = {'flowtable': {'FAST': {'interface': ['veth995']}},
          'ipv4': {'ingress': {'filter': {'interface': ['veth995'], 'default-action': 'drop'}}}}
apply(config)
chain = next(item['chain'] for item in snapshot() if item.get('chain', {}).get('name') == 'ingress')
flow = next(item['flowtable'] for item in snapshot() if 'flowtable' in item)
assert chain['prio'] < flow['prio']
send_ingress_udp()
assert_firewall_rule_packets('ipv4_ingress', 'default', 1, timeout=5)
apply({})
''')
