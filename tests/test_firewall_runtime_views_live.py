"""Native nftables runtime reports in disposable network namespaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires isolated privileged nftables container')


def exercise_runtime_views(family, address):
    """Create real bucket/connection state and quota usage, then read without mutation."""
    isolated(f'family = {family!r}\naddress = {address!r}\n' + r"""
import contextlib, io, socket
from nvyr.helpers.nftables_normalizer import normalize
from nvyr.op_scripts import firewall as operational

run('ip', 'link', 'set', 'lo', 'up')
protocol = 'ip' if family == 'ipv4' else 'ip6'
rules = f'''
table inet nvyr_filter {{
 set rule_limit_{family}_output_10 {{
  type {family}_addr . inet_service
  flags dynamic,timeout
  timeout 1m
  size 100
 }}
 set rule_connection_limit_{family}_output_10 {{
  type {family}_addr
  flags dynamic
  size 100
 }}
 set {family}_limit_group_SHARED {{
  type {family}_addr
  flags dynamic,timeout
  timeout 1m
  size 200
 }}
 quota quota_group_TOTAL {{ over 1 mbytes; }}
 chain {family}_name_POLICY {{
  quota name quota_group_TOTAL continue comment "30|"
 }}
 chain {family}_output {{
  type filter hook output priority 0; policy accept;
  udp dport 53001-53002 update @rule_limit_{family}_output_10 {{ {protocol} saddr . udp dport limit rate 10/second burst 5 packets }} add @rule_connection_limit_{family}_output_10 {{ {protocol} saddr ct count over 5 }} continue comment "10|"
  udp dport 53001-53002 update @{family}_limit_group_SHARED {{ {protocol} saddr limit rate 10/second }} continue comment "20|"
  udp dport 53001-53002 quota over 1 mbytes continue comment "25|"
  udp dport 53001-53002 jump {family}_name_POLICY comment "40|"
 }}
}}
'''
subprocess.run(['nft', '-f', '-'], input=rules, text=True, check=True)
af = socket.AF_INET if family == 'ipv4' else socket.AF_INET6
with socket.socket(af, socket.SOCK_DGRAM) as first, socket.socket(af, socket.SOCK_DGRAM) as second:
    first.bind((address, 53001))
    second.bind((address, 53002))
    with socket.socket(af, socket.SOCK_DGRAM) as sender:
        sender.sendto(b'firewall-runtime-test', (address, 53001))
        sender.sendto(b'firewall-runtime-test', (address, 53002))
    first.recv(100)
    second.recv(100)

table = normalize(json.loads(run('nft', '-j', 'list', 'ruleset')))['tables']['inet']['nvyr_filter']
operational._load_table = lambda: table
state = json.loads(operational.runtime('limit', family, hook='output', rule='10', raw=True))
rate, connection = state[0]['records']
assert not state[0]['incomplete'], state
assert rate['active-keys'] == 2, rate
assert sorted(entry['key'] for entry in rate['entries']) == [[address, 53001], [address, 53002]]
assert all(0 < entry['expires'] <= 60 for entry in rate['entries']), rate
assert connection['active-keys'] == 1, connection
assert 'timeout' not in connection
shared = json.loads(operational.runtime('limit', family, hook='output', rule='20', raw=True))
assert shared[0]['records'][0]['group'] == 'SHARED'
assert shared[0]['records'][0]['active-keys'] == 1

quota = json.loads(operational.runtime('quota', family, hook='output', rule='25', raw=True))[0]['records'][0]
assert quota['used'] > 0 and quota['remaining'] == quota['bytes'] - quota['used'], quota
named = json.loads(operational.runtime('quota', family, named=True, chain_name='POLICY', raw=True))[0]['records'][0]
assert named['group'] == 'TOTAL' and named['used'] == quota['used'], named

before = run('nft', '-j', 'list', 'quota', 'inet', 'nvyr_filter', 'quota_group_TOTAL')
with contextlib.redirect_stdout(io.StringIO()) as output:
    operational.runtime('limit', family, hook='output', rule='10')
    operational.runtime('quota', family, named=True, chain_name='POLICY')
text = output.getvalue()
assert address in text and 'Expires' in text and 'Remaining' in text, text
assert before == run('nft', '-j', 'list', 'quota', 'inet', 'nvyr_filter', 'quota_group_TOTAL')
""")


def test_ipv4_runtime_keys_and_quotas():
    """IPv4 packet activity is visible through rule and named-chain selectors."""
    exercise_runtime_views('ipv4', '127.0.0.1')


def test_ipv6_runtime_keys_and_quotas():
    """IPv6 concatenated keys and named shared state retain their address family."""
    exercise_runtime_views('ipv6', '::1')
