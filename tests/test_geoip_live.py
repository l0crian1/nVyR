"""GeoIP refreshes against native nftables in disposable network namespaces."""

import os

import pytest

from tests.test_firewall_maps_live import isolated


pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires an isolated privileged nftables container')


def refresh(family, address, replacement, version):
    isolated(f'''
import gzip, threading
from dataclasses import replace
from types import SimpleNamespace
from nvyr.helpers import geoip, nftables
from tests.test_geoip import page, release

run('ip', 'link', 'set', 'lo', 'up')
geoip.manager = geoip.Manager(directory / 'geoip')
first = b'127.0.0.1,127.0.0.1,US\\n::1,::1,US\\n'
second = first.replace(b'{address},{address}', b'{replacement},{replacement}')
current_payload = first

def fetch(url, destination, limit):
    metadata = release(current_payload)
    destination.write(page(metadata) if url == geoip.PAGE else gzip.compress(current_payload))

geoip.fetch = fetch
tree = {{'firewall': {{'group': {{'address-group': {{'{family}': {{'LOCAL': {{'geoip': {{'country': ['US']}}}}}}}}}},
                    '{family}': {{'output': {{'filter': {{'rule': {{'10': {{'destination-address-group': 'LOCAL', 'action': 'drop', 'counter': {{}}}}}}}}}}}}}}}}
effective = schema.defaults(tree)
context = replace(firewall_context(effective, {{}}, 'firewall', ('firewall',), previous_effective={{}}), state_directory=directory)
firewall.verify(effective, context)
firewall.apply(firewall.generate(effective, context), context)

def ping():
    return subprocess.run(['ping', '{version}', '-c', '1', '-W', '1', '{address}'], capture_output=True).returncode

assert ping() != 0
native = '{family}_address_group_LOCAL'
before = json.loads(run('nft', '-j', 'list', 'set', 'inet', 'nvyr_filter', native))['nftables'][1]['set']
rules = run('nft', '-a', 'list', 'chain', 'inet', 'nvyr_filter', '{family}_output')
assert 'counter packets 1' in rules

# A database refresh updates membership while retaining the referenced set and chain.
engine = SimpleNamespace(running=tree, mutex=threading.RLock(), busy=False, unhealthy=False,
                         store=SimpleNamespace(directory=directory))
current_payload = second
assert 'refreshed 1' in geoip.manager.update(engine)['text']
after = json.loads(run('nft', '-j', 'list', 'set', 'inet', 'nvyr_filter', native))['nftables'][1]['set']
assert before['handle'] == after['handle']
assert run('nft', '-a', 'list', 'chain', 'inet', 'nvyr_filter', '{family}_output') == rules
assert ping() == 0
assert 'unchanged' in geoip.manager.update(engine)['text']

# A failing batch that starts by flushing must leave the previous membership intact.
old_set = run('nft', 'list', 'set', 'inet', 'nvyr_filter', native)
try:
    nftables.manager.apply('flush set inet nvyr_filter ' + native + '\\nadd element inet nvyr_filter missing {{ 192.0.2.1 }}', directory, owner='geoip')
except RouterError:
    pass
else:
    raise AssertionError('invalid batch was accepted')
assert run('nft', 'list', 'set', 'inet', 'nvyr_filter', native) == old_set
''')


def test_ipv4_geoip_refresh_preserves_rules_and_rolls_back_failed_batch():
    refresh('ipv4', '127.0.0.1', '192.0.2.1', '-4')


def test_ipv6_geoip_refresh_preserves_rules_and_rolls_back_failed_batch():
    refresh('ipv6', '::1', '2001:db8::1', '-6')


def test_interval_automerge_across_multiple_insert_commands():
    isolated('''
from nvyr.helpers.geoip import elements
from nvyr.helpers.nftables_formatters import nft_singleton_group
import ipaddress

groups = {('ipv4', 'MERGE'): ('US',)}
base = int(ipaddress.ip_address('192.0.2.0'))
members = {('ipv4', 'MERGE'): [str(ipaddress.ip_address(base + index)) for index in range(2001)]}
definition = nft_singleton_group('address-group', 'ipv4', 'MERGE', {})
Manager().apply('add table inet nvyr_filter\\ntable inet nvyr_filter {\\n' + definition + '\\n}\\n' + elements(groups, members), directory)
listing = run('nft', 'list', 'set', 'inet', 'nvyr_filter', 'ipv4_address_group_MERGE')
assert '192.0.2.0-192.0.9.208' in listing, listing
''')
