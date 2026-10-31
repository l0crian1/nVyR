"""DNS set population and packet decisions against the pinned nftables release."""

import os
import pytest

from tests.test_firewall_maps_live import isolated

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_NETWORK_TEST') != '1',
                                reason='requires an isolated privileged nftables container')


def exercise(family, address, replacement, version):
    isolated(f'''
from dataclasses import replace
from types import SimpleNamespace
import threading
from nvyr.helpers import domain_groups, nftables
from nvyr.helpers.nftables_normalizer import normalize
run('ip', 'link', 'set', 'lo', 'up')
family, address, replacement, version = {family!r}, {address!r}, {replacement!r}, {version!r}
manager = domain_groups.Manager(directory / 'dns')
domain_groups.manager = manager
answers = [address]
class Resolver:
    def resolve(self, *args, **kwargs):
        return [SimpleNamespace(address=value) for value in answers]
domain_groups.dns.resolver.Resolver = Resolver

tree = {{'firewall': {{'group': {{'domain-group': {{family: {{
    'CHILD': {{'domain': ['api.example.com']}},
    'PARENT': {{'include-group': ['CHILD'], 'counter': True, 'last-used': True}},
}}}}}}, family: {{'output': {{'filter': {{'rule': {{
    '10': {{'action': 'drop', 'destination-domain-group': 'PARENT', 'counter': {{}}}}
}}}}}}}}}}}}
effective = ReadOnlyTree(schema.defaults(tree))
context = replace(firewall_context(effective, {{}}, 'firewall', ('firewall',), False,
                                  previous_effective={{}}), state_directory=directory)
firewall.verify(effective, context)
firewall.apply(firewall.generate(effective, context), context)

def ping():
    return subprocess.run(['ping', version, '-c', '1', '-W', '1', address], capture_output=True).returncode
assert ping() != 0
before = json.loads(run('nft', '-j', '-a', 'list', 'chain', 'inet', 'nvyr_filter', family + '_output'))
set_name = family + '_domain_group_PARENT'
assert 'counter packets 1' in run('nft', 'list', 'set', 'inet', 'nvyr_filter', set_name)
assert set_name in Manager().singleton_groups()
normalized = normalize(json.loads(run('nft', '-j', 'list', 'ruleset')), configuration=tree)
assert 'domain-group' in json.dumps(normalized)

# Updating DNS membership leaves the chain and its counters in place.
engine = SimpleNamespace(mutex=threading.RLock(), running=tree, busy=False, unhealthy=False,
                         store=SimpleNamespace(directory=directory))
answers[:] = [replacement]
assert 'refreshed 2' in manager.update(engine, family, 'CHILD')['text']
after = json.loads(run('nft', '-j', '-a', 'list', 'chain', 'inet', 'nvyr_filter', family + '_output'))
assert before == after
assert replacement in run('nft', 'list', 'set', 'inet', 'nvyr_filter', set_name)
assert ping() == 0

# An outage retains the last successful membership.
def failed(*args, **kwargs):
    raise OSError('resolver unavailable')
Resolver.resolve = failed
assert 'Warning:' in manager.update(engine)['text']
assert replacement in run('nft', 'list', 'set', 'inet', 'nvyr_filter', set_name)

# Recovery discovers and removes abandoned DNS sets as owned objects.
apply({{}}, recovery=True)
assert not Manager().singleton_groups()
''')


def test_ipv4_dns_sets_refresh_packet_matching():
    exercise('ipv4', '127.0.0.1', '192.0.2.1', '-4')


def test_ipv6_dns_sets_refresh_packet_matching():
    exercise('ipv6', '::1', '2001:db8::1', '-6')
