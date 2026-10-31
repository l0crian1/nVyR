"""Native trace capture and VRF probe wrappers inside an isolated network namespace."""

from tests.test_nftables_live import isolated, pytestmark


PACKET_TEST = '''
import os, shutil
from build_tools.op_scripts import install_scripts
from nvyr.op_scripts import firewall_trace, ping, traceroute
from nvyr.helpers.nftables_normalizer import normalize
from smoketests.assertions import assert_firewall_trace_capture, assert_probe_command

source = directory / 'scripts'
source.mkdir()
for module in (firewall_trace, ping, traceroute):
    shutil.copyfile(module.__file__, source / Path(module.__file__).name)
install_scripts(source, directory / 'bin')
os.environ['PATH'] = str(directory / 'bin') + ':' + os.environ['PATH']
run('ip', 'link', 'set', 'lo', 'up')

for family, address, protocol in [('ipv4', '127.0.0.1', 'icmp'), ('ipv6', '::1', 'ipv6-icmp'),
                                  ('inet', '127.0.0.1', 'icmp')]:
    config = {family: {'output': {'filter': {'rule': {
        '10': {'nftrace': True, 'protocol': [protocol], 'action': 'jump', 'jump-target': 'TRACE'}}}},
        'name': {'TRACE': {'rule': {'20': {'nftrace': True, 'action': 'accept'}}}}}}
    apply(config)
    assert_firewall_trace_capture(address, f'firewall {family} name TRACE rule 20')
    table = normalize({'nftables': snapshot()})['tables']['inet']['nvyr_filter']
    rule = table['chains'][family + '_name_TRACE']['rules'][0]
    assert rule['nftrace'] is True and 'unsupported' not in rule, rule

# The probe target exists only in BLUE, so the wrapper must bind the correct domain.
apply({})
run('ip', 'link', 'add', 'BLUE', 'type', 'vrf', 'table', '198')
run('ip', 'link', 'set', 'BLUE', 'up')
run('ip', 'link', 'add', 'probe0', 'type', 'dummy')
run('ip', 'link', 'set', 'probe0', 'master', 'BLUE')
run('ip', 'link', 'set', 'probe0', 'up')
run('ip', 'addr', 'add', '198.18.110.1/24', 'dev', 'probe0')
run('ip', '-6', 'addr', 'add', '2001:db8:110::1/64', 'dev', 'probe0', 'nodad')
assert_probe_command('ping 198.18.110.1 vrf BLUE count 1 deadline 3 numeric', '198.18.110.1')
assert_probe_command('ping 2001:db8:110::1 vrf BLUE ipv6 count 1 deadline 3 numeric', '2001:db8:110::1')
assert_probe_command('traceroute 198.18.110.1 vrf BLUE no-resolve icmp probes 1 max-ttl 1 wait 1', '198.18.110.1')
assert_probe_command('traceroute 2001:db8:110::1 vrf BLUE ipv6 no-resolve icmp probes 1 max-ttl 1 wait 1', '2001:db8:110::1')
result = subprocess.run(ping._argv('ping 127.0.0.1 vrf MISSING count 1'), capture_output=True, text=True)
assert result.returncode != 0, result
assert 'Invalid VRF' in result.stderr, result.stderr
'''


def test_native_traces_and_vrf_probes():
    """Exercise native parsing, installed commands, timed saves and both VRF families."""
    isolated(PACKET_TEST)
