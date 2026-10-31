"""Opt-in native enrollment, lifecycle, and interface display checks."""

from tests.test_nftables_live import isolated, pytestmark


def test_global_flowtable_native_order_and_lifecycle():
    isolated('''
from nvyr.helpers.nftables_normalizer import normalize
run('ip', 'link', 'add', 'dum0', 'type', 'dummy')
run('ip', 'link', 'add', 'dum1', 'type', 'dummy')
run('ip', 'link', 'set', 'dum0', 'up')
run('ip', 'link', 'set', 'dum1', 'up')
config = {
    'flowtable': {'FAST': {'interface': ['dum0']}},
    'global-options': {'flowtable': 'FAST', 'state-policy': {'established': {'action': 'accept'}}},
    'ipv4': {'input': {'filter': {}}, 'output': {'filter': {}}},
}
apply(config)
forward = run('nft', 'list', 'chain', 'inet', 'nvyr_filter', 'forward')
assert forward.index('flow add @flowtable_FAST') < forward.index('ct state vmap')
assert 'flow add' not in run('nft', 'list', 'chain', 'inet', 'nvyr_filter', 'input')
assert 'flow add' not in run('nft', 'list', 'chain', 'inet', 'nvyr_filter', 'output')
table = normalize({'nftables': snapshot()})['tables']['inet']['nvyr_filter']
rule = table['chains']['forward']['rules'][0]
assert rule['action'] == 'offload' and rule['offload-target'] == 'FAST', rule
assert 'unsupported' not in rule

# Device changes release the forward rule before replacing its native flowtable.
config['flowtable']['FAST']['interface'] = ['dum1']
apply(config)
assert 'dum1' in run('nft', 'list', 'flowtable', 'inet', 'nvyr_filter', 'flowtable_FAST')

# Removing global enrollment retains explicitly configured non-forward hooks.
del config['global-options']['flowtable']
del config['flowtable']
apply(config)
assert 'flowtable_FAST' not in run('nft', 'list', 'ruleset')
assert 'chain input' in run('nft', 'list', 'ruleset')
''')


def test_interface_display_reads_native_vrf_slave_data():
    isolated('''
from nvyr.op_scripts.interfaces import _get_kernel_data
run('ip', 'link', 'add', 'BLUE', 'type', 'vrf', 'table', '100')
run('ip', 'link', 'add', 'dum0', 'type', 'dummy')
run('ip', 'link', 'set', 'dum0', 'master', 'BLUE')
raw, rows = _get_kernel_data(False, ifname='dum0')
assert rows[0][3] == 'BLUE', rows
raw, rows = _get_kernel_data(False)
assert next(row for row in rows if row[0] == 'dum0')[3] == 'BLUE'
assert all(row[0] != 'BLUE' for row in rows)
run('ip', 'link', 'set', 'dum0', 'nomaster')
raw, rows = _get_kernel_data(False, ifname='dum0')
assert rows[0][3] == 'default'
''')
