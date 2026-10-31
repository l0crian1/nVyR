"""Validate actual generated NFLOG batches against the native nftables parser."""

from tests.test_nftables_live import isolated, pytestmark


LOGGING = '''
from dataclasses import replace
from nvyr.config_scripts import firewall_failsafe

(directory / 'logging').mkdir()
(directory / 'logging' / 'groups.json').write_text(json.dumps({
    'normal:TEST': 37, 'failsafe:TEST': 41, 'normal:DEFAULT': 42,
}))

def install_logging(configuration, *, failsafe=False):
    schema = Schema.bundled()
    schema.validate_configuration(configuration)
    effective = ReadOnlyTree(schema.defaults(configuration))
    owner = firewall_failsafe if failsafe else firewall
    name = 'firewall_failsafe' if failsafe else 'firewall'
    root = firewall_failsafe.ROOT if failsafe else ('firewall',)
    context = firewall_context(effective, {}, name, root,
                               previous_effective=schema.defaults({}), schema=schema)
    context = replace(context, state_directory=directory)
    selected = owner.get_config(context) if failsafe else effective
    owner.verify(selected, context)
    rendered = owner.generate(selected, context)
    Manager().apply(rendered, directory, owner=name)

    logs = {}
    for item in snapshot():
        rule = item.get('rule', {})
        for expression in rule.get('expr', []):
            if 'log' in expression:
                logs[rule['chain']] = expression['log']
    return logs

def assert_log(log, group, snaplen, threshold):
    assert log['group'] == group, log
    assert log['snaplen'] == snaplen, log
    assert log['queue-threshold'] == threshold, log
'''


def test_generated_filter_raw_and_named_chain_nflog():
    """Default and custom settings survive generation, parsing and kernel readback."""
    isolated(LOGGING + '''
logs = install_logging({'firewall': {
    'group': {'log-group': {'TEST': {'snaplen': '128', 'queue-threshold': '2'}, 'DEFAULT': {}}},
    'ipv4': {'input': {'filter': {'rule': {
        '10': {'action': 'accept', 'connection': {'state': ['new']}, 'log': {'group': 'TEST'}},
    }}}},
    'ipv6': {
        'output': {'raw': {'rule': {'10': {'action': 'accept', 'log': {'group': 'DEFAULT'}}}}},
        'input': {'filter': {'rule': {'10': {'action': 'jump', 'jump-target': 'LOGGED'}}}},
        'name': {'LOGGED': {'rule': {'10': {'action': 'accept', 'log': {'group': 'TEST'}}}}},
    },
}})
assert_log(logs['ipv4_input'], 37, 128, 2)
assert_log(logs['ipv6_output_raw'], 42, 65535, 1)
assert_log(logs['ipv6_name_LOGGED'], 37, 128, 2)
''')


def test_generated_nat_nflog():
    """NAT consumers receive the same resolved NFLOG settings as filter rules."""
    isolated(LOGGING + '''
logs = install_logging({
    'firewall': {'group': {'log-group': {'TEST': {'snaplen': '256', 'queue-threshold': '3'}}}},
    'nat': {
        'source': {'rule': {'10': {'outbound-interface': ['lo'],
                                  'translation': {'address': '192.0.2.1'}, 'log': {'group': 'TEST'}}}},
        'destination': {'rule': {'10': {'inbound-interface': ['lo'],
                                       'translation': {'address': '192.0.2.2'}, 'log': {'group': 'TEST'}}}},
    },
})
assert len(logs) == 2, logs
for log in logs.values():
    assert_log(log, 37, 256, 3)
''')


def test_generated_failsafe_nflog_uses_its_own_subscription():
    """Same-named normal and early groups never send packets to each other's ID."""
    isolated(LOGGING + '''
logs = install_logging({'firewall': {
    'group': {'log-group': {'TEST': {'snaplen': '128'}}},
    'fail-safe': {
        'group': {'log-group': {'TEST': {}}},
        'ipv4': {'input': {'filter': {'rule': {'10': {'action': 'accept', 'log': {'group': 'TEST'}}}}}},
    },
}}, failsafe=True)
assert_log(logs['ipv4_input'], 41, 65535, 1)
''')
