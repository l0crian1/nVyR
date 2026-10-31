#!/usr/bin/env python3
"""Show installed NAT rules using the shared nftables normalizer."""

import json

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import OperationalError
from nvyr.op_scripts import firewall


@opmode.command
def show(*, direction: str, rule: str = None, detail: bool = False, raw: bool = False):
    """Preserve native rule order and distinguish missing counters from zero traffic."""
    # Only the two supported NAT hooks have nVyR-managed rule chains.
    if direction not in ('source', 'destination'):
        raise OperationalError('Choose source or destination NAT.')
    hook = 'postrouting' if direction == 'source' else 'prerouting'
    table = firewall._load_table(read_configuration=False)
    rules = table.get('chains', {}).get(f'ipv4_nat_{hook}', {}).get('rules', [])
    if rule is not None:
        rules = [record for record in rules if record.get('number') == str(rule)]
        if not rules:
            raise OperationalError(f'Rule {rule} is not installed in {direction} NAT.')
    if raw:
        return json.dumps(rules)

    firewall._section_heading(direction.capitalize() + ' NAT')
    if not rules:
        print('No rules installed.')
        return
    if detail:
        for record in rules:
            firewall._rule_detail(record, False)
        return

    rows = []
    for record in rules:
        translation = record.get('translation', {})
        target = 'map ' + record['map'] if 'map' in record else firewall._value(translation, 'translation', False)
        if not translation and 'map' not in record:
            target = firewall.MISSING
        counters = record.get('counter', {})
        action = record.get('action', firewall.MISSING)
        if action == 'return':
            action = 'exclude'
        if record.get('unsupported'):
            action += ' [incomplete]'
        rows.append([record.get('number', firewall.MISSING), action, target,
                     counters.get('packets', firewall.MISSING), counters.get('bytes', firewall.MISSING),
                     firewall._last_used(record), record.get('description', '')])
    print(tabulate(rows, headers=['Rule', 'Action', 'Translation', 'Packets', 'Bytes', 'Last used', 'Description'],
                   disable_numparse=True))
    if any(record.get('unsupported') for record in rules):
        print('Warning: unsupported expressions are present; this display is incomplete.')


if __name__ == '__main__':
    opmode.run()
