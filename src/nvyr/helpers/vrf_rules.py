"""Shared IPv4/IPv6 routing policy for VRF isolation and local delivery."""

import socket

from nvyr.errors import RouterError

# RTNL fib-rule actions from linux/fib_rules.h.
LOOKUP = 1
UNREACHABLE = 7


def matches(message, *, priority, table=0, action=LOOKUP, l3mdev=0):
    """Identify an unconditional rule without mistaking a selected rule for it."""
    if any(message.get(key, 0) for key in ('src_len', 'dst_len', 'tos', 'flags')):
        return False

    attributes = dict(message['attrs'])
    actual = (attributes.pop('FRA_PRIORITY', 0), attributes.pop('FRA_TABLE', message['table']),
              message['action'], attributes.pop('FRA_L3MDEV', 0))
    attributes.pop('FRA_PROTOCOL', None)
    attributes.pop('FRA_PAD', None)

    # The kernel reports disabled suppressors as UINT32_MAX, not as selectors.
    for key in ('FRA_SUPPRESS_PREFIXLEN', 'FRA_SUPPRESS_IFGROUP'):
        if attributes.get(key) == 4294967295:
            attributes.pop(key)

    return actual == (priority, table, action, l3mdev) and not attributes


def reconcile(ipr, dump):
    """Install VRF lookup, scoped failure, then local lookup without a local gap.

    These are a shared routing baseline, retained when the last VRF is deleted.
    With no VRF, l3mdev rules do not match and ordinary local/main routing remains.
    Reconciliation is repeatable after a partial failure or daemon restart.
    """
    desired = (
        {'priority': 1000, 'table': 0, 'action': LOOKUP, 'l3mdev': 1},
        {'priority': 2000, 'table': 0, 'action': UNREACHABLE, 'l3mdev': 1},
        {'priority': 32765, 'table': 255, 'action': LOOKUP},
    )
    inventories = {family: dump(ipr.get_rules, family=family)
                   for family in (socket.AF_INET, socket.AF_INET6)}

    # Do not overwrite unrelated policy at the priorities reserved for this baseline.
    for family, rules in inventories.items():
        for definition in desired:
            for rule in rules:
                if rule.get_attr('FRA_PRIORITY') == definition['priority'] and not matches(rule, **definition):
                    raise RouterError(f'IPv{4 if family == socket.AF_INET else 6} routing-rule priority '
                                      f'{definition["priority"]} is occupied by another policy')

    for family, rules in inventories.items():
        for definition in desired:
            if not any(matches(rule, **definition) for rule in rules):
                ipr.rule('add', family=family, **definition)

        # Only remove the original unconditional local rule after its replacement
        # and the isolation guard have been acknowledged by the kernel.
        for rule in rules:
            if matches(rule, priority=0, table=255):
                ipr.rule('del', family=family, priority=0, table=255, action=LOOKUP)
