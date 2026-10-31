"""Routing-rule ordering, failure safety and repeatable VRF reconciliation."""

from copy import deepcopy
import socket

import pytest

from nvyr.errors import RouterError
from nvyr.helpers.vrf_rules import matches, reconcile


class Rule(dict):
    def get_attr(self, name):
        return dict(self['attrs']).get(name)


class RuleSocket:
    """In-memory RTNL rule inventory with the same defaults as Linux."""

    def __init__(self):
        self.rules = []
        self.calls = []
        for family in (socket.AF_INET, socket.AF_INET6):
            self.rule('add', family=family, priority=0, table=255)
            self.rule('add', family=family, priority=32766, table=254)
        self.calls.clear()

    def get_rules(self, *, family):
        return deepcopy([rule for rule in self.rules if rule['family'] == family])

    def rule(self, operation, *, family, priority, table=0, action=1, l3mdev=0):
        self.calls.append((operation, family, priority))
        definition = dict(priority=priority, table=table, action=action, l3mdev=l3mdev)
        if operation == 'del':
            rule = next(rule for rule in self.rules if rule['family'] == family and matches(rule, **definition))
            self.rules.remove(rule)
            return

        self.rules.append(Rule(family=family, table=table, action=action,
                               attrs=[('FRA_PRIORITY', priority), ('FRA_TABLE', table),
                                      ('FRA_L3MDEV', l3mdev), ('FRA_PROTOCOL', 2),
                                      ('FRA_SUPPRESS_PREFIXLEN', 4294967295)]))


def dump(method, **arguments):
    return tuple(method(**arguments))


def test_rule_order_idempotence_and_drift_repair():
    """Both families retain local delivery and get the scoped no-fallback rule."""
    ipr = RuleSocket()
    reconcile(ipr, dump)

    for family in (socket.AF_INET, socket.AF_INET6):
        rules = sorted(ipr.get_rules(family=family), key=lambda rule: rule.get_attr('FRA_PRIORITY'))
        assert [rule.get_attr('FRA_PRIORITY') for rule in rules] == [1000, 2000, 32765, 32766]
        assert matches(rules[0], priority=1000, l3mdev=1)
        assert matches(rules[1], priority=2000, l3mdev=1, action=7)
        assert matches(rules[2], priority=32765, table=255)
        assert ipr.calls.index(('add', family, 32765)) < ipr.calls.index(('del', family, 0))

    ipr.calls.clear()
    reconcile(ipr, dump)
    assert not ipr.calls

    ipr.rule('del', family=socket.AF_INET6, priority=2000, l3mdev=1, action=7)
    ipr.rule('add', family=socket.AF_INET, priority=0, table=255)
    reconcile(ipr, dump)
    assert any(matches(rule, priority=2000, l3mdev=1, action=7)
               for rule in ipr.get_rules(family=socket.AF_INET6))
    assert not any(matches(rule, priority=0, table=255) for rule in ipr.rules)


def test_failed_local_replacement_keeps_original_lookup(monkeypatch):
    """An interrupted installation never removes the only local-table lookup."""
    ipr = RuleSocket()
    original = ipr.rule

    def fail(operation, **arguments):
        if operation == 'add' and arguments['priority'] == 32765:
            raise OSError('injected failure')
        return original(operation, **arguments)

    monkeypatch.setattr(ipr, 'rule', fail)
    with pytest.raises(OSError, match='injected failure'):
        reconcile(ipr, dump)
    assert len([rule for rule in ipr.rules if matches(rule, priority=0, table=255)]) == 2

    monkeypatch.setattr(ipr, 'rule', original)
    reconcile(ipr, dump)
    assert len([rule for rule in ipr.rules if matches(rule, priority=32765, table=255)]) == 2


def test_reserved_priority_conflict_is_reported_without_mutations():
    """Do not mistake a user's selected lookup for the unconditional local rule."""
    ipr = RuleSocket()
    ipr.rule('add', family=socket.AF_INET6, priority=32765, table=255)
    ipr.rules[-1]['attrs'].append(('FRA_FWMARK', 42))
    ipr.calls.clear()

    with pytest.raises(RouterError, match='IPv6 routing-rule priority 32765'):
        reconcile(ipr, dump)
    assert not ipr.calls


def test_selected_priority_zero_local_rule_is_preserved():
    """Only the kernel's unconditional rule is relocated."""
    ipr = RuleSocket()
    ipr.rules[0]['attrs'].append(('FRA_IIFNAME', 'eth9'))
    reconcile(ipr, dump)
    assert ipr.rules[0].get_attr('FRA_IIFNAME') == 'eth9'
