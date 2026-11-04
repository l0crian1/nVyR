"""Operator syntax and authorization at the boundary with the bond command."""

import pytest

from nvyr.cli import completion_rows
from nvyr.errors import RouterError
from nvyr.helpers import access
from nvyr.op_scripts import bond


def test_bond_views_take_the_name_directly(controller, monkeypatch):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    controller.execute('show interfaces bond')
    controller.execute('show interfaces bond bond0 lacp')
    controller.execute('show interfaces bond bond0 lacp detail')
    controller.execute('show interfaces bond bond0 member eth2')
    assert calls == [
        ['bond.nvyr.op', 'show'],
        ['bond.nvyr.op', 'show', '--bond', 'bond0', '--section', 'lacp'],
        ['bond.nvyr.op', 'show', '--bond', 'bond0', '--section', 'lacp', '--detail'],
        ['bond.nvyr.op', 'show', '--bond', 'bond0', '--member', 'eth2'],
    ]
    candidates = dict(completion_rows(controller.completion('show interfaces bond ', explicit=True)))
    assert '<bondN>' in candidates
    assert 'bond-name' not in candidates and 'identifier' not in candidates


def test_lacp_distinguishes_missing_state_from_clear_flags(monkeypatch):
    ports = [
        {'Slave Interface': 'eth2', 'Aggregator ID': '1', 'actor': {'port state': '63', 'port key': '15'},
         'partner': {'port state': '8', 'oper key': '27', 'system mac address': '02:00:00:00:00:01'}},
        {'Slave Interface': 'eth3', 'Aggregator ID': '1', 'actor': {'port state': '0'}},
    ]
    monkeypatch.setattr(bond, 'report', lambda name: ({'Bonding Mode': 'IEEE 802.3ad'}, ports))

    summary = bond.show('bond0', section='lacp')
    rows = [line.split() for line in summary.splitlines() if line.startswith('eth')]
    assert rows == [
        ['eth2', '1', '02:00:00:00:00:01', 'SCD', 'S--'],
        ['eth3', '1', 'Unknown', '---', 'Unknown'],
    ]
    assert 'S = synchronized, C = collecting, D = distributing' in summary

    detail = bond.show('bond0', section='lacp', detail=True)
    first, second = detail.split('\n\n')
    first_rows = [line.split() for line in first.splitlines()]
    assert ['Key', '15', '27'] in first_rows
    assert ['Collecting', 'Yes', 'No'] in first_rows
    assert ['Activity', 'Passive', 'Unknown'] in [line.split() for line in second.splitlines()]


def test_active_member_selection_requires_management_access(controller, monkeypatch):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    command = 'reset interfaces bond bond0 active-member eth3'
    token = access.role.set('read-only')
    try:
        with pytest.raises(RouterError, match='requires net-admin'):
            controller.execute(command)
    finally:
        access.role.reset(token)

    token = access.role.set('net-admin')
    try:
        controller.execute(command)
    finally:
        access.role.reset(token)
    assert calls == [['bond.nvyr.op', 'select', 'bond0', 'eth3']]
