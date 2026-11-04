"""Operator syntax and authorization at the boundary with the bond command."""

import pytest

from nvyr.cli import completion_rows
from nvyr.errors import RouterError
from nvyr.helpers import access


def test_bond_views_take_the_name_directly(controller, monkeypatch):
    calls = []
    monkeypatch.setattr('nvyr.controller.cmd', lambda argv, **kwargs: calls.append(argv) or '')
    controller.execute('show interfaces bond')
    controller.execute('show interfaces bond bond0 lacp')
    controller.execute('show interfaces bond bond0 member eth2')
    assert calls == [
        ['bond.nvyr.op', 'show'],
        ['bond.nvyr.op', 'show', '--bond', 'bond0', '--section', 'lacp'],
        ['bond.nvyr.op', 'show', '--bond', 'bond0', '--member', 'eth2'],
    ]
    candidates = dict(completion_rows(controller.completion('show interfaces bond ', explicit=True)))
    assert '<bondN>' in candidates
    assert 'bond-name' not in candidates and 'identifier' not in candidates


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
