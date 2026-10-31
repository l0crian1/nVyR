"""Opt-in account lifecycle checks in a disposable systemd container.

Exercises prepared account targets, Linux credentials/roles, disabled developer
removal and compensation. Requires root and creates private test users/groups;
never enable this suite on a router or a general-purpose development host.
"""

import grp
import os
from pathlib import Path
import pwd
from types import SimpleNamespace

import pytest

from nvyr.config_scripts import system_login
from nvyr.errors import RouterError
from nvyr.helpers import accounts, developer_access
from nvyr.helpers.access import ROLE_GROUPS
from nvyr.helpers.passwords import hash_password
from nvyr.helpers.process import cmd, run

pytestmark = pytest.mark.skipif(os.environ.get('NVYR_ACCOUNT_NATIVE') != '1',
                                reason='requires an isolated privileged systemd container')


def test_native_prepared_accounts_and_disabled_developer_compensation(tmp_path, monkeypatch):
    assert Path('/.dockerenv').exists() and os.geteuid() == 0
    names = ('nvyrtestsys', 'nvyrtestdev')
    manager = accounts.Manager()
    assert all(manager.account(name) is None for name in names)

    for group in ('nvyr-users', 'nvyr-access', *ROLE_GROUPS.values()):
        try:
            grp.getgrnam(group)
        except KeyError:
            assert run(['groupadd', group]) == 0

    monkeypatch.setattr(accounts, 'manager', manager)
    policy = {'enabled': True}
    monkeypatch.setattr(developer_access, 'enabled', lambda: policy['enabled'])
    monkeypatch.setattr(developer_access, 'disable_pending', lambda: not policy['enabled'])
    password = hash_password('native-account-test')
    users = {
        names[0]: {'role': 'sys-admin', 'authentication': {'encrypted-password': password}},
        names[1]: {'role': 'dev-admin', 'authentication': {'encrypted-password': password}},
    }

    def prepare(current, previous):
        context = SimpleNamespace(
            effective={'system': {'login': {'user': current}}},
            previous={'system': {'login': {'user': previous}}},
            state_directory=tmp_path, startup=True, recovery=False,
        )
        gathered = system_login.get_config(context)
        system_login.verify(gathered, context)
        return system_login.generate(gathered, context), context

    try:
        plan, context = prepare(users, {})
        system_login.apply(plan, context)
        identities = {name: pwd.getpwnam(name).pw_uid for name in names}
        for name in names:
            assert pwd.getpwnam(name).pw_shell == accounts.SHELL
            assert cmd(['getent', 'shadow', name]).split(':')[1] == password
            assert name in grp.getgrnam(ROLE_GROUPS[users[name]['role']]).gr_mem

        # A boot with developer access disabled removes Linux access while the
        # durable account record remains in the configuration supplied above.
        policy['enabled'] = False
        plan, context = prepare(users, users)
        system_login.apply(plan, context)
        assert manager.account(names[1]) is None
        assert pwd.getpwnam(names[0]).pw_uid == identities[names[0]]

        failed = []

        def fail_once(command, **kwargs):
            if command[0] == 'usermod' and not failed:
                failed.append(True)
                return 1
            return run(command, **kwargs)

        monkeypatch.setattr(manager, 'run', fail_once)
        with pytest.raises(RouterError, match='previous accounts restored'):
            system_login.apply(plan, context)

        assert manager.account(names[1]) is None
        assert pwd.getpwnam(names[0]).pw_uid == identities[names[0]]
        assert cmd(['getent', 'shadow', names[0]]).split(':')[1] == password
    finally:
        manager.run = run
        manager.apply({}, users, tmp_path, recovery=True)

    assert all(manager.account(name) is None for name in names)
