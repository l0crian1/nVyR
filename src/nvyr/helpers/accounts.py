"""Linux account reconciliation. Only ledger-owned accounts may be modified."""

import json
import os
from pathlib import Path
import pwd
import subprocess

from nvyr.errors import RouterError, RecoveryError, ValidationError
from nvyr.storage import atomic_json
from nvyr.helpers.access import ROLE_GROUPS
from nvyr.helpers.process import run

SHELL = '/usr/bin/nvyr-login'


class Manager:
    def __init__(self, *, run=run):
        self.run = run

    def ledger(self, directory):
        path = Path(directory) / 'login' / 'accounts.json'
        return path, json.loads(path.read_text()) if path.exists() else {}

    def account(self, name):
        try:
            return pwd.getpwnam(name)
        except KeyError:
            return None

    def verify(self, users, directory):
        """Reject collisions with accounts not identified by the managed UID ledger."""
        _, ledger = self.ledger(directory)

        for name in users:
            account = self.account(name)
            # Matching names alone cannot establish ownership after UID reuse or
            # out-of-band account creation.
            if account and (name not in ledger or account.pw_uid != ledger[name]['uid']):
                raise ValidationError(f'User {name} exists outside nVyR management; refusing to take over this account')

    def _password(self, name, encrypted):
        # Hashes must not appear in ps output or operational command diagnostics.
        result = subprocess.run(['/usr/sbin/chpasswd', '--encrypted'], input=f'{name}:{encrypted}\n',
                                text=True, capture_output=True, timeout=15, check=False)
        if result.returncode:
            raise RouterError(f'Could not update password for user {name}')

    def _terminate(self, uid):
        # Revoke existing shells, SSH forwarding and cached supplementary groups.
        self.run(['loginctl', 'terminate-user', str(uid)])
        result = self.run(['pkill', '-KILL', '-u', str(uid)])
        if result not in (0, 1):
            raise RouterError(f'Could not terminate sessions for UID {uid}')

    def _install(self, users, directory):
        # Recheck live identity ownership immediately before any account changes.
        self.verify(users, directory)
        path, ledger = self.ledger(directory)

        for name, user in sorted(users.items(), key=lambda item: item[1]['role'] != 'sys-admin'):
            account = self.account(name)

            if name not in ledger:
                used = {p.pw_uid for p in pwd.getpwall()} | {entry['uid'] for entry in ledger.values()}
                uid = next((value for value in range(1000, 60000) if value not in used), None)
                if uid is None:
                    raise RouterError('No local user IDs remain available')

                ledger[name] = {'uid': uid}
                atomic_json(path, ledger)  # Reserve identity before touching Linux.

            uid = ledger[name]['uid']
            groups = 'nvyr-access,' + ROLE_GROUPS[user['role']]

            if account is None:
                try:
                    other = pwd.getpwuid(uid)
                except KeyError:
                    other = None

                if other:
                    raise RouterError(f'Reserved UID {uid} for {name} is in use')

                if self.run(['useradd', '--uid', str(uid), '--gid', 'nvyr-users', '--groups', groups,
                          '--shell', SHELL, '--create-home', '--home-dir', '/home/' + name,
                          '--comment', 'nVyR managed account', name]):
                    raise RouterError(f'Could not create user {name}')

            import grp

            current_roles = {role for role, group in ROLE_GROUPS.items()
                             if name in grp.getgrnam(group).gr_mem}

            if self.run(['usermod', '--groups', groups, '--shell', SHELL, '--expiredate', '', '--inactive', '-1', name]):
                raise RouterError(f'Could not update user {name}')

            self._password(name, user['authentication']['encrypted-password'])

            if self.run(['chage', '--maxdays', '-1', '--mindays', '0', name]):
                raise RouterError(f'Could not update password aging for user {name}')

            if account and current_roles != {user['role']}:
                self._terminate(uid)

            workspace = Path('/config/users') / name
            # The parent is root-owned; a user's existing workspace must be a real directory.
            if workspace.is_symlink():
                raise RouterError(f'User workspace cannot be a symlink: {workspace}')
            workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
            workspace.chmod(0o700)
            os.chown(workspace, uid, grp.getgrnam('nvyr-users').gr_gid)

        for name, entry in ledger.items():
            if name in users:
                continue

            account = self.account(name)
            if account is None:
                continue

            if account.pw_uid != entry['uid']:
                raise RouterError(f'UID changed outside nVyR for {name}; refusing deletion')

            # Lock first, revoke existing sessions, then delete. Keep home/UID for
            # rollback and upgrades; a deleted UID is never given to a new name.
            if self.run(['usermod', '--lock', '--expiredate', '1', name]):
                raise RouterError(f'Could not lock user {name}')

            self._terminate(account.pw_uid)

            if self.run(['userdel', name]):
                raise RouterError(f'Could not delete user {name}')

    def apply(self, users, previous, directory, *, recovery=False):
        if not users and not previous and not self.ledger(directory)[1]:
            return

        try:
            self._install(users, directory)
        except Exception as error:
            if recovery:
                raise RecoveryError(f'Local account recovery failed: {error}') from error

            try:
                self._install(previous, directory)
            except Exception as rollback:
                raise RecoveryError(f'Local account apply failed ({error}); compensation failed ({rollback}); restart configd to recover') from rollback

            raise RouterError(f'Local account apply failed ({error}); previous accounts restored') from error


manager = Manager()


def boot_configuration(saved, running):
    """Account changes are durable at commit, even if other settings are unsaved."""
    from copy import deepcopy

    result = deepcopy(saved)

    if 'login' in running.get('system', {}):
        result.setdefault('system', {})['login'] = deepcopy(running['system']['login'])

    return result


def factory_configuration(username='nvyr', encrypted=None, *, developer=False):
    from nvyr.helpers.passwords import hash_password

    return {'system': {'login': {'user': {username: {
        'role': 'dev-admin' if developer else 'sys-admin',
        'authentication': {'encrypted-password': encrypted or hash_password('nvyr')}}}}},
        'service': {'ssh': {}}}


def initialize(store):
    """Seed a fresh system once. Upgrades/restarts never reintroduce credentials."""
    marker = store.directory / 'login' / 'initialized'
    if marker.exists():
        return

    if store.read('boot.json') is None and not (store.directory / 'state.json').exists():
        from nvyr.helpers.developer_access import enabled
        store.write('boot.json', factory_configuration(developer=enabled()), metadata={'factory': True})

    # Never overwrite configured credentials with the factory password.
    atomic_json(marker, {'format': 1})
