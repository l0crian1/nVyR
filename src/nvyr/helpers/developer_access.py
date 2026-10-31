"""Installation-owned developer policy and console-selected, one-boot recovery."""

import json
import os
from pathlib import Path
import pwd
import secrets
import subprocess

from nvyr.errors import RouterError
from nvyr.storage import atomic_json

POLICY = Path('/config/.nvyr/login/developer.json')
RUNTIME = Path('/run/nvyr-developer')
RECOVERY_OWNER = Path('/var/lib/nvyr-developer/recovery.json')


def enabled():
    """Use this boot's policy, so scheduling disable never revokes the caller early."""
    path = RUNTIME / 'boot.json'
    return path.exists() and json.loads(path.read_text())['enabled']


def recovery_active():
    path = RUNTIME / 'recovery.json'
    if not path.exists():
        return False

    try:
        return pwd.getpwnam('nvyr-dev').pw_uid == json.loads(path.read_text())['uid']
    except KeyError:
        return False


def disable_pending():
    """A scheduled disable must retain a usable nondeveloper account until boot."""
    return POLICY.exists() and not json.loads(POLICY.read_text())['enabled']


def disable():
    """Ask configd to serialize the policy change with commits and rollbacks."""
    from nvyr.protocol import Client

    client = Client('/run/nvyr/configd.sock')
    try:
        return client.request('disable_developer_access')['text']
    finally:
        client.close()


def schedule_disable(engine):
    from nvyr.helpers import access

    access.require_role('dev-admin')
    if json.loads((RUNTIME / 'boot.json').read_text()).get('live', False):
        raise RouterError('Live media always enables developer access; choose its permanent policy during installation')

    with engine.mutex:
        if engine.busy or engine.pending or engine.scheduled or engine.unhealthy:
            raise RouterError('Complete configuration recovery, commits and confirmed rollback before disabling developer access')
        users = engine.running.get('system', {}).get('login', {}).get('user', {})
        if not any(user.get('role') == 'sys-admin' and user.get('authentication', {}).get('encrypted-password')
                   for user in users.values()):
            raise RouterError('Create a usable sys-admin account before disabling developer access')
        atomic_json(POLICY, {'enabled': False})
        return {'text': 'Permanent developer access will be disabled after reboot.\n'}


def boot():
    """Run before configd, including when configuration recovery cannot start."""
    from nvyr.helpers.passwords import hash_password

    RUNTIME.mkdir(mode=0o755, exist_ok=True)
    command_line = Path('/proc/cmdline').read_text().split()
    live = 'boot=live' in command_line
    policy = json.loads(POLICY.read_text()) if POLICY.exists() else {'enabled': False}
    atomic_json(RUNTIME / 'boot.json', {'enabled': live or policy['enabled'], 'live': live}, mode=0o644)
    (RUNTIME / 'recovery.json').unlink(missing_ok=True)

    # /etc survives installed-image reboots; remove only our recorded recovery UID.
    if RECOVERY_OWNER.exists():
        owner = json.loads(RECOVERY_OWNER.read_text())
        try:
            account = pwd.getpwnam('nvyr-dev')
        except KeyError:
            account = None
        if account:
            if account.pw_uid != owner['uid']:
                raise RouterError('Recovery account identity changed outside nVyR')
            subprocess.run(['userdel', 'nvyr-dev'], check=True)
        RECOVERY_OWNER.unlink()

    if 'nvyr.developer-recovery=1' not in command_line:
        return

    # Reserve the name, not a UID block; never adopt an unrelated host account.
    try:
        pwd.getpwnam('nvyr-dev')
    except KeyError:
        pass
    else:
        raise RouterError('nvyr-dev already exists outside recovery account management')

    # Recovery must remain usable when configd and the CLI cannot start.
    subprocess.run(['useradd', '--no-create-home', '--home-dir', '/run/nvyr-developer',
                    '--gid', 'nvyr-users', '--groups', 'nvyr-access,nvyr-dev-admin',
                    '--shell', '/bin/bash', 'nvyr-dev'], check=True)
    account = pwd.getpwnam('nvyr-dev')
    atomic_json(RECOVERY_OWNER, {'uid': account.pw_uid})
    password = secrets.token_urlsafe(24)
    subprocess.run(['chpasswd', '--encrypted'], input=f'nvyr-dev:{hash_password(password)}\n',
                   text=True, check=True)
    atomic_json(RUNTIME / 'recovery.json', {'uid': account.pw_uid}, mode=0o644)

    # Do not send the password to stdout/journal or save it in configuration.
    message = ('\nnVyR one-boot developer recovery\nUsername: nvyr-dev\nPassword: ' + password +
               '\nThis account is removed on the next boot.\n')
    consoles = Path('/sys/class/tty/console/active').read_text().split()
    for console in consoles:
        with open('/dev/' + console, 'w') as stream:
            stream.write(message)


def main():
    if os.geteuid() != 0:
        raise SystemExit('Developer boot setup requires root')
    boot()
