"""Authorization shared by configd dispatch and configuration mutation boundaries."""

from contextvars import ContextVar
from copy import deepcopy
import os

from nvyr.errors import RouterError
from nvyr.tree import lookup

ROLE_GROUPS = {'dev-admin': 'nvyr-dev-admin', 'sys-admin': 'nvyr-sys-admin',
               'net-admin': 'nvyr-net-admin', 'read-only': 'nvyr-read-only'}
ROLE_LEVELS = {'read-only': 0, 'net-admin': 1, 'sys-admin': 2, 'dev-admin': 3}
role = ContextVar('nvyr_role', default='dev-admin')  # Trusted in-process callers/recovery.
principal = ContextVar('nvyr_principal', default=None)
terminal = ContextVar('nvyr_terminal', default='')


def command_environment():
    """Pass the authenticated caller's terminal for display, not authorization."""
    return dict(os.environ, NVYR_SESSION_TTY=terminal.get())


def current_role():
    identity = principal.get()
    return peer_role(*identity) if identity is not None else role.get()


def require(capability):
    current = current_role()
    required = ('net-admin' if capability == 'configure' else
                'sys-admin' if capability == 'manage login accounts' else 'dev-admin')
    allowed = allows(required, current=current)
    if not allowed:
        raise RouterError(f'Permission denied: {capability} requires {required} access')


def allows(required, *, current=None):
    """Whether an authenticated role meets a command's minimum access level."""
    current = current_role() if current is None else current

    return ROLE_LEVELS.get(current, -1) >= ROLE_LEVELS[required]


def require_role(required):
    if not allows(required):
        raise RouterError(f'Permission denied: this command requires {required} access')


def peer_role(engine, user):
    if user == 'root':
        return 'dev-admin'

    from nvyr.helpers import developer_access
    if user == 'nvyr-dev' and developer_access.recovery_active():
        return 'dev-admin'

    value = lookup(engine.running, ('system', 'login', 'user', user, 'role'), None)
    if value not in ROLE_GROUPS:
        raise RouterError('This account is not authorized for nVyR')
    if value == 'dev-admin' and not developer_access.enabled():
        raise RouterError('Developer access is disabled on this installation')

    return value


def visible(configuration):
    if allows('sys-admin'):
        return configuration

    result = deepcopy(configuration)
    users = lookup(result, ('system', 'login', 'user'), {})

    for user in users.values():
        user.pop('authentication', None)

    return result


def protect_login(before, after):
    if lookup(before, ('system', 'login'), None) != lookup(after, ('system', 'login'), None):
        require('manage login accounts')

    old = lookup(before, ('system', 'login', 'user'), {})
    new = lookup(after, ('system', 'login', 'user'), {})
    if current_role() != 'dev-admin':
        for name in old.keys() | new.keys():
            if (old.get(name, {}).get('role') == 'dev-admin' or
                    new.get(name, {}).get('role') == 'dev-admin') and old.get(name) != new.get(name):
                raise RouterError('Permission denied: managing developer accounts requires dev-admin access')
