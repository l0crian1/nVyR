"""Developer host login or a role-specific isolated CLI session."""

import grp
import os
import pwd
import sys

from nvyr.helpers.access import ROLE_GROUPS


def local_role():
    if os.getuid() == 0:
        return 'dev-admin'

    name = pwd.getpwuid(os.getuid()).pw_name

    # Query current membership, not potentially stale supplementary process groups.
    for role, group in ROLE_GROUPS.items():
        if name in grp.getgrnam(group).gr_mem:
            if role == 'dev-admin':
                from nvyr.helpers import developer_access
                if not developer_access.enabled() and not (name == 'nvyr-dev' and developer_access.recovery_active()):
                    raise SystemExit('Developer access is disabled')
            return role

    raise SystemExit('This account no longer has nVyR login access')


def main():
    role = local_role()
    args = sys.argv[1:]
    if role == 'dev-admin':
        # SSH command execution still needs the host shell; interactive logins
        # enter the host CLI and can use its shell command for Linux access.
        if args:
            os.execv('/bin/bash', ['bash', *args])
        else:
            os.execv('/usr/bin/nvyr', ['nvyr'])

    if args and (args != ['-c', '/usr/bin/nvyr-login'] or os.environ.get('SSH_ORIGINAL_COMMAND')):
        raise SystemExit('This role permits interactive nVyR CLI sessions only')

    os.execv('/usr/bin/sudo', ['sudo', '-n', '/usr/bin/nvyr-session', 'launch'])
