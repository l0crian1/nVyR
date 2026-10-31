"""SSH lifecycle; an absent subtree disables the default service instance."""

import ipaddress

from nvyr.errors import ValidationError
from nvyr.helpers import interfaces, ssh
from nvyr.helpers.logging_formatters import level
from nvyr.helpers.template import render
from nvyr.tree import lookup

ROOT = ('service', 'ssh')
INSTANCE = 'default'


def get_config(context):
    return {
        'current': lookup(context.effective, ROOT, None),
        'previous': lookup(context.previous_effective, ROOT, None),
        'log-level': level(context.effective, 'ssh'),
        'previous-log-level': level(context.previous_effective, 'ssh'),
    }


def verify(configuration, context):
    """Check explicit SSH listeners against live default-VRF addresses at apply time."""
    configuration = configuration['current']
    # Removal and wildcard listening do not require a local address assignment.
    if configuration is None or 'listen-address' not in configuration:
        return

    # Earlier interface owners have not applied pending addresses during commit check.
    if context.check_only:
        context.report('SSH: skipped listen-address host assignment check; it runs during commit.\n')
        return

    local = interfaces.local_addresses(vrf='default')

    for value in configuration['listen-address']:
        address = ipaddress.ip_address(value)
        # SSH must be able to bind the selected address in its own routing instance.
        if address not in local:
            raise ValidationError(f'service ssh listen-address {address}: address is not assigned to the local system in the default routing instance')


def render_service(section, log_level, host_key):
    if section is None:
        return None

    severity = {'emerg': 'FATAL', 'alert': 'FATAL', 'crit': 'FATAL', 'err': 'ERROR',
                'warn': 'ERROR', 'notice': 'INFO', 'info': 'INFO', 'debug': 'DEBUG3'}
    return render('ssh/sshd_config.j2', {
        'configuration': section, 'host_key': str(host_key), 'log_level': severity[log_level],
    })


def generate(configuration, context):
    key = ssh.host_key(context.state_directory)
    desired = render_service(configuration['current'], configuration['log-level'], key)
    previous = render_service(configuration['previous'], configuration['previous-log-level'], key)

    return ssh.Plan(INSTANCE, desired, previous)


def apply(plan, context):
    ssh.manager.apply(plan, context.state_directory, recovery=context.recovery)
