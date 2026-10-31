"""File routing and rotation configuration for nVyR's local log collectors."""

import json

from nvyr.tree import lookup


LEVELS = ('emerg', 'alert', 'crit', 'err', 'warn', 'notice', 'info', 'debug')
SERVICES = {
    'configd': ('nvyr-configd',),
    'netlinkd': ('nvyr-netlinkd', 'nvyr-interface-naming', 'nvyr-dhcp4'),
    'bgp': ('bgpd',),
    'static': ('staticd',),
    'zebra': ('zebra',),
    'ospf': ('ospfd', 'ospf6d'),
    'ntp': ('chronyd', 'nvyr-ntp'),
    'ssh': ('sshd', 'sshd-session'),
    'dhcp-server': ('kea-dhcp4',),
    'dhcpv6-server': ('kea-dhcp6',),
}
ROOT = '/var/log/nvyr'


def level(configuration, service):
    options = lookup(configuration, ('system', 'logging'), {})
    return lookup(options, ('service', service, 'level'), options.get('level', 'info'))


def severity(options, service):
    """Translate a schema-validated threshold to rsyslog's numeric severity."""
    value = lookup(options, ('service', service, 'level'), options.get('level', 'info'))
    return LEVELS.index(value)


def program_condition(identifiers):
    return ' or '.join('$programname == ' + json.dumps(name) for name in identifiers)


def render(options):
    """Use the same native templates for configured and early-boot collectors."""
    from nvyr.helpers import template

    variables = {'configuration': options}
    return {
        'rsyslog': template.render('logging/rsyslog.conf.j2', variables),
        'logrotate': template.render('logging/logrotate.conf.j2', variables),
    }


def ulogd(identifier, path):
    """One NFLOG subscription per service, avoiding reloads of unrelated groups."""
    return '\n'.join([
        '[global]', 'logfile="syslog"', 'loglevel=5',
        'stack=packets:NFLOG,base:BASE,interfaces:IFINDEX,addresses:IP2STR,print:PRINTPKT,file:LOGEMU',
        '', '[packets]', f'group={identifier}', '', '[file]',
        f'file="{path}"', 'sync=1', '',
    ])
