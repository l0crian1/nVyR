"""Translate LLDP selection and exact-port overrides into native lldpd settings."""

import fnmatch

from nvyr.errors import ValidationError
from nvyr.helpers import lldp
from nvyr.helpers.template import render
from nvyr.tree import lookup


def get_config(context):
    return lookup(context.effective, ('service', 'lldp'), None)


def verify(configuration, context):
    # Removal has no remaining selection or override relationships to validate.
    if configuration is None:
        return

    # An explicit chassis identifier replaces the interface-derived identity.
    if 'chassis-id' in configuration and 'chassis-interface' in configuration:
        raise ValidationError('service lldp: chassis-id and chassis-interface are mutually exclusive')

    exclusions = lookup(configuration, ('exclude-interface',), ())
    for name, settings in lookup(configuration, ('interface',), {}).items():
        path = f'service lldp interface {name}'

        # Native selectors cannot carry per-interface overrides.
        if (name == 'all' or '*' in name) and settings:
            raise ValidationError(f'{path}: per-interface settings require an exact interface name')

        # An excluded port cannot receive meaningful per-port settings.
        if settings and any(fnmatch.fnmatchcase(name, pattern) for pattern in exclusions):
            raise ValidationError(f'{path}: cannot override an excluded interface')

        # Disable already selects a native administrative mode for this port.
        if 'disable' in settings and 'mode' in settings:
            raise ValidationError(f'{path}: disable and mode are mutually exclusive')

        # A port has one native transmit VLAN, not a list of encapsulations.
        if len(lookup(settings, ('transmit-vlan',), {})) > 1:
            raise ValidationError(f'{path}: only one transmit-vlan can be configured')


def generate(configuration, context):
    if configuration is None or 'disable' in configuration:
        return None

    return {
        'configuration': render('lldp/lldpd.conf.j2', {'configuration': configuration}),
        'environment': render('lldp/daemon.env.j2', {'configuration': configuration}),
        'overrides': [name for name, settings in lookup(configuration, ('interface',), {}).items() if settings],
    }


def apply(plan, context):
    lldp.install(plan)
