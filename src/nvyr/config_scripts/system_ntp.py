"""One Chrony instance owns the router clock in the selected routing domain."""

import ipaddress

from nvyr.errors import ValidationError
from nvyr.helpers import interfaces, ntp
from nvyr.helpers.template import render
from nvyr.tree import lookup

ROOT = ('system', 'ntp')


def get_config(context):
    return {
        'current': lookup(context.effective, ROOT, None),
        'previous': lookup(context.previous_effective, ROOT, None),
        'vrfs': lookup(context.effective, ('vrf', 'name'), {}),
    }


def verify(configuration, context):
    vrfs = configuration['vrfs']
    configuration = configuration['current']
    # Removing NTP must remain possible even when its former interfaces are gone.
    if configuration is None:
        return

    vrf = lookup(configuration, ('vrf',), 'default')

    # Dependency registration prevents deletion; verification also requires creation.
    if 'vrf' in configuration and vrf not in vrfs:
        raise ValidationError(f'system ntp vrf {vrf}: VRF is not configured')

    listeners = lookup(configuration, ('listen-address',), {})

    # Wildcard listeners do not need an address-assignment query.
    if not listeners:
        return

    # A dry run precedes interface application, so inspect host addresses at commit only.
    if context.check_only:
        context.report('NTP: skipped listener address assignment check; it runs during commit.\n')
        return

    local = interfaces.local_addresses(vrf=vrf)
    for family, value in listeners.items():
        address = ipaddress.ip_address(value)

        # Explicit listeners must belong to the selected routing domain.
        if not address.is_unspecified and address not in local:
            raise ValidationError(f'system ntp listen-address {family} {value}: address is not assigned in VRF {vrf}')


def render_service(section):
    if section is None:
        return None

    return render('ntp/chrony.conf.j2', {'configuration': section})


def generate(configuration, context):
    return ntp.Plan(render_service(configuration['current']), render_service(configuration['previous']))


def apply(plan, context):
    ntp.manager.apply(plan, recovery=context.recovery)
