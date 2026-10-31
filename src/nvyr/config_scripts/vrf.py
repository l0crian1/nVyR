"""Linux VRF device lifecycle through the shared Netlink daemon."""

from nvyr.errors import ValidationError
from nvyr.helpers import interfaces
from nvyr.tree import lookup

ROOT = ('vrf', 'name')


def get_config(context):
    return {
        'vrfs': lookup(context.effective, ROOT, {}),
        'previous': lookup(context.previous, ROOT, {}),
        'zones': lookup(context.effective, ('firewall', 'zone'), {}),
    }


def link_definitions(configuration):
    return {name: {'kind': 'vrf', 'attributes': {'table': int(values['table'])}}
            for name, values in configuration.items()}


def verify(configuration, context):
    previous = configuration['previous']
    tables = {}
    zone_interfaces = {
        interface: zone for zone, options in configuration['zones'].items()
        for interface in lookup(options, ('interface',), [])
    }

    for name, values in configuration['vrfs'].items():
        # A later VRF creation must not turn an existing zone member into a master device.
        if name in zone_interfaces:
            raise ValidationError(f'VRF {name}: VRF masters cannot belong to firewall zone {zone_interfaces[name]}')

        # A Linux VRF requires a routing-table identifier.
        if 'table' not in values:
            raise ValidationError(f'VRF {name}: a routing table is required')

        table = int(values['table'])
        # Separate VRFs must not share their routing table.
        if table in tables:
            raise ValidationError(f'VRF {name}: table {table} is already configured for VRF {tables[table]}')

        tables[table] = name
        old = lookup(previous, (name, 'table'), None)
        # The kernel cannot change an existing VRF table in place.
        if old is not None and int(old) != table:
            raise ValidationError(f'VRF {name}: table cannot be changed in place; '
                                  'delete and commit the VRF before recreating it with another table')

    # Native preflight checks live device ownership before the commit changes links.
    interfaces.manager.request('validate', owner='vrf', links=link_definitions(configuration['vrfs']),
                               recovery=context.recovery)


def generate(configuration, context):
    return link_definitions(configuration['vrfs'])


def apply(links, context):
    interfaces.manager.replace('vrf', links, recovery=context.recovery)
