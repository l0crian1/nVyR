"""Virtual Ethernet pairs managed together by the shared Netlink daemon."""

from nvyr.errors import ValidationError
from nvyr.helpers import interfaces, netlink
from nvyr.tree import lookup

ROOT = ('interfaces', 'virtual-ethernet')


def get_config(context):
    return {
        'virtual-ethernet': lookup(context.effective, ROOT, {}),
        'previous': lookup(context.previous, ROOT, {}),
        'vrfs': lookup(context.effective, ('vrf', 'name'), {}),
        'bridge_members': interfaces.bridge_members(context.effective),
    }


def link_definitions(configuration):
    """Prepare endpoints and VIFs for read-only preflight and application."""
    links = interfaces.NetlinkManager.definitions('virtual-ethernet', interfaces.settings(configuration))
    for name, values in configuration.items():
        links[name]['attributes']['peer-name'] = lookup(values, ('peer-name',), None)

    return links | interfaces.vlan_definitions(configuration)


def verify(configuration, context):
    endpoints = configuration['virtual-ethernet']
    previous = configuration['previous']

    # VRFs must exist in the proposed configuration; switched ports cannot own L3 settings.
    interfaces.verify_membership(endpoints, vrfs=configuration['vrfs'],
                                 bridge_members=configuration['bridge_members'])

    # Child VLAN names and MTUs must fit their parent and kernel limits.
    interfaces.verify_vifs(endpoints)

    for name, values in endpoints.items():
        # Each configured endpoint needs a peer before any kernel work begins.
        if 'peer-name' not in values:
            raise ValidationError(f'Virtual Ethernet {name}: peer-name is required')

        # The pair cannot be rewired while retaining either configured endpoint.
        old = lookup(previous, (name, 'peer-name'), None)
        if old is not None and old != values['peer-name']:
            raise ValidationError(f'{name}: peer-name cannot be changed in place; '
                                  'delete and commit the pair before recreating it')

    # Shared daemon validation enforces distinct, reciprocal endpoints in the proposed tree.
    links = link_definitions(endpoints)
    netlink.normalize(links)

    # Ownership and existing kernel peers must be safe before applying changes.
    interfaces.manager.request('validate', owner='virtual-ethernet', links=links,
                               recovery=context.recovery)


def generate(configuration, context):
    return link_definitions(configuration['virtual-ethernet'])


def apply(links, context):
    interfaces.manager.replace('virtual-ethernet', links, recovery=context.recovery)
