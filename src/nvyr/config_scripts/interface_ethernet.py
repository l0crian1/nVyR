"""Ethernet configuration using the shared netlinkd/Netlink interface manager."""

from nvyr.errors import ValidationError
from nvyr.helpers import interfaces, netlink
from nvyr.tree import lookup


ROOT = ('interfaces', 'ethernet')


def get_config(context):
    return {
        'ethernet': lookup(context.effective, ROOT, {}),
        'vrfs': lookup(context.effective, ('vrf', 'name'), {}),
        'bridge_members': interfaces.bridge_members(context.effective),
    }


def link_definitions(configuration):
    """Prepare parent and VIF definitions for read-only preflight and application."""
    parents = interfaces.NetlinkManager.definitions('ethernet', interfaces.settings(configuration))
    return parents | interfaces.vlan_definitions(configuration)


def verify(configuration, context):
    values = configuration['ethernet']

    # VRFs must exist in the proposed configuration; switched ports cannot own L3 settings.
    interfaces.verify_membership(values, vrfs=configuration['vrfs'],
                                 bridge_members=configuration['bridge_members'])

    # Child VLAN names and MTUs must fit their parent and kernel limits.
    interfaces.verify_vifs(values)

    for name in values:
        # Physical ports must have completed persistent naming before configuration.
        interfaces.require_named(name)

        # Recovery may wait for hotplug; an ordinary commit requires the port now.
        if not context.recovery and not interfaces.exists(name):
            raise ValidationError(f'interfaces ethernet {name}: interface does not exist on this system')

    # Validate child topology and ownership before applying any parent changes.
    links = link_definitions(values)
    netlink.normalize(links)
    interfaces.manager.request('validate', owner='ethernet', links=links, recovery=context.recovery)


def generate(configuration, context):
    return link_definitions(configuration['ethernet'])


def apply(links, context):
    interfaces.manager.replace('ethernet', links, recovery=context.recovery)
