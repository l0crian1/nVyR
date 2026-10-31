"""Dummy link lifecycle using the shared Netlink daemon."""

from nvyr.helpers import interfaces, netlink
from nvyr.tree import lookup

ROOT = ('interfaces', 'dummy')


def get_config(context):
    return {
        'dummy': lookup(context.effective, ROOT, {}),
        'vrfs': lookup(context.effective, ('vrf', 'name'), {}),
        'bridge_members': interfaces.bridge_members(context.effective),
    }


def link_definitions(configuration):
    """Prepare the same definitions for read-only preflight and application."""
    return interfaces.NetlinkManager.definitions('dummy', interfaces.settings(configuration))


def verify(configuration, context):
    values = configuration['dummy']

    # VRFs must exist in the proposed configuration; switched ports cannot own L3 settings.
    interfaces.verify_membership(values, vrfs=configuration['vrfs'],
                                 bridge_members=configuration['bridge_members'])

    # Native preflight checks DHCP/IP relationships and supported device attributes.
    links = link_definitions(values)
    netlink.normalize(links)

    # Live ownership must permit this transaction, including during commit check.
    interfaces.manager.request('validate', owner='dummy', links=links, recovery=context.recovery)


def generate(configuration, context):
    return link_definitions(configuration['dummy'])


def apply(links, context):
    interfaces.manager.replace('dummy', links, recovery=context.recovery)
