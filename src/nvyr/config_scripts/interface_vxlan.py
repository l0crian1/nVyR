"""VXLAN tunnel interface configuration."""

from nvyr.helpers import interfaces, netlink, vxlan, vxlan_config
from nvyr.tree import lookup

ROOT = ('interfaces', 'vxlan')


def get_config(context):
    return {
        'tunnels': lookup(context.effective, ROOT, {}),
        'macvlans': lookup(context.effective, ('interfaces', 'macvlan'), {}),
        'filtered': vxlan_config.filtered_ports(lookup(context.effective, ('interfaces', 'bridge'), {})),
        'inventory': dict(interfaces.configured(context.effective)),
        'vrfs': lookup(context.effective, ('vrf', 'name'), {}),
        'bridge_members': interfaces.bridge_members(context.effective),
        'bond_members': interfaces.bond_members(context.effective),
    }


def link_definitions(profiles):
    links = interfaces.NetlinkManager.definitions('vxlan', interfaces.settings(profiles))
    for name, values in profiles.items():
        links[name]['attributes']['vxlan'] = vxlan.settings(values)

    return links


def verify(configuration, context):
    profiles = configuration['tunnels']
    inventory = configuration['inventory']

    # Opposing stacks have no valid order between the two configuration scripts.
    interfaces.verify_macvlan_vxlan_order(configuration['macvlans'], configuration['tunnels'])

    # Switched ports cannot own L3 settings, and routed ports need a configured VRF.
    interfaces.verify_membership(profiles, vrfs=configuration['vrfs'],
                                 bridge_members=configuration['bridge_members'], bond_members=configuration['bond_members'])

    # A delegated LAN needs a routable interface in the candidate topology.
    interfaces.verify_pd(inventory, configuration['bridge_members'] | configuration['bond_members'])

    for name, profile in profiles.items():
        vxlan_config.verify_interface(name, profile, inventory, configuration['filtered'])

    # Validate the same definitions and ownership that apply will submit to netlinkd.
    links = link_definitions(profiles)
    netlink.normalize(links)
    interfaces.manager.request('validate', owner='vxlan', links=links, recovery=context.recovery)


def generate(configuration, context):
    return link_definitions(configuration['tunnels'])


def apply(links, context):
    interfaces.manager.replace('vxlan', links, recovery=context.recovery)
