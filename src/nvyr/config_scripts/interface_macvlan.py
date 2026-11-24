"""Routed MACVLAN interface configuration."""

from nvyr.errors import ValidationError
from nvyr.helpers import interfaces, netlink
from nvyr.tree import lookup

ROOT = ('interfaces', 'macvlan')


def apply_after(effective):
    tunnels = lookup(effective, ('interfaces', 'vxlan'), {})
    profiles = lookup(effective, ROOT, {})
    if any(profile.get('source-interface') in tunnels for profile in profiles.values()):
        return ('vxlan',)
    return ()


def get_config(context):
    return {
        'macvlans': lookup(context.effective, ROOT, {}),
        'tunnels': lookup(context.effective, ('interfaces', 'vxlan'), {}),
        'inventory': dict(interfaces.configured(context.effective)),
        'vrfs': lookup(context.effective, ('vrf', 'name'), {}),
        'bridge_members': interfaces.bridge_members(context.effective),
        'bond_members': interfaces.bond_members(context.effective),
    }


def link_definitions(profiles):
    links = interfaces.NetlinkManager.definitions('macvlan', interfaces.settings(profiles))
    for name, values in profiles.items():
        links[name]['attributes'].update(parent=values['source-interface'], mode=values['mode'])

    return links


def verify(configuration, context):
    profiles = configuration['macvlans']
    inventory = configuration['inventory']

    # Opposing stacks have no valid order between the two configuration scripts.
    interfaces.verify_macvlan_vxlan_order(configuration['macvlans'], configuration['tunnels'])

    # Switched ports cannot own L3 settings, and routed ports need a configured VRF.
    interfaces.verify_membership(profiles, vrfs=configuration['vrfs'],
                                 bridge_members=configuration['bridge_members'], bond_members=configuration['bond_members'])

    # A delegated LAN needs a routable interface in the candidate topology.
    interfaces.verify_pd(inventory, configuration['bridge_members'] | configuration['bond_members'])

    for name, profile in profiles.items():
        parent = profile.get('source-interface')
        # A MACVLAN needs a distinct lower device, which may be created in this commit.
        if not parent or parent == name or parent not in inventory:
            raise ValidationError(f'{name}: source-interface must name a different configured interface')

        # Linux flattens stacked MACVLANs onto the original lower device.
        if parent in profiles:
            raise ValidationError(f'{name}: select the underlying link of {parent} as the source-interface')

    # Validate the same definitions and ownership that apply will submit to netlinkd.
    links = link_definitions(profiles)
    netlink.normalize(links)
    interfaces.manager.request('validate', owner='macvlan', links=links, recovery=context.recovery)


def generate(configuration, context):
    return link_definitions(configuration['macvlans'])


def apply(links, context):
    interfaces.manager.replace('macvlan', links, recovery=context.recovery)
