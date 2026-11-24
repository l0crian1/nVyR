"""MACsec interfaces backed by the kernel data plane and per-interface MKA."""

from nvyr.errors import ValidationError
from nvyr.helpers import interfaces, netlink
from nvyr.tree import lookup


def get_config(context):
    return {
        'interfaces': lookup(context.effective, ('interfaces', 'macsec'), {}),
        'inventory': dict(interfaces.configured(context.effective)),
        'vrfs': lookup(context.effective, ('vrf', 'name'), {}),
        'bridge-members': interfaces.bridge_members(context.effective),
        'bond-members': interfaces.bond_members(context.effective),
    }


def verify(configuration, context):
    profiles = configuration['interfaces']
    # The secured device can carry routed addresses or be attached to a master.
    interfaces.verify_membership(profiles, vrfs=configuration['vrfs'],
                                 bridge_members=configuration['bridge-members'],
                                 bond_members=configuration['bond-members'])
    # A delegated LAN must remain in the requesting uplink's VRF with usable IPv6 settings.
    interfaces.verify_pd(configuration['inventory'], configuration['bridge-members'] | configuration['bond-members'])
    channels = set()
    for name, values in profiles.items():
        parent = lookup(values, ('source-interface',), '')
        # A channel needs a distinct parent, including when both links are new.
        if not parent or parent == name:
            raise ValidationError(f'{name}: a distinct source-interface is required')
        # Permit both configured interfaces and existing Ethernet links.
        if parent not in configuration['inventory'] and not interfaces.exists(parent) and not context.recovery:
            raise ValidationError(f'{name}: source-interface {parent} does not exist')
        association = lookup(values, ('mka', 'preshared-key'), {})
        # MKA authenticates peers with the complete CAK/CKN pair.
        if not {'cak', 'ckn'} <= association.keys():
            raise ValidationError(f'{name}: MKA requires both cak and ckn')
        channel = (parent, int(lookup(values, ('sci-port',), '1')))
        # The supplicant locates its controlled device by parent and SCI.
        if channel in channels:
            raise ValidationError(f'{name}: duplicate SCI port {channel[1]} on {parent}')
        channels.add(channel)

    # Confirm that native link ownership and the dependency graph allow the transaction.
    links = generate(configuration, context)
    netlink.normalize(links)
    interfaces.manager.request('validate', owner='macsec', links=links, recovery=context.recovery)


def generate(configuration, context):
    profiles = configuration['interfaces']
    links = interfaces.NetlinkManager.definitions('macsec', interfaces.settings(profiles))
    for name, values in profiles.items():
        mka = values['mka']
        links[name]['attributes']['macsec'] = {
            'parent': values['source-interface'],
            'port': int(lookup(values, ('sci-port',), '1')),
            'cak': mka['preshared-key']['cak'].lower(),
            'ckn': mka['preshared-key']['ckn'].lower(),
            'priority': lookup(mka, ('key-server-priority',), None),
            'encrypt': lookup(values, ('transmit-mode',), 'encrypt') == 'encrypt',
            'window': int(lookup(values, ('replay-protection', 'window'), '0'))
                      if 'replay-protection' in values else None,
        }
    return links


def apply(links, context):
    interfaces.manager.replace('macsec', links, recovery=context.recovery)
