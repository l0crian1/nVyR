"""Apply bridge port membership and forwarding policy after interface creation."""

from nvyr.config_scripts import interface_bridge
from nvyr.helpers import interfaces, vxlan_config


def get_config(context):
    return interface_bridge.get_config(context)


def verify(configuration, context):
    # Member MTUs, VLANs, static forwarding and tunnel mappings depend on the candidate topology.
    interface_bridge.verify_bridges(configuration)

    # Removing a member or disabling filtering must not strand its external mappings.
    filtered = vxlan_config.filtered_ports(configuration['bridges'])
    for name, profile in configuration['tunnels'].items():
        vxlan_config.verify_mapping_port(name, profile, filtered)


def generate(configuration, context):
    bridges = {}
    for name, settings in configuration['bridges'].items():
        if settings.get('member', {}).get('interface'):
            bridges[name] = {key: settings[key] for key in (
                'member', 'static-mac', 'multicast', 'vlan', 'default-pvid', 'vlan-filtering', 'disable')
                if key in settings}

    return bridges


def apply(bridges, context):
    interfaces.manager.request('replace-bridge-ports', bridges=bridges)
