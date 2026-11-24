"""VXLAN link configuration and underlay/bridge validation."""

import ipaddress

from nvyr.errors import ValidationError


def verify_interface(name, values, inventory, filtered):
    # Every link selects exactly one kernel VXLAN mode.
    if ('vni' in values) == ('external' in values):
        raise ValidationError(f'{name}: configure either vni or external')

    ext = values.get('external', {})
    # Static remote destinations belong to fixed-VNI devices.
    if 'external' in values and any(key in values for key in ('remote', 'multicast-group', 'static-mac', 'flood-vtep')):
        raise ValidationError(f'{name}: external mode obtains remote destinations per VNI')

    # The kernel has one default destination, either unicast or multicast.
    if 'remote' in values and 'multicast-group' in values:
        raise ValidationError(f'{name}: choose either remote or multicast-group')

    source = values.get('source-interface')
    # Underlay devices must resolve and cannot be the tunnel itself.
    if source and (source == name or source not in inventory):
        raise ValidationError(f'{name}: source-interface must be a different configured interface')

    # Multicast delivery needs an outgoing interface for group membership.
    if 'multicast-group' in values and not source:
        raise ValidationError(f'{name}: multicast-group requires source-interface')

    destinations = [(key, values[key]) for key in ('source-address', 'remote', 'multicast-group') if key in values]
    destinations.extend(('flood-vtep', remote) for remote in values.get('flood-vtep', ()))
    for mac, entry in values.get('static-mac', {}).items():
        # The static FDB entry needs a unicast VTEP.
        if 'remote' not in entry:
            raise ValidationError(f'{name} static-mac {mac}: remote is required')
        destinations.append(('static-mac', entry['remote']))

    families = set()
    for key, host in destinations:
        address = ipaddress.ip_address(host)
        # Tunnel endpoint addresses must match the selected delivery mechanism.
        if (address.is_unspecified and key != 'source-address') or address.is_multicast != (key == 'multicast-group'):
            raise ValidationError(f'{name}: invalid {key} address {host}')
        families.add(address.version)

    # Fixed tunnels use one underlay address family.
    if len(families) > 1 or (4 in families and 'flow-label' in values):
        raise ValidationError(f'{name}: use a single underlay family and an IPv6 underlay for flow-label')

    ports = values.get('source-port', {})
    # A UDP source range requires both bounds in ascending order.
    if 'source-port' in values and (set(ports) != {'minimum', 'maximum'} or int(ports['minimum']) > int(ports['maximum'])):
        raise ValidationError(f'{name}: source-port requires minimum <= maximum')

    vlans = ext.get('vlan', {})
    # Different textual VLAN keys must not collapse onto the same native port mapping.
    if len(set(map(int, vlans))) != len(vlans):
        raise ValidationError(f'{name}: duplicate VLAN ID')
    # Linux identifies a static FDB entry by the MAC bytes, independent of letter case.
    macs = values.get('static-mac', {})
    if len({mac.lower() for mac in macs}) != len(macs):
        raise ValidationError(f'{name}: duplicate static MAC address')
    # Mappings operate on the tunnel port of a VLAN-filtering bridge.
    if vlans and name not in filtered:
        raise ValidationError(f'{name}: external VLAN mappings require membership in a VLAN-filtering bridge')

    used = set()
    for vid, mapping in vlans.items():
        # Reverse classification must identify one VLAN for each VNI on this port.
        if 'vni' not in mapping or int(mapping['vni']) in used:
            raise ValidationError(f'{name} vlan {vid}: each VLAN needs its own VNI')
        # Linux rejects a standalone VNI zero filter entry even though a tunnel mapping may use zero.
        if 'vni-filter' in ext and int(mapping['vni']) == 0:
            raise ValidationError(f'{name} vlan {vid}: vni-filter requires a nonzero VNI')
        used.add(int(mapping['vni']))
