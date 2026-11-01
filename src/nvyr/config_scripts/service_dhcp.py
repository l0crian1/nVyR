"""DHCPv4/v6 configuration lifecycle for independently registered service owners."""

import ipaddress
import json
from pathlib import Path

from nvyr.errors import ValidationError, Warning
from nvyr.helpers import dhcp_hosts, kea
from nvyr.helpers.kea_formatters import reservation, scope_options, subnet_id
from nvyr.helpers.logging_formatters import level
from nvyr.helpers.validators import duration_seconds
from nvyr.helpers.verification import require_fields
from nvyr.tree import lookup


def service_name(family):
    return 'dhcp-server' if family == 4 else 'dhcpv6-server'


def get_config(context):
    owner = context.owner
    family = {'dhcp-server': 4, 'dhcpv6-server': 6}[owner]
    result = {}
    for vrf in context.scripts.get(owner, {}).get('vrf', ()):
        root = ('service', owner) if vrf == 'default' else ('vrf', 'name', vrf, 'service', owner)
        section = lookup(context.effective, root, None)
        if section is not None:
            result[vrf] = section

    devices = None
    if not context.check_only and any('disable' not in server for server in result.values()):
        devices = kea.inventory()

    ha_listeners = []
    roots = [('default', context.effective)]
    roots.extend(lookup(context.effective, ('vrf', 'name'), {}).items())
    for vrf, root in roots:
        for service in ('dhcp-server', 'dhcpv6-server'):
            server = lookup(root, ('service', service), {})
            ha = lookup(server, ('ha',), {})
            if 'disable' not in server and 'source-address' in ha:
                ha_listeners.append((vrf, service, ha['source-address'], ha['port']))

    return {
        'family': family, 'servers': result, 'devices': devices,
        'ha-listeners': ha_listeners,
        'log-level': level(context.effective, owner),
        # Interface watches require rebinding even if native text is unchanged.
        'rebind': any(path[:2] != ('system', 'logging') for path in context.reapply_paths),
    }


def verify_lifetimes(values, family, path):
    # Preferred IPv6 lifetimes cannot outlive address validity.
    if family == 6 and duration_seconds(values['preferred-lifetime']) > duration_seconds(values['valid-lifetime']):
        raise ValidationError(f'{path}: preferred-lifetime cannot exceed valid-lifetime')


def verify_reservations(section, network, family, path):
    addresses = set()
    identifiers = set()
    for name, reservation in lookup(section, ('reservation',), {}).items():
        location = f'{path} reservation {name}'
        keys = ('mac-address', 'client-id') if family == 4 else ('duid',)
        chosen = [key for key in keys if key in reservation]

        # A reservation needs exactly one stable client identifier and an address.
        if len(chosen) != 1 or 'address' not in reservation:
            raise ValidationError(f'{location}: specify an address and exactly one of {", ".join(keys)}')

        address = ipaddress.ip_address(reservation['address'])
        # Reserved addresses must remain within their containing subnet.
        if address not in network:
            raise ValidationError(f'{location}: reserved address is outside {network}')

        # IPv4 network and broadcast addresses are not usable host reservations.
        if family == 4 and address in (network.network_address, network.broadcast_address):
            raise ValidationError(f'{location}: network and broadcast addresses cannot be reserved')

        identifier = (chosen[0], reservation[chosen[0]].lower())
        # Duplicate client or address assignments cannot be safely served.
        if address in addresses or identifier in identifiers:
            raise ValidationError(f'{location}: duplicate reserved address or client identifier')

        addresses.add(address)
        identifiers.add(identifier)


def verify_subnet(prefix, section, inherited, family, path):
    network = ipaddress.ip_network(prefix)
    verify_lifetimes(inherited | dict(section), family, path)
    intervals = []
    for value in lookup(section, ('range',), ()):
        first, last = (ipaddress.ip_address(part) for part in value.split('-'))
        # Every allocation range must be contained in its declared subnet.
        if first not in network or last not in network:
            raise ValidationError(f'{path}: range {value} is outside {network}')

        # Explicit IPv4 pools must not allocate network or broadcast addresses.
        if family == 4 and (first == network.network_address or last == network.broadcast_address):
            raise ValidationError(f'{path}: range {value} includes a network or broadcast address')
        intervals.append((int(first), int(last)))

    intervals.sort()
    for left, right in zip(intervals, intervals[1:]):
        # Separate pools in one subnet must not allocate the same address.
        if right[0] <= left[1]:
            raise ValidationError(f'{path}: allocation ranges overlap')

    # Reservation-only subnets are valid, but empty allocation definitions are not useful.
    if not intervals and not lookup(section, ('reservation',), None):
        raise ValidationError(f'{path}: configure a range or reservation, or disable this subnet')

    verify_reservations(section, network, family, path)


def selected_interfaces(server):
    selected = set(lookup(server, ('listen-interface',), ()))
    selected.update(shared['interface'] for shared in lookup(server, ('shared-network',), {}).values()
                    if 'disable' not in shared and 'interface' in shared)
    return selected


def address_interfaces(address, vrf, devices):
    return [name for name, device in devices.items()
            if device['vrf'] == vrf and not device.get('vrf-device') and address in device['addresses']]


def listener_bindings(server, family, vrf, devices):
    """Format validated receive selections using the inventory gathered for this commit."""
    selected = selected_interfaces(server)
    qualified = {}
    for value in lookup(server, ('listen-address',), ()):
        address = str(ipaddress.ip_address(value))
        name = address_interfaces(address, vrf, devices)[0]
        qualified[name] = address
        selected.add(name)

    result = []
    for name in sorted(selected):
        address = qualified.get(name)
        if address is None and family == 4:
            address = next(value for value in devices[name]['addresses'] if ipaddress.ip_address(value).version == 4)
        result.append(f'{name}/{address}' if address else name)
    return result


def verify_listeners(configuration, family, vrf, devices):
    explicit = set(lookup(configuration, ('listen-interface',), ()))
    selected = selected_interfaces(configuration)

    qualified = {}
    for value in lookup(configuration, ('listen-address',), ()):
        address = str(ipaddress.ip_address(value))
        matches = address_interfaces(address, vrf, devices)
        # Address-only listeners must resolve uniquely inside their own VRF.
        if len(matches) != 1:
            raise ValidationError(f'{vrf}: listen-address {value} must belong to exactly one interface in this VRF')
        name = matches[0]
        # Whole-interface and address-qualified selections have conflicting intent.
        if name in explicit:
            raise ValidationError(f'{vrf}: listen-address {value} overlaps listen-interface {name}')
        qualified.setdefault(name, set()).add(address)
        selected.add(name)

    # A server must have an explicit receive path; never silently listen everywhere.
    if not selected:
        raise ValidationError(f'{vrf}: configure listen-interface, listen-address or a shared-network interface')

    for name in sorted(selected):
        device = devices.get(name)
        # Bind only member interfaces owned by this instance, never a VRF master.
        if device is None or device['vrf'] != vrf or device.get('vrf-device'):
            raise ValidationError(f'{vrf}: DHCP interface {name} does not exist in this VRF or is a VRF device')
        # Kea cannot open service sockets on administratively disabled interfaces.
        if not device['up']:
            raise ValidationError(f'{vrf}: DHCP interface {name} is administratively disabled')

        addresses = [ipaddress.ip_address(value) for value in device['addresses']]
        # IPv4 sockets require an assigned IPv4 address; IPv6 requires link-local.
        if family == 4 and not any(address.version == 4 for address in addresses):
            raise ValidationError(f'{vrf}: DHCP interface {name} needs an IPv4 address')
        # Carrierless ports can acquire their link-local address when plugged in.
        if family == 6 and device.get('running', True) and not any(
                address.version == 6 and address.is_link_local for address in addresses):
            raise ValidationError(f'{vrf}: DHCPv6 interface {name} needs a link-local IPv6 address')

        # Multiple IPv4 raw listeners duplicate broadcast replies; Kea permits one
        # additional IPv6 unicast listener per interface as well.
        if len(qualified.get(name, ())) > 1:
            raise ValidationError(f'{vrf}: select only one listen-address per interface ({name})')
    return listener_bindings(configuration, family, vrf, devices)


def shared_interface_candidates(shared, family, selected, devices):
    if 'interface' in shared:
        return [shared['interface']]
    if family != 6:
        return []

    networks = [ipaddress.ip_network(prefix) for prefix, subnet in lookup(shared, ('subnet',), {}).items()
                if 'disable' not in subnet]
    matches = []
    for name in sorted(selected):
        addresses = [ipaddress.ip_address(value) for value in devices[name]['addresses']]
        if any(address in network for address in addresses for network in networks):
            matches.append(name)
    return matches


def verify_shared_interfaces(configuration, family, listeners, devices):
    """Resolve DHCPv6's required local subnet selector without changing the CLI tree."""
    selected = {value.split('/', 1)[0] for value in listeners}
    result = {}
    used = {}
    for name, shared in lookup(configuration, ('shared-network',), {}).items():
        # Disabled scopes do not participate in native subnet selection.
        if 'disable' in shared:
            continue
        networks = [ipaddress.ip_network(prefix) for prefix, subnet in lookup(shared, ('subnet',), {}).items()
                    if 'disable' not in subnet]
        if not networks:
            continue

        candidates = shared_interface_candidates(shared, family, selected, devices)
        # Local DHCPv6 clients need one unambiguous shared-network interface.
        if family == 6 and len(candidates) != 1:
            raise ValidationError(f'shared-network {name}: cannot derive one DHCPv6 interface from local '
                                  'subnets; configure its interface explicitly')
        interface = candidates[0] if candidates else None

        if interface is not None:
            # Two shared networks on one interface have indistinguishable local clients.
            if interface in used:
                raise ValidationError(f'shared-network {name}: interface {interface} is already selected by '
                                      f'shared-network {used[interface]}; place its subnets in that shared network')
            used[interface] = name
            result[name] = interface
    return result


def verify_ha(ha, path, vrf, devices):
    # An HA relationship needs a complete local identity before Kea can start it.
    require_fields(ha, ('name', 'source-address', 'role'), f'{path} ha')
    peers = lookup(ha, ('peer',), {})
    # The local member is generated separately, so a remote name cannot alias it.
    if ha['name'] in peers:
        raise ValidationError(f'{path} ha: peer names must differ from the local name')

    roles = [ha['role']]
    endpoints = {(str(ipaddress.ip_address(ha['source-address'])), int(ha['port']))}
    for name, peer in peers.items():
        # Each remote member needs an endpoint and role in the generated relationship.
        require_fields(peer, ('address', 'role'), f'{path} ha peer {name}')
        endpoint = (str(ipaddress.ip_address(peer['address'])), int(peer['port']))
        # Different member names must not send HA requests to the same listener.
        if endpoint in endpoints:
            raise ValidationError(f'{path} ha peer {name}: duplicate HA address and port')
        endpoints.add(endpoint)
        roles.append(peer['role'])

    partner = 'secondary' if ha['mode'] == 'active-active' else 'standby'
    # Kea requires exactly two serving roles; further replicas may only be backups.
    if sorted(role for role in roles if role != 'backup') != sorted(('primary', partner)):
        raise ValidationError(f'{path} ha: {ha["mode"]} requires exactly one primary '
                              f'and one {partner}; additional members must be backups')

    # The HA listener must bind a local address in this instance's routing domain.
    if devices is not None and not address_interfaces(str(ipaddress.ip_address(ha['source-address'])), vrf, devices):
        raise ValidationError(f'{path} ha: source-address must belong to an interface in this VRF')


def verify_ha_listeners(listeners):
    used = {}
    for vrf, service, address, port in listeners:
        endpoint = (vrf, str(ipaddress.ip_address(address)), int(port))
        # DHCPv4 and DHCPv6 are separate processes and cannot share one HA socket.
        if endpoint in used:
            raise ValidationError(f'VRF {vrf}: service {service} ha listener conflicts with '
                                  f'{used[endpoint]} at {address} port {port}')
        used[endpoint] = service


def verify(configuration, context):
    family = configuration['family']
    devices = configuration['devices']
    bindings = {}
    verify_ha_listeners(configuration['ha-listeners'])
    for vrf, server in configuration['servers'].items():
        # Disabled instances keep their configuration without binding any sockets.
        if 'disable' in server:
            continue

        path = f'VRF {vrf}: service {service_name(family)}'
        if 'ha' in server:
            verify_ha(server['ha'], path, vrf, devices)
            context.report(Warning(
                f'{path} ha: pool ranges must match on the local server and every remote peer. '
                'Active-active ranges are split by primary and secondary role.'
            ))
        shared_listeners = any('interface' in shared and 'disable' not in shared
                               for shared in lookup(server, ('shared-network',), {}).values())
        # A receive path is required even when commit-check skips live socket checks.
        if not lookup(server, ('listen-interface',), None) and not lookup(server, ('listen-address',), None) and not shared_listeners:
            raise ValidationError(f'{path}: configure listen-interface, listen-address or a shared-network interface')

        verify_lifetimes(server, family, path)
        networks = []
        ids = set()
        for name, shared in lookup(server, ('shared-network',), {}).items():
            # Disabled shared networks do not contribute active allocations.
            if 'disable' in shared:
                continue

            location = f'{path} shared-network {name}'
            inherited = dict(server) | dict(shared)
            verify_lifetimes(inherited, family, location)
            # An enabled shared network must contain at least one subnet definition.
            if not lookup(shared, ('subnet',), None):
                raise ValidationError(f'{location}: configure at least one subnet or disable this shared network')

            for prefix, subnet in lookup(shared, ('subnet',), {}).items():
                # Disabled subnets retain their leases but stop offering addresses.
                if 'disable' in subnet:
                    continue

                network = ipaddress.ip_network(prefix)
                # Overlapping subnet definitions need classification, outside this service contract.
                if any(network.overlaps(existing) for existing in networks):
                    raise ValidationError(f'{location} subnet {prefix}: overlaps another subnet in this VRF')

                identifier = subnet_id(prefix)
                # Deterministic IDs must never silently alias two lease scopes.
                if identifier in ids:
                    raise ValidationError(f'{location} subnet {prefix}: stable subnet ID collision')

                ids.add(identifier)
                networks.append(network)
                verify_subnet(prefix, subnet, inherited, family, f'{location} subnet {prefix}')

        # Commit checks cannot require interfaces that earlier owners have not created yet.
        if context.check_only:
            context.report(f'{path}: skipped live listener checks; they run during commit.\n')
            continue

        listeners = verify_listeners(server, family, vrf, devices)
        verify_shared_interfaces(server, family, listeners, devices)
        bindings[vrf] = {value.split('/', 1)[1] for value in listeners if '/' in value}

    # Kea's unbound IPv4 fallback socket in the default VRF conflicts with the
    # same local address in a named VRF, even with udp_l3mdev_accept disabled.
    if family == 4:
        default = bindings.get('default', set())
        for vrf, addresses in bindings.items():
            if vrf != 'default' and default & addresses:
                raise ValidationError(f'{vrf}: IPv4 listen-address overlaps the default VRF: '
                                      f'{", ".join(sorted(default & addresses))}. Kea fallback sockets '
                                      'require different local listener addresses for default and named VRFs.')


def ha_peer(name, address, port, role):
    address = ipaddress.ip_address(address)
    host = f'[{address}]' if address.version == 6 else str(address)
    return {'name': name, 'url': f'http://{host}:{port}/', 'role': role,
            'auto-failover': role != 'backup'}


def ha_hooks(ha):
    peers = [ha_peer(ha['name'], ha['source-address'], ha['port'], ha['role'])]
    peers.extend(ha_peer(name, peer['address'], peer['port'], peer['role'])
                 for name, peer in lookup(ha, ('peer',), {}).items())
    relationship = {
        'this-server-name': ha['name'],
        'mode': {'active-active': 'load-balancing', 'active-passive': 'hot-standby'}[ha['mode']],
        'peers': peers,
        # Dedicated listeners retain the existing Unix management socket and
        # avoid a separate Control Agent. Bound worker counts avoid CPU-sized pools.
        'multi-threading': {'enable-multi-threading': True, 'http-dedicated-listener': True,
                            'http-listener-threads': 2, 'http-client-threads': 2},
    }
    directory = '/usr/lib/x86_64-linux-gnu/kea/hooks'
    return [
        {'library': f'{directory}/libdhcp_lease_cmds.so'},
        {'library': f'{directory}/libdhcp_ha.so', 'parameters': {'high-availability': [relationship]}},
    ]


def allocation_pools(ranges, ha):
    """Split each active-active range identically on every member, without enumerating it."""
    if ha is None or ha['mode'] == 'active-passive':
        return [{'pool': value} for value in ranges]

    members = {ha['role']: ha['name']}
    members.update({peer['role']: name for name, peer in lookup(ha, ('peer',), {}).items()})
    result = []
    for value in ranges:
        first, last = (ipaddress.ip_address(part) for part in value.split('-'))
        address_type = type(first)
        # Split each range separately so adding another range never moves the
        # ownership boundary of an existing range. The primary takes an odd extra.
        primary_last = int(first) + (int(last) - int(first)) // 2
        result.append({'pool': f'{first}-{address_type(primary_last)}',
                       'client-classes': [f'HA_{members["primary"]}']})
        if primary_last < int(last):
            result.append({'pool': f'{address_type(primary_last + 1)}-{last}',
                           'client-classes': [f'HA_{members["secondary"]}']})
    return result


def generate(configuration, context):
    family = configuration['family']
    devices = configuration['devices']
    desired = {}
    severity = {'emerg': 'FATAL', 'alert': 'FATAL', 'crit': 'FATAL', 'err': 'ERROR',
                'warn': 'WARN', 'notice': 'INFO', 'info': 'INFO', 'debug': 'DEBUG'}[configuration['log-level']]

    for vrf, section in configuration['servers'].items():
        if 'disable' in section:
            continue

        instance = kea.instance_name(family, vrf)
        listeners = listener_bindings(section, family, vrf, devices)
        selected = {value.split('/', 1)[0] for value in listeners}
        lease_file = Path(context.state_directory).resolve() / 'kea' / instance / 'leases.csv'
        server = scope_options(section, family)
        server['interfaces-config'] = {
            'interfaces': listeners, 'service-sockets-require-all': True,
            'service-sockets-max-retries': 12, 'service-sockets-retry-wait-time': 1000,
        }
        if family == 4:
            server['interfaces-config']['dhcp-socket-type'] = lookup(section, ('socket-type',))

        server['lease-database'] = {'type': 'memfile', 'persist': True, 'name': str(lease_file)}
        server['control-sockets'] = [{'socket-type': 'unix', 'socket-name': str(kea.RUNTIME / f'{instance}.sock')}]
        # An explicit empty list unloads removed HA and hostfile hooks on config-set.
        server['hooks-libraries'] = []
        if 'ha' in section:
            server['multi-threading'] = {'enable-multi-threading': True, 'thread-pool-size': 2}
            server['hooks-libraries'].extend(ha_hooks(section['ha']))
        if family == 4 and 'update-hostfile' in section:
            server['hooks-libraries'].append({
                'library': dhcp_hosts.HOOK_LIBRARY,
                'parameters': {'name': dhcp_hosts.HOOK_SCRIPT, 'sync': False},
            })
        server['loggers'] = [{
            'name': f'kea-dhcp{family}', 'severity': severity, 'debuglevel': 99,
            'output-options': [{'output': 'syslog:local0', 'pattern': f'[nvyr-kea-{instance}] %m'}],
        }]
        server['shared-networks'] = []

        for name, shared in lookup(section, ('shared-network',), {}).items():
            if 'disable' in shared:
                continue

            network = scope_options(shared, family)
            network['name'] = name
            candidates = shared_interface_candidates(shared, family, selected, devices)
            if candidates:
                network['interface'] = candidates[0]
            subnets = []
            for prefix, values in lookup(shared, ('subnet',), {}).items():
                if 'disable' in values:
                    continue

                subnet = scope_options(values, family)
                subnet.update({
                    'subnet': prefix, 'id': subnet_id(prefix),
                    'pools': allocation_pools(lookup(values, ('range',), ()), lookup(section, ('ha',), None)),
                    'reservations': [reservation(label, item, family)
                                     for label, item in lookup(values, ('reservation',), {}).items()],
                })
                subnets.append(subnet)

            # Fully disabled scopes must not leave an empty native shared network.
            if subnets:
                network[f'subnet{family}'] = subnets
                server['shared-networks'].append(network)

        desired[instance] = json.dumps({f'Dhcp{family}': server}, indent=2, sort_keys=True)

    return kea.Plan(family, desired, rebind=configuration['rebind'])


def apply(plan, context):
    kea.manager.apply(plan, context.state_directory, recovery=context.recovery, report=context.report)
