"""DHCPv4 client options and local lease policy, shared by scripts and netlinkd."""

from collections.abc import Mapping
import socket

from nvyr.errors import ValidationError
from nvyr.helpers.validators import dhcp_domain, dhcp_identifier


def verify(values):
    """Check DHCP options and their combined packet budget without changing them."""
    allowed = {'client-id', 'default-route-distance', 'host-name', 'mtu',
               'no-default-route', 'user-class', 'vendor-class-id'}

    # Reject unknown options at the daemon boundary as well as in the CLI.
    if not isinstance(values, Mapping) or set(values) - allowed:
        raise ValidationError('Invalid DHCPv4 options')

    distance = values.get('default-route-distance', 210)
    # AD 255 is unusable, and zero would compete with connected routes.
    if isinstance(distance, bool) or not str(distance).isdigit() or not 1 <= int(distance) <= 254:
        raise ValidationError('DHCP default-route-distance must be between 1 and 254')

    for key in ('mtu', 'no-default-route'):
        # These options are valueless switches, never arbitrary RPC payloads.
        if key in values and values[key] is not True:
            raise ValidationError(f'DHCP {key} must be valueless')

    for key, maximum in (('host-name', 253), ('user-class', 254), ('vendor-class-id', 255)):
        if key not in values:
            continue
        value = values[key]
        # DHCP options have a one-byte length; user-class also has a class-length byte.
        if not isinstance(value, str) or not 1 <= len(value.encode('utf-8')) <= maximum or '\0' in value:
            raise ValidationError(f'DHCP {key} must contain 1-{maximum} UTF-8 bytes without NUL')

    # The hostname must be a valid DNS name, rather than arbitrary option bytes.
    if 'host-name' in values and not dhcp_domain(values['host-name']):
        raise ValidationError('DHCP host-name must be a valid hostname')

    if 'client-id' in values:
        identifier = values['client-id']
        # Exactly one encoding prevents ambiguous or empty identifiers.
        if not isinstance(identifier, Mapping) or set(identifier) not in ({'text'}, {'hex'}):
            raise ValidationError('DHCP client-id requires exactly one of text or hex')
        key, value = next(iter(identifier.items()))
        # Text leaves room for the non-hardware type byte; hex includes that byte.
        if not isinstance(value, str):
            raise ValidationError('DHCP client-id must be text')
        if key == 'text' and (not 1 <= len(value.encode('utf-8')) <= 254 or '\0' in value):
            raise ValidationError('DHCP client-id text must contain 1-254 UTF-8 bytes without NUL')
        # RFC 2132 identifiers include a type byte and at least one identifier byte.
        if key == 'hex' and not dhcp_identifier(value, 2, 255):
            raise ValidationError('DHCP client-id hex requires 2-255 colon-separated bytes')

    verify_packet_budget(client_options(values))


def format_options(values):
    """Copy verified DHCP options into the daemon's JSON transport format."""
    result = dict(values)
    result['default-route-distance'] = int(values.get('default-route-distance', 210))
    if 'client-id' in values:
        result['client-id'] = dict(values['client-id'])

    return result


def normalize(values):
    """Validate untrusted daemon input before formatting it."""
    verify(values)
    return format_options(values)


def verify_packet_budget(options):
    """Bound identity options so udhcpc never silently drops a configured field."""
    # BusyBox's transmit option buffer is 308 bytes. Reserve space for message
    # type, requested IP/server, max size, parameter list, end and default vendor.
    # The nVyR identity allowance is deliberately 240 bytes, including TLV headers.
    size = 0
    for key in ('host-name', 'user-class', 'vendor-class-id'):
        if key in options:
            size += 2 + len(options[key].encode('utf-8'))
            if key == 'user-class':
                size += 1
    identifier = options.get('client-id', {})
    if 'text' in identifier:
        size += 3 + len(identifier['text'].encode('utf-8'))
    elif 'hex' in identifier:
        size += 2 + len(identifier['hex'].split(':'))
    else:
        size += 9  # Default Ethernet type/MAC identifier and option header.

    # Reject an oversized combination rather than sending an incomplete identity.
    if size > 240:
        raise ValidationError(f'DHCP client identity options require {size} bytes (maximum 240 including option headers)')


def client_options(options):
    """Only wire options change the client generation; route policy is local."""
    result = {key: options[key] for key in ('client-id', 'host-name', 'user-class', 'vendor-class-id')
              if key in options}
    result.setdefault('host-name', socket.gethostname())
    return result


def client_arguments(name, options, hook='/usr/bin/nvyr-dhcp4-hook'):
    """Encode strings as raw bytes so BusyBox cannot reinterpret their syntax."""
    arguments = ['udhcpc', '-f', '-R', '-a', '-i', name, '-s', hook,
                 '-O', 'staticroutes', '-O', 'mtu']
    wire = client_options(options)
    # BusyBox emits its own default option 60 unless the dedicated switch replaces it.
    if 'vendor-class-id' in wire:
        arguments.extend(['-V', wire['vendor-class-id']])

    for key, number in (('host-name', 12), ('user-class', 77)):
        if key in wire:
            data = wire[key].encode('utf-8')
            if key == 'user-class':
                data = bytes([len(data)]) + data
            arguments.extend(['-x', f'{number}:{data.hex()}'])

    if 'client-id' in wire:
        identifier = wire['client-id']
        if 'text' in identifier:
            data = b'\x00' + identifier['text'].encode('utf-8')
        else:
            data = bytes.fromhex(identifier['hex'].replace(':', ''))
        arguments.extend(['-x', f'61:{data.hex()}'])

    return arguments


def lease_routes(lease, options):
    """Encode FRR administrative distance in the upper byte of default metrics."""
    routes = []
    for route in lease['routes']:
        if route['dst'] == '0.0.0.0/0':
            if 'no-default-route' in options:
                continue
            metric = (options.get('default-route-distance', 210) << 24) | (route['metric'] & 0xffffff)
            route = dict(route, metric=metric)
        routes.append(route)
    return routes


def lease_spec(spec, lease):
    """Use a leased MTU only while requested and valid; retain the saved profile."""
    if not lease or 'mtu' not in spec.get('dhcp-options', {}) or 'mtu' not in lease:
        return spec

    mtu = lease['mtu']
    # nVyR enables IPv6 on its interfaces, so an advertised MTU must support it too.
    if type(mtu) is not int or not 1280 <= mtu <= 65535:
        raise ValidationError(f"{spec['name']}: DHCP MTU must be between 1280 and 65535")
    return dict(spec, attributes=spec['attributes'] | {'mtu': mtu})
