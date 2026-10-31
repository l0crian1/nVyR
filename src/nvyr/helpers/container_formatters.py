"""Native Podman argv and Quadlet rendering, without host mutations."""

import ipaddress
import json

from nvyr.helpers.container_config import network_unit_name, veth_name
from nvyr.helpers.validators import container_argument_words, container_memory_bytes


def quoted(value):
    # systemd expands specifiers even in quotes; literal percent signs need doubling.
    return json.dumps(str(value).replace('%', '%%'), ensure_ascii=False)


def network_gateway(prefix, settings):
    return settings.get('gateway', str(ipaddress.ip_network(prefix).network_address + 1))


def network_ipv6(configuration):
    return any(ipaddress.ip_network(prefix).version == 6 for prefix in configuration['subnet'])


def attachment(name, network, settings):
    """Encode one Netavark attachment, including its stable host-side veth name."""
    options = ['host_interface_name=' + veth_name(name, settings)]
    for address in settings.get('address', ()):
        key = 'ip6' if ipaddress.ip_address(address).version == 6 else 'ip'
        options.append(f'{key}={address}')
    options.extend('alias=' + alias for alias in settings.get('alias', ()))
    return network_unit_name(network) + '.network:' + ','.join(options)


def published_port(settings):
    address = settings.get('source-address', '0.0.0.0')
    if ':' in address:
        address = '[' + address + ']'
    return f'{address}:{settings["source-port"]}:{settings["destination-port"]}/{settings["protocol"]}'


def capabilities(configuration):
    selected = set(configuration.get('capability', ()))
    if 'none' not in selected:
        selected.add('net-bind-service')
    return [value.upper().replace('-', '_') for value in sorted(selected - {'none'})]


def image_user(value):
    """Preserve an image's user when Quadlet needs User for a group-only override."""
    if value is None:
        raise ValueError('Image user metadata is required for a group-only override')
    return quoted((value.split(':', 1)[0] or '0').replace('$', '$$'))


def entrypoint(value):
    # Quadlet expects raw JSON and performs systemd argument quoting itself.
    return json.dumps(container_argument_words(value)).replace('%', '%%').replace('$', '$$')


def arguments(configuration):
    # Exec is passed as argv to the image entrypoint, without a host shell.
    words = [configuration['command']] if 'command' in configuration else []
    words.extend(container_argument_words(configuration.get('argument', '')))
    return ' '.join(quoted(word.replace('$', '$$')) for word in words)


def tmpfs_options(settings):
    options = ['rw', 'noexec', 'nosuid', 'nodev']
    if 'size' in settings:
        options.append('size=' + str(container_memory_bytes(settings['size'])))
    if 'mode' in settings:
        options.append('mode=' + settings['mode'])
    return ','.join(options)
