"""Comprehensive saved lab configuration, shared by preboot and postboot checks."""

import ipaddress
import json
from pathlib import Path
import re

from nvyr.helpers.process import cmd
from nvyr.lexer import quote
from nvyr.tree import lookup
from smoketests.assertions import assert_config_names_unused
from acceptance.checks import CHECKS


CONFIG = Path(__file__).parent / 'config'
CONFIG_FILES = ('interfaces.set', 'routing.set', 'services.set', 'firewall.set')
LINKS = ('BOOTLEFT', 'BOOTRIGHT', 'dum992', 'dum995', 'dum996', 'dum997', 'dum998',
         'dum999', 'veth993', 'veth994', 'veth995', 'veth997', 'br994', 'br995',
         'pd-BOOTNET', 'pd-BOOTVRF', 'pd-BOOTBOX-0', 'pd-BOOTBOX-1', 'pd-BOOTPOD-0')
TABLES = (41995, 41996)
PREFIXES = ('198.18.192.0/19',) + tuple(f'2001:db8:{number}::/64' for number in range(192, 211))


def commands(options):
    """Keep full CLI commands reviewable, with only the lab inputs substituted."""
    replacements = {'@ethernet': options['ethernet'], '@image': quote(options['image']),
                    '@assets': options['assets']}
    for filename in CONFIG_FILES:
        for number, line in enumerate((CONFIG / filename).read_text().splitlines(), 1):
            if not line.strip() or line.startswith('#'):
                continue
            for token, value in replacements.items():
                line = line.replace(token, value)
            yield filename, number, line


def validate_options(options):
    """Validate inputs even when the agent is invoked without the external controller."""
    if not re.fullmatch(r'eth[0-9]+', options.get('ethernet', '')):
        raise ValueError('Select a spare physical Ethernet port, for example eth1')
    if not isinstance(options.get('image'), str) or not options['image'] or '\n' in options['image']:
        raise ValueError('A preloaded Alpine-compatible image is required')
    if not re.fullmatch(r'boot-[0-9a-f-]{36}', options.get('assets', '')):
        raise ValueError('Invalid persistent acceptance asset directory')


def overlaps_reserved(prefix):
    """Avoid borrowing addresses or routes already in use by the lab."""
    network = ipaddress.ip_network(prefix, strict=False)
    for reserved in PREFIXES:
        candidate = ipaddress.ip_network(reserved)
        if candidate.version == network.version and candidate.overlaps(network):
            return True
    return False


def automatic_ipv6_route(route):
    """Recognize kernel link-local and multicast routes on an otherwise spare link."""
    # User routes and routes through another next hop still make the port occupied.
    if route.get('protocol') != 'kernel' or any(key in route for key in ('gateway', 'via', 'multipath', 'nhid')):
        return False

    try:
        destination = ipaddress.ip_network(route.get('dst', ''), strict=False)
    except ValueError:
        return False

    # Only IPv6's automatic link-local and multicast entries qualify for exemption.
    if destination.version != 6:
        return False

    table = str(route.get('table', 'main'))
    route_type = route.get('type', 'unicast')
    if destination.subnet_of(ipaddress.ip_network('fe80::/10')):
        return (table in ('main', '254') and route_type == 'unicast'
                or table in ('local', '255') and route_type in ('local', 'anycast'))

    return (destination == ipaddress.ip_network('ff00::/8')
            and table in ('local', '255') and route_type == 'multicast')


def preflight(configuration, options):
    """Require an exclusive minimal lab and explicit hardware/workload inputs."""
    validate_options(options)
    # Global policy cannot be meaningfully checked alongside an unrelated ruleset.
    for section in ('firewall', 'nat', 'policy', 'protocols', 'container', 'vrf'):
        if configuration.get(section):
            raise ValueError(f'Comprehensive acceptance needs a clean lab {section} section')
    for service in ('dhcp-server', 'dhcpv6-server'):
        if lookup(configuration, ('service', service), {}):
            raise ValueError(f'Comprehensive acceptance needs no existing {service}')

    assert_config_names_unused(configuration, *LINKS)
    port = options['ethernet']
    configured_port = lookup(configuration, ('interfaces', 'ethernet', port), {})
    if set(configured_port) - {'description', 'disable'}:
        raise ValueError(f'{port} must be a spare port without configured addresses or consumers')

    devices = json.loads(cmd(['ip', '-j', '-d', 'address', 'show']))
    spare = next((link for link in devices if link['ifname'] == port), None)
    if spare is None or spare.get('link_type') != 'ether' or spare.get('master'):
        raise ValueError(f'{port} is not an available Ethernet port')
    if not (Path('/sys/class/net') / port / 'device').exists():
        raise ValueError(f'{port} is not a physical Ethernet device')
    for address in spare.get('addr_info', []):
        if not ipaddress.ip_address(address['local']).is_link_local:
            raise ValueError(f'{port} already has an address; do not select the management port')

    for link in devices:
        if link['ifname'] in LINKS or link['ifname'].startswith(('veth995.', 'veth997.', 'br995.')):
            raise ValueError(f"Acceptance interface already exists: {link['ifname']}")
        if link.get('linkinfo', {}).get('info_data', {}).get('table') in TABLES:
            raise ValueError('Acceptance VRF table is already in use')
        for address in link.get('addr_info', []):
            if overlaps_reserved(f"{address['local']}/{address['prefixlen']}"):
                raise ValueError(f"Acceptance address space already in use on {link['ifname']}")

    for family in ('-4', '-6'):
        for route in json.loads(cmd(['ip', family, '-j', 'route', 'show', 'table', 'all'])):
            # Reserved tables must be empty, including any automatic IPv6 routes.
            if str(route.get('table')) in {'41995', '41996'}:
                raise ValueError(f'Acceptance VRF table already has routes: {route}')

            # An enabled spare port may have kernel IPv6 routes without configured policy.
            if route.get('dev') == port and not (family == '-6' and automatic_ipv6_route(route)):
                raise ValueError(f'Acceptance spare port {port} already has routes: {route}')
            destination = route.get('dst', 'default')
            if destination != 'default' and overlaps_reserved(destination):
                raise ValueError(f'Acceptance address space overlaps route {destination}')

    # Confirm the exact image is already available; acceptance never pulls at boot.
    cmd(['podman', 'image', 'inspect', options['image']])
    containers = json.loads(cmd(['podman', 'ps', '-a', '--format', 'json']))
    if any(set(item.get('Names', [])) & {'BOOTBOX', 'BOOTAPP', 'BOOTCACHE', 'BOOTPOD', 'BOOTPOD-infra'}
           for item in containers):
        raise ValueError('An acceptance container already exists')
    pods = json.loads(cmd(['podman', 'pod', 'ps', '--format', 'json']))
    if any(item['Name'] in {'BOOTPOD', 'BOOTAPP', 'BOOTCACHE', 'BOOTBOX'} for item in pods):
        raise ValueError('An acceptance pod already exists')
    networks = json.loads(cmd(['podman', 'network', 'ls', '--format', 'json']))
    if any(item.get('name', item.get('Name')) in ('BOOTNET', 'BOOTVRF') for item in networks):
        raise ValueError('An acceptance container network already exists')


def prepare_assets(options):
    """Create persistent inputs once; never recreate them during postboot verification."""
    directory = Path('/config/containers') / options['assets']
    directory.mkdir(parents=True, mode=0o700)
    (directory / 'data').mkdir(mode=0o700)
    (directory / 'data' / 'sentinel').write_text(options['assets'] + '\n')
    (directory / 'environment').write_text('BOOT_FILE=from-file\nBOOT_OVERRIDE=file\n')


def configure(config, options):
    """Apply everything together to expose dependency/startup ordering defects."""
    if lookup(config.get_config(), ('system', 'ntp'), None) is not None:
        config.delete('delete system ntp')
    if lookup(config.get_config(), ('interfaces', 'ethernet', options['ethernet']), None) is not None:
        config.delete('delete interfaces ethernet ' + options['ethernet'])
    for filename, number, line in commands(options):
        try:
            config.set(line)
        except Exception as error:
            raise ValueError(f'{filename}:{number}: {line}\n{error}') from error
