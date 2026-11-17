"""WireGuard configuration, cross-peer validation and native link generation."""

import ipaddress
import hashlib

from nvyr.errors import ValidationError
from nvyr.helpers import interfaces, netlink, task_schedule, template, wireguard
from nvyr.helpers.process import cmd
from nvyr.tree import lookup

ROOT = ('interfaces', 'wireguard')


def get_config(context):
    return {
        'interfaces': lookup(context.effective, ROOT, {}),
        'inventory': dict(interfaces.configured(context.effective)),
        'vrfs': lookup(context.effective, ('vrf', 'name'), {}),
        'bridge_members': interfaces.bridge_members(context.effective),
        'bond_members': interfaces.bond_members(context.effective),
    }


def verify(configuration, context):
    values = configuration['interfaces']
    ports = {}
    for name, settings in values.items():
        # A routed WireGuard device cannot act as an Ethernet bridge or bond port.
        if name in configuration['bridge_members'] | configuration['bond_members']:
            raise ValidationError(f'{name}: WireGuard cannot be a bridge or bond member')
        # Every configured interface needs its local cryptographic identity.
        if 'private-key' not in settings:
            raise ValidationError(f'{name}: private-key is required')
        port = lookup(settings, ('listen-port',), '0')
        # Transport sockets live in the default namespace regardless of the inner VRF.
        if int(port) and 'disable' not in settings:
            other = ports.setdefault(int(port), name)
            if other != name:
                raise ValidationError(f'{name} and {other}: listen-port {port} is already assigned')
        keys, prefixes = {}, {}
        for peer_name, peer in lookup(settings, ('peer',), {}).items():
            path = f'{name} peer {peer_name}'
            # A peer needs a public identity even when initially disabled.
            if 'public-key' not in peer:
                raise ValidationError(f'{path}: public-key is required')
            key = peer['public-key']
            # Native WireGuard indexes peers by public key, not their CLI names.
            other = keys.setdefault(key, peer_name)
            if other != peer_name:
                raise ValidationError(f'{path}: public-key is also assigned to peer {other}')
            for prefix in lookup(peer, ('allowed-ips',), ()):
                canonical = str(ipaddress.ip_network(prefix))
                # Exact duplicates transfer ownership to the last peer; nested prefixes use longest match.
                if 'disable' not in peer:
                    other = prefixes.setdefault(canonical, peer_name)
                    if other != peer_name:
                        raise ValidationError(f'{path}: allowed-ips {canonical} is also assigned to peer {other}')
            endpoint = lookup(peer, ('endpoint',), {})
            # An endpoint is one address/port pair; DNS controls cannot stand alone.
            if endpoint and not {'address', 'port'} <= endpoint.keys():
                raise ValidationError(f'{path}: endpoint requires address and port')
            # Family selection and periodic resolution only apply to hostname endpoints.
            if endpoint and not wireguard.hostname(endpoint['address']) and any(
                    field in endpoint for field in ('address-family', 'resolve-interval')):
                raise ValidationError(f'{path}: address-family and resolve-interval require a hostname')

    # An inner routing domain must exist in the proposed configuration.
    interfaces.verify_membership(values, vrfs=configuration['vrfs'], bridge_members=())

    # Changing a delegated LAN's VRF or link-local policy also affects its uplink.
    interfaces.verify_pd(configuration['inventory'], configuration['bridge_members'] | configuration['bond_members'])

    links = interfaces.NetlinkManager.definitions('wireguard', interfaces.settings(values))
    # Check native link ownership and common IP options without resolving DNS or applying keys.
    netlink.normalize(links)
    interfaces.manager.request('validate', owner='wireguard', links=links, recovery=context.recovery)


def generate(configuration, context):
    values = configuration['interfaces']
    links = interfaces.NetlinkManager.definitions('wireguard', interfaces.settings(values))
    schedules = {}
    retries = []
    for name, settings in values.items():
        peers = {}
        for peer_name, peer in lookup(settings, ('peer',), {}).items():
            if 'disable' in peer:
                continue
            peers[peer_name] = {
                'public-key': peer['public-key'],
                'preshared-key': lookup(peer, ('preshared-key',), wireguard.ZERO_KEY),
                'allowed-ips': sorted({str(ipaddress.ip_network(value)) for value in lookup(peer, ('allowed-ips',), ())}),
                'persistent-keepalive': int(lookup(peer, ('persistent-keepalive',), '0')),
                'endpoint': dict(lookup(peer, ('endpoint',), {})),
            }
        peers = wireguard.prepare_endpoints(name, peers, context.report)
        links[name]['attributes']['wireguard'] = {
            'private-key': settings['private-key'],
            'listen-port': int(lookup(settings, ('listen-port',), '0')),
            'firewall-mark': int(lookup(settings, ('firewall-mark',), '0'),
                                 16 if lookup(settings, ('firewall-mark',), '0').lower().startswith('0x') else 10),
            'peers': peers,
        }
        if 'disable' not in settings:
            if any(peer['endpoint'] and wireguard.hostname(peer['endpoint']['address']) for peer in peers.values()):
                unit = task_schedule.unit('wireguard', 'op', name + '-initial')
                schedules[unit + '.service'] = template.render('wireguard/resolve.service.j2', {
                    'interface': name, 'log': task_schedule.LOGS / (unit + '.log')})
                retries.append(unit + '.service')
            for peer_name, peer in peers.items():
                interval = lookup(peer, ('endpoint', 'resolve-interval'), None)
                if interval:
                    identity = name + '-' + hashlib.sha256(peer_name.encode()).hexdigest()[:32]
                    schedules.update(task_schedule.render('wireguard', identity, 'op',
                        ['/usr/bin/wireguard.nvyr.op', 'refresh', name, '--peer', peer_name, '--scheduled'],
                        {'interval': interval}))
    return {'links': links, 'schedules': schedules, 'retries': retries}


def apply(configuration, context):
    interfaces.manager.replace('wireguard', configuration['links'], recovery=context.recovery)
    task_schedule.reconcile('wireguard', configuration['schedules'], recover=context.recovery)
    if configuration['retries']:
        cmd(['systemctl', 'start', '--no-block', *configuration['retries']])
