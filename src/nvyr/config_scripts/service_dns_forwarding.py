"""Unbound forwarding instances: gather, verify, render, then install."""

import ipaddress
import json

from nvyr.errors import ValidationError
from nvyr.helpers import dns_forwarding, kea
from nvyr.render import json_text
from nvyr.tree import lookup


def get_config(context):
    roots = [('default', context.effective)]
    roots.extend(lookup(context.effective, ('vrf', 'name'), {}).items())
    instances = {}
    for vrf, root in roots:
        section = lookup(root, ('service', 'dns', 'forwarding'), None)
        if section is not None and 'disable' not in section:
            instances[vrf] = section

    return {
        'instances': instances,
        'static': lookup(context.effective, ('system', 'static-host-mapping'), {}),
        'devices': None if context.check_only or not instances else kea.inventory(),
    }


def verify_forwarders(section, path):
    servers = lookup(section, ('name-server',), {})
    encrypted = ['tls' in settings for settings in servers.values()]

    # Unbound chooses the transport for an entire forwarding zone.
    if any(encrypted) and (not all(encrypted) or lookup(section, ('name-server-interface',), ())):
        raise ValidationError(f'{path}: TLS and plaintext/learned upstreams cannot share a forwarding zone')

    for address, settings in servers.items():
        # Authentication requires an explicit certificate identity, not encryption alone.
        if 'tls' in settings and not lookup(settings, ('tls', 'authentication-name'), None):
            raise ValidationError(f'{path} name-server {address} tls: requires authentication-name')


def verify(configuration, context):
    devices = configuration['devices']
    for vrf, section in configuration['instances'].items():
        path = f'DNS forwarding in VRF {vrf}'
        verify_forwarders(section, path)
        domains = set()
        sources = set(lookup(section, ('name-server-interface',), ()))
        for domain, forwarding in lookup(section, ('domain',), {}).items():
            canonical = domain.lower().rstrip('.')
            # DNS names are case insensitive; alternate spellings cannot define two policies.
            if canonical in domains:
                raise ValidationError(f'{path}: duplicate forwarding domain {domain}')
            domains.add(canonical)
            verify_forwarders(forwarding, f'{path} domain {domain}')
            sources.update(lookup(forwarding, ('name-server-interface',), ()))

        cache = lookup(section, ('cache',), {})
        # A minimum TTL above the maximum cannot express a coherent cache lifetime.
        if ('minimum-ttl' in cache and 'maximum-ttl' in cache
                and int(cache['minimum-ttl']) > int(cache['maximum-ttl'])):
            raise ValidationError(f'{path}: minimum-ttl cannot exceed maximum-ttl')

        # Offline validation cannot observe addresses created by preceding interface scripts.
        if devices is None:
            continue

        local = {ipaddress.ip_address(address) for device in devices.values() if device['vrf'] == vrf
                 for address in device['addresses']}
        for interface in set(lookup(section, ('listen-interface',), ())) | sources:
            device = lookup(devices, (interface,), None)
            # A VRF instance must neither listen on nor learn upstreams from another VRF.
            if device is None or device['vrf'] != vrf:
                raise ValidationError(f'{path}: interface {interface} is not present in this VRF')

        for address in (*lookup(section, ('listen-address',), ()), *lookup(section, ('source-address',), ())):
            value = ipaddress.ip_address(address)
            # Wildcard bindings are valid, but other explicit addresses must belong to the instance.
            if not value.is_unspecified and value not in local:
                raise ValidationError(f'{path}: address {address} is not assigned in this VRF')

        listeners = dns_forwarding.listener_addresses(section, vrf, devices)
        for forwarding in [section, *lookup(section, ('domain',), {}).values()]:
            for address, settings in lookup(forwarding, ('name-server',), {}).items():
                port = int(lookup(settings, ('port',), 853 if 'tls' in settings else 53))
                # An upstream targeting this listener would recursively forward to itself.
                if port == int(lookup(section, ('port',), 53)) and dns_forwarding.is_listener(address, listeners, local):
                    raise ValidationError(f'{path}: upstream {address}:{port} points to this DNS listener')


def generate(configuration, context):
    # Materialize the read-only commit view for the refresh process's JSON snapshot.
    intent = json.loads(json_text({'instances': configuration['instances'], 'static': configuration['static']}))
    return {'intent': intent, 'bundles': dns_forwarding.generate(intent, devices=configuration['devices'],
                                                               offline=context.check_only)}


def apply(plan, context):
    dns_forwarding.install(plan)
