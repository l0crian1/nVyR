"""Translate validated DHCP configuration into Kea's native JSON structure."""

import hashlib
import ipaddress

from nvyr.helpers.validators import duration_seconds


def subnet_id(prefix):
    """Stable across ordering, shared-network renames, and process restarts."""
    digest = hashlib.sha256(str(ipaddress.ip_network(prefix)).encode()).digest()
    return int.from_bytes(digest[:4], 'big') % 4294967294 + 1


def scope_options(section, family):
    names = {'name-server': 'domain-name-servers' if family == 4 else 'dns-servers',
             'domain-search': 'domain-search',
             'domain-name': 'domain-name', 'default-router': 'routers', 'ntp-server': 'ntp-servers'}
    result = {}
    timers = {'lease-time': 'valid-lifetime', 'preferred-lifetime': 'preferred-lifetime',
              'valid-lifetime': 'valid-lifetime'}
    for key, target in timers.items():
        if key in section:
            result[target] = duration_seconds(section[key])

    if 'description' in section:
        result['user-context'] = {'description': section['description']}

    if section.get('option'):
        result['option-data'] = []
        for key, value in section['option'].items():
            data = ', '.join(value) if isinstance(value, (list, tuple)) else value
            result['option-data'].append({'name': names[key], 'data': data})
    return result


def reservation(name, values, family):
    """Encode one reservation, retaining its CLI name for operational displays."""
    result = {'user-context': {'name': name}}
    if 'description' in values:
        result['user-context']['description'] = values['description']
    for key, value in values.items():
        if key == 'mac-address':
            result['hw-address'] = value
        elif key == 'address':
            result['ip-address' if family == 4 else 'ip-addresses'] = value if family == 4 else [value]
        elif key in ('hostname', 'duid', 'client-id'):
            result[key] = value
    return result
