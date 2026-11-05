#!/usr/bin/env python3
"""Inspect and clear a selected Unbound forwarding instance."""

import json

from tabulate import tabulate

from nvyr import opmode
from nvyr.errors import RouterError
from nvyr.helpers import dns_forwarding as dns


def observation(vrf):
    path = dns.ROOT / dns.instance_id(vrf) / 'status.json'
    if not path.exists():
        raise RouterError(f'DNS forwarding is not configured in VRF {vrf}')
    return json.loads(path.read_text())


@opmode.command
def show(kind: str, vrf: str = 'default', name: str = '', raw: bool = False):
    state = observation(vrf)
    configuration = state['configuration']
    if kind == 'status':
        rows = {'VRF': vrf, 'State': 'Waiting for listener addresses' if state['waiting'] else
                ('Running' if dns.active(vrf) else 'Stopped'),
                'Listeners': ', '.join(state['listeners']), 'Port': configuration.get('port', '53'),
                'Allow from': ', '.join(configuration.get('allow-from', ())) or 'Loopback only',
                'Default upstreams': len(configuration.get('name-server', {})) + len(state['learned']['.']),
                'Excluded self-upstreams': ', '.join(state['excluded-upstreams']) or '-',
                'Local records': len(state['records'])}
        return json.dumps(rows) if raw else tabulate(rows.items(), tablefmt='presto', disable_numparse=True) + '\n'
    if kind == 'upstreams':
        rows = []
        for domain, forwarding in [('.', configuration), *configuration.get('domain', {}).items()]:
            for address, settings in forwarding.get('name-server', {}).items():
                rows.append({'Domain': domain, 'Server': address, 'Port': settings.get('port', 853 if 'tls' in settings else 53),
                             'Transport': 'TLS' if 'tls' in settings else 'UDP/TCP', 'Source': 'Static'})
            for address in state['learned'][domain]:
                rows.append({'Domain': domain, 'Server': address, 'Port': 53, 'Transport': 'UDP/TCP', 'Source': 'Learned'})
        return json.dumps(rows) if raw else (tabulate(rows, headers='keys', disable_numparse=True) + '\n' if rows else 'No upstream DNS servers available.\n')
    if kind == 'statistics':
        fields = dict(line.split('=', 1) for line in dns.control(vrf, 'stats_noreset').splitlines() if '=' in line)
        return json.dumps(fields) if raw else tabulate(fields.items(), tablefmt='presto', disable_numparse=True) + '\n'
    if kind == 'local-data':
        text = dns.control(vrf, 'list_local_data')
    elif kind == 'cache':
        # dump_cache is native text; filter by the exact owner name rather than substring.
        text = dns.control(vrf, 'dump_cache')
        if name:
            canonical = name.lower().rstrip('.') + '.'
            text = '\n'.join(line for line in text.splitlines() if line.split() and line.split()[0].lower() == canonical) + '\n'
    else:
        raise RouterError('Unknown DNS display')
    return json.dumps(text.splitlines()) if raw else text


@opmode.command
def clear(kind: str, vrf: str = 'default', scope: str = '', name: str = ''):
    if kind == 'statistics':
        dns.control(vrf, 'stats')
    elif kind == 'cache' and scope == 'all':
        dns.control(vrf, 'flush_zone', '.')
    elif kind == 'cache' and scope in ('name', 'domain') and name:
        dns.control(vrf, 'flush' if scope == 'name' else 'flush_zone', name)
    else:
        raise RouterError('Select cache all, cache name, cache domain, or statistics')
    return 'DNS ' + kind + ' cleared.\n'


if __name__ == '__main__':
    opmode.run()
