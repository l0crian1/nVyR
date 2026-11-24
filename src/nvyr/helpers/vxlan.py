"""VXLAN link, tunnel FDB and bridge tunnel-map operations."""

import ipaddress

from nvyr.helpers.bridge_netlink import query, write
from nvyr.helpers.validators import duration_seconds

FLOOD_MAC = '00:00:00:00:00:00'


def settings(values):
    """Translate the configuration into the native ip/bridge argument vocabulary."""
    options = {}
    for key, option in (('vni', 'id'), ('source-interface', 'dev'), ('source-address', 'local'),
                        ('remote', 'remote'), ('multicast-group', 'group'), ('destination-port', 'dstport'),
                        ('dont-fragment', 'df'), ('ttl', 'ttl'), ('flow-label', 'flowlabel')):
        if key in values:
            value = str(values[key])
            if option in ('local', 'remote', 'group'):
                value = str(ipaddress.ip_address(value))
            elif value.isdecimal():
                value = str(int(value))
            options[option] = value
    if 'external' in values:
        options['external'] = True
        if 'vni-filter' in values['external']:
            options['vnifilter'] = True
    if 'tos' in values:
        tos = values['tos']
        options['tos'] = 'inherit' if tos == 'inherit' else hex(int(tos))
    if 'source-port' in values:
        ports = values['source-port']
        options['srcport'] = [str(int(ports['minimum'])), str(int(ports['maximum']))]
    learning = values.get('learning', {})
    if 'learning' in values:
        options['learning'] = 'disable' not in learning
    if 'ageing-time' in learning:
        age = duration_seconds(learning['ageing-time'])
        # Linux interprets zero as its default ageing interval (300 seconds).
        options['ageing'] = str(age or 300)
    if 'maximum-entries' in learning:
        options['maxaddress'] = str(int(learning['maximum-entries']))

    for subtree, key, option in ((values, 'proxy', 'proxy'), (values, 'route-short-circuit', 'rsc'),
                                 (values.get('miss-notification', {}), 'l2', 'l2miss'),
                                 (values.get('miss-notification', {}), 'l3', 'l3miss'),
                                 (values.get('checksum', {}), 'ipv6-zero-receive', 'udp6zerocsumrx'),
                                 (values.get('checksum', {}), 'ipv6-zero-transmit', 'udp6zerocsumtx')):
        if key in subtree:
            options[option] = True

    checksum = values.get('checksum', {})
    if 'ipv4' in checksum:
        options['udpcsum'] = checksum['ipv4'] == 'enable'

    fdb = {(FLOOD_MAC, str(ipaddress.ip_address(remote))) for remote in values.get('flood-vtep', ())}
    fdb.update((mac.lower(), str(ipaddress.ip_address(entry['remote'])))
               for mac, entry in values.get('static-mac', {}).items())
    vnis = sorted(int(row['vni']) for row in values.get('external', {}).get('vlan', {}).values())
    return {'options': options, 'fdb': [list(pair) for pair in sorted(fdb)], 'vnis': vnis}


def family(settings):
    options = settings['options']
    for key in ('local', 'remote', 'group'):
        if key in options:
            return ipaddress.ip_address(options[key]).version
    if settings['fdb']:
        return ipaddress.ip_address(settings['fdb'][0][1]).version
    return 6 if 'flowlabel' in options else 4


def arguments(options):
    result = []
    for key, value in options.items():
        if isinstance(value, bool):
            result.append(key if value else 'no' + key)
        elif isinstance(value, list):
            result.extend([key, *value])
        else:
            result.extend([key, value])
    return result


def create(name, settings):
    options = dict(settings['options'])
    if family(settings) == 6 and not {'local', 'remote', 'group'} & options.keys():
        options['local'] = '::'
    write('ip', 'link', 'add', 'name', name, 'type', 'vxlan', *arguments(options))


def immutable_change(old, new):
    before, after = old['options'], new['options']
    defaults = {'id': None, 'external': False, 'vnifilter': False, 'srcport': ['0', '0'],
                'dstport': '8472', 'maxaddress': '0', 'proxy': False, 'rsc': False, 'l2miss': False,
                'l3miss': False, 'udpcsum': True, 'udp6zerocsumrx': False, 'udp6zerocsumtx': False}
    for key, default in defaults.items():
        if before.get(key, default) != after.get(key, default):
            return key
    if (before.get('ttl') == 'inherit') != (after.get('ttl') == 'inherit'):
        return 'ttl inherit'
    if family(old) != family(new):
        return 'underlay address family'
    # Linux can rebind to another device but cannot clear the binding, including during rollback.
    if ('dev' in before) != ('dev' in after):
        return 'source-interface binding'
    return None


def reconcile_options(name, settings):
    options = settings['options']
    current = query('ip', '-d', '-j', 'link', 'show', 'dev', name)[0]['linkinfo']['info_data']
    underlay = options.get('dev')
    any_address = '::' if family(settings) == 6 else '0.0.0.0'
    changes = {}
    if underlay and current.get('link') != underlay:
        changes['dev'] = underlay
    for option, observed, desired in (
            ('local', current.get('local') or current.get('local6'), options.get('local')),
            ('remote', current.get('remote') or current.get('remote6') or current.get('group') or current.get('group6'),
             options.get('remote') or options.get('group'))):
        if (ipaddress.ip_address(observed or any_address) != ipaddress.ip_address(desired or any_address)):
            changes['group' if option == 'remote' and 'group' in options else option] = desired or any_address

    ttl = options.get('ttl', 'auto')
    tos = options.get('tos', '0x0')
    expected = {'df': options.get('df', 'unset'), 'learning': options.get('learning', 'external' not in options),
                'ageing': options.get('ageing', '300'), 'flowlabel': str(int(options.get('flowlabel', 0))),
                'tos': tos}
    present = {'df': current['df'], 'learning': current['learning'],
               'ageing': str(current['ageing']),
               'flowlabel': str(int(str(current.get('label', 0)), 0)),
               'tos': hex(int(str(current.get('tos', 0)), 0))}
    if tos == 'inherit':
        present['tos'] = 'inherit' if present['tos'] == '0x1' else present['tos']
    if ttl != 'inherit':
        expected['ttl'] = ttl
        present['ttl'] = str(current['ttl']) if current.get('ttl') else 'auto'
    changes.update({key: value for key, value in expected.items() if value != present[key]})
    if changes:
        write('ip', 'link', 'set', 'dev', name, 'type', 'vxlan', *arguments(changes))
    return bool(changes)


def mappings(name):
    result = {}
    for port in query('bridge', '-j', 'vlan', 'tunnelshow', 'dev', name):
        for row in port.get('tunnels', []):
            first = row['vlan']
            for vid in range(first, row.get('vlanEnd', first) + 1):
                result[vid] = row['tunid'] + vid - first
    return result


def admitted_vnis(name):
    return {vni for port in query('bridge', '-j', 'vni', 'show', 'dev', name)
            for row in port.get('vnis', [])
            for vni in range(row['vni'], row.get('vniEnd', row['vni']) + 1)}


def reconcile_mappings(name, desired):
    desired = {int(vid): int(vni) for vid, vni in desired.items()}
    port = query('bridge', '-d', '-j', 'link', 'show', 'dev', name)[0]
    if not desired and not port.get('vlan_tunnel'):
        return
    if not port.get('vlan_tunnel'):
        write('bridge', 'link', 'set', 'dev', name, 'vlan_tunnel', 'on')
    present = mappings(name)
    for vid, vni in sorted(present.items() - desired.items()):
        write('bridge', 'vlan', 'del', 'dev', name, 'vid', vid, 'tunnel_info', 'id', vni)
    for vid, vni in sorted(desired.items() - present.items()):
        write('bridge', 'vlan', 'add', 'dev', name, 'vid', vid, 'tunnel_info', 'id', vni)
    if not desired:
        write('bridge', 'link', 'set', 'dev', name, 'vlan_tunnel', 'off')


def reconcile_tables(name, settings, record, save):
    if settings['options'].get('vnifilter'):
        present = admitted_vnis(name)
        desired = set(settings['vnis'])
        for vni in sorted(present - desired):
            write('bridge', 'vni', 'del', 'dev', name, 'vni', vni)
        for vni in sorted(desired - present):
            write('bridge', 'vni', 'add', 'dev', name, 'vni', vni)

    desired = {tuple(pair) for pair in settings['fdb']}
    owned = {tuple(pair) for pair in record.get('vxlan-fdb', [])}
    if not (desired or owned):
        return
    entries = query('bridge', '-j', 'fdb', 'show', 'dev', name)
    present = {(row['mac'], row['dst']) for row in entries if row.get('dst')
               and 'self' in row.get('flags', []) and row.get('state') == 'permanent'}
    default = settings['options'].get('remote') or settings['options'].get('group')
    for mac, remote in sorted((owned - desired) & present):
        if mac != FLOOD_MAC or remote != default:
            write('bridge', 'fdb', 'del', mac, 'dev', name, 'dst', remote, 'self')
    # Journal the new ownership before insertion so partial writes can be rolled back.
    if owned != desired:
        record['vxlan-fdb'] = sorted(desired)
        save(name)
    for mac, remote in sorted(desired - present):
        operation = 'append' if mac == FLOOD_MAC else 'replace'
        write('bridge', 'fdb', operation, mac, 'dev', name, 'dst', remote, 'self', 'permanent')
