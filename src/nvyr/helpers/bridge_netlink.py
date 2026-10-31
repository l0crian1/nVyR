"""Bridge driver: rtnetlink link lifecycle plus iproute2's bridge table API.

All operations run inside netlinkd's serialized, journaled owner transaction.
The bridge utility is an argument-vector Netlink client, never a shell script.
Learned FDB/MDB entries are not flushed during ordinary reconciliation.
"""

import json

from nvyr.helpers import bridge_config as config
from nvyr.helpers.process import cmd


def query(*arguments):
    return json.loads(cmd(list(arguments)))


def write(*arguments):
    cmd([str(value) for value in arguments])


def bridge_data(name):
    result = query('ip', '-d', '-j', 'link', 'show', 'dev', name)[0]['linkinfo']['info_data']
    # iproute2 prints an unnamed EtherType as a bracketed decimal number.
    protocol = result.get('vlan_protocol')
    if protocol in ('[34984]', '[33024]'):
        result['vlan_protocol'] = {'[34984]': '802.1ad', '[33024]': '802.1Q'}[protocol]
    return result


def native_value(name, value):
    if name.endswith('_interval') or name in ('hello_time', 'forward_delay', 'max_age', 'ageing_time'):
        return int(value * 100)
    return value


def data_key(name):
    return name.replace('_interval', '_intvl').replace('_count', '_cnt')


def set_bridge_options(name, desired):
    present = bridge_data(name)
    # Send related timer changes together in one native bridge update.
    changes = []
    for key, value in desired.items():
        current = present.get(data_key(key))
        if key == 'group_fwd_mask' and current is not None:
            current = int(str(current), 0)
        if current != native_value(key, value):
            changes.extend([key, native_value(key, value)])
    if changes:
        write('ip', 'link', 'set', 'dev', name, 'type', 'bridge', *changes)
    return bool(changes)


def vlan_inventory(name):
    result = {}
    for device in query('bridge', '-j', 'vlan', 'show', 'dev', name):
        for entry in device.get('vlans', []):
            flags = entry.get('flags', [])
            for identifier in range(entry['vlan'], entry.get('vlanEnd', entry['vlan']) + 1):
                result[identifier] = ('PVID' in flags, 'Egress Untagged' in flags)
    return result


def reconcile_vlans(name, desired, *, local=False):
    present = vlan_inventory(name)
    scope = ['self'] if local else []
    for identifier, flags in present.items():
        if desired.get(identifier) != flags:
            write('bridge', 'vlan', 'del', 'dev', name, 'vid', identifier, *scope)
    for identifier, (pvid, untagged) in desired.items():
        if present.get(identifier) != (pvid, untagged):
            flags = (['pvid'] if pvid else []) + (['untagged'] if untagged else [])
            write('bridge', 'vlan', 'add', 'dev', name, 'vid', identifier, *scope, *flags)


def reconcile_port(kernel, name, options):
    present = query('bridge', '-d', '-j', 'link', 'show', 'dev', name)[0]
    changes = []
    for key, value in config.port_options(options).items():
        if present.get(key) != value:
            changes.extend([key, ('on' if value else 'off') if type(value) is bool else value])

    backup = options.get('backup-interface')
    if present.get('backup_port') != backup:
        changes.extend(['backup_port', backup] if backup else ['nobackup_port'])
    if changes:
        write('bridge', 'link', 'set', 'dev', name, *changes)

    # group_fwd_mask is exposed by ip's bridge_slave API, not bridge link set.
    device = query('ip', '-d', '-j', 'link', 'show', 'dev', name)[0]
    port_data = device.get('linkinfo', {}).get('info_slave_data', {})
    mask = config.forwarding_mask(options.get('link-local-forward', []))
    current_mask = int(str(port_data.get('group_fwd_mask', '0')), 0)
    if current_mask != mask:
        write('ip', 'link', 'set', 'dev', name, 'type', 'bridge_slave', 'group_fwd_mask', mask)
    kernel.refresh(name)


def reconcile_vlan_options(name, values, members):
    multicast = values.get('multicast', {})
    global_entries = {}
    if 'vlan-snooping' in multicast:
        for device in query('bridge', '-j', 'vlan', 'global', 'show', 'dev', name):
            for entry in device.get('vlans', []):
                global_entries[entry['vlan']] = entry

        for identifier, current in global_entries.items():
            desired = config.multicast_options(lookup_vlan(values, identifier).get('multicast', {}))
            changes = []
            for key, value in desired.items():
                if current.get(key) != native_value(key, value):
                    changes.extend([key, native_value(key, value)])
            if changes:
                write('bridge', 'vlan', 'global', 'set', 'dev', name, 'vid', identifier, *changes)

    for member, options in members.items():
        # Detailed VLAN dumps include port-specific router/suppression attributes.
        current_entries = {}
        for device in query('bridge', '-d', '-j', 'vlan', 'show', 'dev', member):
            for entry in device.get('vlans', []):
                current_entries[entry['vlan']] = entry
        for identifier in config.vlan_memberships(options, bridge=values):
            settings = lookup_vlan(options, identifier)
            mc = settings.get('multicast', {})
            desired = {'neigh_suppress': int('neighbor-suppression' in settings)}
            if 'vlan-snooping' in multicast:
                desired.update(mcast_router=config.ROUTER_MODES[mc.get('router', 'auto')],
                               mcast_max_groups=int(mc.get('maximum-groups', 0)))
            current = current_entries.get(identifier, {})
            changes = []
            for key, value in desired.items():
                if current.get(key, 0 if key == 'neigh_suppress' else None) != value:
                    native = ('on' if value else 'off') if key == 'neigh_suppress' else value
                    changes.extend([key, native])
            if changes:
                write('bridge', 'vlan', 'set', 'dev', member, 'vid', identifier, *changes)


def lookup_vlan(values, identifier):
    return values.get('vlan', {}).get(str(identifier), {})


def forwarding_entries(values):
    entries = set()
    for mac, options in values.get('static-mac', {}).items():
        if 'interface' in options:
            entries.add((mac.lower(), options['interface'], 0))
        for identifier, entry in options.get('vlan', {}).items():
            entries.add((mac.lower(), entry['interface'], int(identifier)))
    return entries


def reconcile_fdb(kernel, name, values):
    desired = forwarding_entries(values)
    members = values.get('member', {}).get('interface', {})
    # An unaware bridge installs an unscoped entry in VLAN zero and each
    # admitted VLAN. Represent that native expansion explicitly when comparing.
    if 'vlan-filtering' not in values:
        for mac, port, identifier in list(desired):
            for vlan in config.vlan_memberships(members[port], bridge=values):
                desired.add((mac, port, vlan))
    present = set()
    for entry in query('bridge', '-j', 'fdb', 'show', 'br', name):
        if entry.get('master') == name and entry.get('state') == 'static':
            present.add((entry['mac'].lower(), entry['ifname'], entry.get('vlan', 0)))
    for mac, port, identifier in sorted(present - desired):
        if (mac, port, identifier) not in present:
            continue
        arguments = {'vlan': identifier} if identifier else {}
        kernel.ipr.fdb('del', ifindex=kernel.device(port)['index'],
                       lladdr=mac, flags=4, state=64, **arguments)
        if identifier:
            present.discard((mac, port, identifier))
        else:
            present = {entry for entry in present if entry[:2] != (mac, port)}
    for mac, port, identifier in sorted(desired - present):
        if (mac, port, identifier) in present:
            continue
        arguments = {'vlan': identifier} if identifier else {}
        kernel.ipr.fdb('replace', ifindex=kernel.device(port)['index'],
                       lladdr=mac, flags=4, state=64, **arguments)
        present.add((mac, port, identifier))
        if not identifier:
            present.update((mac, port, vlan) for vlan in config.vlan_memberships(members[port], bridge=values))


def multicast_entries(values):
    entries = set()
    for entry in values.get('multicast', {}).get('static-group', {}).values():
        for port in entry['interface']:
            entries.add((entry['address'], port, int(entry.get('vlan', 0)), entry.get('source', '')))
    return entries


def reconcile_mdb(name, values):
    desired = multicast_entries(values)
    present = set()
    for bridge in query('bridge', '-j', 'mdb', 'show', 'dev', name):
        for entry in bridge.get('mdb', []):
            if entry.get('state') == 'permanent':
                present.add((entry['grp'], entry['port'], entry.get('vid', 0), entry.get('src', '')))
    for operation, entries in [('del', present - desired), ('replace', desired - present)]:
        for address, port, identifier, source in sorted(entries):
            extra = (['vid', identifier] if identifier else []) + (['src', source] if source else [])
            write('bridge', 'mdb', operation, 'dev', name, 'port', port, 'grp', address, 'permanent', *extra)
