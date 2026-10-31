"""Native bridge option conversion shared by verification and netlinkd."""

from nvyr.helpers.validators import duration_seconds


ROUTER_MODES = {'disabled': 0, 'auto': 1, 'permanent': 2}
FORWARD_PROTOCOLS = {'lldp': 1 << 14, 'eapol': 1 << 3}
MULTICAST_DEFAULTS = {
    'last-member-count': 2,
    'last-member-interval': '1s',
    'startup-query-count': 2,
    'startup-query-interval': 31.25,
    'membership-interval': '260s',
    'querier-interval': '255s',
    'query-interval': '125s',
    'query-response-interval': '10s',
}


def disabled(configuration, name):
    return 'disable' in configuration.get(name, {})


def multicast_options(configuration):
    result = {
        'mcast_snooping': int(not disabled(configuration, 'snooping')),
        'mcast_querier': int('querier' in configuration),
        'mcast_igmp_version': int(configuration.get('igmp-version', 2)),
        'mcast_mld_version': int(configuration.get('mld-version', 1)),
    }

    for name, default in MULTICAST_DEFAULTS.items():
        value = configuration.get(name, default)
        if name.endswith('interval') and isinstance(value, str):
            value = duration_seconds(value)
        result['mcast_' + name.replace('-', '_')] = value if name.endswith('interval') else int(value)

    return result


def forwarding_mask(values):
    return sum(FORWARD_PROTOCOLS[name] for name in set(values))


def bridge_options(configuration):
    stp = configuration.get('spanning-tree', {})
    learning = configuration.get('mac-learning', {})
    multicast = configuration.get('multicast', {})
    result = multicast_options(multicast)
    result.update({
        'stp_state': int('spanning-tree' in configuration),
        'priority': int(stp.get('priority', 32768)),
        'hello_time': duration_seconds(stp.get('hello-time', '2s')),
        'forward_delay': duration_seconds(stp.get('forward-delay', '15s')),
        'max_age': duration_seconds(stp.get('max-age', '20s')),
        'ageing_time': duration_seconds(learning.get('ageing-time', '300s')),
        'fdb_max_learned': int(learning.get('maximum-entries', 0)),
        'no_linklocal_learn': int(disabled(learning, 'link-local')),
        'group_fwd_mask': forwarding_mask(configuration.get('link-local-forward', [])),
        'vlan_filtering': int('vlan-filtering' in configuration),
        'vlan_protocol': configuration.get('vlan-protocol', '802.1q').replace('q', 'Q'),
        'vlan_default_pvid': int(configuration.get('default-pvid', 1)),
        'vlan_stats_enabled': int('vlan-statistics' in configuration),
        'vlan_stats_per_port': int('vlan-statistics-per-port' in configuration),
        'mcast_vlan_snooping': int('vlan-snooping' in multicast),
        'mcast_router': ROUTER_MODES[multicast.get('router', 'auto')],
        'mcast_query_use_ifaddr': int('query-use-interface-address' in multicast),
        'mcast_stats_enabled': int('statistics' in multicast),
    })
    return result


def port_options(configuration):
    stp = configuration.get('spanning-tree', {})
    flood = configuration.get('flood', {})
    multicast = configuration.get('multicast', {})
    return {
        'cost': int(stp.get('cost', 100)),
        'priority': int(stp.get('priority', 32)),
        'guard': 'bpdu-guard' in stp,
        'root_block': 'root-guard' in stp,
        'learning': not disabled(configuration, 'learning'),
        'hairpin': 'hairpin' in configuration,
        'isolated': 'isolated' in configuration,
        'locked': 'locked' in configuration,
        'flood': not disabled(flood, 'unknown-unicast'),
        'mcast_flood': not disabled(flood, 'unknown-multicast'),
        'bcast_flood': not disabled(flood, 'broadcast'),
        'fastleave': 'fast-leave' in multicast,
        'mcast_to_unicast': 'to-unicast' in multicast,
        'mcast_router': ROUTER_MODES[multicast.get('router', 'auto')],
        'mcast_max_groups': int(multicast.get('maximum-groups', 0)),
        'neigh_suppress': 'neighbor-suppression' in configuration,
        'neigh_vlan_suppress': 'neighbor-vlan-suppression' in configuration,
    }


def vlan_memberships(configuration, *, local=False, bridge=None):
    """Return explicit plus implicit membership; an explicit PVID replaces the default."""
    result = {}
    for identifier, options in configuration.get('vlan', {}).items():
        if local:
            if 'local' not in options:
                continue
            options = options['local']
        result[int(identifier)] = ('pvid' in options, 'untagged' in options)

    if local:
        for identifier in configuration.get('vif', {}):
            result.setdefault(int(identifier), (False, False))

    default = int((bridge or configuration).get('default-pvid', 1))
    if default and not any(pvid for pvid, untagged in result.values()):
        result.setdefault(default, (True, True))
    return result
